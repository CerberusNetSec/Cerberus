"""SQLite storage. One writer connection behind a lock and a small pool of
readers (WAL, so reads never wait for the writer); async callers go through the
a* wrappers, which run in worker threads.

Events live in a chain of segment tables (events_000001, events_000002, ...),
each holding a bounded number of rows in arrival order. Only the newest is
written to, so its indexes stay small enough to update cheaply however much
history is kept, and expiring old data is dropping a table rather than deleting
millions of rows."""
from __future__ import annotations

import asyncio
import json
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

READERS = 4
SEGMENT_ROWS = 250_000  # events per segment table
SEGMENT_SECONDS = 86400  # ... or a day, whichever fills first, so retention is honoured on quiet systems
EVENT_COLUMNS = ("ts", "device", "hostname", "connector", "app", "sev", "event_type", "action", "src_ip", "dst_ip",
                 "src_port", "dst_port", "proto", "bytes", "user", "interface", "message", "extra")
# Rows inside a segment are in id order, and SQLite keeps each index in id order
# within one value, so "this address, newest first" walks an index and stops after a page.
SEGMENT_DDL = (
    """CREATE TABLE {name} (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    device TEXT, hostname TEXT, connector TEXT, app TEXT, sev INTEGER,
    event_type TEXT, action TEXT,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, proto TEXT,
    bytes INTEGER, user TEXT, interface TEXT, message TEXT, extra TEXT
)""",
    "CREATE INDEX {name}_src ON {name}(src_ip) WHERE src_ip IS NOT NULL",
    "CREATE INDEX {name}_dst ON {name}(dst_ip) WHERE dst_ip IS NOT NULL",
    "CREATE INDEX {name}_device ON {name}(device)",
    "CREATE INDEX {name}_port ON {name}(dst_port) WHERE dst_port IS NOT NULL",
)


def segment_rows_for(max_events: int) -> int:
    """Segment size for a given event cap: at least eight segments, so pruning (which
    removes whole segments) never takes more than an eighth of the history at once."""
    return max(5_000, min(SEGMENT_ROWS, max_events // 8))


from .models import SEVERITIES  # noqa: E402
from .storage import TOTAL, Batch, QueryTimeout, Store  # noqa: E402,F401  (QueryTimeout: re-exported)

SCHEMA = """
CREATE TABLE IF NOT EXISTS event_segments (
    n INTEGER PRIMARY KEY, name TEXT NOT NULL,
    first_id INTEGER NOT NULL, first_ts REAL NOT NULL, rows INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    created REAL NOT NULL, last_seen REAL NOT NULL,
    detector TEXT, severity TEXT, title TEXT, description TEXT, entity TEXT,
    src_ip TEXT, device TEXT, count INTEGER DEFAULT 1,
    status TEXT DEFAULT 'open', details TEXT
);
CREATE INDEX IF NOT EXISTS alerts_last ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status, last_seen);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    ip TEXT, hostname TEXT, name TEXT DEFAULT '',
    connector_pin TEXT DEFAULT '', connector_seen TEXT DEFAULT '',
    first_seen REAL, last_seen REAL, events INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stats_minute (
    minute INTEGER NOT NULL, device TEXT NOT NULL,
    events INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0,
    PRIMARY KEY (minute, device)
);

-- Traffic on high-risk ports, for the High Risk Ports page. direction: inbound, outbound or internal.
CREATE TABLE IF NOT EXISTS port_minute (
    minute INTEGER NOT NULL, port INTEGER NOT NULL, direction TEXT NOT NULL,
    allowed INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0,
    PRIMARY KEY (minute, port, direction)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

-- Dashboard logins. Only a hash of each session token is kept.
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, expires REAL NOT NULL);

-- Central console only: the sites that report here, and their alerts.
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, token_hash TEXT UNIQUE, managed INTEGER DEFAULT 0,
    created REAL, last_seen REAL, silent INTEGER DEFAULT 0,
    address TEXT, version TEXT, reported_name TEXT, instance TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS site_alerts (
    id INTEGER PRIMARY KEY,
    site_id INTEGER NOT NULL, instance TEXT NOT NULL, alert_id INTEGER NOT NULL,
    created REAL, last_seen REAL, received REAL,
    detector TEXT, severity TEXT, title TEXT, description TEXT, entity TEXT,
    src_ip TEXT, device TEXT, count INTEGER, details TEXT,
    status TEXT DEFAULT 'open', pending TEXT,
    UNIQUE (site_id, instance, alert_id)
);
CREATE INDEX IF NOT EXISTS site_alerts_last ON site_alerts(last_seen);
CREATE INDEX IF NOT EXISTS site_alerts_status ON site_alerts(status, last_seen);

CREATE TABLE IF NOT EXISTS snmp_data (
    device TEXT PRIMARY KEY,
    polled REAL, ok INTEGER, error TEXT, last_ok REAL, data TEXT
);

CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL, name TEXT NOT NULL,
    enabled INTEGER DEFAULT 1, min_severity TEXT DEFAULT 'medium',
    config TEXT DEFAULT '{}',
    last_ts REAL, last_ok INTEGER, last_error TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL NOT NULL, channel_id INTEGER NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
    attempts INTEGER DEFAULT 0, next_try REAL NOT NULL, done INTEGER DEFAULT 0, error TEXT
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(done, next_try);
CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL NOT NULL, detector TEXT NOT NULL, entity TEXT NOT NULL, title TEXT, alert_id INTEGER,
    justification TEXT NOT NULL, analyst TEXT NOT NULL, source TEXT,
    active INTEGER NOT NULL DEFAULT 1, removed REAL, removed_by TEXT, removed_source TEXT, removed_justification TEXT,
    hits INTEGER NOT NULL DEFAULT 0, last_hit REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS suppressions_active ON suppressions(detector, entity) WHERE active = 1;
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, action TEXT NOT NULL, analyst TEXT, source TEXT,
    alert_id INTEGER, suppression_id INTEGER, detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_alert ON audit_log(alert_id);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, scope TEXT NOT NULL,
    last_used REAL, revoked REAL
);
"""

# Columns added after the first release: (table, column, definition).
MIGRATIONS = [
    ("devices", "snmp_mode", "TEXT DEFAULT 'default'"),
    ("devices", "snmp_community", "TEXT DEFAULT ''"),
    ("devices", "snmp_host", "TEXT DEFAULT ''"),
    ("alerts", "updated", "REAL DEFAULT 0"),  # when the row last changed; what a site reports from
    ("outbox", "payload", "TEXT"),  # the alert as JSON, for webhooks and API calls (0.11.0)
]


class Database(Store):
    def __init__(self, path: Path, segment_rows: int = SEGMENT_ROWS):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.segment_rows = segment_rows
        self._segments: list[dict] = []  # oldest first; the last one is being written
        self._next_id = 1
        self._w = self._connect(path)
        # The writer keeps the hot ends of five indexes in memory; with too little cache
        # every batch of events turns into scattered disk reads once the table is large.
        self._w.execute("PRAGMA cache_size=-131072")  # 128 MB
        self._wlock = threading.Lock()
        # Several readers, so one slow search cannot freeze the dashboard for everyone.
        self._all_readers = [self._connect(path) for _ in range(READERS)]
        self._readers: queue.SimpleQueue = queue.SimpleQueue()
        for conn in self._all_readers:
            self._readers.put(conn)
        with self._wlock:
            self._w.executescript(SCHEMA)
            for table, column, definition in MIGRATIONS:
                have = {row["name"] for row in self._w.execute(f"PRAGMA table_info({table})")}
                if column not in have:
                    self._w.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            self._w.execute("CREATE INDEX IF NOT EXISTS alerts_updated ON alerts(updated, id)")
            self._adopt_legacy_events()
            self._w.commit()
            self._load_segments()

    def _adopt_legacy_events(self) -> None:
        """Databases from before segments have one `events` table. Keep it as the oldest segment."""
        legacy = self._w.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
        known = self._w.execute("SELECT 1 FROM event_segments WHERE name='events'").fetchone()
        if not legacy or known:
            return
        first = self._w.execute("SELECT id, ts FROM events ORDER BY id LIMIT 1").fetchone()
        if first is None:
            self._w.execute("DROP TABLE events")
            return
        rows = self._w.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self._w.execute("INSERT INTO event_segments(n, name, first_id, first_ts, rows) VALUES(0, 'events', ?, ?, ?)",
                        (first["id"], first["ts"], rows))

    def _load_segments(self) -> None:
        self._segments = [dict(r) for r in self._w.execute("SELECT * FROM event_segments ORDER BY n")]
        self._next_id = 1
        if self._segments:
            last = self._segments[-1]
            top = self._w.execute(f"SELECT MAX(id) FROM {last['name']}").fetchone()[0]
            self._next_id = max(last["first_id"], (top or 0) + 1)

    def _segment_for(self, ts: float) -> dict:
        """The segment to write an event stamped ts into, starting a new one when the
        current is full or a day old. Caller holds the write lock, with no transaction open."""
        cur = self._segments[-1] if self._segments else None
        if cur is not None and cur["rows"] < self.segment_rows and ts - cur["first_ts"] <= SEGMENT_SECONDS:
            return cur
        seg = {"n": (cur["n"] if cur else 0) + 1, "first_id": self._next_id, "first_ts": ts, "rows": 0}
        seg["name"] = f"events_{seg['n']:06d}"
        for statement in SEGMENT_DDL:
            self._w.execute(statement.format(name=seg["name"]))
        self._w.execute("INSERT INTO event_segments(n, name, first_id, first_ts, rows) VALUES(?,?,?,?,0)",
                        (seg["n"], seg["name"], seg["first_id"], ts))
        self._w.commit()
        self._segments.append(seg)
        return seg

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-32000")  # 32 MB per connection
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA journal_size_limit=67108864")  # keep the WAL file from growing without bound
        return conn

    # --- sync primitives -------------------------------------------------
    def q(self, sql: str, params=(), timeout: float = 0) -> list[dict]:
        """Run a read. With a timeout (seconds), a query still running at the deadline
        is cancelled and QueryTimeout raised."""
        conn = self._readers.get()
        try:
            if timeout:
                deadline = time.monotonic() + timeout
                conn.set_progress_handler(lambda: time.monotonic() > deadline, 20_000)
            return [dict(row) for row in conn.execute(sql, params).fetchall()]
        except sqlite3.OperationalError as exc:
            if timeout and "interrupt" in str(exc).lower():
                raise QueryTimeout() from None
            raise
        finally:
            if timeout:
                conn.set_progress_handler(None, 0)
            self._readers.put(conn)

    @contextmanager
    def transaction(self):
        """The writer connection, inside one transaction (committed on success, rolled back on error)."""
        with self._wlock:
            try:
                yield self._w
                self._w.commit()
            except Exception:
                self._w.rollback()
                raise

    def x(self, sql: str, params=()) -> int:
        """Run one write statement; returns lastrowid for inserts, else rowcount."""
        with self._wlock:
            cur = self._w.execute(sql, params)
            self._w.commit()
            return cur.lastrowid if sql.lstrip()[:6].upper() == "INSERT" else cur.rowcount

    def batch(self, statements: list[tuple[str, list]]) -> None:
        """Run several executemany() calls in one transaction."""
        with self._wlock:
            try:
                for sql, rows in statements:
                    if rows:
                        self._w.executemany(sql, rows)
                self._w.commit()
            except Exception:
                self._w.rollback()
                raise

    def write(self, events: list[tuple], statements: list[tuple[str, list]] = ()) -> None:
        """Store a batch of events (tuples in EVENT_COLUMNS order, oldest first) and run
        the other statements, all in one transaction."""
        with self._wlock:
            try:
                seg = None
                if events:
                    seg = self._segment_for(events[0][0])
                    first = self._next_id
                    self._w.executemany(
                        f"INSERT INTO {seg['name']}(id, {', '.join(EVENT_COLUMNS)}) "
                        f"VALUES({','.join('?' * (len(EVENT_COLUMNS) + 1))})",
                        [(first + i, *row) for i, row in enumerate(events)])
                    self._w.execute("UPDATE event_segments SET rows = rows + ? WHERE n = ?", (len(events), seg["n"]))
                for sql, rows in statements:
                    if rows:
                        self._w.executemany(sql, rows)
                self._w.commit()
            except Exception:
                self._w.rollback()
                raise
            if seg is not None:
                self._next_id += len(events)
                seg["rows"] += len(events)

    def _search(self, where: list[str] = (), params: list = (), since: float = 0, before: int = 0,
                limit: int = 200, timeout: float = 0) -> list[dict]:
        """Newest-first events matching the SQL conditions, at or after `since`, with id
        below `before` if given. Segments are read newest to oldest and reading stops as
        soon as the page is full or the time range is left behind."""
        deadline = time.monotonic() + timeout if timeout else 0
        segments = list(self._segments)
        out: list[dict] = []
        for i in range(len(segments) - 1, -1, -1):
            seg = segments[i]
            if i + 1 < len(segments) and segments[i + 1]["first_ts"] <= since:
                break  # this segment and all older ones end before the range starts
            if not seg["rows"] or (before and seg["first_id"] >= before):
                continue
            left = 0.0
            if deadline:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise QueryTimeout()
            clauses = ["ts >= ?", *(["id < ?"] if before else []), *where]
            args = [since, *([before] if before else []), *params, limit - len(out)]
            try:
                out += self.q(f"SELECT * FROM {seg['name']} WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?",
                              args, timeout=left)
            except sqlite3.OperationalError as exc:
                if "no such table" in str(exc):
                    continue  # expired while we were searching
                raise
            if len(out) >= limit:
                break
        return out

    def events_stored(self) -> int:
        return sum(seg["rows"] for seg in list(self._segments))

    def oldest_event_ts(self) -> float | None:
        return next((seg["first_ts"] for seg in list(self._segments) if seg["rows"]), None)

    def get_setting(self, key: str, default=None):
        rows = self.q("SELECT value FROM settings WHERE key=?", (key,))
        if not rows:
            return default
        try:
            return json.loads(rows[0]["value"])
        except ValueError:
            return default

    def leadership(self, name: str):
        from .storage import SingleProcess
        return SingleProcess()

    def settings_with_prefix(self, prefix: str) -> dict:
        out = {}
        for row in self.q("SELECT key, value FROM settings WHERE substr(key, 1, length(?)) = ?", (prefix, prefix)):
            try:
                out[row["key"]] = json.loads(row["value"])
            except ValueError:
                pass
        return out

    def set_setting(self, key: str, value) -> None:
        self.x(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )

    def prune(self, now: float, retention_days: int, max_events: int, alert_days: int) -> int:
        """Drop what is past retention. Returns the number of events removed.

        Whole segments go at once: the oldest is dropped when everything in it is older
        than the retention period, or when the rest still hold max_events without it.
        The segment being written is never dropped."""
        cutoff = now - retention_days * 86400
        removed = 0
        while len(self._segments) > 1:
            with self._wlock:
                oldest, following = self._segments[0], self._segments[1]
                total = sum(seg["rows"] for seg in self._segments)
                if following["first_ts"] >= cutoff and total - oldest["rows"] < max_events:
                    break
                self._w.execute(f"DROP TABLE IF EXISTS {oldest['name']}")
                self._w.execute("DELETE FROM event_segments WHERE n = ?", (oldest["n"],))
                self._w.commit()
                del self._segments[0]
                removed += oldest["rows"]
        self.x("DELETE FROM stats_minute WHERE minute < ?", (int(cutoff),))
        self.x("DELETE FROM port_minute WHERE minute < ?", (int(cutoff),))
        self.x("DELETE FROM alerts WHERE last_seen < ?", (now - alert_days * 86400,))
        self.x("DELETE FROM sessions WHERE expires < ?", (now,))
        self.x("DELETE FROM site_alerts WHERE last_seen < ?", (now - alert_days * 86400,))
        from .storage import OUTBOX_KEEP_SECONDS
        self.x("DELETE FROM outbox WHERE done != 0 AND next_try < ?", (now - OUTBOX_KEEP_SECONDS,))
        return removed

    # =====================================================================
    # The storage contract (cerberus/storage.py), on SQLite.
    # =====================================================================

    # --- the pipeline's writes --------------------------------------------
    def write_batch(self, batch: Batch) -> None:
        self.write(batch.events, [
            ("INSERT INTO stats_minute(minute, device, events, blocked) VALUES(?,?,?,?) "
             "ON CONFLICT(minute, device) DO UPDATE SET events=events+excluded.events, "
             "blocked=blocked+excluded.blocked", batch.stats),
            ("INSERT INTO devices(id, ip, hostname, connector_seen, first_seen, last_seen, events) "
             "VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET ip=excluded.ip, hostname=excluded.hostname, "
             "connector_seen=excluded.connector_seen, last_seen=excluded.last_seen, events=excluded.events",
             batch.devices),
            ("INSERT INTO port_minute(minute, port, direction, allowed, blocked) VALUES(?,?,?,?,?) "
             "ON CONFLICT(minute, port, direction) DO UPDATE SET allowed=allowed+excluded.allowed, "
             "blocked=blocked+excluded.blocked", batch.ports),
            ("INSERT OR REPLACE INTO alerts(id, created, last_seen, detector, severity, title, description, "
             "entity, src_ip, device, count, status, details, updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             batch.new_alerts),
            ("UPDATE alerts SET last_seen=?, count=?, severity=?, description=?, details=?, updated=? WHERE id=?",
             batch.alert_updates),
            ("INSERT INTO outbox(created, channel_id, subject, body, payload, next_try) VALUES(?,?,?,?,?,?)",
             [(*n[:4], n[4] if len(n) > 4 else None, n[0]) for n in batch.notices]),
            ("UPDATE suppressions SET hits = hits + ?, last_hit = ? WHERE id = ?", batch.suppression_hits),
        ])

    # --- false positives ------------------------------------------------------
    def false_positive(self, alert_id: int, when: float, justification: str, analyst: str, source: str) -> dict:
        from .storage import NotFound
        with self.transaction() as conn:
            alert = conn.execute("SELECT detector, entity, title FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if alert is None:
                raise NotFound(f"no alert {alert_id}")
            detector, entity, title = alert
            row = conn.execute("SELECT id FROM suppressions WHERE detector = ? AND entity = ? AND active = 1",
                               (detector, entity)).fetchone()
            if row:
                suppression_id, action = row[0], "false_positive_again"
            else:
                suppression_id = conn.execute(
                    "INSERT INTO suppressions(created, detector, entity, title, alert_id, justification, analyst, "
                    "source) VALUES(?,?,?,?,?,?,?,?)",
                    (when, detector, entity, title, alert_id, justification, analyst, source)).lastrowid
                action = "false_positive"
            conn.execute("UPDATE alerts SET status = 'false_positive', updated = ? WHERE id = ?", (when, alert_id))
            conn.execute("INSERT INTO audit_log(ts, action, analyst, source, alert_id, suppression_id, detail) "
                         "VALUES(?,?,?,?,?,?,?)",
                         (when, action, analyst, source, alert_id, suppression_id,
                          json.dumps({"justification": justification, "detector": detector, "entity": entity,
                                      "title": title})))
        return self.q("SELECT * FROM suppressions WHERE id = ?", (suppression_id,))[0]

    def suppression_remove(self, suppression_id: int, when: float, justification: str, analyst: str,
                           source: str) -> dict:
        from .storage import NotFound
        with self.transaction() as conn:
            row = conn.execute("SELECT detector, entity FROM suppressions WHERE id = ? AND active = 1",
                               (suppression_id,)).fetchone()
            if row is None:
                raise NotFound(f"no active suppression {suppression_id}")
            conn.execute("UPDATE suppressions SET active = 0, removed = ?, removed_by = ?, removed_source = ?, "
                         "removed_justification = ? WHERE id = ?",
                         (when, analyst, source, justification, suppression_id))
            conn.execute("INSERT INTO audit_log(ts, action, analyst, source, alert_id, suppression_id, detail) "
                         "VALUES(?,?,?,?,?,?,?)",
                         (when, "suppression_removed", analyst, source, None, suppression_id,
                          json.dumps({"justification": justification, "detector": row[0], "entity": row[1]})))
        return self.q("SELECT * FROM suppressions WHERE id = ?", (suppression_id,))[0]

    def suppressions(self) -> list[dict]:
        return self.q("SELECT * FROM suppressions ORDER BY id DESC")

    def audit_add(self, row: dict) -> int:
        with self.transaction() as conn:
            return conn.execute(
                "INSERT INTO audit_log(ts, action, analyst, source, alert_id, suppression_id, detail) VALUES(?,?,?,?,?,?,?)",
                (row["ts"], row["action"], row.get("analyst"), row.get("source"), row.get("alert_id"),
                 row.get("suppression_id"), row.get("detail"))).lastrowid

    def token_add(self, row: dict) -> int:
        with self.transaction() as conn:
            return conn.execute("INSERT INTO api_tokens(created, name, token_hash, scope) VALUES(?,?,?,?)",
                                (row["created"], row["name"], row["token_hash"], row["scope"])).lastrowid

    def tokens(self) -> list[dict]:
        return self.q("SELECT id, created, name, scope, last_used, revoked FROM api_tokens ORDER BY id DESC")

    def token_by_hash(self, token_hash: str) -> dict | None:
        rows = self.q("SELECT id, created, name, scope, last_used, revoked FROM api_tokens "
                      "WHERE token_hash = ? AND revoked IS NULL", (token_hash,))
        return rows[0] if rows else None

    def token_used(self, token_id: int, when: float) -> None:
        self.x("UPDATE api_tokens SET last_used = ? WHERE id = ?", (when, token_id))

    def token_revoke(self, token_id: int, when: float) -> dict | None:
        if not self.x("UPDATE api_tokens SET revoked = ? WHERE id = ? AND revoked IS NULL", (when, token_id)):
            return None
        return self.q("SELECT id, created, name, scope, last_used, revoked FROM api_tokens WHERE id = ?", (token_id,))[0]

    def audit_log(self, limit: int, alert_id: int = 0) -> list[dict]:
        if alert_id:
            return self.q("SELECT * FROM audit_log WHERE alert_id = ? ORDER BY id DESC LIMIT ?", (alert_id, limit))
        return self.q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    # --- notification outbox --------------------------------------------------
    def outbox_due(self, now: float, limit: int) -> list[dict]:
        return self.q("SELECT id, created, channel_id, subject, body, attempts, payload FROM outbox "
                      "WHERE done = 0 AND next_try <= ? ORDER BY id LIMIT ?", (now, limit))

    def outbox_done(self, outbox_id: int, now: float, error: str | None) -> None:
        from .storage import OUTBOX_ATTEMPTS, outbox_retry_at
        if error is None:
            self.x("UPDATE outbox SET done = 1, next_try = ?, error = NULL WHERE id = ?", (now, outbox_id))
            return
        rows = self.q("SELECT attempts FROM outbox WHERE id = ?", (outbox_id,))
        attempts = (rows[0]["attempts"] if rows else 0) + 1
        self.x("UPDATE outbox SET attempts = ?, next_try = ?, done = ?, error = ? WHERE id = ?",
               (attempts, outbox_retry_at(now, attempts), 2 if attempts >= OUTBOX_ATTEMPTS else 0, error[:300],
                outbox_id))

    def outbox_pending(self) -> int:
        return self.q("SELECT count(*) AS n FROM outbox WHERE done = 0")[0]["n"]

    # --- events ---------------------------------------------------------------
    def search_events(self, since: float = 0, before: int = 0, limit: int = 200, timeout: float = 0, *,
                      device: str = "", event_type: str = "", action: str = "", ip: str = "",
                      port: int | None = None, text: str = "") -> list[dict]:
        where, params = [], []
        for column, value in (("device", device), ("event_type", event_type), ("action", action)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            params += [ip, ip]
        if port is not None:
            where.append("dst_port = ?")
            params.append(port)
        if text:
            where.append("message LIKE ?")
            params.append(f"%{text}%")
        return self._search(where, params, since, before, limit, timeout)

    # --- per-minute counters ----------------------------------------------------
    def traffic_series(self, start: int, bucket: int) -> list[dict]:
        return self.q("SELECT (minute / ?) * ? AS t, SUM(events) AS e, SUM(blocked) AS b FROM stats_minute "
                      "WHERE minute >= ? AND device = ? GROUP BY t", (bucket, bucket, start, TOTAL))

    def traffic_totals(self, since: int) -> tuple[int, int]:
        row = self.q("SELECT SUM(events) AS e, SUM(blocked) AS b FROM stats_minute WHERE minute >= ? AND device = ?",
                     (since, TOTAL))[0]
        return row["e"] or 0, row["b"] or 0

    def ensure_stats_totals(self) -> None:
        if self.get_setting("stats_totals"):
            return
        self.x("INSERT OR IGNORE INTO stats_minute(minute, device, events, blocked) "
               "SELECT minute, ?, SUM(events), SUM(blocked) FROM stats_minute WHERE device != ? GROUP BY minute",
               (TOTAL, TOTAL))
        self.set_setting("stats_totals", True)

    def port_series(self, start: int, bucket: int) -> list[dict]:
        return self.q("SELECT (minute / ?) * ? AS t, port, direction, SUM(allowed) AS a, SUM(blocked) AS b "
                      "FROM port_minute WHERE minute >= ? GROUP BY t, port, direction", (bucket, bucket, start))

    def port_minutes_since(self, minute: int) -> list[dict]:
        return self.q("SELECT * FROM port_minute WHERE minute >= ? ORDER BY minute", (minute,))

    # --- alerts -------------------------------------------------------------------
    def alert_next_id(self) -> int:
        return (self.q("SELECT MAX(id) AS m FROM alerts")[0]["m"] or 0) + 1

    def alerts_active_since(self, last_seen: float) -> list[dict]:
        return self.q("SELECT * FROM alerts WHERE status IN ('open', 'ack') AND last_seen > ?", (last_seen,))

    @staticmethod
    def _alert_filters(prefix: str, status: str, severity: str, text: str) -> tuple[list[str], list]:
        where, params = [], []
        if status in ("open", "ack", "resolved", "false_positive"):
            where.append(f"{prefix}status = ?")
            params.append(status)
        elif status == "active":
            where.append(f"{prefix}status IN ('open', 'ack')")
        if severity in SEVERITIES:
            wanted = SEVERITIES[SEVERITIES.index(severity):]
            where.append(f"{prefix}severity IN ({','.join('?' * len(wanted))})")
            params += wanted
        if text:
            where.append(f"({prefix}title LIKE ? OR {prefix}description LIKE ? OR {prefix}src_ip LIKE ? "
                         f"OR {prefix}device LIKE ?)")
            params += [f"%{text}%"] * 4
        return where, params

    def alerts_find(self, *, status: str = "", severity: str = "", text: str = "", limit: int = 200,
                    alert_id: int = 0, detectors: list[str] | None = None) -> list[dict]:
        if alert_id:
            where, params = ["id = ?"], [alert_id]
            more, extra = self._alert_filters("", "", severity, text)
            where, params = where + more, params + extra
        else:
            where, params = self._alert_filters("", status, severity, text)
        if detectors:
            detectors = list(detectors)[:50]
            where.append(f"detector IN ({','.join('?' * len(detectors))})")
            params = [*params, *detectors]
        sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "")
        return self.q(sql + " ORDER BY last_seen DESC, id DESC LIMIT ?", (*params, limit))

    def alert_counts_by_detector(self, since: float, status: str) -> list[dict]:
        where = {"active": "status IN ('open', 'ack')", "all": "1 = 1"}.get(status, "status != 'false_positive'")
        return self.q(f"SELECT detector, severity, COUNT(*) AS alerts, SUM(count) AS occurrences, MAX(last_seen) AS last_seen "
                      f"FROM alerts WHERE last_seen >= ? AND {where} GROUP BY detector, severity", (since,))

    def alerts_recent(self, limit: int) -> list[dict]:
        return self.q("SELECT id, created, last_seen, severity, title, description, status, count FROM alerts "
                      "ORDER BY last_seen DESC, id DESC LIMIT ?", (limit,))

    def alerts_unresolved_since(self, last_seen: float, limit: int) -> list[dict]:
        return self.q("SELECT id, detector, severity, title, last_seen, src_ip, device, details FROM alerts "
                      "WHERE status IN ('open', 'ack') AND last_seen >= ? ORDER BY last_seen DESC, id DESC LIMIT ?",
                      (last_seen, limit))

    def alert_counts_open(self) -> dict[str, int]:
        return {r["severity"]: r["n"] for r in self.q(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE status = 'open' GROUP BY severity")}

    def alert_counts_open_by_device(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for row in self.q("SELECT device, severity, COUNT(*) AS n FROM alerts WHERE status = 'open' "
                          "GROUP BY device, severity"):
            out.setdefault(row["device"] or "", {})[row["severity"]] = row["n"]
        return out

    def alert_ids_open(self) -> list[int]:
        return [r["id"] for r in self.q("SELECT id FROM alerts WHERE status = 'open' ORDER BY id")]

    def set_alert_status(self, ids: list[int], status: str, stamp: float) -> None:
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            self.x(f"UPDATE alerts SET status = ?, updated = ? WHERE id IN ({','.join('?' * len(chunk))})",
                   (status, stamp, *chunk))

    def alert_changes_since(self, updated: float, alert_id: int, limit: int) -> list[dict]:
        return self.q(
            "SELECT id, created, last_seen, updated, detector, severity, title, description, entity, src_ip, device, "
            "count, status, details FROM alerts WHERE updated > ? OR (updated = ? AND id > ?) "
            "ORDER BY updated, id LIMIT ?", (updated, updated, alert_id, limit))

    # --- devices ----------------------------------------------------------------------
    def devices_all(self) -> list[dict]:
        return self.q("SELECT * FROM devices ORDER BY first_seen, id")

    def update_device(self, device_id: str, name: str, connector_pin: str, snmp_mode: str,
                      snmp_community: str, snmp_host: str) -> None:
        self.x("UPDATE devices SET name=?, connector_pin=?, snmp_mode=?, snmp_community=?, snmp_host=? WHERE id=?",
               (name, connector_pin, snmp_mode, snmp_community, snmp_host, device_id))

    def forget_device(self, device_id: str) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
            conn.execute("DELETE FROM snmp_data WHERE device=?", (device_id,))

    # --- notification channels ----------------------------------------------------------
    def channels(self) -> list[dict]:
        return self.q("SELECT * FROM channels ORDER BY id")

    def channel(self, channel_id: int) -> dict | None:
        rows = self.q("SELECT * FROM channels WHERE id=?", (channel_id,))
        return rows[0] if rows else None

    def add_channel(self, row: dict) -> int:
        return self.x("INSERT INTO channels(type, name, enabled, min_severity, config) VALUES(?,?,?,?,?)",
                      (row["type"], row["name"], row["enabled"], row["min_severity"], row["config"]))

    def update_channel(self, channel_id: int, row: dict) -> None:
        self.x("UPDATE channels SET name=?, enabled=?, min_severity=?, config=? WHERE id=?",
               (row["name"], row["enabled"], row["min_severity"], row["config"], channel_id))

    def delete_channel(self, channel_id: int) -> None:
        self.x("DELETE FROM channels WHERE id=?", (channel_id,))

    def channel_result(self, channel_id: int, when: float, ok: bool, error: str | None) -> None:
        self.x("UPDATE channels SET last_ts=?, last_ok=?, last_error=? WHERE id=?",
               (when, 1 if ok else 0, error, channel_id))

    # --- SNMP --------------------------------------------------------------------------------
    def snmp_records(self) -> list[dict]:
        return self.q("SELECT * FROM snmp_data")

    def save_snmp_record(self, device: str, polled: float, ok: bool, error: str, last_ok: float | None,
                         data: str | None) -> None:
        self.x("INSERT INTO snmp_data(device, polled, ok, error, last_ok, data) VALUES(?,?,?,?,?,?) "
               "ON CONFLICT(device) DO UPDATE SET polled=excluded.polled, ok=excluded.ok, error=excluded.error, "
               "last_ok=excluded.last_ok, data=excluded.data", (device, polled, int(ok), error, last_ok, data))

    # --- migration ----------------------------------------------------------------------------------
    def import_table(self, table: str, rows: list[dict]) -> None:
        columns = self.IMPORTABLE[table]
        with self.transaction() as conn:
            conn.executemany(f"INSERT INTO {table}({', '.join(columns)}) VALUES({', '.join('?' * len(columns))})",
                             [tuple(row.get(c) for c in columns) for row in rows])

    # --- dashboard sessions ----------------------------------------------------------------------
    def session_add(self, token_hash: str, expires: float) -> None:
        self.x("INSERT OR REPLACE INTO sessions(token_hash, expires) VALUES(?, ?)", (token_hash, expires))

    def session_expires(self, token_hash: str) -> float | None:
        rows = self.q("SELECT expires FROM sessions WHERE token_hash = ?", (token_hash,))
        return rows[0]["expires"] if rows else None

    def session_delete(self, token_hash: str) -> None:
        self.x("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    # --- central console: sites and their alerts -----------------------------------------------
    def sites_provision(self, entries: list[tuple[str, str]], now: float) -> None:
        with self.transaction() as conn:
            for name, digest in entries:
                conn.execute("UPDATE sites SET token_hash = NULL, managed = 0 WHERE token_hash = ? AND name != ?",
                             (digest, name))
                if conn.execute("UPDATE sites SET token_hash = ?, managed = 1 WHERE name = ?", (digest, name)).rowcount == 0:
                    conn.execute("INSERT INTO sites(name, token_hash, created, managed) VALUES(?,?,?,1)",
                                 (name, digest, now))

    def site_create(self, name: str, token_hash: str, now: float) -> int:
        with self.transaction() as conn:
            if conn.execute("SELECT 1 FROM sites WHERE name = ?", (name,)).fetchone():
                raise ValueError("A site with that name already exists.")
            return conn.execute("INSERT INTO sites(name, token_hash, created) VALUES(?,?,?)",
                                (name, token_hash, now)).lastrowid

    def site_rotate(self, site_id: int, token_hash: str) -> bool:
        return self.x("UPDATE sites SET token_hash = ? WHERE id = ? AND managed = 0", (token_hash, site_id)) > 0

    def site_delete(self, site_id: int) -> None:
        with self.transaction() as conn:
            row = conn.execute("SELECT managed FROM sites WHERE id = ?", (site_id,)).fetchone()
            if row is None:
                raise LookupError(site_id)
            if row[0]:
                raise ValueError("This site is set in configuration; remove it there instead.")
            conn.execute("DELETE FROM site_alerts WHERE site_id = ?", (site_id,))
            conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))

    def site(self, site_id: int) -> dict | None:
        rows = self.q("SELECT * FROM sites WHERE id = ?", (site_id,))
        return rows[0] if rows else None

    def sites_all(self) -> list[dict]:
        return self.q("SELECT * FROM sites ORDER BY name")

    def site_alert_open_counts(self) -> dict[int, dict[str, int]]:
        out: dict[int, dict[str, int]] = {}
        for row in self.q("SELECT site_id, severity, COUNT(*) AS n FROM site_alerts WHERE status = 'open' "
                          "GROUP BY site_id, severity"):
            out.setdefault(row["site_id"], {})[row["severity"]] = row["n"]
        return out

    def site_report(self, token_hash: str, instance: str, meta: dict, alerts: list[dict],
                    now: float) -> tuple[int, str, list[dict], list[dict]] | None:
        fresh: list[dict] = []
        with self.transaction() as conn:
            site = conn.execute("SELECT id, name FROM sites WHERE token_hash = ?", (token_hash,)).fetchone()
            if site is None:
                return None
            site_id, site_name = site["id"], site["name"]
            conn.execute("UPDATE sites SET last_seen = ?, address = ?, version = ?, reported_name = ?, instance = ?, "
                         "summary = ?, silent = 0 WHERE id = ?",
                         (now, meta["address"], meta["version"], meta["reported_name"], instance, meta["summary"],
                          site_id))
            for row in alerts:
                found = conn.execute("SELECT id, pending FROM site_alerts WHERE site_id = ? AND instance = ? "
                                     "AND alert_id = ?", (site_id, instance, row["alert_id"])).fetchone()
                fields = (row["created"], row["last_seen"], now, row["detector"], row["severity"], row["title"],
                          row["description"], row["entity"], row["src_ip"], row["device"], row["count"], row["details"])
                if found is None:
                    cur = conn.execute(
                        "INSERT INTO site_alerts(site_id, instance, alert_id, created, last_seen, received, detector, "
                        "severity, title, description, entity, src_ip, device, count, details, status) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (site_id, instance, row["alert_id"], *fields, row["status"]))
                    if row["status"] == "open":
                        fresh.append({**row, "id": cur.lastrowid})
                    continue
                status, pending = row["status"], found["pending"]
                if pending:
                    # Set at the console and not yet applied at the site: keep the console's
                    # choice until the site reports it back.
                    status, pending = (status, None) if status == pending else (pending, pending)
                conn.execute(
                    "UPDATE site_alerts SET created = ?, last_seen = ?, received = ?, detector = ?, severity = ?, "
                    "title = ?, description = ?, entity = ?, src_ip = ?, device = ?, count = ?, details = ?, "
                    "status = ?, pending = ? WHERE id = ?", (*fields, status, pending, found["id"]))
            pending = [{"id": r["alert_id"], "status": r["pending"]} for r in conn.execute(
                "SELECT alert_id, pending FROM site_alerts WHERE site_id = ? AND instance = ? AND pending IS NOT NULL "
                "ORDER BY id LIMIT 5000", (site_id, instance))]
        return site_id, site_name, fresh, pending

    def site_alerts_find(self, *, site_id: int = 0, status: str = "", severity: str = "", text: str = "",
                         limit: int = 200, alert_id: int = 0) -> list[dict]:
        if alert_id:
            where, params = ["a.id = ?"], [alert_id]
        else:
            where, params = self._alert_filters("a.", status, severity, text)
            if site_id:
                where.insert(0, "a.site_id = ?")
                params.insert(0, site_id)
        return self.q("SELECT a.*, s.name AS site FROM site_alerts a JOIN sites s ON s.id = a.site_id"
                      + (" WHERE " + " AND ".join(where) if where else "")
                      + " ORDER BY a.last_seen DESC, a.id DESC LIMIT ?", (*params, limit))

    def site_alerts_set_status(self, ids: list[int], status: str) -> int:
        changed = 0
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            changed += self.x(
                f"UPDATE site_alerts SET status = ?, pending = ? WHERE status != ? AND id IN ({','.join('?' * len(chunk))})",
                (status, status, status, *chunk))
        return changed

    def sites_newly_silent(self, cutoff: float) -> list[dict]:
        with self.transaction() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT id, name, last_seen FROM sites WHERE silent = 0 AND last_seen IS NOT NULL AND last_seen < ? "
                "ORDER BY id", (cutoff,))]
            for row in rows:
                conn.execute("UPDATE sites SET silent = 1 WHERE id = ?", (row["id"],))
        return rows

    def close(self) -> None:
        with self._wlock:
            self._w.close()
        for conn in self._all_readers:
            conn.close()

    # --- async wrappers --------------------------------------------------
    async def aq(self, sql: str, params=(), timeout: float = 0) -> list[dict]:
        return await asyncio.to_thread(self.q, sql, params, timeout)

    async def ax(self, sql: str, params=()) -> int:
        return await asyncio.to_thread(self.x, sql, params)

    async def abatch(self, statements) -> None:
        await asyncio.to_thread(self.batch, statements)

    async def aget_setting(self, key: str, default=None):
        return await asyncio.to_thread(self.get_setting, key, default)

    async def aset_setting(self, key: str, value) -> None:
        await asyncio.to_thread(self.set_setting, key, value)
