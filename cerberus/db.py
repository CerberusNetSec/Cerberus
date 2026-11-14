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


class QueryTimeout(Exception):
    """A read ran past its deadline and was cancelled."""

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

-- Traffic on high-risk ports, for the Risk ports page. direction: inbound, outbound or internal.
CREATE TABLE IF NOT EXISTS port_minute (
    minute INTEGER NOT NULL, port INTEGER NOT NULL, direction TEXT NOT NULL,
    allowed INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0,
    PRIMARY KEY (minute, port, direction)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

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
"""

# Columns added after the first release: (table, column, definition).
MIGRATIONS = [
    ("devices", "snmp_mode", "TEXT DEFAULT 'default'"),
    ("devices", "snmp_community", "TEXT DEFAULT ''"),
    ("devices", "snmp_host", "TEXT DEFAULT ''"),
]


class Database:
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

    def search_events(self, where: list[str] = (), params: list = (), since: float = 0, before: int = 0,
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
        return removed

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
