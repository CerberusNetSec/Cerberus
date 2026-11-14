"""Federation: one Cerberus per site, each reporting to a central console.

A site runs the full application against its own devices and, when
CERBERUS_CENTRAL_URL is set, a Forwarder sends the console its alerts (new and
changed since the last report) and a health summary every few seconds. The
console (CERBERUS_CENTRAL=on) stores them per site, shows every site's alerts
in one list, notifies on new ones, and raises its own alert when a site stops
reporting. Acknowledging or resolving a site's alert at the console is handed
back to the site in the reply to its next report.

Delivery is at least once: a site keeps a cursor (the last alert change the
console accepted) and resends from there after any failure, and the console
stores alerts idempotently by (site, site instance, alert id).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import time

import httpx

from . import __version__
from .models import SEVERITIES, Candidate

log = logging.getLogger("cerberus.federation")

REPORT_SECONDS = 15
MAX_BACKOFF = 300
BATCH = 500  # alerts per report
MAX_REPORT_BYTES = 8 * 1024 * 1024
MIN_TOKEN_LENGTH = 24
STATUSES = ("open", "ack", "resolved")


def token_hash(token: str) -> str:
    # Tokens are long random strings, so a plain hash is enough to keep them off disk.
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def site_summary(engine, db, now: float) -> dict:
    """What the console shows about a site at a glance."""
    day = db.q("SELECT SUM(events) AS e, SUM(blocked) AS b FROM stats_minute WHERE minute >= ? AND device = '*'",
               (int(now - 86400),))[0]
    open_alerts = {r["severity"]: r["n"] for r in db.q(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE status = 'open' GROUP BY severity")}
    devices = list(engine.devices.values())
    return {
        "rate": round(engine.rate(), 1),
        "events_24h": day["e"] or 0, "blocked_24h": day["b"] or 0,
        "devices_total": len(devices), "devices_active": sum(1 for d in devices if now - d.last_seen < 900),
        "open_alerts": open_alerts,
        "dropped": engine.dropped, "unwritten": engine.unwritten, "queue": engine.queue.qsize(),
        "flush_ms": round(engine.flush_seconds * 1000),
        "events_since": db.oldest_event_ts(),
        "uptime": int(now - engine.started),
    }


# --- site side ----------------------------------------------------------------------
class Forwarder:
    """Runs on a site: reports alerts and health to the central console."""

    def __init__(self, cfg, db, engine, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        self.db = db
        self.engine = engine
        self.url = cfg.central_url.rstrip("/")
        self.transport = transport
        self.client: httpx.AsyncClient | None = None
        self.instance = ""
        self.cursor = [0.0, 0]  # (updated, id) of the last alert change the console accepted
        self.last_ok: float | None = None
        self.last_error = ""
        self.failures = 0

    def load(self) -> None:
        self.instance = self.db.get_setting("instance_id") or ""
        if not self.instance:
            # Identifies this database to the console, so a site rebuilt from scratch
            # (alert ids starting again at 1) does not overwrite its earlier alerts there.
            self.instance = secrets.token_hex(8)
            self.db.set_setting("instance_id", self.instance)
        stored = self.db.get_setting("federation_cursor")
        if isinstance(stored, list) and len(stored) == 2:
            self.cursor = [float(stored[0]), int(stored[1])]

    def _client(self) -> httpx.AsyncClient:
        if self.client is None:
            self.client = httpx.AsyncClient(
                base_url=self.url, transport=self.transport, timeout=30,
                verify=self.cfg.central_ca or True,
                headers={"Authorization": f"Bearer {self.cfg.central_token}",
                         "User-Agent": f"cerberus-site/{__version__}"})
        return self.client

    def _changes(self) -> list[dict]:
        rows = self.db.q(
            "SELECT id, created, last_seen, updated, detector, severity, title, description, entity, src_ip, device, "
            "count, status, details FROM alerts WHERE updated > ? OR (updated = ? AND id > ?) "
            "ORDER BY updated, id LIMIT ?", (self.cursor[0], self.cursor[0], self.cursor[1], BATCH + 1))
        for row in rows:
            try:
                row["details"] = json.loads(row["details"] or "{}")
            except ValueError:
                row["details"] = {}
        return rows

    async def report_once(self) -> bool:
        """Send one report. Returns True if more alert changes are waiting."""
        now = time.time()
        rows = await asyncio.to_thread(self._changes)
        more = len(rows) > BATCH
        rows = rows[:BATCH]
        summary = await asyncio.to_thread(site_summary, self.engine, self.db, now)
        payload = {"site": self.cfg.site_name, "instance": self.instance, "version": __version__,
                   "sent": now, "summary": summary, "alerts": rows}
        resp = await self._client().post("/api/federation/report", json=payload)
        if resp.status_code != 200:
            detail = ""
            try:
                detail = resp.json().get("detail", "")
            except ValueError:
                pass
            raise RuntimeError(f"console answered {resp.status_code}" + (f": {detail}" if detail else ""))
        reply = resp.json()
        if rows:
            self.cursor = [rows[-1]["updated"], rows[-1]["id"]]
            await self.db.aset_setting("federation_cursor", self.cursor)
        await self._apply(reply.get("status") or [])
        return more

    async def _apply(self, changes: list) -> None:
        """Statuses set at the console: apply them here as if set in this site's own UI."""
        by_status: dict[str, list[int]] = {}
        for item in changes[:5000]:
            if isinstance(item, dict) and item.get("status") in STATUSES and isinstance(item.get("id"), int):
                by_status.setdefault(item["status"], []).append(item["id"])
        for status, ids in by_status.items():
            stamp = time.time()
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                await self.db.ax(f"UPDATE alerts SET status = ?, updated = ? WHERE id IN ({','.join('?' * len(chunk))})",
                                 (status, stamp, *chunk))
            self.engine.alerts.set_status(ids, status)
            log.info("console set %d alert(s) to %s", len(ids), status)

    async def run(self) -> None:
        await asyncio.to_thread(self.load)
        log.info("reporting to central console %s as site '%s'", self.url, self.cfg.site_name)
        while True:
            try:
                more = await self.report_once()
                if self.failures:
                    log.info("central console reachable again")
                self.failures, self.last_error, self.last_ok = 0, "", time.time()
                if more:
                    continue  # catching up after an outage: send the next batch straight away
                delay = REPORT_SECONDS
            except Exception as exc:  # network trouble must never stop the site itself
                self.failures += 1
                self.last_error = str(exc)[:200] or type(exc).__name__
                if self.failures == 1 or self.failures % 20 == 0:
                    log.warning("cannot report to central console: %s", self.last_error)
                delay = min(MAX_BACKOFF, REPORT_SECONDS * 2 ** min(self.failures - 1, 5))
            await asyncio.sleep(delay)

    def status(self) -> dict:
        return {"central": self.url, "site": self.cfg.site_name, "last_ok": self.last_ok,
                "error": self.last_error, "failures": self.failures}

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()


# --- console side ---------------------------------------------------------------------
def _num(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _text(value, limit: int) -> str:
    return str(value if value is not None else "")[:limit]


class Central:
    """Runs on the central console: accepts site reports and keeps their alerts."""

    def __init__(self, cfg, db, engine):
        self.cfg = cfg
        self.db = db
        self.engine = engine
        self.silent_after = max(1, cfg.site_silent_minutes) * 60

    # --- site registry ------------------------------------------------------------
    def provision(self, entries: list[tuple[str, str]]) -> None:
        """Sites declared in configuration (CERBERUS_SITE_TOKENS_FILE): created or re-keyed on start."""
        with self.db.transaction() as conn:
            for name, token in entries:
                digest = token_hash(token)
                conn.execute("UPDATE sites SET token_hash = NULL, managed = 0 WHERE token_hash = ? AND name != ?",
                             (digest, name))
                if conn.execute("UPDATE sites SET token_hash = ?, managed = 1 WHERE name = ?", (digest, name)).rowcount == 0:
                    conn.execute("INSERT INTO sites(name, token_hash, created, managed) VALUES(?,?,?,1)",
                                 (name, digest, time.time()))
        if entries:
            log.info("sites from configuration: %s", ", ".join(name for name, _ in entries))

    def create_site(self, name: str) -> tuple[dict, str]:
        token = new_token()
        with self.db.transaction() as conn:
            if conn.execute("SELECT 1 FROM sites WHERE name = ?", (name,)).fetchone():
                raise ValueError("A site with that name already exists.")
            cur = conn.execute("INSERT INTO sites(name, token_hash, created) VALUES(?,?,?)",
                               (name, token_hash(token), time.time()))
        return self.site(cur.lastrowid), token

    def rotate(self, site_id: int) -> str:
        token = new_token()
        if self.db.x("UPDATE sites SET token_hash = ? WHERE id = ? AND managed = 0", (token_hash(token), site_id)) == 0:
            raise ValueError("Unknown site, or one whose token is set in configuration.")
        return token

    def delete(self, site_id: int) -> None:
        with self.db.transaction() as conn:
            if conn.execute("SELECT managed FROM sites WHERE id = ?", (site_id,)).fetchone()[0]:
                raise ValueError("This site is set in configuration; remove it there instead.")
            conn.execute("DELETE FROM site_alerts WHERE site_id = ?", (site_id,))
            conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))

    def site(self, site_id: int) -> dict:
        rows = self.db.q("SELECT * FROM sites WHERE id = ?", (site_id,))
        if not rows:
            raise KeyError(site_id)
        return self._public(rows[0], time.time())

    def sites(self) -> list[dict]:
        now = time.time()
        counts: dict[int, dict] = {}
        for row in self.db.q("SELECT site_id, severity, COUNT(*) AS n FROM site_alerts WHERE status = 'open' "
                             "GROUP BY site_id, severity"):
            counts.setdefault(row["site_id"], {})[row["severity"]] = row["n"]
        return [{**self._public(row, now), "open_alerts": counts.get(row["id"], {})}
                for row in self.db.q("SELECT * FROM sites ORDER BY name")]

    def _public(self, row: dict, now: float) -> dict:
        seen = row.get("last_seen")
        try:
            summary = json.loads(row.get("summary") or "{}")
        except ValueError:
            summary = {}
        state = "waiting" if not seen else "silent" if now - seen > self.silent_after else "reporting"
        return {"id": row["id"], "name": row["name"], "managed": bool(row.get("managed")),
                "created": row.get("created"), "last_seen": seen, "state": state,
                "address": row.get("address") or "", "version": row.get("version") or "",
                "reported_name": row.get("reported_name") or "", "summary": summary}

    # --- reports ----------------------------------------------------------------------
    def receive(self, token: str, payload: dict, address: str, now: float) -> tuple[dict, list[dict]]:
        """Store one report. Returns (reply for the site, alerts that are new here).
        Raises PermissionError for an unknown token and ValueError for a malformed report."""
        if not isinstance(payload, dict) or not isinstance(payload.get("alerts", []), list):
            raise ValueError("malformed report")
        instance = _text(payload.get("instance"), 64)
        if not instance:
            raise ValueError("report has no instance id")
        fresh: list[dict] = []
        with self.db.transaction() as conn:
            site = conn.execute("SELECT id, name FROM sites WHERE token_hash = ?", (token_hash(token),)).fetchone()
            if site is None:
                raise PermissionError("unknown site token")
            site_id, site_name = site["id"], site["name"]
            summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
            conn.execute("UPDATE sites SET last_seen = ?, address = ?, version = ?, reported_name = ?, instance = ?, "
                         "summary = ?, silent = 0 WHERE id = ?",
                         (now, address[:64], _text(payload.get("version"), 32), _text(payload.get("site"), 120),
                          instance, json.dumps(summary)[:20000], site_id))
            for alert in payload.get("alerts", [])[:BATCH * 2]:
                row = self._clean(alert)
                if row is None:
                    continue
                found = conn.execute("SELECT id, pending FROM site_alerts WHERE site_id = ? AND instance = ? AND alert_id = ?",
                                     (site_id, instance, row["alert_id"])).fetchone()
                fields = (row["created"], row["last_seen"], now, row["detector"], row["severity"], row["title"],
                          row["description"], row["entity"], row["src_ip"], row["device"], row["count"], row["details"])
                if found is None:
                    cur = conn.execute(
                        "INSERT INTO site_alerts(site_id, instance, alert_id, created, last_seen, received, detector, "
                        "severity, title, description, entity, src_ip, device, count, details, status) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (site_id, instance, row["alert_id"], *fields, row["status"]))
                    if row["status"] == "open":
                        fresh.append({**row, "id": cur.lastrowid, "site": site_name})
                    continue
                status, pending = row["status"], found["pending"]
                if pending:
                    # Set here and not yet applied at the site: keep ours until the site reports it back.
                    status, pending = (status, None) if status == pending else (pending, pending)
                conn.execute(
                    "UPDATE site_alerts SET created = ?, last_seen = ?, received = ?, detector = ?, severity = ?, "
                    "title = ?, description = ?, entity = ?, src_ip = ?, device = ?, count = ?, details = ?, "
                    "status = ?, pending = ? WHERE id = ?", (*fields, status, pending, found["id"]))
            pending = [{"id": r["alert_id"], "status": r["pending"]} for r in conn.execute(
                "SELECT alert_id, pending FROM site_alerts WHERE site_id = ? AND instance = ? AND pending IS NOT NULL "
                "LIMIT 5000", (site_id, instance))]
        return {"ok": True, "site": site_name, "status": pending, "interval": REPORT_SECONDS}, fresh

    @staticmethod
    def _clean(alert) -> dict | None:
        if not isinstance(alert, dict) or not isinstance(alert.get("id"), int) or alert["id"] <= 0:
            return None
        details = alert.get("details")
        return {
            "alert_id": alert["id"],
            "created": _num(alert.get("created")), "last_seen": _num(alert.get("last_seen")),
            "detector": _text(alert.get("detector"), 64),
            "severity": alert.get("severity") if alert.get("severity") in SEVERITIES else "info",
            "title": _text(alert.get("title"), 200), "description": _text(alert.get("description"), 1000),
            "entity": _text(alert.get("entity"), 300), "src_ip": _text(alert.get("src_ip"), 64) or None,
            "device": _text(alert.get("device"), 128), "count": int(_num(alert.get("count"), 1)),
            "status": alert.get("status") if alert.get("status") in STATUSES else "open",
            "details": json.dumps(details if isinstance(details, dict) else {})[:4000],
        }

    def set_status(self, ids: list[int], status: str) -> int:
        """Acknowledge or resolve site alerts here; each site picks the change up with its next report."""
        changed = 0
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            changed += self.db.x(
                f"UPDATE site_alerts SET status = ?, pending = ? WHERE status != ? AND id IN ({','.join('?' * len(chunk))})",
                (status, status, status, *chunk))
        return changed

    # --- watching for silence ------------------------------------------------------------
    def check(self, now: float) -> list[Candidate]:
        """Sites that have stopped reporting, as alerts for the console itself."""
        out = []
        for row in self.db.q("SELECT id, name, last_seen FROM sites WHERE silent = 0 AND last_seen IS NOT NULL "
                             "AND last_seen < ?", (now - self.silent_after,)):
            self.db.x("UPDATE sites SET silent = 1 WHERE id = ?", (row["id"],))
            minutes = int((now - row["last_seen"]) // 60)
            out.append(Candidate(
                "site_silent", f"site|{row['name']}", "high", f"Site stopped reporting: {row['name']}",
                f"The Cerberus instance at site '{row['name']}' has not reported for {minutes} minutes. Its alerts "
                "are not reaching this console until it does.",
                None, "", {"site": row["name"], "silent_minutes": minutes},
            ))
        return out

    async def run(self) -> None:
        while True:
            await asyncio.sleep(30)
            try:
                for candidate in await asyncio.to_thread(self.check, time.time()):
                    self.engine.raise_alert(candidate, time.time())
            except Exception:
                log.exception("site check failed")
