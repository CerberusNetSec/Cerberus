"""Web UI and JSON API."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import deque
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Config
from .engine import Engine
from .federation import MAX_REPORT_BYTES, Central, Forwarder
from .models import SEVERITIES
from .models import clean_ip, is_internal
from .notifiers import CHANNEL_TYPES, Notifier, public_channel, validate_channel
from .playbooks import STAGES, advice, detector_stage
from .riskports import CATALOG, CLEARTEXT, DIRECTIONS, WEB, flags
from .snmp_poller import MASK as SNMP_MASK
from .snmp_poller import SnmpPoller, parse_target
from .storage import NotFound, QueryTimeout, Store
from .topology import build_topology

log = logging.getLogger("cerberus.web")

STATIC = Path(__file__).parent / "static"
COOKIE = "cerberus_session"
SESSION_TTL = 7 * 86400
SESSION_CACHE_SECONDS = 30  # how long a replica trusts its memory of a session before asking storage again
RISK_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 15}
RANGES = {"1h": (3600, 60), "6h": (6 * 3600, 300), "24h": (86400, 900), "7d": (7 * 86400, 3600)}
SEARCH_SECONDS = 10  # an event search running longer than this is cancelled
OPEN_PATHS = {"/api/login", "/api/logout", "/api/me", "/api/federation/report"}  # the last checks its own token
TOKEN_PREFIX = "cerb_"
# What an API token may do beyond reading (GET): with write scope, triage alerts. Settings,
# channels and tokens themselves always need the dashboard.
TOKEN_WRITE_PATHS = {"/api/alerts/status", "/api/alerts/false-positive"}
TOKEN_NEVER = ("/api/tokens",)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


class Auth:
    def __init__(self, cfg: Config, db: Store):
        self.enabled = cfg.auth_enabled
        self.db = db
        # Sessions live in storage, so they survive restarts and any web replica
        # accepts them; this caches recent answers (token hash -> (expires, checked)).
        self._seen: dict[str, tuple[float, float]] = {}
        self._tokens: dict = {}  # token hash -> (row or None, checked)
        self._used: dict = {}  # token id -> when last_used was last written
        self.failures: dict[str, deque] = {}
        self.salt = b""
        self.digest = b""
        if not self.enabled:
            log.warning("authentication is DISABLED (CERBERUS_AUTH=off)")
            return
        if cfg.password:
            self.salt = secrets.token_bytes(16)
            self.digest = _hash(cfg.password, self.salt)
            return
        stored = db.get_setting("auth")
        if stored:
            self.salt, self.digest = bytes.fromhex(stored["salt"]), bytes.fromhex(stored["hash"])
            return
        password = secrets.token_urlsafe(12)
        self.salt = secrets.token_bytes(16)
        self.digest = _hash(password, self.salt)
        db.set_setting("auth", {"salt": self.salt.hex(), "hash": self.digest.hex()})
        banner = "=" * 62
        print(f"\n{banner}\n  Cerberus generated a dashboard password: {password}\n"
              f"  It is shown only once. Set CERBERUS_PASSWORD to choose your own.\n{banner}\n", flush=True)

    def throttled(self, ip: str, now: float) -> bool:
        attempts = self.failures.get(ip)
        if not attempts:
            return False
        while attempts and attempts[0] < now - 300:
            attempts.popleft()
        return len(attempts) >= 5

    def login(self, password: str, ip: str) -> str | None:
        now = time.time()
        if hmac.compare_digest(_hash(password, self.salt), self.digest):
            self.failures.pop(ip, None)
            token = secrets.token_urlsafe(32)
            self.db.session_add(_token_hash(token), now + SESSION_TTL)
            return token
        if len(self.failures) > 10_000:
            self.failures.clear()
        self.failures.setdefault(ip, deque(maxlen=10)).append(now)
        return None

    def valid(self, request: Request) -> bool:
        if not self.enabled:
            return True
        token = request.cookies.get(COOKIE, "")
        if not token:
            return False
        key, now = _token_hash(token), time.time()
        cached = self._seen.get(key)
        if cached is None or now - cached[1] > SESSION_CACHE_SECONDS:
            if len(self._seen) > 10_000:
                self._seen.clear()
            cached = self._seen[key] = (self.db.session_expires(key) or 0.0, now)
        return cached[0] > now

    def logout(self, token: str) -> None:
        if token:
            key = _token_hash(token)
            self._seen.pop(key, None)
            self.db.session_delete(key)

    # API tokens: "Authorization: Bearer cerb_..." for agents and scripts.

    def api_token(self, token: str) -> dict | None:
        if not token.startswith(TOKEN_PREFIX):
            return None
        key, now = _token_hash(token), time.time()
        cached = self._tokens.get(key)
        if cached is None or now - cached[1] > SESSION_CACHE_SECONDS:
            if len(self._tokens) > 10_000:
                self._tokens.clear()
            cached = self._tokens[key] = (self.db.token_by_hash(key), now)
        row = cached[0]
        if row and now - self._used.get(row["id"], 0) > 60:
            self._used[row["id"]] = now
            self.db.token_used(row["id"], now)
        return row

    def forget_tokens(self) -> None:
        self._tokens.clear()

    def identify(self, request: Request) -> dict | None:
        """Who is asking: a dashboard session, an API token (with its scope), or nobody."""
        header = request.headers.get("authorization", "")
        if header[:7].lower() == "bearer ":
            row = self.api_token(header[7:].strip())
            if row:
                return {"kind": "token", "scope": row["scope"], "name": row["name"], "id": row["id"]}
            return None if self.enabled else {"kind": "open", "scope": "admin", "name": "open"}
        if not self.enabled:
            return {"kind": "open", "scope": "admin", "name": "open"}
        return {"kind": "session", "scope": "admin", "name": "dashboard"} if self.valid(request) else None


JUSTIFICATION_MIN, JUSTIFICATION_MAX, ANALYST_MAX = 10, 2000, 100


def _by(request: Request, analyst: str) -> str:
    """The name kept in the audit log: through an API token, the token says who it was."""
    who = getattr(request.state, "who", None)
    return f"{analyst} (API token '{who['name']}')" if who and who["kind"] == "token" else analyst


def _attribution(body: dict, request: Request) -> tuple[str, str, str]:
    """(justification, analyst, source address) for an audited change; raises if incomplete."""
    justification = " ".join(str(body.get("justification", "")).split())
    analyst = " ".join(str(body.get("analyst", "")).split())
    if len(justification) < JUSTIFICATION_MIN:
        raise _bad(f"a justification of at least {JUSTIFICATION_MIN} characters is required")
    if not analyst:
        raise _bad("the analyst's name is required")
    if len(justification) > JUSTIFICATION_MAX or len(analyst) > ANALYST_MAX:
        raise _bad("justification or name too long")
    return justification, analyst, request.client.host if request.client else ""


def _bad(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status_code=status, detail=message)


def _loads(text):
    try:
        return json.loads(text) if text else {}
    except ValueError:
        return {}


def _run(fn, *args, **kwargs):
    """A storage call, in a worker thread: storage may block."""
    return asyncio.to_thread(fn, *args, **kwargs)


def create_app(cfg: Config, db: Store, engine: Engine, notifier: Notifier, poller: SnmpPoller,
               forwarder: Forwarder | None = None, central: Central | None = None, heartbeats=None) -> FastAPI:
    app = FastAPI(title="Cerberus", docs_url=None, redoc_url=None, openapi_url=None)
    auth = Auth(cfg, db)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        request.state.who = None
        if (path.startswith("/api/") and path not in OPEN_PATHS) or path == "/mcp":
            who = await _run(auth.identify, request)
            if who is None:
                return JSONResponse({"detail": "not signed in"}, status_code=401,
                                    headers={"WWW-Authenticate": 'Bearer realm="cerberus"'})
            if who["kind"] == "token" and path != "/mcp":
                reading = request.method in ("GET", "HEAD") and not path.startswith(TOKEN_NEVER)
                triage = who["scope"] == "write" and request.method == "POST" and path in TOKEN_WRITE_PATHS
                if not (reading or triage):
                    return JSONResponse({"detail": "API tokens can read; with write scope they can also acknowledge, "
                                                   "resolve and mark false positives. Other changes need the dashboard."},
                                        status_code=403)
            request.state.who = who
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        if path.startswith("/api/") or path == "/":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    @app.get("/readyz")
    async def readyz():
        """Ready for traffic. A standby processor answers 503 here (see leader.py)."""
        return {"ok": True, "role": "active"}

    from .bus import collector_name
    from .metrics import add_endpoint, common, processor_samples

    async def samples():
        try:
            pending = await _run(db.outbox_pending)
        except Exception:
            pending = None
        return (common("processor" if engine.source else "all", collector_name(cfg))
                + processor_samples(engine, notifier, heartbeats, pending))
    add_endpoint(app, cfg.metrics_token, samples)

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    # --- auth ------------------------------------------------------------
    @app.get("/api/me")
    async def me(request: Request):
        return {"signed_in": await _run(auth.valid, request), "auth": auth.enabled, "version": __version__,
                "central": central is not None, "site": cfg.site_name if forwarder else None}

    @app.post("/api/login")
    async def login(request: Request, body: dict = Body(...)):
        ip = request.client.host if request.client else "?"
        if auth.throttled(ip, time.time()):
            raise _bad("Too many attempts. Wait a few minutes and try again.", 429)
        token = await _run(auth.login, str(body.get("password", ""))[:256], ip)
        if not token:
            log.warning("failed dashboard login from %s", ip)
            raise _bad("Wrong password.", 401)
        response = JSONResponse({"ok": True})
        response.set_cookie(COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="strict",
                            secure=request.url.scheme == "https")
        return response

    @app.post("/api/logout")
    async def logout(request: Request):
        await _run(auth.logout, request.cookies.get(COOKIE, ""))
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE)
        return response

    # --- dashboard -------------------------------------------------------
    @app.get("/api/summary")
    async def summary(range: str = "24h"):
        span, bucket = RANGES.get(range, RANGES["24h"])
        now = time.time()
        start = int((now - span) // bucket) * bucket
        found = {r["t"]: r for r in await _run(db.traffic_series, start, bucket)}
        series = []
        t = start
        while t < now:
            # The newest bucket is still filling, so scale it by the time elapsed
            # (at least 20 s, so its first seconds are not blown up into a spike).
            minutes = max(20.0, min(bucket, now - t)) / 60
            row = found.get(t)
            series.append({"t": t, "events": round((row["e"] if row else 0) / minutes, 1),
                           "blocked": round((row["b"] if row else 0) / minutes, 1)})
            t += bucket
        day_events, day_blocked = await _run(db.traffic_totals, int(now - 86400))
        counts = await _run(db.alert_counts_open)
        recent = await _run(db.alerts_recent, 8)
        sources, ports = engine.top_blocked()
        devices = list(engine.devices.values())

        # Who needs attention first: unresolved alerts from the last 24 hours, scored per
        # host (the alert's source address, or the reporting device when there is none).
        active = await _run(db.alerts_unresolved_since, now - 86400, 2000)
        hosts: dict[str, dict] = {}
        stages: dict[str, int] = {}
        for row in active:
            stage = detector_stage(row["detector"])
            stages[stage] = stages.get(stage, 0) + 1
            name = row["src_ip"] or row["device"] or ""
            if not name or not RISK_WEIGHT.get(row["severity"]):
                continue
            host = hosts.setdefault(name, {"host": name, "internal": bool(row["src_ip"]) and is_internal(row["src_ip"]),
                                           "is_device": not row["src_ip"], "score": 0, "alerts": 0,
                                           "severity": "info", "kinds": []})
            host["score"] += RISK_WEIGHT[row["severity"]]
            host["alerts"] += 1
            if RISK_WEIGHT[row["severity"]] > RISK_WEIGHT[host["severity"]]:
                host["severity"] = row["severity"]
            if stage not in host["kinds"]:
                host["kinds"].append(stage)
        # Several kinds of behaviour from one host matter more than one kind repeated.
        for host in hosts.values():
            host["score"] *= 1 + 0.5 * (len(host["kinds"]) - 1)
            host["score"] = round(host["score"])
        risk = sorted(hosts.values(), key=lambda h: (-h["score"], h["host"]))[:8]
        return {
            "risk": risk,
            "stages": [{"stage": s, "count": stages[s]} for s in STAGES if stages.get(s)],
            "series": series,
            "bucket_minutes": bucket // 60,
            "rate": round(engine.rate(), 1),
            "events_24h": day_events,
            "blocked_24h": day_blocked,
            "open_alerts": counts,
            "recent_alerts": recent,
            "top_sources": sources,
            "top_ports": ports,
            "devices_total": len(devices),
            "devices_active": sum(1 for d in devices if now - d.last_seen < 900),
            "dropped": engine.dropped,
            "queue": engine.queue.qsize(),
            "queue_size": engine.queue.maxsize,
            "unstored": engine.unstored,
            "traffic_sample": cfg.traffic_sample,
            "refused_devices": engine.refused_devices,
            "refused_tcp": engine.receiver.refused if engine.receiver else 0,
            "flush_ms": round(engine.flush_seconds * 1000),
            "unwritten": engine.unwritten,
            "events_since": db.oldest_event_ts(),
            "events_stored": db.events_stored(),
            "max_events": cfg.max_events,
            "retention_days": cfg.retention_days,
            "uptime": int(now - engine.started),
            "federation": forwarder.status() if forwarder else None,
            "duplicates": engine.dedup.duplicates if engine.dedup else None,
            "collectors": [
                {**{k: v for k, v in status.items() if k not in ("bus_error",)},
                 "state": "silent" if now - status.get("received_at", now) > cfg.collector_silent_seconds else "reporting"}
                for status in sorted(heartbeats.latest.values(), key=lambda s: str(s.get("name")))
            ] if heartbeats else None,
        }

    # --- federation: the central console -------------------------------------
    if central is not None:
        @app.post("/api/federation/report")
        async def federation_report(request: Request):
            scheme, _, token = request.headers.get("authorization", "").partition(" ")
            if scheme.lower() != "bearer" or not token:
                raise _bad("missing site token", 401)
            if int(request.headers.get("content-length") or 0) > MAX_REPORT_BYTES:
                raise _bad("report too large", 413)
            body = await request.body()
            if len(body) > MAX_REPORT_BYTES:
                raise _bad("report too large", 413)
            try:
                payload = json.loads(body)
            except ValueError:
                raise _bad("report is not JSON")
            address = request.client.host if request.client else ""
            try:
                reply, fresh = await asyncio.to_thread(central.receive, token, payload, address, time.time())
            except PermissionError:
                log.warning("site report with an unknown token from %s", address)
                raise _bad("unknown site token", 401)
            except ValueError as exc:
                raise _bad(str(exc))
            cutoff = time.time() - 86400
            for alert in fresh:
                if alert["created"] >= cutoff:  # a site catching up after a long outage does not page for old news
                    notifier.notify({**alert, "title": f"{alert['site']}: {alert['title']}",
                                     "device": f"{alert['device']} at {alert['site']}" if alert["device"] else alert["site"],
                                     "details": _loads(alert["details"]), "link": f"#/sites?alert={alert['id']}"})
            return reply

        @app.get("/api/sites")
        async def sites():
            return {"sites": await asyncio.to_thread(central.sites), "silent_minutes": cfg.site_silent_minutes}

        @app.post("/api/sites")
        async def site_create(body: dict = Body(...)):
            name = str(body.get("name", "")).strip()
            if not name or len(name) > 64 or any(c.isspace() for c in name):
                raise _bad("Give the site a name of up to 64 characters, without spaces.")
            try:
                site, token = await asyncio.to_thread(central.create_site, name)
            except ValueError as exc:
                raise _bad(str(exc))
            return {"site": site, "token": token}

        @app.post("/api/sites/{site_id}/token")
        async def site_rotate(site_id: int):
            try:
                return {"token": await asyncio.to_thread(central.rotate, site_id)}
            except ValueError as exc:
                raise _bad(str(exc))

        @app.delete("/api/sites/{site_id}")
        async def site_delete(site_id: int):
            try:
                await asyncio.to_thread(central.delete, site_id)
            except (ValueError, LookupError) as exc:
                raise _bad(str(exc) if isinstance(exc, ValueError) else "unknown site", 400)
            return {"ok": True}

        @app.get("/api/site-alerts")
        async def site_alerts(site: int = 0, status: str = "open", severity: str = "", q: str = "",
                              limit: int = 200, id: int = 0):
            rows = await _run(db.site_alerts_find, site_id=site, status=status, severity=severity, text=q,
                              limit=max(1, min(limit, 1000)), alert_id=id)
            for row in rows:
                row["details"] = _loads(row["details"])
                row["advice"] = advice(row)
            return {"alerts": rows}

        @app.post("/api/site-alerts/status")
        async def site_alert_status(body: dict = Body(...)):
            status = body.get("status")
            if status not in ("open", "ack", "resolved"):
                raise _bad("invalid status")
            ids = [int(i) for i in body.get("ids", []) if str(i).isdigit()][:5000]
            return {"updated": await asyncio.to_thread(central.set_status, ids, status)}

    # --- high-risk ports --------------------------------------------------
    async def _port_alerts(now: float) -> dict[int, list[dict]]:
        """Unresolved alerts from the last day that name a port, by port."""
        out: dict[int, list[dict]] = {}
        for row in await _run(db.alerts_unresolved_since, now - 86400, 2000):
            port = _loads(row["details"]).get("port")
            if isinstance(port, int):
                out.setdefault(port, []).append({k: row[k] for k in ("id", "severity", "title", "last_seen", "src_ip")})
        return out

    async def port_memory(now: float) -> dict:
        """What the High Risk Ports page reads from detector memory: this process's, or, when
        detection workers run the port family, the summaries they publish."""
        rp = engine.risk_ports
        if not engine.families or "port" in engine.families:
            fresh: dict[int, int] = {}
            for (port, _way, _src), first in list(rp.first_seen.items()):
                if now - first < 86400 and first - rp.since > 6 * 3600:
                    fresh[port] = fresh.get(port, 0) + 1
            return {"since": rp.since, "spikes": rp.spikes(now) if rp.enabled else [], "fresh": fresh,
                    "top": lambda port: {way: rp.top(port, way, now) for way in DIRECTIONS}}
        from .worker import merge_views, RISKPORTS_VIEW
        merged = merge_views((await _run(db.settings_with_prefix, RISKPORTS_VIEW)).values(), now)
        empty = {way: {"sources": [], "destinations": []} for way in DIRECTIONS}
        return {**merged, "top": lambda port: merged["talkers"].get(port, empty)}

    @app.get("/api/riskports")
    async def riskports(range: str = "24h"):
        rp = engine.risk_ports
        span, bucket = RANGES.get(range, RANGES["24h"])
        now = time.time()
        start = int((now - span) // bucket) * bucket
        rows = await _run(db.port_series, start, bucket)
        totals: dict[int, dict[str, list[int]]] = {}
        series: dict[int, dict[int, list[int]]] = {}
        for row in rows:
            if row["port"] not in rp.ports or row["direction"] not in DIRECTIONS:
                continue  # removed from the list since it was recorded
            per = totals.setdefault(row["port"], {d: [0, 0] for d in DIRECTIONS})
            per[row["direction"]][0] += row["a"]
            per[row["direction"]][1] += row["b"]
            point = series.setdefault(row["port"], {}).setdefault(row["t"], [0, 0])
            point[0] += row["a"]
            point[1] += row["b"]
        memory = await port_memory(now)
        spikes, fresh = memory["spikes"], memory["fresh"]
        alerts = await _port_alerts(now)
        buckets = []
        t = start
        while t < now:
            buckets.append(t)
            t += bucket
        ports = []
        for port, per in totals.items():
            found = flags(port, per, spikes, fresh.get(port, 0), rp.label(port))
            mine = alerts.get(port, [])
            ports.append({
                "port": port, "name": rp.label(port), "protocols": rp.protocol_text(port),
                "why": CATALOG.get(port, ("", ""))[1],
                "totals": per, "allowed": sum(per[d][0] for d in DIRECTIONS), "blocked": sum(per[d][1] for d in DIRECTIONS),
                "series": [series[port].get(b, [0, 0]) for b in buckets],
                "flags": found, "severity": found[0]["severity"] if found else "",
                "alerts": len(mine),
                "alert_severity": max((a["severity"] for a in mine), key=SEVERITIES.index, default=""),
            })
        rank = {"high": 0, "medium": 1, "low": 2, "": 3}
        ports.sort(key=lambda p: (rank[p["severity"]], -p["alerts"], -p["allowed"], -p["blocked"], p["port"]))
        plain = [p for p in ports if p["port"] not in WEB]
        return {
            "range": range if range in RANGES else "24h", "bucket_minutes": bucket // 60, "buckets": buckets,
            "ports": ports,
            "quiet": sorted(({"port": p, "name": rp.label(p), "protocols": rp.protocol_text(p)}
                             for p in rp.ports if p not in totals), key=lambda q: q["port"]),
            "summary": {
                "flagged": sum(1 for p in ports if p["severity"] in ("high", "medium")),
                "exposed": sum(p["totals"]["inbound"][0] for p in plain),
                "exposed_ports": sum(1 for p in plain if p["totals"]["inbound"][0]),
                "blocked_inbound": sum(p["totals"]["inbound"][1] for p in ports),
                "cleartext": sum(p["totals"]["outbound"][0] + p["totals"]["internal"][0] for p in plain if p["port"] in CLEARTEXT),
                "egress": sum(p["totals"]["outbound"][0] for p in plain if p["port"] != 22),
            },
            "enabled": rp.enabled, "since": memory["since"] or None,
            "history_hours": rp.cfg["history_hours"],
        }

    @app.get("/api/riskports/port")
    async def riskport_detail(port: int):
        now = time.time()
        rp = engine.risk_ports
        return {"port": port, "name": rp.label(port), "protocols": rp.protocol_text(port),
                "directions": (await port_memory(now))["top"](port),
                "alerts": (await _port_alerts(now)).get(port, [])[:20]}

    # --- display options (Settings -> General) ---------------------------------
    DISPLAY_DEFAULTS = {"attack_hide_uncovered": False}

    async def display_options() -> dict:
        saved = await db.aget_setting("display") or {}
        return {k: bool(saved.get(k, v)) if isinstance(v, bool) else saved.get(k, v) for k, v in DISPLAY_DEFAULTS.items()}

    @app.get("/api/display")
    async def display_get():
        return {"display": await display_options()}

    @app.put("/api/display")
    async def display_put(body: dict = Body(...)):
        given = body.get("display", body)
        if not isinstance(given, dict):
            raise _bad("invalid display options")
        options = {**await display_options(), **{k: bool(v) for k, v in given.items() if k in DISPLAY_DEFAULTS}}
        await db.aset_setting("display", options)
        return {"display": options}

    # --- MITRE ATT&CK --------------------------------------------------------
    ATTACK_RANGES = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "all": 0}

    @app.get("/api/attack")
    async def attack(range: str = "30d", status: str = "real"):
        """Alerts counted in the ATT&CK Enterprise matrix, by tactic and technique."""
        from .attack import matrix
        span = ATTACK_RANGES.get(range, ATTACK_RANGES["30d"])
        status = status if status in ("real", "active", "all") else "real"
        rows = await _run(db.alert_counts_by_detector, time.time() - span if span else 0, status)
        for r in rows:
            r["alerts"], r["occurrences"] = int(r["alerts"] or 0), int(r["occurrences"] or 0)
        names = {d.id: d.name for d in engine.detectors}
        return {"range": range if range in ATTACK_RANGES else "30d", "status": status,
                "hide_uncovered": (await display_options())["attack_hide_uncovered"], **matrix(rows, names)}

    @app.get("/api/alerts/counts")
    async def alert_counts():
        """Open alerts by severity: cheap enough for the navigation badge to poll."""
        counts = await _run(db.alert_counts_open)
        return {"open": counts, "total": sum(counts.values())}

    # --- false positives -----------------------------------------------------
    @app.post("/api/alerts/false-positive")
    async def false_positive(request: Request, body: dict = Body(...)):
        """Mark an alert a false positive: the same detector finding the same thing again
        raises nothing. Needs a justification and a name, both kept in the audit log."""
        try:
            alert_id = int(body.get("id"))
        except (TypeError, ValueError):
            raise _bad("alert id required")
        justification, analyst, source = _attribution(body, request)
        return {"suppression": await mark_false_positive(alert_id, justification, _by(request, analyst), source)}

    async def mark_false_positive(alert_id: int, justification: str, analyst: str, source: str) -> dict:
        try:
            row = await _run(db.false_positive, alert_id, time.time(), justification, analyst, source)
        except NotFound:
            raise _bad("no such alert", 404)
        engine.alerts.set_status([alert_id], "false_positive")
        engine.load_suppressions(await _run(db.suppressions))
        return row

    @app.get("/api/suppressions")
    async def suppressions():
        return {"suppressions": await _run(db.suppressions)}

    @app.post("/api/suppressions/remove")
    async def suppression_remove(request: Request, body: dict = Body(...)):
        try:
            suppression_id = int(body.get("id"))
        except (TypeError, ValueError):
            raise _bad("suppression id required")
        justification, analyst, source = _attribution(body, request)
        try:
            row = await _run(db.suppression_remove, suppression_id, time.time(), justification, analyst, source)
        except NotFound:
            raise _bad("no such active suppression", 404)
        engine.load_suppressions(await _run(db.suppressions))
        return {"suppression": row}

    @app.get("/api/audit")
    async def audit(limit: int = 200, alert_id: int = 0):
        rows = await _run(db.audit_log, max(1, min(limit, 5000)), alert_id)
        for row in rows:
            row["detail"] = _loads(row["detail"])
        return {"audit": rows}

    # --- alerts ----------------------------------------------------------
    @app.get("/api/alerts")
    async def alerts(status: str = "open", severity: str = "", q: str = "", limit: int = 200, id: int = 0,
                     detector: str = ""):
        rows = await _run(db.alerts_find, status=status, severity=severity, text=q,
                          limit=max(1, min(limit, 1000)), alert_id=id,
                          detectors=[d for d in detector.split(",") if d.strip()] or None)
        if any(r["status"] == "false_positive" for r in rows):
            # Who marked it, why, and how often it has come back since.
            every = await _run(db.suppressions)
            by_alert: dict = {}
            for s in every:
                by_alert.setdefault(s["alert_id"], s)
            by_key = {(s["detector"], s["entity"]): s for s in every if s["active"]}
            for r in rows:
                if r["status"] == "false_positive":
                    s = by_key.get((r["detector"], r["entity"])) or by_alert.get(r["id"])
                    if s:
                        r["false_positive"] = {k: s[k] for k in ("id", "created", "analyst", "justification", "active",
                                                                  "hits", "last_hit")}
        for row in rows:
            row["details"] = _loads(row["details"])
            row["advice"] = advice(row)
        return {"alerts": rows}

    @app.post("/api/ignore")
    async def ignore(body: dict = Body(...)):
        """Add one address to the ignored sources or destinations."""
        ip = clean_ip(str(body.get("ip", "")))
        key = "ignore_destinations" if body.get("kind") == "destination" else "ignore_sources"
        if not ip:
            raise _bad("not an IP address")
        general = engine.general_settings()
        if ip not in general[key]:
            general[key] = [*general[key], ip]
            engine.apply_settings({d.id: d.settings() for d in engine.detectors}, general)
            await db.aset_setting("general", engine.general_settings())
        return {"general": engine.general_settings()}

    @app.post("/api/alerts/status")
    async def alert_status(request: Request, body: dict = Body(...)):
        status = body.get("status")
        if status not in ("open", "ack", "resolved"):
            raise _bad("invalid status")
        if body.get("all_open"):
            ids = await _run(db.alert_ids_open)
        else:
            ids = [int(i) for i in body.get("ids", []) if str(i).isdigit()][:5000]
        return {"updated": await set_status(ids, status, request.state.who, request.client.host if request.client else "")}

    async def set_status(ids: list[int], status: str, who: dict | None, source: str) -> int:
        await _run(db.set_alert_status, ids, status, time.time())
        engine.alerts.set_status(ids, status)
        if who and who["kind"] == "token" and ids:  # what agents and scripts change is on the record
            await _run(db.audit_add, {"ts": time.time(), "action": "alert_status", "analyst": f"API token '{who['name']}'",
                                      "source": source, "alert_id": ids[0] if len(ids) == 1 else None,
                                      "detail": json.dumps({"ids": ids[:200], "status": status})})
        return len(ids)

    # --- events ----------------------------------------------------------
    @app.get("/api/events")
    async def events(hours: float = 24, device: str = "", type: str = "", action: str = "", ip: str = "",
                     port: str = "", q: str = "", before: int = 0, limit: int = 200):
        since = time.time() - max(0.1, min(hours, 24 * 365)) * 3600
        try:
            rows = await _run(db.search_events, since, max(0, before), max(1, min(limit, 1000)), SEARCH_SECONDS,
                              device=device, event_type=type, action=action, ip=ip,
                              port=int(port) if port.isdigit() else None, text=q)
        except QueryTimeout:
            raise _bad(f"That search was stopped after {SEARCH_SECONDS} seconds. Choose a shorter time range, "
                       "or add a device, address or port so it has less to read.", 504)
        for row in rows:
            row["extra"] = _loads(row["extra"])
        return {"events": rows}

    # --- devices ---------------------------------------------------------
    @app.get("/api/devices")
    async def devices():
        rows = sorted(({**d.as_dict(), "snmp": poller.status(d)} for d in engine.devices.values()),
                      key=lambda d: -d["last_seen"])
        return {"devices": rows, "identity": cfg.device_identity}

    @app.put("/api/devices")
    async def device_update(body: dict = Body(...)):
        dev = engine.devices.get(str(body.get("id", "")))
        if not dev:
            raise _bad("unknown device", 404)
        pin = str(body.get("connector_pin", dev.connector_pin))
        if pin and pin not in engine.connectors.by_id:
            raise _bad("unknown connector")
        mode = str(body.get("snmp_mode", dev.snmp_mode))
        if mode not in ("default", "custom", "off"):
            raise _bad("invalid SNMP mode")
        host = str(body.get("snmp_host", dev.snmp_host)).strip()
        if host:
            try:
                parse_target(host)
            except ValueError:
                raise _bad("SNMP address must be an IPv4 address, optionally with :port")
        community = str(body.get("snmp_community", SNMP_MASK)).strip()[:128]
        if community != SNMP_MASK:  # the UI sends the mask back when the field was left alone
            dev.snmp_community = community
        if mode == "custom" and not dev.snmp_community:
            raise _bad("Enter a community string for this device, or use the default")
        changed = (mode, host) != (dev.snmp_mode, dev.snmp_host) or community != SNMP_MASK
        dev.name = str(body.get("name", dev.name)).strip()[:80]
        dev.connector_pin = pin
        dev.snmp_mode, dev.snmp_host = mode, host
        await _run(db.update_device, dev.id, dev.name, pin, mode, dev.snmp_community, host)
        if changed and poller.target(dev)[0]:
            asyncio.create_task(poller.poll(dev))
        return {**dev.as_dict(), "snmp": poller.status(dev)}

    @app.post("/api/devices/forget")
    async def device_forget(body: dict = Body(...)):
        device_id = str(body.get("id", ""))
        engine.forget_device(device_id)
        poller.forget(device_id)
        await _run(db.forget_device, device_id)
        return {"ok": True}

    # --- SNMP and topology -------------------------------------------------
    @app.get("/api/topology")
    async def topology():
        counts = await _run(db.alert_counts_open_by_device)
        devices = [d.as_dict() for d in engine.devices.values()]
        # Off the event loop: on a big network this takes long enough to delay log intake.
        graph = await asyncio.to_thread(build_topology, devices, dict(poller.records), counts)
        polled = [r["polled"] for r in poller.records.values() if r.get("polled")]
        return {**graph, "settings": poller.public_settings(),
                "polled_ok": sum(1 for d in engine.devices.values() if (poller.records.get(d.id) or {}).get("ok")),
                "pollable": sum(1 for d in engine.devices.values() if poller.target(d)[0]),
                **poller.progress(),
                "last_poll": max(polled) if polled else None}

    @app.get("/api/topology/device")
    async def topology_device(id: str):
        dev = engine.devices.get(id)
        if not dev:
            raise _bad("unknown device", 404)
        data = (poller.records.get(id) or {}).get("data") or {}
        interfaces = sorted(data.get("interfaces", {}).values(), key=lambda i: (i["oper"] != "up", i["name"]))
        return {"device": dev.as_dict(), "snmp": poller.status(dev), "system": data.get("system", {}),
                "ips": data.get("ips", []), "interfaces": interfaces[:500], "neighbors": data.get("neighbors", [])}

    @app.put("/api/snmp")
    async def snmp_update(body: dict = Body(...)):
        rejected = poller.apply_settings(body if isinstance(body, dict) else {})
        return {"settings": poller.public_settings(), "rejected": rejected}

    @app.post("/api/snmp/poll")
    async def snmp_poll(body: dict = Body(default={})):
        if not poller.settings["enabled"]:
            raise _bad("SNMP polling is switched off")
        wanted = body.get("id")
        devices = [d for d in engine.devices.values() if (not wanted or d.id == wanted) and poller.target(d)[0]]
        if not devices:
            raise _bad("No device can be polled. Check the community string and allowed networks.")
        if not wanted and len(devices) > 20:
            # Too many to wait for: start it and let the page watch it finish.
            started = poller.start_sweep()
            return {"started": started or len(devices), "background": True}
        await asyncio.wait_for(poller.poll_all(devices), 120)
        return {"polled": len(devices),
                "ok": sum(1 for d in devices if (poller.records.get(d.id) or {}).get("ok"))}

    # --- connectors ------------------------------------------------------
    @app.get("/api/connectors")
    async def connectors():
        return {"connectors": [c.info() for c in engine.connectors.connectors],
                "errors": engine.connectors.errors,
                "user_dir": str(engine.connectors.user_dir)}

    @app.post("/api/connectors/reload")
    async def connectors_reload():
        engine.connectors.reload()
        return {"connectors": [c.info() for c in engine.connectors.connectors],
                "errors": engine.connectors.errors}

    @app.post("/api/connectors/test")
    async def connectors_test(body: dict = Body(...)):
        raw = str(body.get("raw", ""))[:8192]
        if not raw.strip():
            raise _bad("paste a syslog line to test")
        ev = engine.build_event(raw, "192.0.2.1", time.time(), pin=str(body.get("connector", "")))
        data = ev.as_dict()
        return {"event": {k: v for k, v in data.items() if v not in (None, "", {}) and k not in ("ts", "device", "source_ip")}}

    # --- detection settings ----------------------------------------------
    @app.get("/api/detectors")
    async def detectors():
        return {"detectors": [d.schema() for d in engine.detectors], "general": engine.general_settings()}

    @app.put("/api/detectors")
    async def detectors_update(body: dict = Body(...)):
        given = body.get("detectors") or {}
        general = body.get("general") or {}
        if not isinstance(given, dict) or not isinstance(general, dict):
            raise _bad("invalid settings")
        stored = {}
        for det in engine.detectors:
            if isinstance(given.get(det.id), dict):
                det.configure({**det.settings(), **given[det.id]})
            stored[det.id] = det.settings()
        merged = {**engine.general_settings(),
                  **{k: general[k] for k in ("ignore_sources", "ignore_destinations", "cooldown_minutes") if k in general}}
        if not isinstance(merged["ignore_sources"], list) or not isinstance(merged["ignore_destinations"], list):
            raise _bad("ignore lists must be lists")
        engine.apply_settings(stored, merged)
        await db.aset_setting("detectors", stored)
        await db.aset_setting("general", engine.general_settings())
        return {"detectors": [d.schema() for d in engine.detectors], "general": engine.general_settings()}

    # --- syslog listeners -------------------------------------------------
    def listeners_view(errors: dict | None = None) -> dict:
        from .listeners import SETTING, from_config
        receiver = engine.receiver
        saved = (db.get_setting(SETTING) if receiver is not None else None) or None
        status = receiver.status() if receiver is not None else {}
        listeners = {}
        for kind, entry in (saved or from_config(cfg)).items():
            st = status.get(kind, {})
            listeners[kind] = {**entry, "listening": bool(st.get("listening")),
                               "listening_port": st.get("port") if st.get("listening") else None,
                               "error": (errors or {}).get(kind) or st.get("error", "")}
        return {
            # Collectors (scale-out) keep their environment; a processor receives no syslog itself.
            "available": receiver is not None, "mode": cfg.mode, "bind": cfg.bind,
            "tls_certificate": bool(cfg.syslog_tls_cert and cfg.syslog_tls_key),
            "client_certificates": bool(cfg.syslog_tls_client_ca),
            "container": Path("/.dockerenv").exists(), "saved": saved is not None,
            "listeners": listeners, "environment": from_config(cfg),
        }

    @app.get("/api/listeners")
    async def listeners_get():
        return await asyncio.to_thread(listeners_view)

    @app.put("/api/listeners")
    async def listeners_put(body: dict = Body(...)):
        from .listeners import SETTING, clean, from_config, ports
        if engine.receiver is None:
            raise _bad("this process receives no syslog: collectors take their ports from their environment", 409)
        current = (await db.aget_setting(SETTING)) or from_config(cfg)
        try:
            wanted = clean(body.get("listeners", body), current)
        except ValueError as exc:
            raise _bad(str(exc))
        if wanted["tls"]["enabled"] and not (cfg.syslog_tls_cert and cfg.syslog_tls_key):
            raise _bad("TLS needs a certificate and key: set CERBERUS_SYSLOG_TLS_CERT and CERBERUS_SYSLOG_TLS_KEY")
        if not any(w["enabled"] for w in wanted.values()):
            raise _bad("switch on at least one listener, or no syslog can arrive")
        failed = await engine.receiver.reconfigure(ports(wanted))
        for kind in failed:  # keep what is actually running for those that could not change
            wanted[kind] = current[kind]
        await db.aset_setting(SETTING, wanted)
        return await asyncio.to_thread(listeners_view, failed)

    # --- notification channels -------------------------------------------
    def _types():
        return {k: {"label": v["label"], "required": v["required"], "help": v.get("help", ""),
                    "fields": [{"key": f[0], "label": f[1], "kind": f[2], "default": f[3]} for f in v["fields"]]}
                for k, v in CHANNEL_TYPES.items()}

    async def _channel(channel_id: int) -> dict:
        row = await _run(db.channel, channel_id)
        if row is None:
            raise _bad("unknown channel", 404)
        return row

    @app.get("/api/channels")
    async def channels():
        rows = await _run(db.channels)
        return {"channels": [public_channel(r) for r in rows], "types": _types(), "severities": SEVERITIES}

    @app.post("/api/channels")
    async def channel_create(body: dict = Body(...)):
        try:
            row = validate_channel(body)
        except ValueError as exc:
            raise _bad(str(exc))
        new_id = await _run(db.add_channel, row)
        await notifier.reload()
        return public_channel(await _channel(new_id))

    @app.put("/api/channels/{channel_id}")
    async def channel_update(channel_id: int, body: dict = Body(...)):
        existing = await _channel(channel_id)
        try:
            row = validate_channel(body, existing)
        except ValueError as exc:
            raise _bad(str(exc))
        await _run(db.update_channel, channel_id, row)
        await notifier.reload()
        return public_channel(await _channel(channel_id))

    @app.delete("/api/channels/{channel_id}")
    async def channel_delete(channel_id: int):
        await _run(db.delete_channel, channel_id)
        await notifier.reload()
        return {"ok": True}

    @app.post("/api/channels/{channel_id}/test")
    async def channel_test(channel_id: int):
        channel = await _channel(channel_id)
        from .notifiers import SAMPLE, payload_for
        subject, text = "[Cerberus] Test notification", "This is a test from Cerberus. If you can read it, this channel works."
        error = await notifier.deliver(channel, subject, text, retry=False,
                                       payload=payload_for(SAMPLE, subject, text, notifier.link({}), event="test"))
        if error:
            raise _bad(error, 502)
        return {"ok": True}

    # --- API tokens (Settings -> API & agents) ------------------------------
    @app.get("/api/tokens")
    async def tokens_list():
        return {"tokens": await _run(db.tokens), "mcp_path": "/mcp", "public_url": cfg.public_url}

    @app.post("/api/tokens")
    async def token_create(request: Request, body: dict = Body(...)):
        name = " ".join(str(body.get("name", "")).split())[:60]
        scope = body.get("scope", "read")
        if not name:
            raise _bad("give the token a name (who or what will use it)")
        if scope not in ("read", "write"):
            raise _bad("scope must be read or write")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = time.time()
        token_id = await _run(db.token_add, {"created": now, "name": name, "token_hash": _token_hash(token), "scope": scope})
        await _run(db.audit_add, {"ts": now, "action": "token_created", "analyst": "dashboard",
                                  "source": request.client.host if request.client else "",
                                  "detail": json.dumps({"token_id": token_id, "name": name, "scope": scope})})
        return {"id": token_id, "name": name, "scope": scope, "token": token}  # shown once, never again

    @app.post("/api/tokens/{token_id}/revoke")
    async def token_revoke(token_id: int, request: Request):
        row = await _run(db.token_revoke, token_id, time.time())
        if row is None:
            raise _bad("no such active token", 404)
        auth.forget_tokens()
        await _run(db.audit_add, {"ts": time.time(), "action": "token_revoked", "analyst": "dashboard",
                                  "source": request.client.host if request.client else "",
                                  "detail": json.dumps({"token_id": token_id, "name": row["name"], "scope": row["scope"]})})
        return {"token": row}

    # --- MCP: tools for AI agents (cerberus/mcp.py) -----------------------------
    from .mcp import McpServer, Tool, ToolError

    def compact_alert(a: dict) -> dict:
        g = a.get("advice") or advice(a)
        return {k: a.get(k) for k in ("id", "severity", "status", "title", "description", "detector", "src_ip", "device",
                                      "count", "created", "last_seen")} | {
            "technique": f"{g['technique']['id']} {g['technique']['name']}" if g.get("technique") else None,
            "stage": g.get("stage")}

    async def tool_status(args, ctx):
        counts = await _run(db.alert_counts_open)
        now = time.time()
        devices = list(engine.devices.values())
        out = {
            "version": __version__, "mode": cfg.mode, "messages_per_second": round(engine.rate(), 1),
            "events_received": engine.received, "events_stored": await _run(db.events_stored),
            "open_alerts": counts, "open_alerts_total": sum(counts.values()),
            "devices": len(devices), "devices_reporting_last_15_min": sum(1 for d in devices if now - d.last_seen < 900),
            "last_event_seconds_ago": round(now - max((d.last_seen for d in devices), default=now)),
            "dropped": engine.dropped, "parse_errors": engine.parse_errors,
            "notifications_waiting": await _run(db.outbox_pending),
        }
        if engine.receiver is not None:
            out["listeners"] = engine.receiver.status()
        if heartbeats is not None:
            out["collectors_and_workers"] = [{"name": n, "role": s.get("role", "collector"),
                                              "seconds_since_report": round(now - s.get("received_at", now))}
                                             for n, s in heartbeats.latest.items()]
        return out

    async def tool_list_alerts(args, ctx):
        res = await alerts(status=args.get("status", "open"), severity=args.get("severity", ""), q=args.get("query", ""),
                           limit=args.get("limit", 25), id=0, detector=args.get("detector", ""))
        return {"alerts": [compact_alert(a) for a in res["alerts"]]}

    async def tool_get_alert(args, ctx):
        res = await alerts(status="all", severity="", q="", limit=1, id=args["id"], detector="")
        if not res["alerts"]:
            raise ToolError(f"no alert {args['id']}")
        return {"alert": res["alerts"][0]}

    async def tool_search_events(args, ctx):
        try:
            res = await events(hours=args.get("hours", 1), device=args.get("device", ""), type=args.get("event_type", ""),
                               action=args.get("action", ""), ip=args.get("ip", ""),
                               port=str(args["port"]) if "port" in args else "", q=args.get("text", ""), before=0,
                               limit=args.get("limit", 50))
        except HTTPException as exc:
            raise ToolError(str(exc.detail))
        return res

    async def tool_devices(args, ctx):
        now = time.time()
        return {"devices": sorted(({"id": d.id, "ip": d.ip, "hostname": d.hostname, "name": getattr(d, "name", ""),
                                    "connector": d.connector_seen, "events": d.events,
                                    "last_seen_seconds_ago": round(now - d.last_seen)} for d in engine.devices.values()),
                                  key=lambda d: d["last_seen_seconds_ago"])}

    async def tool_attack(args, ctx):
        d = await attack(range=args.get("range", "30d"), status="real")
        return {"range": d["range"], "total": d["total"], "tactics": [
            {"tactic": t["name"], "alerts": t["alerts"],
             "techniques": [{"id": c["id"], "name": c["name"], "alerts": c["alerts"],
                             "detectors": [x["id"] for x in c["detectors"]]} for c in t["techniques"]]}
            for t in d["tactics"] if t["techniques"]], "outside_attack": [
            {"name": o["name"], "alerts": o["alerts"]} for o in d["other"]]}

    async def tool_risk_ports(args, ctx):
        d = await riskports(range=args.get("range", "24h"))
        return {"range": d["range"], "summary": d["summary"], "ports": [
            {k: p[k] for k in ("port", "name", "protocols", "allowed", "blocked", "totals", "severity", "alerts")}
            | {"findings": [f["label"] for f in p["flags"]]} for p in d["ports"]]}

    async def tool_set_status(args, ctx):
        ids = [i for i in args["ids"] if isinstance(i, int)][:500]
        if not ids:
            raise ToolError("ids must be alert ids (integers)")
        return {"updated": await set_status(ids, args["status"], {"kind": "token", "name": ctx["name"]}, ctx["source"])}

    async def tool_false_positive(args, ctx):
        why = " ".join(args["justification"].split())
        if len(why) < JUSTIFICATION_MIN:
            raise ToolError(f"a justification of at least {JUSTIFICATION_MIN} characters is required")
        try:
            row = await mark_false_positive(args["id"], why[:JUSTIFICATION_MAX], f"agent (API token '{ctx['name']}')",
                                            ctx["source"])
        except HTTPException as exc:
            raise ToolError(str(exc.detail))
        return {"suppression": row}

    statuses = ["open", "ack", "active", "resolved", "false_positive", "all"]
    mcp = McpServer([
        Tool("get_status", "Cerberus status", "Health and load: messages a second, stored events, open alerts by "
             "severity, devices reporting, listeners, collectors and workers.", tool_status),
        Tool("list_alerts", "List alerts", "Alerts, newest activity first, with ATT&CK technique and stage.",
             tool_list_alerts, {"status": {"type": "string", "enum": statuses, "default": "open"},
                                "severity": {"type": "string", "enum": ["", *SEVERITIES[1:]],
                                             "description": "minimum severity"},
                                "query": {"type": "string", "description": "text in title, description, address or device"},
                                "detector": {"type": "string", "description": "detector id(s), comma-separated"},
                                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25}}),
        Tool("get_alert", "Alert details", "One alert in full: details, why it matters, what to do, ATT&CK technique, "
             "and false-positive status.", tool_get_alert, {"id": {"type": "integer"}}, ["id"]),
        Tool("search_events", "Search events", "Stored log events, newest first.", tool_search_events,
             {"hours": {"type": "number", "minimum": 0.1, "maximum": 8760, "default": 1},
              "ip": {"type": "string", "description": "source or destination address"},
              "port": {"type": "integer", "minimum": 0, "maximum": 65535, "description": "destination port"},
              "device": {"type": "string"}, "event_type": {"type": "string", "description": "e.g. traffic, auth_failure"},
              "action": {"type": "string", "enum": ["", "allow", "block"]}, "text": {"type": "string"},
              "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}}),
        Tool("list_devices", "List devices", "Devices sending logs, most recently heard first.", tool_devices),
        Tool("get_attack_matrix", "ATT&CK matrix", "Alert counts by MITRE ATT&CK tactic and technique.", tool_attack,
             {"range": {"type": "string", "enum": ["24h", "7d", "30d", "90d", "all"], "default": "30d"}}),
        Tool("get_high_risk_ports", "High risk ports", "Traffic and findings on high-risk ports (RDP, SMB, Telnet...).",
             tool_risk_ports, {"range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"}}),
        Tool("set_alert_status", "Acknowledge or resolve alerts", "Set alerts open, acknowledged or resolved. Needs a "
             "write token; recorded in the audit log.", tool_set_status,
             {"ids": {"type": "array", "items": {"type": "integer"}},
              "status": {"type": "string", "enum": ["open", "ack", "resolved"]}}, ["ids", "status"], write=True),
        Tool("mark_false_positive", "Mark a false positive", "Mark an alert a false positive: the same detector on the "
             "same entity will not alert again. Needs a write token and a justification; recorded in the audit log.",
             tool_false_positive, {"id": {"type": "integer"}, "justification": {"type": "string"}},
             ["id", "justification"], write=True),
    ], __version__)

    def _same_origin(request: Request) -> bool:
        """MCP over HTTP: refuse browsers on other sites (DNS rebinding); agents send no Origin."""
        origin = request.headers.get("origin")
        if not origin:
            return True
        from urllib.parse import urlsplit
        host = urlsplit(origin).netloc
        return host == request.headers.get("host") or (bool(cfg.public_url) and host == urlsplit(cfg.public_url).netloc)

    @app.post("/mcp")
    async def mcp_endpoint(request: Request):
        if not _same_origin(request):
            return JSONResponse({"detail": "cross-origin requests are not allowed"}, status_code=403)
        version = request.headers.get("mcp-protocol-version")
        from .mcp import PROTOCOL_VERSIONS
        if version and version not in PROTOCOL_VERSIONS:
            return JSONResponse({"detail": f"unsupported MCP protocol version {version}"}, status_code=400)
        try:
            message = json.loads(await request.body())
        except ValueError:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
                                status_code=400)
        if isinstance(message, list):
            return JSONResponse({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32600, "message": "batches are not supported"}}, status_code=400)
        who = request.state.who
        reply = await mcp.handle(message, {"scope": who["scope"], "name": who["name"],
                                           "source": request.client.host if request.client else ""})
        if reply is None:
            return Response(status_code=202)
        return JSONResponse(reply)

    @app.api_route("/mcp", methods=["GET", "DELETE"])
    async def mcp_other():
        return Response(status_code=405, headers={"Allow": "POST"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
