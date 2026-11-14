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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Config
from .db import Database, QueryTimeout
from .engine import TOTAL, Engine
from .models import SEVERITIES
from .models import clean_ip, is_internal
from .notifiers import CHANNEL_TYPES, Notifier, public_channel, validate_channel
from .playbooks import STAGES, advice, detector_stage
from .riskports import CATALOG, CLEARTEXT, DIRECTIONS, WEB, flags, service_name
from .snmp_poller import MASK as SNMP_MASK
from .snmp_poller import SnmpPoller, parse_target
from .topology import build_topology

log = logging.getLogger("cerberus.web")

STATIC = Path(__file__).parent / "static"
COOKIE = "cerberus_session"
SESSION_TTL = 7 * 86400
RISK_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 15}
RANGES = {"1h": (3600, 60), "6h": (6 * 3600, 300), "24h": (86400, 900), "7d": (7 * 86400, 3600)}
SEARCH_SECONDS = 10  # an event search running longer than this is cancelled
OPEN_PATHS = {"/api/login", "/api/logout", "/api/me"}


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


class Auth:
    def __init__(self, cfg: Config, db: Database):
        self.enabled = cfg.auth_enabled
        self.sessions: dict[str, float] = {}
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
            for token in [t for t, exp in self.sessions.items() if exp < now]:
                del self.sessions[token]
            token = secrets.token_urlsafe(32)
            self.sessions[token] = now + SESSION_TTL
            return token
        if len(self.failures) > 10_000:
            self.failures.clear()
        self.failures.setdefault(ip, deque(maxlen=10)).append(now)
        return None

    def valid(self, request: Request) -> bool:
        if not self.enabled:
            return True
        expiry = self.sessions.get(request.cookies.get(COOKIE, ""))
        return bool(expiry and expiry > time.time())


def _bad(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status_code=status, detail=message)


def _loads(text):
    try:
        return json.loads(text) if text else {}
    except ValueError:
        return {}


def create_app(cfg: Config, db: Database, engine: Engine, notifier: Notifier, poller: SnmpPoller) -> FastAPI:
    app = FastAPI(title="Cerberus", docs_url=None, redoc_url=None, openapi_url=None)
    auth = Auth(cfg, db)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path not in OPEN_PATHS and not auth.valid(request):
            return JSONResponse({"detail": "not signed in"}, status_code=401)
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

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    # --- auth ------------------------------------------------------------
    @app.get("/api/me")
    async def me(request: Request):
        return {"signed_in": auth.valid(request), "auth": auth.enabled, "version": __version__}

    @app.post("/api/login")
    async def login(request: Request, body: dict = Body(...)):
        ip = request.client.host if request.client else "?"
        if auth.throttled(ip, time.time()):
            raise _bad("Too many attempts. Wait a few minutes and try again.", 429)
        token = auth.login(str(body.get("password", ""))[:256], ip)
        if not token:
            log.warning("failed dashboard login from %s", ip)
            raise _bad("Wrong password.", 401)
        response = JSONResponse({"ok": True})
        response.set_cookie(COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="strict",
                            secure=request.url.scheme == "https")
        return response

    @app.post("/api/logout")
    async def logout(request: Request):
        auth.sessions.pop(request.cookies.get(COOKIE, ""), None)
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE)
        return response

    # --- dashboard -------------------------------------------------------
    @app.get("/api/summary")
    async def summary(range: str = "24h"):
        span, bucket = RANGES.get(range, RANGES["24h"])
        now = time.time()
        start = int((now - span) // bucket) * bucket
        rows = await db.aq(
            "SELECT (minute / ?) * ? AS t, SUM(events) AS e, SUM(blocked) AS b FROM stats_minute "
            "WHERE minute >= ? AND device = ? GROUP BY t", (bucket, bucket, start, TOTAL))
        found = {r["t"]: r for r in rows}
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
        day = await db.aq("SELECT SUM(events) AS e, SUM(blocked) AS b FROM stats_minute WHERE minute >= ? AND device = ?",
                          (int(now - 86400), TOTAL))
        counts = await db.aq("SELECT severity, COUNT(*) AS n FROM alerts WHERE status='open' GROUP BY severity")
        recent = await db.aq(
            "SELECT id, created, last_seen, severity, title, description, status, count FROM alerts "
            "ORDER BY last_seen DESC LIMIT 8")
        sources, ports = engine.top_blocked()
        devices = list(engine.devices.values())

        # Who needs attention first: unresolved alerts from the last 24 hours, scored per
        # host (the alert's source address, or the reporting device when there is none).
        active = await db.aq(
            "SELECT detector, severity, title, src_ip, device FROM alerts "
            "WHERE status != 'resolved' AND last_seen >= ? ORDER BY last_seen DESC LIMIT 2000", (now - 86400,))
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
            "events_24h": day[0]["e"] or 0,
            "blocked_24h": day[0]["b"] or 0,
            "open_alerts": {r["severity"]: r["n"] for r in counts},
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
        }

    # --- high-risk ports --------------------------------------------------
    async def _port_alerts(now: float) -> dict[int, list[dict]]:
        """Unresolved alerts from the last day that name a port, by port."""
        rows = await db.aq(
            "SELECT id, severity, title, last_seen, src_ip, details FROM alerts "
            "WHERE status != 'resolved' AND last_seen >= ? ORDER BY last_seen DESC LIMIT 2000", (now - 86400,))
        out: dict[int, list[dict]] = {}
        for row in rows:
            port = _loads(row.pop("details")).get("port")
            if isinstance(port, int):
                out.setdefault(port, []).append(row)
        return out

    @app.get("/api/riskports")
    async def riskports(range: str = "24h"):
        rp = engine.risk_ports
        span, bucket = RANGES.get(range, RANGES["24h"])
        now = time.time()
        start = int((now - span) // bucket) * bucket
        rows = await db.aq(
            "SELECT (minute / ?) * ? AS t, port, direction, SUM(allowed) AS a, SUM(blocked) AS b FROM port_minute "
            "WHERE minute >= ? GROUP BY t, port, direction", (bucket, bucket, start))
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
        spikes = rp.spikes(now) if rp.enabled else []
        fresh: dict[int, int] = {}
        for (port, _way, _src), first in list(rp.first_seen.items()):
            if now - first < 86400 and first - rp.since > 6 * 3600:
                fresh[port] = fresh.get(port, 0) + 1
        alerts = await _port_alerts(now)
        buckets = []
        t = start
        while t < now:
            buckets.append(t)
            t += bucket
        ports = []
        for port, per in totals.items():
            found = flags(port, per, spikes, fresh.get(port, 0))
            mine = alerts.get(port, [])
            ports.append({
                "port": port, "name": service_name(port), "why": CATALOG.get(port, ("", ""))[1],
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
            "quiet": sorted(({"port": p, "name": service_name(p)} for p in rp.ports if p not in totals), key=lambda q: q["port"]),
            "summary": {
                "flagged": sum(1 for p in ports if p["severity"] in ("high", "medium")),
                "exposed": sum(p["totals"]["inbound"][0] for p in plain),
                "exposed_ports": sum(1 for p in plain if p["totals"]["inbound"][0]),
                "blocked_inbound": sum(p["totals"]["inbound"][1] for p in ports),
                "cleartext": sum(p["totals"]["outbound"][0] + p["totals"]["internal"][0] for p in plain if p["port"] in CLEARTEXT),
                "egress": sum(p["totals"]["outbound"][0] for p in plain if p["port"] != 22),
            },
            "enabled": rp.enabled, "since": rp.since or None,
            "history_hours": rp.cfg["history_hours"],
        }

    @app.get("/api/riskports/port")
    async def riskport_detail(port: int):
        rp = engine.risk_ports
        now = time.time()
        return {"port": port, "name": service_name(port),
                "directions": {way: rp.top(port, way, now) for way in DIRECTIONS},
                "alerts": (await _port_alerts(now)).get(port, [])[:20]}

    # --- alerts ----------------------------------------------------------
    @app.get("/api/alerts")
    async def alerts(status: str = "open", severity: str = "", q: str = "", limit: int = 200, id: int = 0):
        where, params = [], []
        if id:
            where.append("id = ?")
            params.append(id)
        elif status in ("open", "ack", "resolved"):
            where.append("status = ?")
            params.append(status)
        elif status == "active":
            where.append("status != 'resolved'")
        if severity in SEVERITIES:
            where.append("severity IN (%s)" % ",".join("?" * (len(SEVERITIES) - SEVERITIES.index(severity))))
            params += SEVERITIES[SEVERITIES.index(severity):]
        if q:
            where.append("(title LIKE ? OR description LIKE ? OR src_ip LIKE ? OR device LIKE ?)")
            params += [f"%{q}%"] * 4
        sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "")
        rows = await db.aq(sql + " ORDER BY last_seen DESC LIMIT ?", (*params, max(1, min(limit, 1000))))
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
    async def alert_status(body: dict = Body(...)):
        status = body.get("status")
        if status not in ("open", "ack", "resolved"):
            raise _bad("invalid status")
        if body.get("all_open"):
            ids = [r["id"] for r in await db.aq("SELECT id FROM alerts WHERE status = 'open'")]
        else:
            ids = [int(i) for i in body.get("ids", []) if str(i).isdigit()][:5000]
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            await db.ax(f"UPDATE alerts SET status=? WHERE id IN ({','.join('?' * len(chunk))})", (status, *chunk))
        engine.alerts.set_status(ids, status)
        return {"updated": len(ids)}

    # --- events ----------------------------------------------------------
    @app.get("/api/events")
    async def events(hours: float = 24, device: str = "", type: str = "", action: str = "", ip: str = "",
                     port: str = "", q: str = "", before: int = 0, limit: int = 200):
        since = time.time() - max(0.1, min(hours, 24 * 365)) * 3600
        where, params = [], []
        for column, value in (("device", device), ("event_type", type), ("action", action)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            params += [ip, ip]
        if port.isdigit():
            where.append("dst_port = ?")
            params.append(int(port))
        if q:
            where.append("message LIKE ?")
            params.append(f"%{q}%")
        try:
            rows = await asyncio.to_thread(db.search_events, where, params, since, max(0, before),
                                           max(1, min(limit, 1000)), SEARCH_SECONDS)
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
        await db.ax("UPDATE devices SET name=?, connector_pin=?, snmp_mode=?, snmp_community=?, snmp_host=? WHERE id=?",
                    (dev.name, pin, mode, dev.snmp_community, host, dev.id))
        if changed and poller.target(dev)[0]:
            asyncio.create_task(poller.poll(dev))
        return {**dev.as_dict(), "snmp": poller.status(dev)}

    @app.post("/api/devices/forget")
    async def device_forget(body: dict = Body(...)):
        device_id = str(body.get("id", ""))
        engine.forget_device(device_id)
        poller.forget(device_id)
        await db.ax("DELETE FROM devices WHERE id=?", (device_id,))
        await db.ax("DELETE FROM snmp_data WHERE device=?", (device_id,))
        return {"ok": True}

    # --- SNMP and topology -------------------------------------------------
    @app.get("/api/topology")
    async def topology():
        rows = await db.aq("SELECT device, severity, COUNT(*) AS n FROM alerts WHERE status='open' GROUP BY device, severity")
        counts: dict[str, dict] = {}
        for row in rows:
            counts.setdefault(row["device"] or "", {})[row["severity"]] = row["n"]
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

    # --- notification channels -------------------------------------------
    def _types():
        return {k: {"label": v["label"], "required": v["required"],
                    "fields": [{"key": f[0], "label": f[1], "kind": f[2], "default": f[3]} for f in v["fields"]]}
                for k, v in CHANNEL_TYPES.items()}

    async def _channel(channel_id: int) -> dict:
        rows = await db.aq("SELECT * FROM channels WHERE id=?", (channel_id,))
        if not rows:
            raise _bad("unknown channel", 404)
        return rows[0]

    @app.get("/api/channels")
    async def channels():
        rows = await db.aq("SELECT * FROM channels ORDER BY id")
        return {"channels": [public_channel(r) for r in rows], "types": _types(), "severities": SEVERITIES}

    @app.post("/api/channels")
    async def channel_create(body: dict = Body(...)):
        try:
            row = validate_channel(body)
        except ValueError as exc:
            raise _bad(str(exc))
        new_id = await db.ax(
            "INSERT INTO channels(type, name, enabled, min_severity, config) VALUES(?,?,?,?,?)",
            (row["type"], row["name"], row["enabled"], row["min_severity"], row["config"]))
        await notifier.reload()
        return public_channel(await _channel(new_id))

    @app.put("/api/channels/{channel_id}")
    async def channel_update(channel_id: int, body: dict = Body(...)):
        existing = await _channel(channel_id)
        try:
            row = validate_channel(body, existing)
        except ValueError as exc:
            raise _bad(str(exc))
        await db.ax("UPDATE channels SET name=?, enabled=?, min_severity=?, config=? WHERE id=?",
                    (row["name"], row["enabled"], row["min_severity"], row["config"], channel_id))
        await notifier.reload()
        return public_channel(await _channel(channel_id))

    @app.delete("/api/channels/{channel_id}")
    async def channel_delete(channel_id: int):
        await db.ax("DELETE FROM channels WHERE id=?", (channel_id,))
        await notifier.reload()
        return {"ok": True}

    @app.post("/api/channels/{channel_id}/test")
    async def channel_test(channel_id: int):
        channel = await _channel(channel_id)
        error = await notifier.deliver(
            channel, "[Cerberus] Test notification",
            "This is a test from Cerberus. If you can read it, this channel works.",
            retry=False)
        if error:
            raise _bad(error, 502)
        return {"ok": True}

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
