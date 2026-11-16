#!/usr/bin/env python3
"""Build the static demo site: the real dashboard on recorded answers.

    python tools/build_demo.py --out site
    python -m http.server -d site 8000        # then open http://localhost:8000

A Cerberus instance is run in this process on simulated traffic (the scenarios
of tools/simulate.py and the fake SNMP agents of tools/snmp_sim.py), a few
people do ordinary work in it, and every answer the dashboard asks for is saved
as a JSON file. The site is the dashboard's own HTML, CSS and JavaScript plus
tools/demo/demo.js, which answers its API calls from those files. Nothing in it
is live and nothing can be changed; every address and name is simulated.
GitHub Pages serves it (.github/workflows/pages.yml).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASSWORD = "demo-only-password-1"  # for accounts that exist only while this script runs
TICK = 10.0


def key_for(path: str) -> str:
    """The name an API call is filed under: its path and its query, sorted."""
    parts = urlsplit(path)
    query = "&".join(f"{k}={v}" for k, v in sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return parts.path + ("?" + query if query else "")


def seed_history(db, now: float, until: float) -> None:
    """A day of plausible per-minute counters up to `until`, where the simulated run takes
    over, so the charts have a shape."""
    rnd = random.Random(11)
    minute0 = int(now // 60) * 60
    stats, ports = [], []
    for i in range(24 * 60, 0, -1):
        minute = minute0 - i * 60
        if minute >= int(until // 60) * 60:
            break
        hour = time.gmtime(minute).tm_hour + time.gmtime(minute).tm_min / 60
        day = 0.35 + 0.65 * max(0.0, math.sin((hour - 7) / 12 * math.pi))  # busy in working hours
        events = int(900 * day * rnd.uniform(0.85, 1.15)) + 120
        stats.append((minute, "*", events, int(events * rnd.uniform(0.08, 0.14))))
        for port, way, allowed, denied in ((80, "outbound", 40, 0), (22, "internal", 6, 0), (22, "inbound", 0, 9),
                                           (3389, "inbound", 0, 7), (445, "internal", 14, 1), (445, "inbound", 0, 6),
                                           (23, "inbound", 0, 8), (3389, "internal", 5, 0), (5900, "inbound", 0, 2),
                                           (1433, "inbound", 0, 3), (21, "internal", 1, 0)):
            a, b = int(allowed * day * rnd.uniform(0.6, 1.4)), int(denied * rnd.uniform(0.4, 1.6))
            if a or b:
                ports.append((minute, port, way, a, b))
    db.batch([("INSERT INTO stats_minute(minute, device, events, blocked) VALUES(?,?,?,?)", stats),
              ("INSERT INTO port_minute(minute, port, direction, allowed, blocked) VALUES(?,?,?,?,?)", ports)])
    db.set_setting("stats_totals", True)


def timeline(simulate) -> list[tuple[float, str]]:
    """(seconds from the start, syslog line): warm-up traffic, then every scenario, a beacon,
    and ordinary traffic to the end. About 70 minutes."""
    random.seed(20261116)
    out: list[tuple[float, str]] = []

    def ordinary(start: float, seconds: float) -> None:
        """Background traffic at about the level of the seeded history, and the odd routine
        line from the switches, so every device is seen to be reporting."""
        at, n = start, 0
        while at < start + seconds:
            for i, line in enumerate(simulate.baseline(28)):
                out.append((at + i * 0.1, line))
            if n % 12 == 0:
                out.append((at + 3, simulate.cisco(1000 + n, "%NTP-6-PEERREACH: Peer 192.168.1.1 is reachable")))
                out.append((at + 4, f"<14>{simulate.bsd_time()} {simulate.RTL} ntp: time synchronised with 192.168.1.1"))
            at += TICK
            n += 1

    t = 2400.0  # 40 minutes: past the rate baselines' warm-up
    ordinary(0, t)
    for name, scenario in simulate.SCENARIOS.items():
        if name in simulate.SLOW:
            continue
        began = t
        for line in scenario():
            out.append((t, line))
            t += 0.05
        t = (int(t // TICK) + 3) * TICK
        ordinary(began, t - began)
    began = t
    for _ in range(13):  # a beacon: check-ins thirty seconds apart
        out.append((t, simulate.forti_traffic("192.168.3.61", "45.77.12.34", 8443)))
        t += 30
    t += 180
    ordinary(began, t - began)
    out.sort(key=lambda item: item[0])
    return out


def run_traffic(engine, lines: list[tuple[float, str]], start: float, now: float) -> None:
    loop = asyncio.new_event_loop()
    next_tick = start + TICK
    for offset, line in lines:
        ts = start + offset
        while next_tick <= ts:
            loop.run_until_complete(engine._flush())
            engine.tick(next_tick)
            next_tick += TICK
        engine._process(line.encode(), "10.255.0.1", ts)
    loop.run_until_complete(engine._flush())
    engine.tick(now)
    loop.run_until_complete(engine._flush())
    loop.close()
    # The running service samples its message counter every second for "Messages / second";
    # here the clock was simulated, so give it the last minute's samples.
    minute = sum(1 for offset, _ in lines if offset >= lines[-1][0] - 60)
    engine._rate.clear()
    engine._rate.extend([(now - 60, engine.received - minute), (now, engine.received)])


class Agents:
    """tools/snmp_sim.py's fake devices, in a thread of their own."""

    def __init__(self):
        self.ports: dict[str, int] = {}
        self._ready = threading.Event()
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._run, daemon=True).start()
        if not self._ready.wait(15):
            raise SystemExit("the fake SNMP agents did not start")

    def _run(self) -> None:
        from tools import snmp_sim
        asyncio.set_event_loop(self._loop)

        async def start():
            agents = await snmp_sim.serve(snmp_sim.network(with_rogue=False), first_port=0)
            self.ports = {name: port for name, (_t, _a, port) in agents.items()}
            self._ready.set()
        self._loop.run_until_complete(start())
        self._loop.run_forever()


def build(out: Path) -> dict:
    from fastapi.testclient import TestClient

    from cerberus import __version__, web
    from cerberus.config import Config
    from cerberus.connectors import ConnectorRegistry
    from cerberus.db import Database
    from cerberus.engine import Engine
    from cerberus.notifiers import Notifier
    from cerberus.snmp_poller import SnmpPoller

    work = Path(tempfile.mkdtemp(prefix="cerberus-demo-"))
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity, cfg.auth_enabled, cfg.password = work, "hostname", True, PASSWORD
    cfg.public_url = "https://cerberus.example.com"
    now = time.time()
    from tools import simulate
    lines = timeline(simulate)
    start = now - lines[-1][0] - 45  # the last line lands under a minute ago
    db = Database(work / "cerberus.db")
    seed_history(db, now, start)
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    engine.installed = now - 3 * 86400  # long installed: new-device alerts are live
    watch = {d.id: d.settings() for d in engine.detectors}
    watch["watchlist"]["entries"] = "45.77.0.0/16"
    engine.apply_settings(watch, engine.general_settings())
    db.set_setting("detectors", watch)
    run_traffic(engine, lines, start, now)

    app = web.create_app(cfg, db, engine, notifier, SnmpPoller(engine, db))

    def session(username: str = "", password: str = PASSWORD) -> TestClient:
        c = TestClient(app, base_url="https://cerberus.example.com")
        r = c.post("/api/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return c

    def ok(response):
        assert response.status_code == 200, (response.request.method, response.request.url, response.text[:300])
        return response.json()

    # --- the people, and what they did ----------------------------------------------
    admin = session()
    for username, display, role in (("jlee", "Jordan Lee", "admin"), ("spatel", "Sam Patel", "analyst"),
                                    ("mgarcia", "Morgan Garcia", "analyst"), ("noc", "NOC wallboard", "viewer"),
                                    ("demo", "Demo visitor", "admin")):
        ok(admin.post("/api/users", json={"username": username, "display_name": display, "role": role,
                                          "password": PASSWORD}))
    jordan = session("jlee")
    agents = Agents()
    for name, port in agents.ports.items():
        if name in engine.devices:
            ok(jordan.put("/api/devices", json={"id": name, "snmp_host": f"127.0.0.1:{port}"}))
    for name in engine.devices:
        if name not in agents.ports:
            ok(jordan.put("/api/devices", json={"id": name, "snmp_mode": "off"}))  # no agent to answer
    ok(jordan.put("/api/snmp", json={"enabled": True, "community": "public",
                                     "networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]}))
    polled = ok(jordan.post("/api/snmp/poll", json={}))
    ok(jordan.post("/api/tokens", json={"name": "SOAR triage agent", "scope": "write"}))
    ok(jordan.post("/api/tokens", json={"name": "Grafana (read only)", "scope": "read"}))
    ok(jordan.post("/api/channels", json={"type": "smtp", "name": "Network security team", "min_severity": "high",
                                          "config": {"host": "smtp.example.com", "port": "587", "security": "starttls",
                                                     "username": "cerberus", "password": "not-a-real-password",
                                                     "from_addr": "cerberus@example.com",
                                                     "to_addrs": "netsec@example.com"}}))
    ok(jordan.post("/api/channels", json={"type": "webhook", "name": "SOAR intake", "min_severity": "medium",
                                          "config": {"url": "https://soar.example.com/hooks/cerberus",
                                                     "secret": "not-a-real-secret"}}))
    session("noc")
    sam, morgan = session("spatel"), session("mgarcia")
    alerts = ok(sam.get("/api/alerts?status=&limit=1000"))["alerts"]

    def pick(prefix: str) -> int:
        return next(a["id"] for a in alerts if a["title"].startswith(prefix))

    ok(sam.post("/api/alerts/status", json={"ids": [pick("Network loop"), pick("Spanning-tree guard tripped")],
                                            "status": "ack"}))
    ok(morgan.post("/api/alerts/false-positive", json={"id": pick("Host sweep from"), "justification":
                   "192.168.1.88 is the vulnerability scanner: weekly authenticated scan of the server VLAN, "
                   "change CHG-2231."}))
    ok(morgan.post("/api/alerts/status", json={"ids": [pick("Configuration changed")], "status": "resolved"}))
    ok(sam.post("/api/alerts/status", json={"ids": [pick("Successful login after")], "status": "ack"}))

    # --- record what the dashboard asks for ---------------------------------------------
    demo = session("demo")
    api = out / "api"
    api.mkdir(parents=True)
    files: dict[str, str] = {}

    def record(path: str):
        data = ok(demo.get("/api" + path))
        name = f"{len(files):03d}.json"
        (api / name).write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        files[key_for(path)] = name
        return data

    record("/me")
    for r in ("1h", "6h", "24h", "7d"):
        record(f"/summary?range={r}")
        ports = record(f"/riskports?range={r}")
    record("/alerts/counts")
    record("/alerts?status=&limit=1000")  # every alert: demo.js filters this list as the server would
    record("/events?hours=8760&limit=1000")  # the newest events: filtered the same way
    for r in ("24h", "7d", "30d", "90d", "all"):
        for status in ("real", "active", "all"):
            record(f"/attack?range={r}&status={status}")
    for row in ports.get("ports", []):
        record(f"/riskports/port?port={row['port']}")
    record("/suppressions")
    record("/audit?limit=500")
    record("/devices")
    topology = record("/topology")
    for node in topology["nodes"]:
        if node.get("device"):
            record("/topology/device?id=" + node["device"])
    for path in ("/connectors", "/listeners", "/detectors", "/channels", "/tokens", "/users", "/display",
                 "/collector-storage"):
        record(path)

    static = out / "static"
    shutil.copytree(ROOT / "cerberus" / "static", static)
    shutil.copy(ROOT / "tools" / "demo" / "demo.js", static / "demo.js")
    index = (static / "index.html").read_text(encoding="utf-8")
    index = index.replace('"/static/', '"static/')
    assert '<script src="static/app.js"></script>' in index
    index = index.replace('<script src="static/app.js"></script>',
                          '<script src="static/demo.js"></script>\n<script src="static/app.js"></script>')
    index = index.replace("<title>Cerberus</title>",
                          "<title>Cerberus demo</title>\n"
                          '<meta name="description" content="A read-only demo of Cerberus, network threat detection '
                          'from syslog, on simulated data.">')
    (static / "index.html").unlink()
    (out / "index.html").write_text(index, encoding="utf-8")
    (out / ".nojekyll").write_text("")
    manifest = {"recorded_at": time.time(), "version": __version__, "files": files}
    (api / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    db.close()
    shutil.rmtree(work, ignore_errors=True)
    return {"alerts": len(alerts), "events": engine.received if hasattr(engine, "received") else None,
            "devices_polled": polled, "topology_links": len(topology["links"]), "files": len(files),
            "bytes": sum(f.stat().st_size for f in out.rglob("*") if f.is_file())}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("site"), help="folder to write (replaced if it exists)")
    args = parser.parse_args()
    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)
    print(json.dumps(build(args.out.resolve()), indent=1, default=str))


if __name__ == "__main__":
    main()
