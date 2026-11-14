"""Sites reporting to a central console, end to end, in one process.

Each site is a real Engine with its own database; the console is the real web
app, reached through httpx's ASGI transport instead of a network.
"""
import asyncio
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus import federation  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.federation import Central, Forwarder  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402
from cerberus.web import create_app  # noqa: E402
from tools import simulate  # noqa: E402


def config(tmp_path, **extra) -> Config:
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity, cfg.auth_enabled = tmp_path, "hostname", False
    for key, value in extra.items():
        setattr(cfg, key, value)
    return cfg


class Console:
    def __init__(self, tmp_path, **extra):
        self.cfg = config(tmp_path, central=True, **extra)
        self.db = Database(tmp_path / "central.db")
        self.notifier = Notifier(self.db)
        self.engine = Engine(self.cfg, self.db, ConnectorRegistry(), self.notifier)
        self.engine.load()
        self.central = Central(self.cfg, self.db, self.engine)
        self.central.provision(list(self.cfg.site_tokens))
        self.app = create_app(self.cfg, self.db, self.engine, self.notifier, SnmpPoller(self.engine, self.db),
                              central=self.central)
        self.http = TestClient(self.app)
        self.sent: list[dict] = []
        self.notifier.notify = self.sent.append  # record instead of delivering

    def add_site(self, name: str) -> str:
        r = self.http.post("/api/sites", json={"name": name})
        assert r.status_code == 200, r.text
        return r.json()["token"]

    def alerts(self, **query) -> list[dict]:
        return self.http.get("/api/site-alerts", params={"status": "", **query}).json()["alerts"]


class Site:
    def __init__(self, tmp_path, console: Console, name: str, token: str):
        self.cfg = config(tmp_path, site_name=name, central_url="http://console", central_token=token)
        self.db = Database(tmp_path / f"{name}.db")
        self.engine = Engine(self.cfg, self.db, ConnectorRegistry(), Notifier(self.db))
        self.engine.load()
        self.engine.installed = time.time()  # inside the learning period: no "new log source" alerts
        self.forwarder = Forwarder(self.cfg, self.db, self.engine, transport=httpx.ASGITransport(app=console.app))
        self.forwarder.load()
        self.now = time.time() - 600

    def feed(self, lines):
        for line in lines:
            self.now += 0.05
            self.engine._process(line.encode(), "10.255.0.1", self.now)
        asyncio.run(self.engine._flush())
        return self

    def report(self) -> bool:
        async def once():
            try:
                return await self.forwarder.report_once()
            finally:
                await self.forwarder.close()
                self.forwarder.client = None
        return asyncio.run(once())

    def statuses(self) -> dict[int, str]:
        return {r["id"]: r["status"] for r in self.db.q("SELECT id, status FROM alerts")}


def test_sites_report_alerts_and_health(tmp_path):
    console = Console(tmp_path)
    north = Site(tmp_path, console, "north", console.add_site("north")).feed(simulate.portscan())
    south = Site(tmp_path, console, "south", console.add_site("south")).feed(simulate.exposed())
    assert north.report() is False and south.report() is False

    alerts = console.alerts()
    assert {(a["site"], a["detector"]) for a in alerts} == {("north", "port_scan"), ("south", "exposed_service")}
    rdp = next(a for a in alerts if a["site"] == "south")
    assert rdp["advice"]["actions"] and rdp["details"]["port"] == 3389 and rdp["status"] == "open"
    # The console pages once per new alert, naming the site, and links to the alert on the console.
    assert sorted(m["title"].split(":")[0] for m in console.sent) == ["north", "south"]
    assert console.sent[0]["link"].startswith("#/sites?alert=")

    sites = {s["name"]: s for s in console.http.get("/api/sites").json()["sites"]}
    assert sites["north"]["state"] == "reporting" and sites["north"]["open_alerts"] == {"high": 1}
    assert sites["north"]["summary"]["devices_total"] == 1 and sites["north"]["version"]
    assert sites["south"]["open_alerts"] == {"high": 1}

    # Reporting again changes nothing and pages nobody: delivery is idempotent.
    north.forwarder.cursor = [0.0, 0]
    north.report()
    assert len(console.alerts()) == 2 and len(console.sent) == 2


def test_alert_changes_flow_and_catch_up_in_batches(tmp_path, monkeypatch):
    monkeypatch.setattr(federation, "BATCH", 3)
    console = Console(tmp_path)
    site = Site(tmp_path, console, "lab", console.add_site("lab"))
    site.feed([*simulate.portscan(), *simulate.sweep(), *simulate.flood(), *simulate.bruteforce(), *simulate.threat()])
    raised = len(site.statuses())
    assert raised > 6
    reports = 1
    while site.report():  # catching up: one batch per report until nothing is left
        reports += 1
    assert reports == -(-raised // 3) and len(console.alerts()) == raised
    # A recurrence updates the same alert at the console rather than adding one.
    before = {a["alert_id"]: a["count"] for a in console.alerts()}
    site.feed(simulate.portscan())
    site.report()
    after = {a["alert_id"]: a["count"] for a in console.alerts()}
    assert len(after) == raised and any(after[k] > before[k] for k in before)


def test_acknowledging_at_the_console_reaches_the_site(tmp_path):
    console = Console(tmp_path)
    site = Site(tmp_path, console, "hq", console.add_site("hq")).feed([*simulate.portscan(), *simulate.exposed()])
    site.report()
    scan = next(a for a in console.alerts() if a["detector"] == "port_scan")
    assert console.http.post("/api/site-alerts/status", json={"ids": [scan["id"]], "status": "ack"}).json()["updated"] == 1
    # Until the site applies it, the console keeps its own choice even though the site still says "open".
    site.report()
    assert site.statuses()[scan["alert_id"]] == "ack"
    assert console.alerts(id=scan["id"])[0]["status"] == "ack"
    site.report()  # the site reports the change back; nothing is pending any more
    row = console.db.q("SELECT status, pending FROM site_alerts WHERE id = ?", (scan["id"],))[0]
    assert row == {"status": "ack", "pending": None}
    # Resolving works the same way, and the site's alert manager forgets it.
    console.http.post("/api/site-alerts/status", json={"ids": [scan["id"]], "status": "resolved"})
    site.report()
    assert site.statuses()[scan["alert_id"]] == "resolved"
    assert all(a.id != scan["alert_id"] for a in site.engine.alerts.active.values())
    # A status changed at the site travels up.
    rdp = next(a for a in console.alerts() if a["detector"] == "exposed_service")
    site.db.x("UPDATE alerts SET status = 'ack', updated = ? WHERE id = ?", (time.time(), rdp["alert_id"]))
    site.report()
    assert console.alerts(id=rdp["id"])[0]["status"] == "ack"


def test_tokens_and_rebuilt_sites(tmp_path):
    console = Console(tmp_path)
    token = console.add_site("edge")
    assert console.http.post("/api/sites", json={"name": "edge"}).status_code == 400
    assert console.http.post("/api/sites", json={"name": "two words"}).status_code == 400
    # No token, a wrong one, junk: all refused, nothing stored.
    assert console.http.post("/api/federation/report", json={}).status_code == 401
    bad = {"Authorization": "Bearer " + "x" * 40}
    assert console.http.post("/api/federation/report", json={"instance": "a", "alerts": []}, headers=bad).status_code == 401
    good = {"Authorization": f"Bearer {token}"}
    assert console.http.post("/api/federation/report", content=b"{nope", headers=good).status_code == 400
    assert console.http.post("/api/federation/report", json={"alerts": []}, headers=good).status_code == 400
    junk = {"instance": "abc", "alerts": [{"id": "1"}, {"id": -4}, "x", {"id": 7, "severity": "dreadful", "status": "?"}]}
    reply = console.http.post("/api/federation/report", json=junk, headers=good).json()
    assert reply["ok"] and [(a["alert_id"], a["severity"], a["status"]) for a in console.alerts()] == [(7, "info", "open")]

    # Rotating the token locks the old one out.
    site_id = console.http.get("/api/sites").json()["sites"][0]["id"]
    fresh = console.http.post(f"/api/sites/{site_id}/token").json()["token"]
    assert console.http.post("/api/federation/report", json=junk, headers=good).status_code == 401
    site = Site(tmp_path, console, "edge", fresh).feed(simulate.portscan())
    site.report()
    # A site rebuilt with an empty database numbers its alerts from 1 again; its old alerts are kept.
    rebuilt = Site(tmp_path / "rebuilt", console, "edge", fresh) if (tmp_path / "rebuilt").mkdir() is None else None
    rebuilt.feed(simulate.exposed())
    rebuilt.report()
    kinds = sorted(a["detector"] for a in console.alerts())
    assert kinds == ["", "exposed_service", "port_scan"]
    assert len({a["alert_id"] for a in console.alerts() if a["detector"]}) == 1  # both are alert 1, kept apart
    # Deleting the site deletes its alerts.
    assert console.http.delete(f"/api/sites/{site_id}").json() == {"ok": True}
    assert console.alerts() == [] and console.http.get("/api/sites").json()["sites"] == []


def test_sites_from_configuration(tmp_path):
    token_file = tmp_path / "sites.txt"
    token_file.write_text("# name token\nalpha " + "a" * 32 + "\nbeta " + "b" * 32 + "\n")
    import os
    os.environ["CERBERUS_SITE_TOKENS_FILE"] = str(token_file)
    try:
        cfg = Config.from_env()
    finally:
        del os.environ["CERBERUS_SITE_TOKENS_FILE"]
    assert cfg.site_tokens == (("alpha", "a" * 32), ("beta", "b" * 32))
    console = Console(tmp_path, site_tokens=cfg.site_tokens)
    sites = {s["name"]: s for s in console.http.get("/api/sites").json()["sites"]}
    assert set(sites) == {"alpha", "beta"} and all(s["managed"] and s["state"] == "waiting" for s in sites.values())
    # Managed sites cannot be deleted or re-keyed from the UI, and restarting keeps them.
    assert console.http.delete(f"/api/sites/{sites['alpha']['id']}").status_code == 400
    assert console.http.post(f"/api/sites/{sites['alpha']['id']}/token").status_code == 400
    console.central.provision(list(cfg.site_tokens))
    assert len(console.http.get("/api/sites").json()["sites"]) == 2
    site = Site(tmp_path, console, "alpha", "a" * 32).feed(simulate.portscan())
    site.report()
    assert [a["site"] for a in console.alerts()] == ["alpha"]
    bad = tmp_path / "bad.txt"
    bad.write_text("gamma short\n")
    os.environ["CERBERUS_SITE_TOKENS_FILE"] = str(bad)
    try:
        with pytest.raises(ValueError):
            Config.from_env()
    finally:
        del os.environ["CERBERUS_SITE_TOKENS_FILE"]


def test_silent_site_alert(tmp_path):
    console = Console(tmp_path, site_silent_minutes=5)
    site = Site(tmp_path, console, "branch", console.add_site("branch")).feed(simulate.baseline(20))
    site.report()
    now = time.time()
    assert console.central.check(now + 60) == []
    found = console.central.check(now + 6 * 60)
    assert [c.title for c in found] == ["Site stopped reporting: branch"] and found[0].severity == "high"
    assert console.central.check(now + 7 * 60) == []  # once per silence
    assert console.http.get("/api/sites").json()["sites"][0]["state"] == "reporting"  # 'now' above is simulated
    site.report()  # reporting again clears it, so the next silence is reported too
    assert len(console.central.check(time.time() + 6 * 60)) == 1


def test_site_keeps_working_when_the_console_is_down(tmp_path):
    console = Console(tmp_path)
    site = Site(tmp_path, console, "island", console.add_site("island")).feed(simulate.portscan())

    def refuse(request):
        raise httpx.ConnectError("connection refused")
    site.forwarder.transport = httpx.MockTransport(refuse)
    with pytest.raises(httpx.ConnectError):
        site.report()
    assert site.forwarder.cursor == [0.0, 0]  # nothing was accepted, so nothing is skipped
    site.forwarder.transport = httpx.ASGITransport(app=console.app)
    site.report()
    assert [a["detector"] for a in console.alerts()] == ["port_scan"]


def test_console_endpoints_absent_on_ordinary_instances(tmp_path):
    cfg = config(tmp_path)
    db = Database(tmp_path / "plain.db")
    engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    engine.load()
    http = TestClient(create_app(cfg, db, engine, engine.notifier, SnmpPoller(engine, db)))
    assert http.post("/api/federation/report", json={}).status_code in (404, 405)
    assert http.get("/api/sites").status_code == 404
    assert http.get("/api/me").json()["central"] is False
    db.close()


def test_sessions_survive_a_restart_and_logout_reaches_every_replica(tmp_path):
    from cerberus import web
    cfg = config(tmp_path, auth_enabled=True, password="correct horse")
    db = Database(tmp_path / "s.db")

    def replica():
        engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
        engine.load()
        return TestClient(web.create_app(cfg, db, engine, engine.notifier, SnmpPoller(engine, db)))

    first = replica()
    assert first.get("/api/devices").status_code == 401
    assert first.post("/api/login", json={"password": "wrong"}).status_code == 401
    assert first.post("/api/login", json={"password": "correct horse"}).status_code == 200
    token = first.cookies.get(web.COOKIE)
    assert first.get("/api/devices").status_code == 200
    # Only a hash of the token is stored.
    assert db.session_expires(token) is None and db.session_expires(web._token_hash(token)) > time.time()

    second = replica()  # another replica, or the same one after a restart
    second.cookies.set(web.COOKIE, token)
    assert second.get("/api/me").json()["signed_in"] is True
    assert first.post("/api/logout").status_code == 200
    third = replica()
    third.cookies.set(web.COOKIE, token)
    assert third.get("/api/devices").status_code == 401  # logged out everywhere
    db.close()
