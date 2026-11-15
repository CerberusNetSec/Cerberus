"""Marking an alert a false positive: audited, and the same finding never alerts again."""
import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from cerberus import web  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402
from cerberus.storage import NotFound  # noqa: E402

T = 1_800_000_000.0
WHY = "Nightly vulnerability scan from the security team's scanner, confirmed with J. Smith."


def scan(entity="10.0.0.9", detector="port_scan"):
    return Candidate(detector, entity, "high", f"Port scan from {entity}", "60 ports in a minute", entity, "")


class Rig:
    def __init__(self, tmp_path):
        self.cfg = Config.from_env()
        self.cfg.data_dir, self.cfg.auth_enabled = tmp_path, False
        self.db = Database(tmp_path / "c.db")
        self.db.add_channel({"type": "webhook", "name": "hook", "enabled": 1, "min_severity": "low",
                             "config": json.dumps({"url": "https://hooks.example/x"})})
        self.notifier = Notifier(self.db)
        self.engine = Engine(self.cfg, self.db, ConnectorRegistry(), self.notifier)
        self.engine.load(now=T)
        asyncio.run(self.notifier.reload())
        self.client = TestClient(web.create_app(self.cfg, self.db, self.engine, self.notifier,
                                                SnmpPoller(self.engine, self.db)))

    def raise_(self, c, ts):
        self.engine.raise_alert(c, ts)

    def flush(self):
        asyncio.run(self.engine._flush())

    def alerts(self, status=""):
        return self.client.get(f"/api/alerts?status={status}&limit=100").json()["alerts"]

    def mark(self, alert_id, justification=WHY, analyst="Alex Analyst"):
        return self.client.post("/api/alerts/false-positive",
                                json={"id": alert_id, "justification": justification, "analyst": analyst})


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.db.close()


def test_the_same_finding_never_alerts_again(rig):
    rig.raise_(scan(), T)
    rig.flush()
    [alert] = rig.alerts()
    assert rig.mark(alert["id"]).status_code == 200
    assert rig.db.outbox_pending() == 1  # the original alert's notification only

    # Long after the cooldown, when it would otherwise be a new alert:
    for i in range(3):
        rig.raise_(scan(), T + 7200 + i)
    rig.flush()
    assert [a["id"] for a in rig.alerts("all")] == [alert["id"]]
    assert rig.db.outbox_pending() == 1  # nothing more to send
    [s] = rig.db.suppressions()
    assert s["hits"] == 3 and s["last_hit"] == T + 7202

    # The same detector on another entity, or another detector on the same entity, still alerts.
    rig.raise_(scan("10.0.0.10"), T + 7300)
    rig.raise_(scan(detector="host_sweep"), T + 7300)
    rig.flush()
    assert sorted((a["detector"], a["entity"]) for a in rig.alerts("open")) == [
        ("host_sweep", "10.0.0.9"), ("port_scan", "10.0.0.10")]


def test_marking_is_audited_and_shown_with_the_alert(rig):
    rig.raise_(scan(), T)
    rig.flush()
    alert_id = rig.alerts()[0]["id"]
    rig.mark(alert_id)
    [a] = rig.alerts("false_positive")
    assert a["status"] == "false_positive"
    assert a["false_positive"]["analyst"] == "Alex Analyst" and a["false_positive"]["justification"] == WHY
    assert rig.alerts("open") == [] and rig.alerts("active") == []
    [entry] = rig.client.get("/api/audit").json()["audit"]
    assert entry["action"] == "false_positive" and entry["analyst"] == "Alex Analyst"
    assert entry["alert_id"] == alert_id and entry["source"] == "testclient"
    assert entry["detail"] == {"justification": WHY, "detector": "port_scan", "entity": "10.0.0.9",
                               "title": "Port scan from 10.0.0.9"}


@pytest.mark.parametrize("body,message", [
    ({"justification": "", "analyst": "A"}, "justification"),
    ({"justification": "too short", "analyst": "A"}, "justification"),
    ({"justification": WHY, "analyst": "  "}, "name"),
    ({"justification": WHY}, "name"),
    ({"justification": "x" * 2001, "analyst": "A"}, "too long"),
])
def test_a_justification_and_a_name_are_required(rig, body, message):
    rig.raise_(scan(), T)
    rig.flush()
    alert_id = rig.alerts()[0]["id"]
    r = rig.client.post("/api/alerts/false-positive", json={"id": alert_id, **body})
    assert r.status_code == 400 and message in r.json()["detail"]
    assert rig.db.suppressions() == [] and rig.client.get("/api/audit").json()["audit"] == []
    assert rig.alerts()[0]["status"] == "open"


def test_unknown_alert(rig):
    assert rig.mark(999).status_code == 404


def test_removing_a_suppression_is_audited_and_alerts_resume(rig):
    rig.raise_(scan(), T)
    rig.flush()
    rig.mark(rig.alerts()[0]["id"])
    [s] = rig.client.get("/api/suppressions").json()["suppressions"]
    r = rig.client.post("/api/suppressions/remove", json={"id": s["id"], "analyst": "Sam",
                                                          "justification": "Scanner decommissioned in change CHG-1234."})
    assert r.status_code == 200
    removed = r.json()["suppression"]
    assert removed["active"] == 0 and removed["removed_by"] == "Sam" and removed["removed"]
    # Removing again: nothing active to remove.
    again = rig.client.post("/api/suppressions/remove", json={"id": s["id"], "analyst": "Sam", "justification": WHY})
    assert again.status_code == 404
    rig.raise_(scan(), T + 7200)
    rig.flush()
    assert len(rig.alerts("open")) == 1
    actions = [e["action"] for e in rig.client.get("/api/audit").json()["audit"]]
    assert actions == ["suppression_removed", "false_positive"]


def test_marking_a_second_alert_for_the_same_finding_reuses_the_suppression(rig):
    """An older alert for the same detector and entity, marked after the first: one rule."""
    rig.raise_(scan(), T)
    rig.flush()
    first = rig.alerts()[0]["id"]
    rig.client.post("/api/alerts/status", json={"ids": [first], "status": "resolved"})
    rig.raise_(scan(), T + 7200)  # comes back as a new alert
    rig.flush()
    second = rig.alerts("open")[0]["id"]
    rig.mark(second)
    rig.mark(first)
    assert len(rig.db.suppressions()) == 1
    assert [e["action"] for e in rig.client.get("/api/audit").json()["audit"]] == ["false_positive_again",
                                                                                  "false_positive"]


def test_suppressions_survive_a_restart(rig, tmp_path):
    rig.raise_(scan(), T)
    rig.flush()
    rig.mark(rig.alerts()[0]["id"])
    fresh = Engine(rig.cfg, rig.db, ConnectorRegistry(), Notifier(rig.db))
    fresh.load(now=T + 7200)
    fresh.raise_alert(scan(), T + 7200)
    asyncio.run(fresh._flush())
    assert len(rig.alerts("all")) == 1 and rig.db.suppressions()[0]["hits"] == 1


def test_a_false_positive_feeds_no_correlation(rig):
    """Three indicators on one host correlate into a compromise alert; a suppressed one
    no longer counts."""
    host = "192.168.1.50"
    kinds = [("port_scan", host), ("brute_force", f"{host}@core-sw1"), ("risky_egress", f"{host}>203.0.113.5:6667")]

    def raise_all(ts):
        for detector, entity in kinds:
            rig.raise_(Candidate(detector, entity, "high", "t", "d", host, ""), ts)
        rig.flush()

    raise_all(T)
    assert any(a["detector"] == "compromise_suspected" for a in rig.alerts("all"))
    scan_alert = next(a for a in rig.alerts("all") if a["detector"] == "port_scan")
    rig.mark(scan_alert["id"])
    before = {a["id"] for a in rig.alerts("all")}
    for a in rig.alerts("open"):
        rig.client.post("/api/alerts/status", json={"ids": [a["id"]], "status": "resolved"})
    rig.engine.correlation.restore(Engine(rig.cfg, rig.db, ConnectorRegistry(), rig.notifier).correlation.snapshot())
    raise_all(T + 86400)
    new = [a for a in rig.alerts("all") if a["id"] not in before]
    assert sorted(a["detector"] for a in new) == ["brute_force", "risky_egress"]  # no compromise_suspected


def test_store_raises_not_found(tmp_path):
    db = Database(tmp_path / "c.db")
    with pytest.raises(NotFound):
        db.false_positive(1, T, WHY, "A", "x")
    with pytest.raises(NotFound):
        db.suppression_remove(1, T, WHY, "A", "x")
    db.close()
