"""The MITRE ATT&CK matrix: placement, counting, and links to the alerts."""
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from cerberus import web  # noqa: E402
from cerberus.attack import TACTIC_NAMES, TECHNIQUE_TACTICS, placement  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.playbooks import PLAYBOOKS  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402


def test_every_technique_sits_under_one_of_its_own_tactics():
    placed, other = placement()
    for detector, (tactic, tid, _name) in placed.items():
        assert tactic in TACTIC_NAMES and tactic in TECHNIQUE_TACTICS[tid], (detector, tactic, tid)
    # Every playbook technique is known, so none falls back to a guess.
    assert {b["technique"][0] for b in PLAYBOOKS.values() if b.get("technique")} <= set(TECHNIQUE_TACTICS)
    # Valid Accounts is not a Lateral Movement technique in ATT&CK.
    assert placed["admin_new_source"][0] == "Defense Evasion" and placed["admin_after_hours"][0] == "Defense Evasion"
    assert placed["plaintext_secret"] == ("Credential Access", "T1552", "Unsecured Credentials")
    assert {"compromise_suspected", "link_flap", "new_device"} <= set(other)


def test_matrix_counts_and_links(tmp_path):
    cfg = Config.from_env()
    cfg.data_dir, cfg.auth_enabled = tmp_path, False
    db = Database(tmp_path / "c.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    now = time.time()
    for i, (det, ts) in enumerate([("port_scan", now), ("port_scan", now), ("risk_ports", now), ("brute_force", now),
                                   ("password_spray", now - 10 * 86400), ("link_flap", now)]):
        engine.raise_alert(Candidate(det, f"e{i}", "high", f"t{i}", "d", f"10.0.0.{i}", ""), ts)
    asyncio.run(engine._flush())
    client = TestClient(web.create_app(cfg, db, engine, notifier, SnmpPoller(engine, db)))

    d = client.get("/api/attack?range=7d").json()
    cells = {(t["name"], c["id"]): c for t in d["tactics"] for c in t["techniques"]}
    discovery = cells[("Discovery", "T1046")]
    assert discovery["alerts"] == 3 and {x["id"] for x in discovery["detectors"]} == {"port_scan", "risk_ports"}
    assert cells[("Credential Access", "T1110")]["alerts"] == 1
    assert cells[("Credential Access", "T1110.003")]["alerts"] == 0  # ten days ago: outside 7 days
    assert d["total"] == 4 and d["max"] == 3 and d["techniques_seen"] == 2
    assert [t["name"] for t in d["tactics"]] == TACTIC_NAMES and d["tactics_covered"] == 8
    assert {o["name"]: o["alerts"] for o in d["other"]} == {"Network health": 1}
    assert client.get("/api/attack?range=30d").json()["total"] == 5
    # Every technique appears once.
    ids = [c["id"] for t in d["tactics"] for c in t["techniques"]]
    assert len(ids) == len(set(ids))

    # A false positive leaves the default view; "all" keeps it.
    first = db.alerts_find(limit=50, detectors=["port_scan"])[0]["id"]
    client.post("/api/alerts/false-positive", json={"id": first, "analyst": "A", "justification": "Known scanner host."})
    assert client.get("/api/attack?range=7d").json()["total"] == 3
    assert client.get("/api/attack?range=7d&status=all").json()["total"] == 4

    # A cell's link: the alerts of its detectors.
    rows = client.get("/api/alerts?status=all&detector=port_scan,risk_ports").json()["alerts"]
    assert sorted(r["detector"] for r in rows) == ["port_scan", "port_scan", "risk_ports"]
    json.dumps(d)
    db.close()
