"""Security detections, correlation and guidance, run through the real engine."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.playbooks import PLAYBOOKS, STAGES, advice  # noqa: E402
from tools import simulate  # noqa: E402


class Harness:
    def __init__(self, tmp_path, **settings):
        cfg = Config.from_env()
        cfg.data_dir, cfg.device_identity = tmp_path, "hostname"
        self.db = Database(tmp_path / "cerberus.db")
        self.engine = Engine(cfg, self.db, ConnectorRegistry(), Notifier(self.db))
        self.engine.load()
        self.now = 1_000_000.0
        if settings:
            self.configure(**settings)

    def configure(self, general=None, **detectors):
        stored = {d.id: {**d.settings(), **detectors.get(d.id, {})} for d in self.engine.detectors}
        self.engine.apply_settings(stored, {**self.engine.general_settings(), **(general or {})})

    def feed(self, lines, step: float = 0.05):
        for line in lines:
            self.now += step
            self.engine._process(line.encode(), "10.255.0.1", self.now)
        return self

    def alerts(self) -> list[dict]:
        keys = ("id", "created", "last_seen", "detector", "severity", "title", "description", "entity", "src_ip",
                "device", "count", "status", "details")
        return [dict(zip(keys, row)) for row in self.engine.alerts.new_rows]

    def kinds(self) -> set:
        return {a["detector"] for a in self.alerts()}

    def one(self, detector: str) -> dict:
        found = [a for a in self.alerts() if a["detector"] == detector]
        assert len(found) == 1, (detector, [a["title"] for a in self.alerts()])
        return found[0]

    def close(self):
        self.db.close()


def test_baseline_raises_nothing(tmp_path):
    h = Harness(tmp_path).feed(simulate.baseline(400))
    assert h.alerts() == []
    h.close()


def test_exposed_service_names_the_rule(tmp_path):
    h = Harness(tmp_path).feed(simulate.exposed(), step=10)  # repeats update an alert at most every 5 s
    a = h.one("exposed_service")
    assert a["severity"] == "high" and "RDP" in a["title"] and "192.168.10.5" in a["title"]
    assert "legacy-rdp-forward" in a["description"] and '"policy": "legacy-rdp-forward"' in a["details"]
    assert h.engine.alerts.active["exposed_service|192.168.10.5:3389"].details["sources_last_hour"] == 3
    # plain (un-NATed) inbound on OPNsense, and things that must not match
    h.feed([simulate.filterlog("pass", "203.0.113.9", "192.168.10.8", 40000, 22, iface="igb1"),
            simulate.filterlog("pass", "192.168.1.20", "203.0.113.9", 40000, 22),      # outbound SSH
            simulate.filterlog("block", "203.0.113.9", "192.168.10.8", 40000, 3389),   # blocked
            simulate.filterlog("pass", "203.0.113.9", "192.168.10.8", 40000, 443)])    # not a sensitive port
    assert sorted(a["entity"] for a in h.alerts()) == ["192.168.10.5:3389", "192.168.10.8:22"]
    h.close()


def test_ignored_destination_silences_exposure(tmp_path):
    h = Harness(tmp_path, general={"ignore_destinations": ["192.168.10.5"]}).feed(simulate.exposed())
    assert h.alerts() == []
    h.close()


def test_risky_egress(tmp_path):
    h = Harness(tmp_path).feed(simulate.egress())
    found = {a["src_ip"]: a for a in h.alerts()}
    assert h.kinds() == {"risky_egress"} and len(found) == 3
    assert found["192.168.1.52"]["severity"] == "high" and "IRC" in found["192.168.1.52"]["title"]
    assert found["192.168.3.44"]["severity"] == "high" and "Tor" in found["192.168.3.44"]["title"]
    assert found["192.168.1.33"]["severity"] == "medium" and "allow-all-out" in found["192.168.1.33"]["description"]
    h.close()


def test_lateral_movement(tmp_path):
    h = Harness(tmp_path).feed(simulate.lateral())
    a = h.one("lateral_movement")
    assert a["severity"] == "high" and a["src_ip"] == "192.168.1.77" and "SMB" in a["title"]
    h2 = Harness(tmp_path / "b", general={"ignore_sources": ["192.168.1.77"]}).feed(simulate.lateral())
    assert h2.alerts() == []  # a management server on the ignore list
    h.close(), h2.close()


def test_beaconing_needs_regular_timing(tmp_path):
    line = lambda: simulate.forti_traffic("192.168.3.61", "45.77.12.34", 8443)  # noqa: E731
    h = Harness(tmp_path)
    for i in range(13):
        h.now += 60 + (1.5 if i % 2 else -1.5)  # a 60 s timer with a little jitter
        h.feed([line()], step=0)
    a = h.one("beaconing")
    assert a["src_ip"] == "192.168.3.61" and "45.77.12.34:8443" in a["title"] and "every 60 seconds" in a["description"]

    h2 = Harness(tmp_path / "b")
    for gap in (40, 300, 75, 900, 20, 130, 610, 55, 240, 33, 480, 90, 700, 25, 160):  # a person browsing
        h2.now += gap
        h2.feed([line()], step=0)
    assert h2.alerts() == []
    h.close(), h2.close()


def test_password_spray_and_distributed_guessing(tmp_path):
    h = Harness(tmp_path).feed(simulate.spray())
    spray = h.one("password_spray")
    assert spray["severity"] == "high" and spray["src_ip"] == "192.168.1.88" and "operator" in spray["description"]
    dist = h.one("distributed_brute_force")
    assert "'root'" in dist["title"] and "from 5 sources" in dist["title"]
    h.close()


def test_admin_access(tmp_path):
    h = Harness(tmp_path).feed(simulate.adminlogin())
    a = h.one("admin_from_internet")
    assert a["severity"] == "high" and a["src_ip"] == "198.51.100.200" and "FGT-60F" in a["title"]

    def login(src):
        return simulate.cisco(1, f"%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: {src}] [localport: 22]")
    h.feed([login("192.168.1.10"), login("192.168.1.11")])  # learning period: remembered silently
    assert h.kinds() == {"admin_from_internet"}
    h.now += 25 * 3600
    h.feed([login("192.168.1.10")])  # a known source stays quiet
    assert h.kinds() == {"admin_from_internet"}
    h.feed([login("192.168.1.99")])
    new = h.one("admin_new_source")
    assert new["src_ip"] == "192.168.1.99" and "2 known admin sources" in new["description"]
    # what was learned survives a restart
    h.engine.save_state()
    h2 = Harness(tmp_path)
    assert set(h2.engine.admin_access.known["core-sw1"]) == {"192.168.1.10", "192.168.1.11", "192.168.1.99"}
    h.close(), h2.close()


def test_out_of_hours_activity(tmp_path):
    hour = time.localtime(1_000_000).tm_hour
    h = Harness(tmp_path, admin_access={"quiet_start": hour, "quiet_end": (hour + 2) % 24})
    h.feed([simulate.cisco(1, "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.10)")])
    assert "admin_after_hours" in h.kinds()
    h2 = Harness(tmp_path / "b", admin_access={"quiet_start": (hour + 3) % 24, "quiet_end": (hour + 5) % 24})
    h2.feed([simulate.cisco(1, "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.10)")])
    assert "admin_after_hours" not in h2.kinds()
    h.close(), h2.close()


def test_watchlist(tmp_path):
    h = Harness(tmp_path, watchlist={"entries": "45.77.0.0/16\nnot-an-ip\n203.0.113.200"})
    assert h.engine.by_id["watchlist"].cfg["entries"] == "45.77.0.0/16\n203.0.113.200"
    h.feed([simulate.forti_traffic("192.168.3.61", "45.77.12.34", 443),
            simulate.filterlog("block", "203.0.113.200", "192.168.10.5", 40000, 22, iface="igb1"),
            simulate.forti_traffic("192.168.3.61", "8.8.8.8", 443)])
    found = sorted((a["severity"], a["src_ip"]) for a in h.alerts())
    assert h.kinds() == {"watchlist"} and found == [("high", "192.168.3.61"), ("low", "203.0.113.200")]
    h.close()


def test_correlation_flags_compromised_host(tmp_path):
    h = Harness(tmp_path).feed(simulate.compromised())
    assert {"port_scan", "lateral_movement", "risky_egress", "compromise_suspected"} <= h.kinds()
    a = h.one("compromise_suspected")
    assert a["severity"] == "critical" and a["src_ip"] == "192.168.1.77"
    assert "network scanning" in a["description"] and "lateral movement" in a["description"]
    # two kinds of behaviour are not enough
    h2 = Harness(tmp_path / "b").feed(simulate.portscan()).feed(simulate.lateral())
    assert "compromise_suspected" not in h2.kinds()
    # nor is one kind seen by several detectors: a sweep plus brute force plus spraying is two kinds
    h3 = Harness(tmp_path / "c").feed(simulate.sweep()).feed(simulate.spray())
    assert {"host_sweep", "brute_force", "password_spray"} <= h3.kinds() and "compromise_suspected" not in h3.kinds()
    h3.close()
    h.close(), h2.close()


def test_hostile_source_later_allowed(tmp_path):
    h = Harness(tmp_path).feed(simulate.hostile())
    a = h.one("hostile_allowed")
    assert a["severity"] == "high" and a["src_ip"] == "203.0.113.66" and "192.168.10.5" in a["title"]
    assert "port scanning" in a["description"]
    # an allowed connection from an address with no history is ordinary
    h2 = Harness(tmp_path / "b").feed([simulate.filterlog("pass", "203.0.113.66", "192.168.10.5", 41001, 8443)])
    assert h2.alerts() == []
    h.close(), h2.close()


def test_threat_not_blocked_is_called_out(tmp_path):
    h = Harness(tmp_path).feed(simulate.threat())
    titles = {a["title"]: a for a in h.alerts() if a["detector"] == "threat"}
    allowed = next(a for t, a in titles.items() if t.startswith("Not blocked: ET USER_AGENTS"))
    blocked = next(a for t, a in titles.items() if t.startswith("Apache Log4j"))
    import json
    assert "NOT blocked" in advice({**allowed, "details": json.loads(allowed["details"])})["actions"][0]
    assert "blocked it" in advice({**blocked, "details": json.loads(blocked["details"])})["actions"][0]
    h.close()


def test_every_alert_type_has_guidance(tmp_path):
    h = Harness(tmp_path, watchlist={"entries": "45.77.0.0/16"})
    for name, scenario in simulate.SCENARIOS.items():
        if name not in simulate.SLOW:
            h.feed(scenario())
    raised = h.kinds()
    assert len(raised) >= 16, raised
    for detector in raised | set(PLAYBOOKS):
        book = advice({"detector": detector, "src_ip": "192.168.1.5", "details": {}})
        assert book["why"] and len(book["actions"]) >= 2 and book["stage"] in STAGES, detector
        assert all("{src}" not in step for step in book["actions"])
        if book["technique"]:
            assert book["technique"]["url"].startswith("https://attack.mitre.org/techniques/T")
    assert detector_ids_without_playbook(raised) == set()
    # internal and external sources get different advice; a missing source still reads properly
    inside = advice({"detector": "port_scan", "src_ip": "192.168.1.5"})["actions"]
    outside = advice({"detector": "port_scan", "src_ip": "203.0.113.5"})["actions"]
    assert inside != outside and "192.168.1.5" in inside[0]
    assert "the source" in " ".join(advice({"detector": "brute_force_success", "src_ip": None})["actions"])
    assert advice({"detector": "password_spray", "src_ip": "1.2.3.4"})["technique"]["url"].endswith("/T1110/003/")
    h.close()


def detector_ids_without_playbook(raised: set) -> set:
    return {d for d in raised if d not in PLAYBOOKS}


def test_notification_carries_guidance(tmp_path):
    h = Harness(tmp_path)
    subject, body = h.engine.notifier.format({
        "severity": "high", "title": "RDP on 192.168.10.5 reached from the internet", "created": 1_000_000.0,
        "description": "PA-440 allowed 203.0.113.7 ...", "device": "PA-440", "src_ip": "203.0.113.7",
        "detector": "exposed_service", "details": {}})
    assert subject.startswith("[Cerberus HIGH]")
    assert "ATT&CK: T1133 External Remote Services (Initial Access)" in body
    assert "Why it matters:" in body and "What to do:" in body and "\n1. Decide whether" in body
    h.close()
