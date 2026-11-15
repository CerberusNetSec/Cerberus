"""The high-risk ports tracker, its alert, and the API the High Risk Ports page reads."""
import asyncio
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Event  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.playbooks import advice  # noqa: E402
from cerberus.riskports import CATALOG, RiskPorts, direction, flags, format_entries, parse_entries, parse_ports  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402
from cerberus.web import create_app  # noqa: E402
from tools import simulate  # noqa: E402


def flow(src: str, dst: str, port: int, action: str = "allow", ts: float = 0.0) -> Event:
    return Event(ts=ts, device="fw", source_ip="10.0.0.1", event_type="traffic", action=action,
                 src_ip=src, dst_ip=dst, dst_port=port, proto="tcp")


def test_direction_and_port_list():
    assert direction("203.0.113.5", "192.168.1.10") == "inbound"
    assert direction("203.0.113.5", "198.51.100.10", "192.168.1.10") == "inbound"  # port forward
    assert direction("192.168.1.10", "8.8.8.8") == "outbound"
    assert direction("192.168.1.10", "10.2.3.4") == "internal"
    assert direction("192.168.1.10", "198.51.100.10", "192.168.9.9") == "internal"  # hairpin NAT
    assert parse_ports("3389, 445;23\n80 80 x 99999 0") == [3389, 445, 23, 80]
    for wanted in (21, 23, 80, 445, 3389):  # the ones the page was asked for
        assert wanted in CATALOG and wanted in RiskPorts().ports


def test_counts_talkers_and_new_sources():
    rp = RiskPorts()
    found = []
    t = 100 * 3600.0
    for i in range(20):
        rp.process(flow("192.168.1.5", "192.168.9.9", 23, ts=t + i), t + i, found.append)
        rp.process(flow("203.0.113.7", "192.168.9.9", 3389, "block", ts=t + i), t + i, found.append)
    rp.process(flow("192.168.1.5", "192.168.9.9", 8443), t, found.append)  # not a watched port
    rp.process(Event(ts=t, device="sw", source_ip="10.0.0.2", event_type="link_state", dst_port=23), t, found.append)
    assert rp.last_hour(t + 30) == {(23, "internal"): [20, 0], (3389, "inbound"): [0, 20]}
    top = rp.top(23, "internal", t + 30)
    assert top["sources"] == [{"ip": "192.168.1.5", "allowed": 20, "blocked": 0, "internal": True, "new": False}]
    assert top["destinations"][0]["ip"] == "192.168.9.9"
    assert rp.top(3389, "inbound", t + 30)["sources"][0] == {
        "ip": "203.0.113.7", "allowed": 0, "blocked": 20, "internal": False, "new": False}
    rows = rp.drain()
    assert sorted(rows) == [(int(t), 23, "internal", 20, 0), (int(t), 3389, "inbound", 0, 20)] and rp.drain() == []
    # A host that starts using Telnet after a day of history is marked new; the first one never was.
    later = t + 30 * 3600
    rp.process(flow("192.168.1.77", "192.168.9.9", 23, ts=later), later, found.append)
    marks = {r["ip"]: r["new"] for r in rp.top(23, "internal", later + 60, hours=48)["sources"]}
    assert marks == {"192.168.1.5": False, "192.168.1.77": True}
    assert found == []


def steady(rp: RiskPorts, start: float, hours: int, per_hour: int, port=3389, src="203.0.113.7", dst="192.168.9.9",
           action="allow") -> float:
    found = []
    t = start
    for _hour in range(hours):
        for i in range(per_hour):
            rp.process(flow(src, dst, port, action, ts=t + i * (3600 / per_hour)), t + i * (3600 / per_hour), found.append)
        t += 3600
        rp.tick(t, found.append)
    assert found == [], [c.title for c in found]
    return t


def test_surge_raises_one_alert_after_enough_history():
    rp = RiskPorts()
    found = []
    t = steady(rp, 200 * 3600.0, hours=3, per_hour=10)
    for i in range(400):  # a surge with only three hours of history: not judged yet
        rp.process(flow("203.0.113.9", "192.168.9.9", 3389, ts=t + i), t + i, found.append)
    rp.tick(t + 600, found.append)
    assert found == [] and rp.spikes(t + 600) == []

    rp = RiskPorts()
    t = steady(rp, 200 * 3600.0, hours=10, per_hour=10)
    for i in range(400):
        rp.process(flow("203.0.113.9", "192.168.9.9", 3389, ts=t + i), t + i, found.append)
    rp.tick(t + 600, found.append)
    rp.tick(t + 601, found.append)  # ... and not again a second later
    assert len(found) == 1
    c = found[0]
    assert c.detector == "risk_ports" and c.severity == "high" and c.src_ip == "203.0.113.9"
    assert c.title == "Surge in allowed RDP (3389) traffic from the internet"
    assert c.details["port"] == 3389 and c.details["last_hour"] >= 400 and 5 <= c.details["usual_per_hour"] <= 15
    assert advice({"detector": c.detector, "src_ip": c.src_ip, "details": c.details})["actions"]

    # Blocked surges are worth knowing about but are low severity; busy ports need a real multiple.
    rp = RiskPorts()
    t = steady(rp, 200 * 3600.0, hours=10, per_hour=300, port=80, src="192.168.1.5", dst="93.184.216.34")
    for i in range(600):  # twice the usual: not a surge
        rp.process(flow("192.168.1.5", "93.184.216.34", 80, ts=t + i), t + i, found.append)
        rp.process(flow("45.1.2.3", "203.0.113.10", 23, "block", ts=t + i), t + i, found.append)
    del found[:]
    rp.tick(t + 700, found.append)
    assert [(c.details["port"], c.details["outcome"], c.severity) for c in found] == [(23, "blocked", "low")]


def test_history_survives_a_restart():
    rp = RiskPorts()
    t = steady(rp, 300 * 3600.0, hours=12, per_hour=20, port=445, src="192.168.1.5", dst="192.168.9.9")
    rows = [{"minute": m, "port": p, "direction": d, "allowed": a, "blocked": b} for m, p, d, a, b in rp.drain()]
    fresh = RiskPorts()
    fresh.restore_rows(rows, t)
    assert fresh.usual((445, "internal"), t)[0][0] == rp.usual((445, "internal"), t)[0][0] > 15
    found = []
    for i in range(500):
        fresh.process(flow("192.168.1.66", f"192.168.9.{i % 200}", 445, ts=t + i), t + i, found.append)
    fresh.tick(t + 600, found.append)
    assert [c.title for c in found] == ["Surge in allowed SMB (445) traffic inside the network"]
    assert found[0].severity == "medium" and found[0].src_ip == "192.168.1.66"


def test_flags():
    none = {"inbound": [0, 0], "outbound": [0, 0], "internal": [0, 0]}
    assert flags(3389, {**none, "inbound": [0, 500]}, [], 0) == []  # blocked probes alone are the firewall working
    rdp = flags(3389, {**none, "inbound": [12, 500]}, [], 0)
    assert [(f["kind"], f["severity"]) for f in rdp] == [("exposed", "high")] and "12 connections" in rdp[0]["text"]
    assert [f["kind"] for f in flags(23, {**none, "internal": [30, 0]}, [], 2)] == ["new", "cleartext"]
    assert [f["kind"] for f in flags(445, {**none, "outbound": [9, 0]}, [], 0)] == ["egress"]
    # Web traffic is everywhere: outbound HTTP is not a finding, a web port open to the internet is a mild one.
    assert flags(80, {**none, "outbound": [5000, 0]}, [], 0) == []
    assert [(f["kind"], f["severity"]) for f in flags(80, {**none, "inbound": [40, 0]}, [], 0)] == [("exposed", "medium")]
    spike = {"port": 22, "direction": "inbound", "outcome": "blocked", "count": 900, "usual": 40.0}
    assert [(f["kind"], f["severity"]) for f in flags(22, {**none, "inbound": [0, 900]}, [spike], 0)] == [("spike", "low")]
    assert flags(22, {**none, "outbound": [50, 0]}, [], 0) == []  # SSH out is ordinary administration


def test_api_end_to_end(tmp_path):
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity, cfg.auth_enabled = tmp_path, "hostname", False
    db = Database(tmp_path / "cerberus.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    engine.installed = 0
    now = time.time()
    lines = list(simulate.riskports())
    for i, line in enumerate(lines):
        engine._process(line.encode(), "10.255.0.1", now - 120 + i * 0.01)
    asyncio.run(engine._flush())
    client = TestClient(create_app(cfg, db, engine, notifier, SnmpPoller(engine, db)))

    data = client.get("/api/riskports?range=1h").json()
    ports = {p["port"]: p for p in data["ports"]}
    assert set(ports) == {21, 22, 23, 80, 445, 1433, 3389, 5900, 6379}
    assert sum(p["allowed"] + p["blocked"] for p in ports.values()) == len(lines)
    rdp = ports[3389]
    assert rdp["totals"]["inbound"][0] == 12 and rdp["totals"]["inbound"][1] > 0 and rdp["name"] == "RDP"
    assert rdp["flags"][0]["kind"] == "exposed" and rdp["severity"] == "high"
    assert rdp["alerts"] >= 1 and rdp["alert_severity"] == "high"  # the exposed-service alert names port 3389
    assert sum(a + b for a, b in rdp["series"]) == rdp["allowed"] + rdp["blocked"] and len(rdp["series"]) == len(data["buckets"])
    assert ports[21]["totals"]["outbound"] == [30, 0] and ports[21]["totals"]["internal"] == [30, 0]
    assert {f["kind"] for f in ports[21]["flags"]} == {"egress", "cleartext"}
    assert {f["kind"] for f in ports[23]["flags"]} == {"cleartext"} and {f["kind"] for f in ports[445]["flags"]} == {"egress"}
    assert ports[80]["flags"] == [] and ports[5900]["flags"] == []
    # Worst first: the exposed port leads, ports with nothing to report trail.
    assert data["ports"][0]["port"] == 3389 and data["ports"][-1]["flags"] == []
    s = data["summary"]
    assert (s["exposed"], s["exposed_ports"], s["egress"], s["cleartext"]) == (12, 1, 42, 90) and s["flagged"] == 3
    assert {"port": 5432, "name": "PostgreSQL", "protocols": "any"} in data["quiet"] and all(q["port"] not in ports for q in data["quiet"])

    detail = client.get("/api/riskports/port?port=3389").json()
    sources = detail["directions"]["inbound"]["sources"]
    assert len(sources) == 6 and all(not r["internal"] for r in sources) and sources[0]["allowed"] == 1
    assert detail["directions"]["inbound"]["destinations"][0]["ip"] == "198.51.100.10"
    assert detail["alerts"] and "RDP" in detail["alerts"][0]["title"]
    telnet = client.get("/api/riskports/port?port=23").json()["directions"]["internal"]
    assert [r["allowed"] for r in telnet["sources"]] == [10, 10, 10] and telnet["destinations"][0]["ip"] == "192.168.10.9"

    # Taking a port off the list under Detection takes it off the page.
    stored = {d.id: d.settings() for d in engine.detectors}
    stored["risk_ports"]["ports"] = "3389,445"
    engine.apply_settings(stored, engine.general_settings())
    assert {p["port"] for p in client.get("/api/riskports?range=1h").json()["ports"]} == {3389, 445}
    db.close()


def test_port_list_by_port_and_protocol():
    entries = parse_entries("161/udp=SNMP agents, 22/TCP,3389\n53/tcp;53/udp, 22/tcp, 8443/tcp=Admin portal,"
                            "x/tcp, 70000, 25/icmp, 9000/udp=a=b")
    assert entries == [
        {"port": 161, "proto": "udp", "name": "SNMP agents"}, {"port": 22, "proto": "tcp", "name": ""},
        {"port": 3389, "proto": "any", "name": ""}, {"port": 53, "proto": "tcp", "name": ""},
        {"port": 53, "proto": "udp", "name": ""}, {"port": 8443, "proto": "tcp", "name": "Admin portal"},
        {"port": 9000, "proto": "udp", "name": "a b"}]
    assert format_entries(entries) == "161/udp=SNMP agents,22/tcp,3389,53/tcp,53/udp,8443/tcp=Admin portal,9000/udp=a b"
    assert parse_entries(format_entries(entries)) == entries
    assert parse_ports("21 22 23") == [21, 22, 23]  # lists saved by earlier versions


def test_protocol_decides_what_counts():
    rp = RiskPorts()
    rp.configure({"ports": "161/udp,22/tcp,3389,53/tcp,53/udp,8443/tcp=Admin portal"})
    assert rp.cfg["ports"] == "161/udp,22/tcp,3389,53/tcp,53/udp,8443/tcp=Admin portal"
    t = 100 * 3600.0

    def send(port, proto):
        ev = flow("192.168.1.5", "192.168.9.9", port, ts=t)
        ev.proto = proto
        rp.process(ev, t, lambda c: None)
    for port, proto in [(161, "udp"), (161, "tcp"), (22, "tcp"), (22, "udp"), (3389, "udp"), (3389, "tcp"),
                        (53, "udp"), (53, "tcp"), (53, "icmp"), (8443, "tcp"), (161, "")]:
        send(port, proto)
    counted = {port: v[0] for (port, _way), v in rp.last_hour(t + 30).items()}
    # 161: udp, and the one without a protocol; 22: tcp only; 3389: both; 53: tcp and udp.
    assert counted == {161: 2, 22: 1, 3389: 2, 53: 2, 8443: 1}
    assert (rp.label(8443), rp.port_text(8443), rp.protocol_text(53)) == ("Admin portal", "8443/tcp", "tcp/udp")
    assert (rp.label(3389), rp.port_text(3389), rp.port_text(53)) == ("RDP", "3389", "53")
    assert rp.label(161) == "SNMP" and rp.port_text(161) == "161/udp"


def test_the_list_is_edited_through_the_detection_settings(tmp_path):
    cfg = Config.from_env()
    cfg.data_dir, cfg.auth_enabled = tmp_path, False
    db = Database(tmp_path / "cerberus.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    client = TestClient(create_app(cfg, db, engine, notifier, SnmpPoller(engine, db)))
    param = next(p for d in client.get("/api/detectors").json()["detectors"] if d["id"] == "risk_ports"
                 for p in d["params"] if p["key"] == "ports")
    assert param["type"] == "ports" and param["entries"] == param["default_entries"]
    assert param["catalog"]["3389"]["name"] == "RDP"
    saved = client.put("/api/detectors", json={"detectors": {"risk_ports": {
        "ports": "3389/tcp,8443/tcp=Admin portal,bogus"}}}).json()
    param = next(p for d in saved["detectors"] if d["id"] == "risk_ports" for p in d["params"] if p["key"] == "ports")
    assert param["value"] == "3389/tcp,8443/tcp=Admin portal"
    assert engine.risk_ports.ports == {3389, 8443} and db.get_setting("detectors")["risk_ports"]["ports"] == param["value"]
    quiet = client.get("/api/riskports?range=1h").json()["quiet"]
    assert quiet == [{"port": 3389, "name": "RDP", "protocols": "tcp"},
                     {"port": 8443, "name": "Admin portal", "protocols": "tcp"}]
    db.close()

