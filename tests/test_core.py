"""Parsing and detection tests. Run with: python -m pytest"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.detectors import build_detectors  # noqa: E402
from cerberus.models import Event  # noqa: E402
from cerberus.syslog_parser import parse_syslog  # noqa: E402
from tools import simulate  # noqa: E402

REG = ConnectorRegistry()
assert not REG.errors, REG.errors


def ev(line: str, ts: float = 1000.0) -> Event:
    return REG.build_event(parse_syslog(line), ts, "10.0.0.1", "10.0.0.1")


# --- envelope -----------------------------------------------------------------
def test_rfc5424():
    p = parse_syslog('<134>1 2026-11-13T10:00:00+00:00 fw.lan filterlog 123 - [meta sequenceId="1"] hello, world')
    assert (p["facility"], p["severity"], p["hostname"], p["app"], p["message"]) == (16, 6, "fw.lan", "filterlog", "hello, world")


def test_rfc3164_with_and_without_tag():
    p = parse_syslog(b"<38>Nov  3 10:00:00 fw sshd[4411]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
    assert (p["hostname"], p["app"], p["severity"]) == ("fw", "sshd", 6)
    assert p["message"].startswith("Failed password")
    p = parse_syslog("<14>Nov 13 10:00:00 PA-440 1,2026/11/13 10:00:00,0123,TRAFFIC,end")
    assert p["hostname"] == "PA-440" and p["app"] == "" and p["message"].startswith("1,2026/11/13")


def test_headerless_and_garbage():
    p = parse_syslog("<14>sw2 STP: loop detected, blocking port 3")
    assert p["hostname"] == "" and p["message"] == "sw2 STP: loop detected, blocking port 3"
    assert parse_syslog(b"\xff\xfe\x00garbage")["severity"] == 5
    assert parse_syslog("<999>x")["message"] == "x"


def test_cisco_envelope():
    p = parse_syslog("<189>45: core-sw1: Nov 13 10:00:00.123 UTC: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)")
    assert p["hostname"] == "core-sw1" and p["message"].startswith("%SYS-5-CONFIG_I")
    p = parse_syslog("<189>123: *Mar  1 00:00:00.000: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up")
    assert p["hostname"] == "" and p["message"].startswith("%LINK-3-UPDOWN")


# --- connectors -----------------------------------------------------------------
def test_opnsense_filterlog_tcp_udp_v6():
    e = ev(simulate.filterlog("block", "192.168.1.77", "192.168.10.5", 51000, 22))
    assert (e.connector, e.event_type, e.action, e.proto) == ("opnsense", "traffic", "block", "tcp")
    assert (e.src_ip, e.dst_ip, e.src_port, e.dst_port, e.interface) == ("192.168.1.77", "192.168.10.5", 51000, 22, "igb0")
    e = ev(simulate.filterlog("pass", "192.168.1.20", "8.8.8.8", 5353, 53, proto="udp"))
    assert (e.action, e.proto, e.dst_port) == ("allow", "udp", 53)
    e = ev("<134>Nov 13 10:00:00 fw filterlog[1]: 5,,,0,igb1,match,block,in,6,0x00,0x00000,64,tcp,6,40,"
           "2001:db8::1,2001:db8::2,44321,443,0,S,1,,65535,,")
    assert (e.src_ip, e.dst_ip, e.src_port, e.dst_port, e.proto) == ("2001:db8::1", "2001:db8::2", 44321, 443, "tcp")
    e = ev("<134>Nov 13 10:00:00 fw filterlog[1]: 5,,,0,igb1,match,block,in,4,0x0,,64,1,0,none,1,icmp,84,1.2.3.4,5.6.7.8,request,1,1")
    assert (e.proto, e.src_ip, e.dst_port) == ("icmp", "1.2.3.4", None)


def test_opnsense_suricata_and_gui():
    e = [x for x in map(ev, simulate.threat()) if x.connector == "opnsense"][0]
    assert (e.event_type, e.level, e.src_ip, e.dst_port) == ("threat", "medium", "192.168.1.52", 80)
    assert e.extra["threat_name"].startswith("ET USER_AGENTS")
    e = ev("<35>Nov 13 10:00:00 fw audit[99]: /index.php: Web GUI authentication error for 'root' from 192.168.1.9")
    assert (e.event_type, e.user, e.src_ip) == ("auth_failure", "root", "192.168.1.9")


def test_paloalto():
    e = ev(simulate.pan_traffic("192.168.1.31", "104.21.55.10", 443, sent=1000))
    assert (e.connector, e.event_type, e.action, e.proto) == ("paloalto", "traffic", "allow", "tcp")
    assert (e.src_ip, e.dst_ip, e.dst_port, e.bytes) == ("192.168.1.31", "104.21.55.10", 443, 6000)
    assert e.extra["bytes_sent"] == "1000" and e.extra["application"] == "ssl"
    assert ev(simulate.pan_traffic("10.0.0.2", "1.1.1.1", 53, action="deny")).action == "block"
    threats = [x for x in map(ev, simulate.threat()) if x.connector == "paloalto"]
    assert [t.level for t in threats] == ["high", "critical"]
    assert threats[1].extra["threat_name"].startswith("Apache Log4j") and threats[1].action == "block"
    e = ev(simulate.pan("SYSTEM", {4: "auth", 8: "auth-fail", 12: "general", 13: "medium",
                                   14: "failed authentication for user 'admin'. Reason: Invalid username/password. From: 10.0.0.5."}))
    assert (e.event_type, e.user, e.src_ip) == ("auth_failure", "admin", "10.0.0.5")
    e = ev(simulate.pan("CONFIG", {4: "0", 7: "10.0.0.5", 9: "commit", 10: "admin", 11: "Web", 12: "Succeeded"}))
    assert (e.event_type, e.user) == ("config_change", "admin")


def test_cisco():
    events = [ev(line) for line in list(simulate.bruteforce())[:9]]
    assert [e.event_type for e in events[:7]] == ["auth_failure"] * 7
    assert events[0].connector == "cisco_ios" and events[0].src_ip == "192.168.1.66" and events[0].user == "admin"
    assert events[7].event_type == "auth_success"
    assert (events[8].event_type, events[8].user, events[8].src_ip) == ("config_change", "admin", "192.168.1.66")
    e = ev("<189>12: *Mar  1 00:01:02.000: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down")
    assert (e.event_type, e.interface, e.state) == ("link_state", "GigabitEthernet0/1", "down")
    e = ev("<190>77: Nov 13 10:00:00: %SEC-6-IPACCESSLOGP: list 101 denied tcp 10.1.1.5(4321) -> 10.2.2.9(23), 1 packet")
    assert (e.event_type, e.action, e.src_ip, e.dst_port) == ("traffic", "block", "10.1.1.5", 23)
    kinds = [ev(line).event_type for line in list(simulate.switch())[:3]]
    assert kinds == ["security_violation", "mac_flap", "stp_guard"]


def test_rtl_playground():
    lines = list(simulate.switch())[3:]
    e = ev(lines[0])
    assert (e.connector, e.event_type, e.interface, e.hostname) == ("rtl_playground", "loop_detected", "3", "rtl-sw2")
    assert ev(lines[1]).event_type == "stp_guard"
    e = ev(lines[2])
    assert (e.event_type, e.hostname, e.extra["link_bits"]) == ("link_state", "rtl-sw2", "0000000015")
    e = ev("<14>STP: root guard blocking port 2")  # firmware with no hostname set
    assert (e.event_type, e.hostname, e.interface) == ("stp_guard", "", "2")


def test_fortinet():
    e = ev(simulate.forti_traffic("192.168.3.21", "104.16.1.1", 443, sent=900))
    assert (e.connector, e.rule, e.event_type, e.action, e.proto) == ("fortinet", "traffic", "traffic", "allow", "tcp")
    assert (e.src_ip, e.dst_ip, e.dst_port, e.interface, e.hostname) == ("192.168.3.21", "104.16.1.1", 443, "internal", "FGT-60F")
    assert e.extra["bytes_sent"] == "900" and e.level == ""
    assert ev(simulate.forti_traffic("192.168.3.21", "10.0.0.1", 53, action="deny", proto=17)).action == "block"
    assert ev(simulate.forti_traffic("192.168.3.21", "10.0.0.1", 53, proto=17)).proto == "udp"
    lines = list(simulate.fortigate())
    ips, virus, anomaly = ev(lines[0]), ev(lines[1]), ev(lines[2])
    assert (ips.event_type, ips.level, ips.action, ips.src_ip) == ("threat", "critical", "block", "203.0.113.50")
    assert ips.extra["threat_name"].startswith("Apache.Log4j")
    assert (virus.rule, virus.event_type, virus.level, virus.extra["threat_name"]) == ("antivirus", "threat", "high", "EICAR_TEST_FILE")
    assert (anomaly.event_type, anomaly.extra["threat_name"]) == ("threat", "tcp_syn_flood")
    fail, ok, cfg, vpn, link = ev(lines[3]), ev(lines[9]), ev(lines[10]), ev(lines[11]), ev(lines[17])
    assert (fail.event_type, fail.user, fail.src_ip) == ("auth_failure", "admin", "192.168.3.90")
    assert (ok.event_type, ok.user, ok.src_ip) == ("auth_success", "admin", "192.168.3.90")
    assert (cfg.event_type, cfg.user, cfg.src_ip, cfg.extra["cfgpath"]) == ("config_change", "admin", "192.168.3.90", "firewall.policy")
    assert (vpn.event_type, vpn.user, vpn.src_ip) == ("auth_failure", "jsmith", "185.220.101.77")
    assert (link.event_type, link.interface, link.state) == ("link_state", "wan2", "DOWN")
    # the same log inside an RFC 5424 envelope
    e = ev("<189>1 2026-11-13T10:00:00Z FGT-60F - - - - " + simulate.forti_traffic("192.168.3.5", "1.1.1.1", 443).split(">", 1)[1])
    assert (e.connector, e.event_type, e.src_ip) == ("fortinet", "traffic", "192.168.3.5")
    e = ev('<189>date=2026-11-13 time=10:00:00 devname="FGT" devid="FG100F" logid="0100040704" type="event" '
           'subtype="system" level="critical" logdesc="Fan failure" msg="Fan 2 failed"')
    assert (e.event_type, e.level) == ("system", "high")


def test_fortigate_scenario_alerts():
    found = run(simulate.fortigate())
    assert kinds(found) == {"threat", "brute_force", "brute_force_success", "notable"}
    assert sorted(c.severity for c in found if c.detector == "threat") == ["critical", "critical", "high"]
    assert {c.src_ip for c in found if c.detector == "brute_force"} == {"192.168.3.90", "185.220.101.77"}


def test_generic_and_pin():
    e = ev("<38>Nov 13 10:00:00 nas sshd[1]: Failed password for invalid user oracle from 185.220.101.4 port 40022 ssh2")
    assert (e.connector, e.event_type, e.user, e.src_ip) == ("generic", "auth_failure", "oracle", "185.220.101.4")
    e = ev("<6>Nov 13 10:00:00 fw kernel: igb0: link state changed to DOWN")
    assert (e.event_type, e.interface, e.state) == ("link_state", "igb0", "DOWN")
    e = ev("<13>Nov 13 10:00:00 host app: nothing interesting")
    assert (e.connector, e.event_type) == ("generic", "other")
    pinned = REG.build_event(parse_syslog("<13>whatever"), 1.0, "d", "1.1.1.1", pin="cisco_ios")
    assert pinned.connector == "cisco_ios" and pinned.event_type == "other"


# --- detectors ------------------------------------------------------------------
def run(lines, step: float = 0.05, start: float = 1000.0):
    detectors = build_detectors()
    found = []
    now = start
    for line in lines:
        now += step
        e = ev(line, now)
        for det in detectors:
            det.process(e, now, found.append)
    return found


def kinds(found) -> set:
    return {c.detector for c in found}


def test_baseline_is_quiet():
    assert run(simulate.baseline(400)) == []


def test_port_scan_sweep_flood():
    found = run(simulate.portscan())
    assert kinds(found) == {"port_scan"} and found[0].severity == "high" and found[0].src_ip == "192.168.1.77"
    found = run(simulate.sweep())
    assert kinds(found) == {"host_sweep"} and found[0].details["port"] == 445
    found = run(simulate.flood())
    assert kinds(found) == {"deny_flood"} and found[0].severity == "low"


def test_scan_spread_over_time_is_not_flagged():
    assert run(simulate.portscan(), step=30) == []


def test_brute_force_then_success():
    found = run(simulate.bruteforce())
    assert {"brute_force", "brute_force_success", "notable"} == kinds(found)
    success = next(c for c in found if c.detector == "brute_force_success")
    assert success.severity == "critical" and success.src_ip == "192.168.1.66"
    assert sum(1 for c in found if c.detector == "brute_force" and c.src_ip == "185.220.101.4") == 1


def test_flap_threat_switch_exfil():
    assert kinds(run(simulate.flap())) == {"link_flap"}
    found = run(simulate.threat())
    assert sorted(c.severity for c in found) == ["critical", "high", "medium"]
    found = run(simulate.switch())
    assert kinds(found) == {"notable"} and len(found) == 5
    found = run(simulate.exfil())
    assert kinds(found) == {"large_transfer"} and found[0].src_ip == "192.168.1.31"


def test_rate_anomaly_and_silence():
    detectors = {d.id: d for d in build_detectors()}
    rate, silent = detectors["rate_anomaly"], detectors["device_silent"]
    found = []
    line = "<13>Nov 13 10:00:00 host app: tick"
    now = 60_000.0
    for minute in range(45):  # a steady 20 messages a minute
        for i in range(20):
            rate.baselines.observe(ev(line, now + i), now + i)
        now += 60
        rate.tick(now, found.append)
        silent.tick(now, found.append)
    assert found == []
    for i in range(900):  # then a burst
        rate.baselines.observe(ev(line, now), now)
    now += 60
    rate.tick(now, found.append)
    assert [c.detector for c in found] == ["rate_anomaly"]
    found.clear()
    for minute in range(20):  # then nothing at all
        now += 60
        rate.tick(now, found.append)
        silent.tick(now, found.append)
    assert [c.detector for c in found] == ["device_silent"]


def test_event_time_is_not_wall_clock():
    assert ev("<13>x", ts=5.0).ts == 5.0 and time.time() > 5.0
