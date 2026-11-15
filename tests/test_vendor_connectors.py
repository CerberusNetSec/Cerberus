"""Juniper, Cisco ASA/Firepower, Ubiquiti, Aruba and Dell/Brocade connectors.

Each sample is a line in the vendor's documented format, with the fields it
must produce. Fields not listed are not checked."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.syslog_parser import parse_syslog  # noqa: E402

REG = ConnectorRegistry()

SAMPLES = [
    # --- Cisco ASA / FTD --------------------------------------------------------------------
    ('<166>Nov 14 2026 10:00:00 asa01 : %ASA-6-302013: Built inbound TCP connection 1234 for outside:203.0.113.5/51515 '
     '(203.0.113.5/51515) to inside:10.0.0.5/443 (198.51.100.10/443)',
     dict(connector="cisco_asa", hostname="asa01", event_type="traffic", action="allow", proto="tcp", src_ip="203.0.113.5",
          src_port=51515, dst_ip="10.0.0.5", dst_port=443, interface="outside")),
    ('<166>Nov 14 2026 10:00:00: %ASA-6-302013: Built outbound TCP connection 99 for outside:93.184.216.34/443 '
     '(93.184.216.34/443) to inside:10.0.0.5/50000 (198.51.100.10/61000)',
     dict(connector="cisco_asa", event_type="traffic", action="allow", src_ip="10.0.0.5", src_port=50000,
          dst_ip="93.184.216.34", dst_port=443)),
    ('<166>%ASA-6-302014: Teardown TCP connection 1234 for outside:203.0.113.5/51515 to inside:10.0.0.5/443 '
     'duration 0:01:02 bytes 52311 TCP FINs',
     dict(connector="cisco_asa", event_type="session_end", bytes=52311)),
    ('<164>%ASA-4-106023: Deny tcp src outside:203.0.113.5/51515 dst inside:10.0.0.5/22 by access-group "OUTSIDE_IN" [0x0, 0x0]',
     dict(connector="cisco_asa", event_type="traffic", action="block", proto="tcp", src_ip="203.0.113.5", dst_ip="10.0.0.5",
          dst_port=22)),
    ('<164>%ASA-4-106023: Deny icmp src outside:203.0.113.5 dst inside:10.0.0.5 (type 8, code 0) by access-group "OUTSIDE_IN" [0x0, 0x0]',
     dict(connector="cisco_asa", event_type="traffic", action="block", proto="icmp", src_ip="203.0.113.5", dst_port=None)),
    ('<166>%ASA-6-106100: access-list OUTSIDE_IN denied tcp outside/203.0.113.5(51515) -> inside/10.0.0.5(3389) hit-cnt 1 '
     'first hit [0x91c26a3, 0x0]',
     dict(connector="cisco_asa", event_type="traffic", action="block", dst_port=3389)),
    ('<166>%ASA-6-106100: access-list INSIDE_OUT permitted udp inside/10.0.0.5(53000) -> outside/8.8.8.8(53) hit-cnt 1 '
     'first hit [0x1, 0x0]',
     dict(connector="cisco_asa", event_type="traffic", action="allow", proto="udp", dst_ip="8.8.8.8", dst_port=53)),
    ('<162>%ASA-2-106001: Inbound TCP connection denied from 203.0.113.5/51515 to 10.0.0.5/23 flags SYN on interface outside',
     dict(connector="cisco_asa", event_type="traffic", action="block", dst_port=23, interface="outside")),
    ('<166>%ASA-6-605004: Login denied from 203.0.113.5/51515 to outside:198.51.100.10/ssh for user "admin"',
     dict(connector="cisco_asa", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<166>%ASA-6-605005: Login permitted from 10.0.0.9/51515 to inside:10.0.0.1/ssh for user "admin"',
     dict(connector="cisco_asa", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<166>%ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : server = 10.0.0.9 : user = jdoe : '
     'user IP = 203.0.113.5',
     dict(connector="cisco_asa", event_type="auth_failure", user="jdoe", src_ip="203.0.113.5")),
    ('<166>%ASA-6-611102: User authentication failed: IP address: 203.0.113.5, Uname: admin',
     dict(connector="cisco_asa", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ("<165>%ASA-5-111010: User 'admin', running 'CLI' from IP 10.0.0.9, executed 'no access-list OUTSIDE_IN'",
     dict(connector="cisco_asa", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<164>%ASA-4-733101: Host 203.0.113.5 is attacking. Current burst rate is 200 per second, max configured rate is 100',
     dict(connector="cisco_asa", event_type="threat", src_ip="203.0.113.5", level="medium")),
    ('<164>%ASA-4-411002: Line protocol on Interface GigabitEthernet0/1, changed state to down',
     dict(connector="cisco_asa", event_type="link_state", interface="GigabitEthernet0/1", state="down")),
    ('<161>%FTD-1-430003: DeviceUUID: 1234, InstanceID: 1, AccessControlRuleAction: Block, SrcIP: 203.0.113.5, '
     'DstIP: 10.0.0.5, SrcPort: 51515, DstPort: 22, Protocol: tcp, IngressInterface: outside, EgressInterface: inside, '
     'ACPolicy: Default, AccessControlRuleName: Block-SSH, Prefilter Policy: none',
     dict(connector="cisco_asa", event_type="traffic", action="block", src_ip="203.0.113.5", dst_port=22, proto="tcp",
          interface="outside")),
    ('<161>%FTD-1-430002: AccessControlRuleAction: Allow, SrcIP: 10.0.0.5, DstIP: 93.184.216.34, SrcPort: 50000, '
     'DstPort: 443, Protocol: tcp, IngressInterface: inside, AccessControlRuleName: Allow-Web',
     dict(connector="cisco_asa", event_type="traffic", action="allow", dst_port=443)),
    ('<161>%FTD-1-430001: Protocol: tcp, SrcIP: 203.0.113.5, DstIP: 10.0.0.5, DstPort: 80, Priority: 1, GID: 1, '
     'SID: 2014, Revision: 4, Message: ET WEB_SERVER SQL Injection, Classification: Web Application Attack, '
     'InlineResult: Blocked',
     dict(connector="cisco_asa", event_type="threat", level="high", action="block", src_ip="203.0.113.5", dst_port=80)),

    # --- Juniper ------------------------------------------------------------------------------
    ('<14>Nov 14 10:00:00 srx01 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 203.0.113.5/51515->198.51.100.10/22 0x0 '
     'junos-ssh 203.0.113.5/51515->10.0.0.5/22 0x0 N/A N/A static-nat r1 6 allow-ssh untrust trust 12345 N/A(N/A) ge-0/0/0.0',
     dict(connector="juniper", hostname="srx01", event_type="traffic", action="allow", proto="tcp", src_ip="203.0.113.5",
          dst_ip="198.51.100.10", dst_port=22, policy="allow-ssh")),
    ('<14>Nov 14 10:00:00 srx01 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 203.0.113.5/51515->10.0.0.5/23 0x0 '
     'junos-telnet 6(0) deny-all untrust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 UNKNOWN policy deny',
     dict(connector="juniper", event_type="traffic", action="block", proto="tcp", dst_port=23, policy="deny-all")),
    ('<14>Nov 14 10:00:00 srx01 RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 10.0.0.5/50000->93.184.216.34/443 '
     '0x0 junos-https 198.51.100.10/61000->93.184.216.34/443 0x0 N/A N/A N/A N/A 6 allow-web trust untrust 12345 '
     '10(1200) 8(48000) 30 UNKNOWN UNKNOWN N/A(N/A) ge-0/0/1.0',
     dict(connector="juniper", event_type="session_end")),
    ('<14>Nov 14 10:00:00 srx01 RT_IDP: IDP_ATTACK_LOG_EVENT: IDP: at 1731578400, SIG Attack log '
     '<203.0.113.5/51515->10.0.0.5/80> for TCP protocol and service HTTP application NONE by rule 3 of rulebase IPS in '
     'policy Recommended. attack: id=4012, repeat=0, action=DROP, threat-severity=HIGH, name=HTTP:SQL:INJ:GENERIC, NAT',
     dict(connector="juniper", event_type="threat", action="block", level="high", src_ip="203.0.113.5", dst_port=80)),
    ('<14>Nov 14 10:00:00 srx01 RT_SCREEN: RT_SCREEN_TCP: TCP port scan! source: 203.0.113.5:51515, destination: '
     '10.0.0.5:22, zone name: untrust, interface name: ge-0/0/0.0, action: drop',
     dict(connector="juniper", event_type="threat", action="block", src_ip="203.0.113.5")),
    ("<14>Nov 14 10:00:00 srx01 mgd[1234]: UI_LOGIN_EVENT: User 'admin' login, class 'j-super-user' [12345], "
     "ssh-connection '10.0.0.9 51515 10.0.0.1 22', client-mode 'cli'",
     dict(connector="juniper", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ("<14>Nov 14 10:00:00 srx01 sshd[999]: SSHD_LOGIN_FAILED: Login failed for user 'admin' from host '203.0.113.5'",
     dict(connector="juniper", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ("<14>Nov 14 10:00:00 srx01 mgd[1234]: UI_COMMIT: User 'admin' requested 'commit' operation (comment: none)",
     dict(connector="juniper", event_type="config_change", user="admin")),
    ('<14>Nov 14 10:00:00 ex01 mib2d[555]: SNMP_TRAP_LINK_DOWN: ifIndex 520, ifAdminStatus up(1), ifOperStatus down(2), '
     'ifName ge-0/0/1',
     dict(connector="juniper", event_type="link_state", interface="ge-0/0/1", state="down")),

    # --- Ubiquiti -----------------------------------------------------------------------------
    ('<4>Nov 14 10:00:00 usg01 kernel: [WAN_IN-2000-D]IN=eth0 OUT=eth1 MAC=00:11 SRC=203.0.113.5 DST=10.0.0.5 LEN=60 '
     'TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=51515 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0',
     dict(connector="ubiquiti", event_type="traffic", action="block", proto="tcp", src_ip="203.0.113.5", dst_port=22,
          policy="WAN_IN-2000")),
    ('<4>Nov 14 10:00:00 udm kernel: [LAN_IN-RULE-3000-A]DESCR="Allow printers" IN=br0 OUT=eth8 MAC=00:11 SRC=10.0.0.5 '
     'DST=10.0.20.9 LEN=60 PROTO=TCP SPT=50000 DPT=9100',
     dict(connector="ubiquiti", event_type="traffic", action="allow", dst_port=9100, policy_description="Allow printers")),
    ('<4>Nov 14 10:00:00 udm kernel: [WAN_LOCAL-default-R]IN=eth4 OUT= MAC=00:11 SRC=203.0.113.5 DST=198.51.100.10 '
     'LEN=40 PROTO=UDP SPT=5000 DPT=161',
     dict(connector="ubiquiti", event_type="traffic", action="block", proto="udp", dst_port=161)),
    ('<1>Nov 14 10:00:00 usg01 suricata[1234]: [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 '
     '[Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 203.0.113.5:5555 -> 10.0.0.5:1433',
     dict(event_type="threat", level="medium", src_ip="203.0.113.5", dst_port=1433)),

    # --- Aruba --------------------------------------------------------------------------------
    ('<14>Nov 14 10:00:00 aruba-cx01 intfd[812]: Event|403|LOG_INFO|AMM|1/1|Link status for interface 1/1/5 is down',
     dict(connector="aruba", event_type="link_state", interface="1/1/5", state="down")),
    ('<14>Nov 14 10:00:00 aruba-cx01 hpe-sessiond[90]: Event|5101|LOG_INFO|AMM|1/1|User admin logged in from 10.0.0.9 '
     'through SSH session.',
     dict(connector="aruba", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<12>Nov 14 10:00:00 aruba-cx01 hpe-sessiond[90]: Event|5102|LOG_WARN|AMM|1/1|User admin login failed from '
     '203.0.113.5 through SSH session.',
     dict(connector="aruba", event_type="auth_failure", src_ip="203.0.113.5")),
    ('<14>Nov 14 10:00:00 10.0.0.2 00076 ports: port 5 is now off-line',
     dict(connector="aruba", event_type="link_state", interface="5", state="down")),
    ('<14>Nov 14 10:00:00 10.0.0.2 00179 mgr: SME SSH from 10.0.0.9 - MANAGER Mode',
     dict(connector="aruba", event_type="auth_success", src_ip="10.0.0.9")),
    ('<12>Nov 14 10:00:00 ctrl01 authmgr[3012]: <522275> <WARN> |authmgr|  User Authentication failed. username=jdoe '
     'MAC=aa:bb:cc:dd:ee:ff IP=10.0.0.20 auth method=802.1x auth server=NPS',
     dict(connector="aruba", event_type="auth_failure", user="jdoe", src_ip="10.0.0.20")),
    ('<14>Nov 14 10:00:00 ctrl01 authmgr[3012]: <522008> <NOTI> |authmgr|  User Authentication Successful: username=jdoe '
     'MAC=aa:bb:cc:dd:ee:ff IP=10.0.0.20 role=employee VLAN=20 AP=ap01 SSID=corp',
     dict(connector="aruba", event_type="auth_success", user="jdoe", src_ip="10.0.0.20")),

    # --- Dell / Brocade ----------------------------------------------------------------------
    ('<14>Nov 14 10:00:00 dell-os10 dn_alm[1234]: Node.1-Unit.1:PRI [event], Dell EMC (OS10) %IFM_OSTATE_DN: Interface '
     'operational state is down :ethernet1/1/5',
     dict(connector="dell_brocade", event_type="link_state", interface="ethernet1/1/5", state="down")),
    ('<13>Nov 14 10:00:00 s4048 %STKUNIT1-M:CP %IFMGR-5-OSTATE_DN: Changed interface state to down: Te 1/5',
     dict(connector="dell_brocade", event_type="link_state", interface="Te 1/5", state="down")),
    ('<190> Nov 14 10:00:00 10.0.0.3-1 TRAPMGR[1234]: traputil.c(721) 3 %% Link Down: Gi1/0/5',
     dict(connector="dell_brocade", hostname="10.0.0.3-1", event_type="link_state", interface="Gi1/0/5", state="down")),
    ('<14>Nov 14 10:00:00 icx7150 Interface ethernet1/1/5, state down',
     dict(connector="dell_brocade", event_type="link_state", interface="ethernet1/1/5", state="down")),
    ('<14>Nov 14 10:00:00 icx7150 Security: SSH login by admin from src IP 10.0.0.9 from src MAC 0011.2233.4455 to '
     'PRIVILEGED EXEC mode',
     dict(connector="dell_brocade", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<12>Nov 14 10:00:00 icx7150 Security: SSH access by admin from src IP 203.0.113.5 rejected, 3 attempt(s)',
     dict(connector="dell_brocade", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<13>Nov 14 10:00:00 icx7150 Security: running-config was changed by admin from src IP 10.0.0.9',
     dict(connector="dell_brocade", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<12>Nov 14 10:00:00 sansw01 raslogd: 2026/11/14-10:00:00, [SEC-1193], 1234, FID 128, INFO, sansw01, Security '
     'violation: Login failure attempt via SSH. IP Addr: 203.0.113.5',
     dict(connector="dell_brocade", event_type="auth_failure", src_ip="203.0.113.5")),
]


def event(line: str):
    parsed = parse_syslog(line)
    return REG.build_event(parsed, 1000.0, parsed["hostname"] or "10.0.0.1", "10.0.0.1")


@pytest.mark.parametrize("line,want", SAMPLES, ids=[f"{w.get('connector', 'any')}-{i}" for i, (_, w) in enumerate(SAMPLES)])
def test_vendor_samples(line, want):
    ev = event(line)
    got = {}
    for key in want:
        got[key] = getattr(ev, key) if hasattr(ev, key) else ev.extra.get(key)
    assert got == want, (ev.connector, ev.event_type, ev.extra)


def test_every_new_connector_loads_and_is_covered():
    assert not REG.errors, REG.errors
    ids = {c.id for c in REG.connectors}
    new = {"cisco_asa", "juniper", "ubiquiti", "aruba", "dell_brocade"}
    assert new <= ids
    covered = {w["connector"] for _, w in SAMPLES if "connector" in w}
    assert new <= covered


def test_cisco_ios_still_handles_ios():
    ev = event("<189>123: core-sw1: Nov 14 10:00:00.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, "
               "changed state to down")
    assert (ev.connector, ev.event_type, ev.state) == ("cisco_ios", "link_state", "down")


def test_syslog_header_variants():
    p = parse_syslog("<166>Nov 14 2026 10:00:00 asa01 : %ASA-6-302013: x")
    assert (p["hostname"], p["message"]) == ("asa01", "%ASA-6-302013: x")
    p = parse_syslog("<166>Nov 14 2026 10:00:00: %ASA-6-302013: x")
    assert (p["hostname"], p["message"]) == ("", "%ASA-6-302013: x")
    p = parse_syslog("<190> Nov 14 10:00:00 10.0.0.3-1 TRAPMGR[1234]: hello")
    assert (p["hostname"], p["app"], p["message"]) == ("10.0.0.3-1", "TRAPMGR", "hello")
