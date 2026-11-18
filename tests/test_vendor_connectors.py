"""Juniper, Cisco ASA/Firepower, Ubiquiti, Aruba, Dell/Brocade, Meraki, SonicWall, Sophos and Suricata
connectors.

Each sample is a line in the vendor's documented format, with the fields it
must produce. Fields not listed are not checked."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.connectors import Connector, ConnectorRegistry  # noqa: E402
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

    # --- Cisco Meraki -------------------------------------------------------------------------
    ('<134>1 1374543986.038687615 MX84 firewall src=192.168.1.186 dst=8.8.8.8 mac=58:1F:AA:CE:61:F2 protocol=udp '
     'sport=55719 dport=53 pattern: allow all',
     dict(connector="meraki", hostname="MX84", event_type="traffic", action="allow", proto="udp", src_ip="192.168.1.186",
          src_port=55719, dst_ip="8.8.8.8", dst_port=53)),
    ('<134>1 1374543986.038687615 MX84 flows src=203.0.113.5 dst=10.0.0.5 mac=58:1F:AA:CE:61:F2 protocol=tcp '
     'sport=51515 dport=3389 pattern: deny all',
     dict(connector="meraki", event_type="traffic", action="block", proto="tcp", dst_port=3389)),
    ('<134>1 1787058162.285901262 MX67 l7_firewall src=10.10.10.3 dst=104.21.4.210 protocol=tcp sport=59526 '
     'dport=443 decision=blocked',
     dict(connector="meraki", hostname="MX67", event_type="traffic", action="block", dst_ip="104.21.4.210", dst_port=443)),
    ('<134>1 1792173599.743929631 MX85 gp_firewall src=10.203.1.19 dst=23.111.186.186 vlan=1 protocol=udp sport=48915 '
     'dport=123 decision=allowed rule=vlan:1:id:3705899543372497478',
     dict(connector="meraki", event_type="traffic", action="allow", dst_port=123)),
    ('<134>1 1792173599.743929631 MX85 ip_flow_start src=10.0.0.5 dst=93.184.216.34 protocol=tcp sport=50000 dport=443 '
     'translated_src_ip=198.51.100.10 translated_port=61000',
     dict(connector="meraki", event_type="traffic", action="allow", src_ip="10.0.0.5", dst_port=443)),
    ('<134>1 1792173599.743929631 MX85 ip_flow_end src=10.0.0.5 dst=93.184.216.34 protocol=tcp sport=50000 dport=443 '
     'translated_src_ip=198.51.100.10 translated_port=61000',
     dict(connector="meraki", event_type="session_end", dst_port=443)),
    ('<134>1 1377449842.514782056 MX84 ids-alerts signature=129:4:1 priority=3 timestamp=1377449842.512569 '
     'direction=ingress protocol=tcp/ip src=74.125.140.132:80 dst=192.168.1.10:51515 '
     'message: STREAM5 TCP Timestamp is outside of PAWS window',
     dict(connector="meraki", event_type="threat", level="low", proto="tcp", src_ip="74.125.140.132", src_port=80,
          dst_ip="192.168.1.10", dst_port=51515, threat_name="STREAM5 TCP Timestamp is outside of PAWS window")),
    ('<134>1 1468531589.810079 MX84 security_event ids_alerted signature=1:28423:1 priority=1 timestamp=1468531589.810079 '
     'dhost=98:5A:EB:E1:81:2F direction=ingress protocol=tcp/ip src=151.101.52.238:80 dst=192.168.128.2:53023 '
     'decision=blocked action=rst message: EXPLOIT-KIT Multiple exploit kit single digit exe detection',
     dict(connector="meraki", event_type="threat", level="high", action="block", src_ip="151.101.52.238",
          dst_port=53023, threat_name="EXPLOIT-KIT Multiple exploit kit single digit exe detection")),
    ("<134>1 1468531589.810079 MX84 security_event security_filtering_file_scanned "
     "url=http://www.eicar.org/download/eicar.com.txt src=192.168.128.2:53150 dst=188.40.238.250:80 "
     "mac=98:5A:EB:E1:81:2F name='EICAR:EICAR_Test_File-tpd' sha256=275a021bbfb6489e54d471899f7db9d1 "
     "disposition=malicious action=block",
     dict(connector="meraki", event_type="threat", level="high", action="block", threat_name="EICAR:EICAR_Test_File-tpd",
          src_ip="192.168.128.2", dst_ip="188.40.238.250")),
    ('<134>1 1374543213.342705328 MX84 urls src=192.168.1.186:63735 dst=69.58.188.40:80 mac=58:1F:AA:CE:61:F2 '
     'request: GET https://example.com/',
     dict(connector="meraki", event_type="web", src_ip="192.168.1.186", dst_port=80, url="https://example.com/")),
    ('<134>1 1379967288.409907239 MS220_8P events port 3 status changed from 100fdx to down',
     dict(connector="meraki", hostname="MS220_8P", event_type="link_state", interface="3", state="down")),
    ('<134>1 1379967288.409907239 MS220_8P events port 3 status changed from down to 1Gfdx',
     dict(connector="meraki", event_type="link_state", interface="3", state="up")),
    ("<134>1 1720045578.495767745 labs_appliance events anyconnect_vpn_connect user id 'miles@example.com' "
     "local ip 192.168.5.224 connected from 203.0.113.5",
     dict(connector="meraki", hostname="labs_appliance", event_type="auth_success", user="miles@example.com",
          src_ip="203.0.113.5")),
    ("<134>1 1380653443.857790533 MR18 events type=8021x_eap_success radio='0' vap='3' identity='woody@example.com' "
     "aid='1849280097'",
     dict(connector="meraki", event_type="network_access", user="woody@example.com")),
    ("<134>1 1380653443.857790533 MR18 events type=device_packet_flood packet='deauth' device='00:18:0A:27:43:80' "
     "radio='0' state='start'",
     dict(connector="meraki", event_type="threat", level="medium", packet="deauth")),
    ("<134>1 1380664922.583851938 MX84 events type=vpn_connectivity_change vpn_type='site-to-site' "
     "peer_contact='98.68.191.209:51856' peer_ident='2814ee002c075181bb1b7478ee073860' connectivity='false'",
     dict(connector="meraki", hostname="MX84", event_type="system", connectivity="false", vpn_type="site-to-site")),
    ('<134>1 1380664922.583851938 MX84 events Cellular connection up',
     dict(connector="meraki", event_type="system", detail="Cellular connection up")),

    # --- SonicWall ----------------------------------------------------------------------------
    ('<134>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=6 c=1024 m=537 '
     "msg=\"Connection Closed\" app=49175 appName='General HTTPS' n=12345 src=10.0.0.5:50000:X0 "
     'dst=93.184.216.34:443:X1 srcMac=00:11:22:33:44:55 proto=tcp/https sent=1500 rcvd=4000 fw_action="NA"',
     dict(connector="sonicwall", event_type="traffic", action="allow", proto="tcp", src_ip="10.0.0.5", src_port=50000,
          interface="X0", dst_ip="93.184.216.34", dst_port=443, out_interface="X1", bytes_sent="1500",
          appName="General HTTPS")),
    ('<132>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=4 c=32 m=36 '
     'msg="TCP packet received on non-existent/closed connection; TCP packet dropped" n=7 src=203.0.113.5:51515:X1 '
     'dst=198.51.100.10:22:X1 proto=tcp/ssh fw_action="drop"',
     dict(connector="sonicwall", event_type="traffic", action="block", src_ip="203.0.113.5", dst_port=22, proto="tcp")),
    ('<132>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=4 c=32 m=38 '
     'msg="ICMP packet dropped due to Policy" n=7 src=203.0.113.5:8:X1 dst=198.51.100.10:0:X1 proto=icmp',
     dict(connector="sonicwall", event_type="traffic", action="block", proto="icmp")),
    ('<129>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=1 c=32 m=609 '
     'msg="IPS Prevention Alert: WEB-ATTACKS Generic SQL Injection" sid=1188 ipscat="WEB-ATTACKS" ipspri=1 n=3 '
     'src=203.0.113.5:51515:X1 dst=10.0.0.5:80:X0 proto=tcp/http',
     dict(connector="sonicwall", event_type="threat", level="high", action="block", src_ip="203.0.113.5", dst_port=80,
          threat_name="WEB-ATTACKS Generic SQL Injection")),
    ('<131>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=3 c=32 m=608 '
     'msg="IPS Detection Alert: INFO SIP Session Progress" sid=1188 ipscat="INFO SIP Session Progress" ipspri=3 n=3 '
     'src=203.0.113.5:5060:X1 dst=10.0.0.5:5060:X0 proto=udp/5060',
     dict(connector="sonicwall", event_type="threat", level="low", action="allow", proto="udp")),
    ('<129>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=1 c=32 m=809 '
     'msg="Gateway Anti-Virus Alert: EICAR (Test File) blocked." n=1 src=93.184.216.34:80:X1 dst=10.0.0.5:50000:X0',
     dict(connector="sonicwall", event_type="threat", level="high", action="block", threat_name="EICAR (Test File)",
          dst_ip="10.0.0.5")),
    ('<133>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=5 c=32 m=30 '
     'msg="Administrator login denied due to bad credentials" n=4 usr="admin" src=203.0.113.5::X1 dst=198.51.100.10::X1',
     dict(connector="sonicwall", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<134>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=6 c=32 m=29 '
     'msg="Administrator login allowed" n=5 usr="admin" src=10.0.0.9::X0 dst=10.0.0.1::X0',
     dict(connector="sonicwall", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<134>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=6 c=4 m=1382 '
     'msg="Configuration changed: Access rule added" n=2 usr="admin" src=10.0.0.9::X0',
     dict(connector="sonicwall", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<130>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=2 c=16 m=1 '
     'msg="Interface X2 Link Is Down" n=1',
     dict(connector="sonicwall", event_type="link_state", interface="X2", state="down")),
    ('<134>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=6 c=262144 m=98 '
     'msg="Connection Opened" n=1 src=10.0.0.5:50000:X0 dst=93.184.216.34:443:X1 proto=tcp/https',
     dict(connector="sonicwall", event_type="session_start", dst_port=443)),
    ('<131>id=firewall sn=18B1690729A8 time="2026-11-14 10:00:00 UTC" fw=198.51.100.10 pri=3 c=4 m=520 '
     'msg="Too many failed DHCP leases" n=1',
     dict(connector="sonicwall", event_type="system", level="medium")),

    # --- Sophos Firewall ----------------------------------------------------------------------
    ('<30>device="SFW" date=2026-11-14 time=10:00:00 timezone="UTC" device_name="XG230" device_id=C01001K234RXPA1 '
     'log_id=010101600001 log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" status="Allow" '
     'priority=Information duration=30 fw_rule_id=5 user_name="" src_ip=10.0.0.5 dst_ip=93.184.216.34 protocol="TCP" '
     'src_port=50000 dst_port=443 sent_bytes=1500 recv_bytes=4000 in_interface="Port1" out_interface="Port2"',
     dict(connector="sophos", hostname="XG230", event_type="traffic", action="allow", proto="tcp", src_ip="10.0.0.5",
          dst_port=443, interface="Port1", bytes_sent="1500", policy="5")),
    ('<30>device_name="SFW" timestamp="2026-11-14T10:00:00+0000" device_model="XG230" device_serial_id="C01001K234RXPA1" '
     'log_id="010102600002" log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" log_version=1 '
     'severity="Information" fw_rule_id="0" src_ip="203.0.113.5" dst_ip="198.51.100.10" protocol="TCP" '
     'src_port="51515" dst_port="22" in_interface="Port2"',
     dict(connector="sophos", event_type="traffic", action="block", src_ip="203.0.113.5", dst_port=22)),
    ('<28>device="SFW" date=2026-11-14 time=10:00:00 timezone="UTC" device_name="XG230" log_id=020804407002 '
     'log_type="IDP" log_component="Signatures" log_subtype="Drop" priority=Warning idp_policy_id=2 fw_rule_id=1 '
     'signature_id=1151209031 signature_msg="SERVER-WEBAPP SQL injection attempt" '
     'classification="Web Application Attack" rule_priority=1 src_ip=203.0.113.5 dst_ip=10.0.0.5 protocol="TCP" '
     'src_port=51515 dst_port=80',
     dict(connector="sophos", event_type="threat", action="block", level="high", src_ip="203.0.113.5", dst_port=80,
          threat_name="SERVER-WEBAPP SQL injection attempt")),
    ('<28>device="SFW" date=2026-11-14 time=10:00:00 timezone="UTC" device_name="XG230" log_id=020804406001 '
     'log_type="IDP" log_component="Anomaly" log_subtype="Detect" priority=Warning idp_policy_id=1 fw_rule_id=2 '
     'signature_msg="Port scan" rule_priority=2 src_ip=203.0.113.5 dst_ip=10.0.0.5',
     dict(connector="sophos", event_type="threat", action="allow", level="medium")),
    ('<26>device="SFW" date=2026-11-14 time=10:00:00 timezone="UTC" device_name="XG230" log_id=030906208001 '
     'log_type="Anti-Virus" log_component="HTTPS" log_subtype="Virus" status="" priority=Critical user_name="jdoe" '
     'virus="EICAR-AV-Test" src_ip=10.0.0.5 dst_ip=93.184.216.34 dst_port=443',
     dict(connector="sophos", event_type="threat", action="block", level="high", threat_name="EICAR-AV-Test", user="jdoe")),
    ('<30>device="SFW" date=2026-11-14 time=10:00:00 timezone="UTC" device_name="XG230" log_id=030906208003 '
     'log_type="Anti-Virus" log_component="HTTP" log_subtype="Clean" status="" priority=Information src_ip=10.0.0.5',
     dict(connector="sophos", event_type="system")),
    ('<29>device="SFW" date=2026-11-14 time=10:00:00 timezone="UTC" device_name="XG230" log_id=062910617701 '
     'log_type="Event" log_component="Admin" log_subtype="Admin" status="Failed" priority=Notice user_name="admin" '
     'src_ip=203.0.113.5 message="User admin failed to login to Webadmin from 203.0.113.5 because of wrong credentials"',
     dict(connector="sophos", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<30>device_name="SFW" timestamp="2026-11-14T10:00:00+0000" log_id="062910617702" messageid="17702" '
     'log_type="Event" log_component="Firewall Authentication" log_subtype="Authentication" status="Failed" '
     'user="test1" client_used="Web Client" reason="wrong credentials" src_ip="203.0.113.5"',
     dict(connector="sophos", event_type="auth_failure", user="test1", src_ip="203.0.113.5")),
    ('<30>device_name="SFW" timestamp="2026-11-14T10:00:00+0000" log_id="062910617701" log_type="Event" '
     'log_component="SSL VPN Authentication" log_subtype="Authentication" status="Successful" user="jdoe" '
     'src_ip="203.0.113.7"',
     dict(connector="sophos", event_type="auth_success", user="jdoe", src_ip="203.0.113.7")),
    ('<30>device_name="SFW" timestamp="2026-11-14T10:00:00+0000" log_id="062009617504" messageid="17504" '
     'log_type="Event" log_component="GUI" log_subtype="Admin" status="Successful" user="admin" '
     "message=\"Interface 'Port4' was turned off by 'admin' from '10.166.71.1' using 'GUI'\"",
     dict(connector="sophos", event_type="config_change", user="admin", src_ip="10.166.71.1")),
    ('<30>device="SFW" date=2026-11-14 time=10:00:00 timezone="UTC" device_name="XG230" log_id=063411617813 '
     'log_type="Event" log_component="Interface" log_subtype="System" priority=Information interface="Port2" '
     'message="Interface Port2 is Down"',
     dict(connector="sophos", event_type="link_state", interface="Port2", state="down")),

    # --- Suricata EVE JSON --------------------------------------------------------------------
    ('<9>Nov 14 10:00:00 sensor01 suricata[1234]: {"timestamp":"2026-11-14T10:00:00.000000+0000","flow_id":1,'
     '"in_iface":"eth1","event_type":"alert","src_ip":"203.0.113.5","src_port":51515,"dest_ip":"10.0.0.5",'
     '"dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2014,"rev":4,'
     '"signature":"ET WEB_SERVER SQL Injection","category":"Web Application Attack","severity":1,'
     '"metadata":{"tag":["SQL"]}}}',
     dict(connector="suricata", hostname="sensor01", event_type="threat", level="high", action="allow", proto="tcp",
          src_ip="203.0.113.5", dst_ip="10.0.0.5", dst_port=80, interface="eth1",
          threat_name="ET WEB_SERVER SQL Injection", sid="2014")),
    ('<9>1 2026-11-14T10:00:00Z sensor01 suricata 1234 - - {"timestamp":"2026-11-14T10:00:00.000000+0000",'
     '"event_type":"alert","src_ip":"2001:db8::5","src_port":51515,"dest_ip":"2001:db8::10","dest_port":22,'
     '"proto":"TCP","alert":{"action":"blocked","signature_id":2001219,"signature":"ET SCAN Potential SSH Scan",'
     '"category":"Attempted Information Leak","severity":2}}',
     dict(connector="suricata", event_type="threat", level="medium", action="block", src_ip="2001:db8::5", dst_port=22)),
    ('<14>Nov 14 10:00:00 sensor01 suricata[1234]: {"timestamp":"2026-11-14T10:00:00.000000+0000","flow_id":2,'
     '"event_type":"flow","src_ip":"10.0.0.5","src_port":50000,"dest_ip":"93.184.216.34","dest_port":443,'
     '"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":10,"pkts_toclient":8,"bytes_toserver":1500,'
     '"bytes_toclient":4000,"start":"x","end":"y","age":3,"state":"closed","reason":"timeout","alerted":false}}',
     dict(connector="suricata", event_type="traffic", action="", proto="tcp", src_ip="10.0.0.5", dst_port=443,
          bytes_sent="1500", app_proto="tls")),
    ('<14>Nov 14 10:00:00 sensor01 suricata[1234]: {"timestamp":"2026-11-14T10:00:00.000000+0000",'
     '"event_type":"dns","src_ip":"10.0.0.5","src_port":53000,"dest_ip":"10.0.0.53","dest_port":53,"proto":"UDP",'
     '"dns":{"type":"query","rrname":"example.com","rrtype":"A"}}',
     dict(connector="suricata", event_type="ids", eve_type="dns", dst_port=53, **{"dns.rrname": "example.com"})),
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
    new = {"cisco_asa", "juniper", "ubiquiti", "aruba", "dell_brocade", "meraki", "sonicwall", "sophos", "suricata"}
    assert new <= ids
    covered = {w["connector"] for _, w in SAMPLES if "connector" in w}
    assert new <= covered


def test_cisco_ios_still_handles_ios():
    ev = event("<189>123: core-sw1: Nov 14 10:00:00.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, "
               "changed state to down")
    assert (ev.connector, ev.event_type, ev.state) == ("cisco_ios", "link_state", "down")


def test_eve_json_from_an_opnsense_box_is_not_taken_by_the_opnsense_connector():
    """A device's last connector is tried first; EVE lines from a box that also sends fast.log alerts must still
    reach the suricata connector."""
    fast = parse_syslog("<1>Nov 14 10:00:00 fw suricata[1]: [1:2010935:3] ET SCAN x [Classification: y] "
                        "[Priority: 2] {TCP} 203.0.113.5:5555 -> 10.0.0.5:1433")
    eve = parse_syslog('<1>Nov 14 10:00:00 fw suricata[1]: {"timestamp":"t","event_type":"alert",'
                       '"src_ip":"203.0.113.5","dest_ip":"10.0.0.5","dest_port":1433,"proto":"TCP",'
                       '"alert":{"severity":2,"signature":"x"}}')
    assert REG.build_event(fast, 1.0, "fw", "10.0.0.1").connector == "opnsense"
    ev = REG.build_event(eve, 1.0, "fw", "10.0.0.1", hint="opnsense")
    assert (ev.connector, ev.event_type, ev.level, ev.dst_port) == ("suricata", "threat", "medium", 1433)


def test_kv_single_quotes_json_nesting_and_envelope_extract():
    conn = Connector({"id": "t", "match": "always", "rules": [
        {"name": "kv", "when": {"message": "^kv "}, "parser": "kv",
         "extract": [{"from": "message", "patterns": [r"^kv (?P<word>\w+)"]}]},
        {"name": "json", "parser": "json", "rename": {"a.b.c": "deep"}},
    ]}, "test")
    envelope = {"raw": "", "app": "", "hostname": ""}
    _, out = conn.parse({**envelope, "message": "kv hello name='two words' q=\"x y\" bare=z"})
    assert (out["word"], out["name"], out["q"], out["bare"]) == ("hello", "two words", "x y", "z")
    # Three levels of nesting are kept; deeper objects and lists are dropped.
    _, out = conn.parse({**envelope, "message": '{"a":{"b":{"c":1,"d":{"e":2}}},"l":[1],"s":"v"}'})
    assert out == {"deep": 1, "s": "v"}


def test_syslog_header_variants():
    p = parse_syslog("<166>Nov 14 2026 10:00:00 asa01 : %ASA-6-302013: x")
    assert (p["hostname"], p["message"]) == ("asa01", "%ASA-6-302013: x")
    p = parse_syslog("<166>Nov 14 2026 10:00:00: %ASA-6-302013: x")
    assert (p["hostname"], p["message"]) == ("", "%ASA-6-302013: x")
    p = parse_syslog("<190> Nov 14 10:00:00 10.0.0.3-1 TRAPMGR[1234]: hello")
    assert (p["hostname"], p["app"], p["message"]) == ("10.0.0.3-1", "TRAPMGR", "hello")
