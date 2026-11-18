"""Check Point, MikroTik, WatchGuard, CEF, NX-OS, Arista, Huawei/H3C, Extreme and Cisco WLC connectors,
and the parsing they need (CEF, key:"value" pairs, timestamps with a year).

Samples follow the vendors' documented formats; fields not listed are not checked."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.connectors import ConnectorRegistry, parse_cef  # noqa: E402
from cerberus.syslog_parser import parse_syslog  # noqa: E402

REG = ConnectorRegistry()

CP = '<134>1 2026-11-14T10:00:00Z gw-313a1b CheckPoint 2734 - '

SAMPLES = [
    # --- Check Point --------------------------------------------------------------------------
    (CP + '[action:"Drop"; flags:"411908"; ifdir:"inbound"; ifname:"eth1"; logid:"0"; loguid:"{0x0,0x0,0x0,0x0}"; '
     'origin:"10.0.0.1"; originsicname:"CN=gw,O=mgmt"; sequencenum:"1"; time:"1763114400"; version:"5"; '
     'dst:"10.0.0.5"; inzone:"External"; layer_name:"Network"; match_id:"3"; outzone:"Internal"; '
     'product:"VPN-1 & FireWall-1"; proto:"6"; rule_action:"Drop"; rule_name:"Cleanup rule"; s_port:"51515"; '
     'service:"22"; service_id:"ssh"; src:"203.0.113.5"]',
     dict(connector="checkpoint", event_type="traffic", action="block", proto="tcp", src_ip="203.0.113.5",
          src_port=51515, dst_ip="10.0.0.5", dst_port=22, interface="eth1", policy="Cleanup rule")),
    (CP + '[action:"Accept"; ifdir:"outbound"; ifname:"eth0"; origin:"10.0.0.1"; client_inbound_bytes:"4000"; '
     'client_outbound_bytes:"1500"; dst:"8.8.8.8"; product:"VPN-1 & FireWall-1"; proto:"17"; s_port:"53000"; '
     'service:"53"; src:"10.0.0.5"]',
     dict(connector="checkpoint", event_type="traffic", action="allow", proto="udp", dst_port=53, bytes_sent="1500")),
    (CP + '[action:"Prevent"; origin:"10.0.0.1"; product:"IPS"; protection_name:"SQL Injection Attempt"; '
     'severity:"3"; confidence_level:"4"; attack:"SQL Servers"; src:"203.0.113.5"; dst:"10.0.0.5"; proto:"6"; '
     'service:"80"]',
     dict(connector="checkpoint", event_type="threat", action="block", level="high",
          threat_name="SQL Injection Attempt", src_ip="203.0.113.5", dst_port=80)),
    (CP + '[action:"Detect"; origin:"10.0.0.1"; product:"Anti-Bot"; malware_family:"Emotet"; '
     'protection_name:"Trojan.Win32.Emotet.TC.a"; severity:"Critical"; src:"10.0.0.5"; dst:"198.51.100.66"]',
     dict(connector="checkpoint", event_type="threat", action="allow", level="critical",
          threat_name="Trojan.Win32.Emotet.TC.a", dst_ip="198.51.100.66")),
    (CP + '[operation:"Log In"; status:"Failure"; administrator:"admin"; client_ip:"203.0.113.5"; '
     'product:"SmartConsole"]',
     dict(connector="checkpoint", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    (CP + '[operation:"Log In"; status:"Success"; administrator:"admin"; client_ip:"10.0.0.9"; product:"SmartConsole"]',
     dict(connector="checkpoint", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    (CP + '[auth_status:"Failed Login"; user:"jdoe"; src:"203.0.113.7"; product:"Mobile Access"]',
     dict(connector="checkpoint", event_type="auth_failure", user="jdoe", src_ip="203.0.113.7")),
    (CP + '[operation:"Install Policy"; administrator:"admin"; client_ip:"10.0.0.9"; product:"SmartConsole"; '
     'subject:"Policy Installation"]',
     dict(connector="checkpoint", event_type="config_change", user="admin", src_ip="10.0.0.9")),

    # --- MikroTik -----------------------------------------------------------------------------
    ('<30>Nov 14 10:00:00 192.168.88.1 firewall,info DROP-IN input: in:ether1 out:(unknown 0), '
     'connection-state:new src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.5:51515->198.51.100.10:22, len 60',
     dict(connector="mikrotik", event_type="traffic", action="block", proto="tcp", interface="ether1",
          src_ip="203.0.113.5", src_port=51515, dst_ip="198.51.100.10", dst_port=22)),
    ('<30>Nov 14 10:00:00 192.168.88.1 firewall,info ACCEPT-WEB forward: in:bridge out:ether1, connection-state:new '
     'src-mac 98:52:b1:79:31:94, proto TCP (SYN), 192.168.88.20:50000->93.184.216.34:443, '
     'NAT (192.168.88.20:50000->203.0.113.2:50000)->93.184.216.34:443, len 60',
     dict(connector="mikrotik", event_type="traffic", action="allow", src_ip="192.168.88.20", dst_ip="93.184.216.34",
          dst_port=443, out_interface="ether1")),
    ('<30>Nov 14 10:00:00 192.168.88.1 firewall,info input: in:ether1 out:(unknown 0), connection-state:new '
     'src-mac 00:11:22:33:44:55, proto ICMP (type 8, code 0), 203.0.113.5->198.51.100.10, len 84',
     dict(connector="mikrotik", event_type="traffic", action="", proto="icmp", src_ip="203.0.113.5", dst_port=None)),
    ('<27>Nov 14 10:00:00 192.168.88.1 system,error,critical login failure for user admin from 203.0.113.5 via ssh',
     dict(connector="mikrotik", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<30>Nov 14 10:00:00 192.168.88.1 system,info,account user admin logged in from 10.0.0.9 via winbox',
     dict(connector="mikrotik", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<30>Nov 14 10:00:00 192.168.88.1 system,info filter rule added by admin',
     dict(connector="mikrotik", event_type="config_change", user="admin")),
    ('<30>Nov 14 10:00:00 192.168.88.1 interface,info ether2 link down',
     dict(connector="mikrotik", event_type="link_state", interface="ether2", state="down")),
    ('<134>Nov 14 10:00:00 192.168.88.1 CEF:0|MikroTik|CCR2004|7.16|132|firewall,info|Low|dvchost=router1 '
     'msg=DROP-IN input: in:ether1 out:(unknown 0), connection-state:new proto TCP (SYN), '
     '203.0.113.5:51515->198.51.100.10:22, len 60',
     dict(connector="mikrotik", event_type="traffic", action="block", dst_port=22)),

    # --- WatchGuard ---------------------------------------------------------------------------
    ('<142>Nov 14 10:00:00 FBX-M370 801002AB12345 (2026-11-14T10:00:00) firewall: msg_id="3000-0148" Deny '
     '1-Trusted 0-External 60 tcp 20 64 10.0.0.5 203.0.113.9 50000 22 offset 10 S 12345 win 64240  '
     '(Unhandled Internal Packet-00)',
     dict(connector="watchguard", hostname="FBX-M370", event_type="traffic", action="block", proto="tcp",
          interface="1-Trusted", src_ip="10.0.0.5", dst_ip="203.0.113.9", dst_port=22,
          policy="Unhandled Internal Packet-00")),
    ('<142>Nov 14 10:00:00 FBX-M370 801002AB12345 (2026-11-14T10:00:00) firewall: msg_id="3000-0151" Allow '
     '1-Trusted 0-External 52 tcp 20 128 10.0.0.5 93.184.216.34 50000 443 offset 8 S 123 win 64240 (Outgoing-00) '
     'proc_id="firewall" rc="100" src_ip_nat="198.51.100.10" sent_bytes="1500" rcvd_bytes="4000"',
     dict(connector="watchguard", event_type="traffic", action="allow", dst_port=443, policy="Outgoing-00",
          bytes_sent="1500")),
    ('<142>Nov 14 10:00:00 FBX-M370 Deny 10.0.1.131 10.0.1.1 echo-request/icmp Trusted Firebox Denied 84 64 '
     '(Ping-00) proc_id="firewall" rc="101" msg_id="3000-0148" type="8"',
     dict(connector="watchguard", event_type="traffic", action="block", proto="icmp", src_ip="10.0.1.131",
          interface="Trusted", policy="Ping-00")),
    ('<140>Nov 14 10:00:00 FBX-M370 801002AB12345 (2026-11-14T10:00:00) firewall: msg_id="3000-0148" Deny '
     '0-External 1-Trusted 60 tcp 20 50 203.0.113.5 10.0.0.5 51515 80 (HTTP-proxy-00) '
     'signature_name="WEB SQL injection attempt" signature_cat="Web Attack" signature_id="1110361" severity="4"',
     dict(connector="watchguard", event_type="threat", action="block", level="high", src_ip="203.0.113.5",
          dst_port=80, threat_name="WEB SQL injection attempt")),
    ('<38>Nov 14 10:00:00 FBX-M370 801002AB12345 (2026-11-14T10:00:00) admd: msg_id="1100-0004" Authentication of '
     'Firewall user [jdoe@Firebox-DB] from 203.0.113.5 was rejected, password is incorrect',
     dict(connector="watchguard", event_type="auth_failure", user="jdoe", src_ip="203.0.113.5")),
    ('<38>Nov 14 10:00:00 FBX-M370 801002AB12345 (2026-11-14T10:00:00) admd: msg_id="1100-0005" Management user '
     'admin@Firebox-DB from 10.0.0.9 logged in',
     dict(connector="watchguard", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<38>Nov 14 10:00:00 FBX-M370 801002AB12345 (2026-11-14T10:00:00) wgagent: msg_id="0101-0001" Configuration '
     'file was saved by admin@Firebox-DB from 10.0.0.9',
     dict(connector="watchguard", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<38>Nov 14 10:00:00 FBX-M370 801002AB12345 (2026-11-14T10:00:00) networkd: msg_id="0109-0001" Interface '
     '0-External link down',
     dict(connector="watchguard", event_type="link_state", interface="0-External", state="down")),

    # --- CEF ----------------------------------------------------------------------------------
    ('<134>Nov 14 10:00:00 ngfw CEF:0|Forcepoint|NGFW|6.10|70018|Connection_Discarded|0|deviceExternalId=ngfw node 1 '
     'dvchost=10.0.0.1 act=Discard src=203.0.113.5 dst=10.0.0.5 spt=51515 dpt=22 proto=6 '
     'deviceInboundInterface=0 msg=Connection discarded by rule',
     dict(connector="cef", event_type="traffic", action="block", proto="tcp", src_ip="203.0.113.5", dst_port=22,
          deviceExternalId="ngfw node 1", msg="Connection discarded by rule")),
    ('<134>Nov 14 10:00:00 ngfw CEF:0|Barracuda|CloudGen Firewall|9.0|1|Allow|1|act=Allow src=10.0.0.5 '
     'dst=93.184.216.34 spt=50000 dpt=443 proto=TCP out=1500 in=4000',
     dict(connector="cef", event_type="traffic", action="allow", proto="tcp", bytes_sent="1500",
          bytes_received="4000")),
    ('<134>Nov 14 10:00:00 dsm CEF:0|Trend Micro|Deep Security Agent|20.0|1001228|Microsoft Windows SMB Remote Code '
     'Execution Vulnerability|8|cn1=12 cn1Label=Host ID dvchost=web01 act=Reset src=203.0.113.5 dst=10.0.0.5 '
     'spt=51515 dpt=445 proto=TCP',
     dict(connector="cef", event_type="threat", level="high", action="block", hostname="web01",
          threat_name="Microsoft Windows SMB Remote Code Execution Vulnerability", dst_port=445)),
    ('<134>Nov 14 10:00:00 waf CEF:0|Imperva Inc.|SecureSphere|14.7|Login|Login failed|5|suser=admin '
     'src=203.0.113.5',
     dict(connector="cef", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<134>Nov 14 10:00:00 waf CEF:0|Imperva Inc.|SecureSphere|14.7|Login|Successful login|1|suser=admin '
     'src=10.0.0.9',
     dict(connector="cef", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<134>Nov 14 10:00:00 f5 CEF:0|F5|BIG-IP|17.1|audit|Configuration changed|5|suser=admin src=10.0.0.9 '
     'msg=modify ltm pool web',
     dict(connector="cef", event_type="config_change", user="admin")),
    ('<134>Nov 14 10:00:00 ngfw CEF:0|Forcepoint|NGFW|6.10|70018|Connection_Allowed|0|act=Allow '
     'c6a2=2001:db8::5 c6a3=2001:db8::10 spt=51515 dpt=443 proto=6',
     dict(connector="cef", event_type="traffic", src_ip="2001:db8::5", dst_ip="2001:db8::10", dst_port=443)),
    ('<134>Nov 14 10:00:00 ngfw CEF:0|Forcepoint|NGFW|6.10|1|Engine started|3|dvchost=ngfw1',
     dict(connector="cef", event_type="system", hostname="ngfw1")),

    # --- Cisco NX-OS --------------------------------------------------------------------------
    ('<189>: 2026 Nov 14 10:00:00 UTC: %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/5 is down (Link failure)',
     dict(connector="cisco_nxos", event_type="link_state", interface="Ethernet1/5", state="down")),
    ('<189>2026 Nov 14 10:00:00 UTC: N9K-1 %ETHPORT-5-IF_UP: Interface Ethernet1/5 is up in mode access',
     dict(connector="cisco_nxos", hostname="N9K-1", event_type="link_state", interface="Ethernet1/5", state="up")),
    ('<189>: 2026 Nov 14 10:00:00 UTC: %ETHPORT-5-IF_DOWN_ADMIN_DOWN: Interface Ethernet1/6 is down '
     '(Administratively down)',
     dict(connector="cisco_nxos", event_type="link_state", state="administratively down")),
    ('<85>: 2026 Nov 14 10:00:00 UTC: %AUTHPRIV-3-SYSTEM_MSG: pam_unix(dcos_sshd:auth): authentication failure; '
     'logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=admin - dcos_sshd[1234]',
     dict(connector="cisco_nxos", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<85>: 2026 Nov 14 10:00:00 UTC: %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user bob '
     'from 203.0.113.5 - dcos_sshd[1234]',
     dict(connector="cisco_nxos", event_type="auth_failure", user="bob", src_ip="203.0.113.5")),
    ('<86>: 2026 Nov 14 10:00:00 UTC: %AUTHPRIV-6-SYSTEM_MSG: Accepted password for admin from 10.0.0.9 port 51515 '
     'ssh2 - dcos_sshd[1234]',
     dict(connector="cisco_nxos", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<189>: 2026 Nov 14 10:00:00 UTC: %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by admin on 10.0.0.9@pts/0',
     dict(connector="cisco_nxos", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<190>: 2026 Nov 14 10:00:00 UTC: %ACLLOG-6-ACLLOG_FLOW_INTERVAL: Src IP: 203.0.113.5, Dst IP: 10.0.0.5, '
     'Src Port: 51515, Dst Port: 22, Src Intf: Ethernet1/1, Protocol: "TCP"(6), Hit-count = 3',
     dict(connector="cisco_nxos", event_type="traffic", src_ip="203.0.113.5", dst_port=22, proto="tcp",
          interface="Ethernet1/1")),
    ('<186>: 2026 Nov 14 10:00:00 UTC: %STP-2-BLOCK_BPDUGUARD: Received BPDU on port Ethernet1/7 with BPDU Guard '
     'enabled. Disabling port.',
     dict(connector="cisco_nxos", event_type="stp_guard", interface="Ethernet1/7")),
    ('<188>: 2026 Nov 14 10:00:00 UTC: %L2FM-4-L2FM_MAC_MOVE: Mac 0011.2233.4455 in vlan 10 has moved from Eth1/1 '
     'to Eth1/2',
     dict(connector="cisco_nxos", event_type="mac_flap", interface="Eth1/1")),
    ('<186>: 2026 Nov 14 10:00:00 UTC: %VPC-2-PEER_KEEP_ALIVE_RECV_FAIL: In domain 10, VPC peer keep-alive receive '
     'has failed',
     dict(connector="cisco_nxos", event_type="system", level="high")),

    # --- Arista EOS ---------------------------------------------------------------------------
    ('<189>Nov 14 10:00:00 leaf1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet5, changed state to '
     'down',
     dict(connector="arista", hostname="leaf1", event_type="link_state", interface="Ethernet5", state="down")),
    ('<189>Nov 14 10:00:00 leaf1 ConfigAgent: %SYS-5-CONFIG_I: Configured from console by admin on vty3 (10.0.0.9)',
     dict(connector="arista", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<190>Nov 14 10:00:00 leaf1 Acl: %ACL-6-IPACCESS: list INBOUND Ethernet1 denied tcp 203.0.113.5(51515) -> '
     '10.0.0.5(22)',
     dict(connector="arista", event_type="traffic", action="block", interface="Ethernet1", dst_port=22)),
    ('<188>Nov 14 10:00:00 leaf1 Bridging: %ETH-4-HOST_FLAPPING: Host 00:11:22:33:44:55 in VLAN 10 is flapping '
     'between interface Ethernet1 and interface Ethernet2',
     dict(connector="arista", event_type="mac_flap", interface="Ethernet1")),
    ('<186>Nov 14 10:00:00 leaf1 Stp: %SPANTREE-2-BPDUGUARD_ERRDISABLE: Received BPDU on Ethernet7, errdisabling port',
     dict(connector="arista", event_type="stp_guard", interface="Ethernet7")),
    ('<38>Nov 14 10:00:00 leaf1 sshd[1234]: Failed password for admin from 203.0.113.5 port 51515 ssh2',
     dict(connector="generic", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),

    # --- Huawei VRP / HPE Comware -------------------------------------------------------------
    ('<187>Nov 14 2026 10:00:00 SW01 %%01IFPDT/4/IF_STATE(l)[0]:Interface GigabitEthernet0/0/5 has turned into '
     'DOWN state.',
     dict(connector="huawei_h3c", hostname="SW01", event_type="link_state", interface="GigabitEthernet0/0/5",
          state="down")),
    ('<189>Nov 14 2026 10:00:00+08:00 SW01 %%01SSH/5/SSH_USER_LOGIN_FAIL(s)[3]:The SSH user failed to login. '
     '(ServiceType=stelnet, UserName=admin, UserAddress=203.0.113.5, LocalAddress=10.0.0.1, VpnInstanceName=, '
     'Reason=Authentication failed)',
     dict(connector="huawei_h3c", hostname="SW01", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<189>Nov 14 2026 10:00:00 SW01 %%01SSH/5/SSH_USER_LOGIN(s)[1]:The SSH user succeeded in logging in. '
     '(ServiceType=stelnet, UserName=admin, UserAddress=10.0.0.9, LocalAddress=10.0.0.1, VpnInstanceName=)',
     dict(connector="huawei_h3c", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<189>Nov 14 2026 10:00:00 SW01 %%01SHELL/5/CMDRECORD(s)[5]:Recorded command information. (Task=VT0, '
     'Ip=10.0.0.9, VpnName=, User=admin, AuthenticationMethod="Local-user", Command="display version")',
     dict(connector="huawei_h3c", event_type="command", user="admin", command="display version")),
    ('<189>Nov 14 2026 10:00:00 SW01 %%01SHELL/5/CMDRECORD(s)[6]:Recorded command information. (Task=VT0, '
     'Ip=10.0.0.9, VpnName=, User=admin, AuthenticationMethod="Local-user", Command="undo shutdown")',
     dict(connector="huawei_h3c", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<188>Nov 14 2026 10:00:00 SW01 %%01L2IFPPI/4/MFLPVLANALARM(l)[2]:MAC flapping detected, VlanId = 10, '
     'MacAddress = 0011-2233-4455, Original-Port = GE0/0/1, Flapping port = GE0/0/2.',
     dict(connector="huawei_h3c", event_type="mac_flap", interface="GE0/0/1", interface2="GE0/0/2")),
    ('<188>Nov 14 10:00:00 2026 H3C-SW01 %%10IFNET/3/PHY_UPDOWN: Physical state on the interface '
     'GigabitEthernet1/0/1 changed to down.',
     dict(connector="huawei_h3c", hostname="H3C-SW01", event_type="link_state", interface="GigabitEthernet1/0/1",
          state="down")),
    ('<189>Nov 14 10:00:00 2026 H3C-SW01 %%10LOGIN/5/LOGIN_FAILED: admin (in VTY0) failed to log in from '
     '203.0.113.5.',
     dict(connector="huawei_h3c", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<190>Nov 14 10:00:00 2026 H3C-SW01 %%10SSHS/6/SSHS_AUTH_FAIL: SSH user admin (IP: 203.0.113.5) didn\'t pass '
     'public key authentication for wrong public key algorithm.',
     dict(connector="huawei_h3c", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<189>Nov 14 10:00:00 2026 H3C-SW01 %%10SHELL/5/SHELL_LOGIN: admin logged in from 10.0.0.9.',
     dict(connector="huawei_h3c", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<190>Nov 14 10:00:00 2026 H3C-SW01 %%10SHELL/6/SHELL_CMD: -Line=vty0-IPAddr=10.0.0.9-User=admin; Command is '
     'interface GigabitEthernet1/0/1',
     dict(connector="huawei_h3c", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<188>Nov 14 10:00:00 2026 H3C-SW01 %%10STP/4/STP_BPDU_PROTECTION: BPDU-Protection port GigabitEthernet1/0/1 '
     'received BPDUs.',
     dict(connector="huawei_h3c", event_type="stp_guard", interface="GigabitEthernet1/0/1")),

    # --- Extreme ------------------------------------------------------------------------------
    ('<134>Nov 14 10:00:00 X460 <Info:vlan.msgs.portLinkStateDown> Port 1:5 link down',
     dict(connector="extreme", hostname="X460", event_type="link_state", interface="1:5", state="down")),
    ('<134>Nov 14 10:00:00 X460 exsh: <Info:vlan.msgs.portLinkStateUp> Port 1:5 link UP at speed 1 Gbps and '
     'full-duplex',
     dict(connector="extreme", event_type="link_state", interface="1:5", state="up")),
    ('<132>Nov 14 10:00:00 X460 <Warn:AAA.authFail> Login failed for user admin through ssh (203.0.113.5)',
     dict(connector="extreme", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),
    ('<134>Nov 14 10:00:00 X460 <Info:AAA.authPass> Login passed for user admin through ssh (10.0.0.9)',
     dict(connector="extreme", event_type="auth_success", user="admin", src_ip="10.0.0.9")),
    ('<134>Nov 14 10:00:00 X460 <Info:cli.logRemoteCmd> Login: admin; Cmd: configure vlan users add ports 1:5 '
     'untagged; Session: ssh(10.0.0.9)',
     dict(connector="extreme", event_type="config_change", user="admin", src_ip="10.0.0.9")),
    ('<134>Nov 14 10:00:00 X460 <Info:cli.logRemoteCmd> Login: admin; Cmd: show ports; Session: ssh(10.0.0.9)',
     dict(connector="extreme", event_type="command", user="admin")),
    ('<134>Nov 14 10:00:00 VSP-01 CP1 [11/14/26 10:00:00.000:UTC] 0x0000c5e8 00300001.238 DYNAMIC SET GlobalRouter HW '
     'INFO Link Down(1/5)',
     dict(connector="extreme", event_type="link_state", interface="1/5", state="down")),
    ('<132>Nov 14 10:00:00 VSP-01 CP1 [11/14/26 10:00:00.000:UTC] 0x00004508 00000000 GlobalRouter SW WARNING Login '
     'Failure: user admin from 203.0.113.5 via ssh',
     dict(connector="extreme", event_type="auth_failure", user="admin", src_ip="203.0.113.5")),

    # --- Cisco wireless controllers -----------------------------------------------------------
    ('<11>WLC01: *apfMsConnTask_0: Nov 14 10:00:00.123: %APF-3-AUTHENTICATION_FAILED: apf_foreignap.c:1234 '
     'Authentication failed for client 00:11:22:33:44:55 user jdoe',
     dict(connector="cisco_wlc", event_type="auth_failure", user="jdoe", mac="00:11:22:33:44:55")),
    ('<12>WLC01: *apfRogueTask_1: Nov 14 10:00:00.123: %APF-4-ROGUE_AP_DETECTED: apf_rogue.c:1000 Rogue AP '
     '00:11:22:33:44:66 detected on Base Radio MAC 00:aa:bb:cc:dd:00 Interface no:0',
     dict(connector="cisco_wlc", event_type="threat", level="medium")),
    ('<133>WLC9800: *Nov 14 10:00:00.123: %CLIENT_EXCLUSION_SERVER-5-ADD_TO_EXCLUSIONLIST_REASON: Chassis 1 R0/0: '
     'wncd: Client MAC: 0011.2233.4455 was added to exclusion list associated with AP Name:AP01, reason:802.1X '
     'Authentication failed 3 times.',
     dict(connector="cisco_wlc", event_type="auth_failure", mac="0011.2233.4455")),
    ('<133>WLC9800: *Nov 14 10:00:00.123: %SESSION_MGR-5-FAIL: Chassis 1 R0/0: wncd: Authorization failed or '
     'unapplied for client (0011.2233.4455) on Interface capwap_90000005 AuditSessionID 0A0B0C0D. Failure reason: '
     'Authc fail. Authc failure reason: Cred Fail. Username: jdoe',
     dict(connector="cisco_ios", event_type="auth_failure", user="jdoe", interface="capwap_90000005")),
]


def event(line: str, hint: str = ""):
    parsed = parse_syslog(line)
    return REG.build_event(parsed, 1000.0, parsed["hostname"] or "10.0.0.1", "10.0.0.1", hint=hint)


@pytest.mark.parametrize("line,want", SAMPLES, ids=[f"{w.get('connector', 'any')}-{i}" for i, (_, w) in enumerate(SAMPLES)])
def test_samples(line, want):
    ev = event(line)
    got = {key: getattr(ev, key) if hasattr(ev, key) else ev.extra.get(key) for key in want}
    assert got == want, (ev.connector, ev.rule, ev.event_type, ev.extra)


def test_every_connector_loads_and_is_covered():
    assert not REG.errors, REG.errors
    new = {"checkpoint", "mikrotik", "watchguard", "cef", "cisco_nxos", "arista", "huawei_h3c", "extreme",
           "cisco_wlc", "netflow"}
    assert new <= set(REG.by_id)
    covered = {w["connector"] for _, w in SAMPLES}
    assert new - {"netflow"} <= covered  # netflow: tests/test_flows.py


@pytest.mark.parametrize("line,want", [
    ('<189>: 2026 Nov 14 10:00:00 UTC: %ETHPORT-5-IF_UP: Interface Ethernet1/5 is up in mode access', "cisco_nxos"),
    ('<133>WLC9800: *Nov 14 10:00:00.123: %CLIENT_EXCLUSION_SERVER-5-ADD_TO_EXCLUSIONLIST_REASON: Client MAC: '
     '0011.2233.4455 was added to exclusion list', "cisco_wlc"),
])
def test_a_device_last_seen_as_ios_still_reaches_its_own_connector(line, want):
    """The per-device hint must not keep NX-OS or controller messages on the IOS connector."""
    assert event(line, hint="cisco_ios").connector == want


def test_ios_is_still_ios():
    ev = event("<189>123: core-sw1: Nov 14 10:00:00.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, "
               "changed state to down")
    assert (ev.connector, ev.event_type, ev.hostname) == ("cisco_ios", "link_state", "core-sw1")


def test_cef_parser():
    out = parse_cef(r"CEF:0|Ven\|dor|Pro\\duct|1.0|100|Name with \| pipe|7|"
                    r"msg=a\=b and more text src=10.0.0.5 cs1Label=Rule Name cs1=Allow all")
    assert out["cef_vendor"] == "Ven|dor"
    assert out["cef_product"] == "Pro\\duct"
    assert out["cef_name"] == "Name with | pipe"
    assert out["cef_severity"] == "7"
    assert out["msg"] == "a=b and more text"
    assert out["src"] == "10.0.0.5"
    assert out["cs1"] == "Allow all"
    assert parse_cef("no cef here") is None
    assert parse_cef("CEF:0|too|few") is None


@pytest.mark.parametrize("line,host,message", [
    ("<187>Nov 14 2026 10:00:00 SW01 %%01IFPDT/4/IF_STATE(l)[0]:x", "SW01", "%%01IFPDT/4/IF_STATE(l)[0]:x"),
    ("<187>Nov  4 2026 10:00:00.123+08:00 SW01 %%01X/4/Y:x", "SW01", "%%01X/4/Y:x"),
    ("<188>Nov 14 10:00:00 2026 H3C %%10IFNET/3/PHY_UPDOWN: x", "H3C", "%%10IFNET/3/PHY_UPDOWN: x"),
    ("<189>: 2026 Nov 14 10:00:00 UTC: %ETHPORT-5-IF_UP: x", "", "%ETHPORT-5-IF_UP: x"),
    ("<189>2026 Nov 14 10:00:00.123 UTC: N9K %ETHPORT-5-IF_UP: x", "N9K", "%ETHPORT-5-IF_UP: x"),
    # Unchanged: plain RFC 3164 and ASA.
    ("<14>Nov 14 10:00:00 host app[1]: hello", "host", "hello"),
    ("<166>Nov 14 2026 10:00:00 asa01 : %ASA-6-302013: x", "asa01", "%ASA-6-302013: x"),
])
def test_timestamps_with_a_year(line, host, message):
    parsed = parse_syslog(line)
    assert (parsed["hostname"], parsed["message"]) == (host, message)
