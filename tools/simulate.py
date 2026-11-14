#!/usr/bin/env python3
"""Send realistic fake syslog to a Cerberus instance, to see detections fire.

    python tools/simulate.py                       # every scenario, to 127.0.0.1:514/udp
    python tools/simulate.py --port 5514 portscan bruteforce
    python tools/simulate.py --tcp --port 5514         # over TCP (Docker Desktop drops external UDP)
    python tools/simulate.py --list

All traffic comes from this machine, so every "device" shares one source IP.
Run Cerberus with CERBERUS_DEVICE_IDENTITY=hostname to see them separately.
Standard library only.
"""
from __future__ import annotations

import argparse
import random
import socket
import time
from datetime import datetime

FW = "OPNsense.lan"
PA = "PA-440"
FGT = "FGT-60F"
SW = "core-sw1"
RTL = "rtl-sw2"


def bsd_time() -> str:
    now = datetime.now()
    return f"{now:%b} {now.day:2d} {now:%H:%M:%S}"


def filterlog(action: str, src: str, dst: str, sport: int, dport: int, proto: str = "tcp", iface: str = "igb0") -> str:
    num = "6" if proto == "tcp" else "17"
    tail = f"{sport},{dport},0,S,123456789,,64240,,mss" if proto == "tcp" else f"{sport},{dport},40"
    body = (f"82,,,02f4bab031b57d1e30553ce08e0ec131,{iface},match,{action},in,4,0x0,,64,{random.randint(1, 65535)},"
            f"0,DF,{num},{proto},60,{src},{dst},{tail}")
    return f"<134>1 {datetime.now().astimezone().isoformat(timespec='seconds')} {FW} filterlog 91234 - - {body}"


def pan(log_type: str, fields: dict[int, str], size: int = 60) -> str:
    cols = [""] * size
    cols[0], cols[1], cols[2], cols[3] = "1", f"{datetime.now():%Y/%m/%d %H:%M:%S}", "012345678901", log_type
    cols[6] = cols[1]
    for index, value in fields.items():
        cols[index] = value
    return f"<14>{bsd_time()} {PA} " + ",".join(f'"{c}"' if "," in c else c for c in cols)


def pan_traffic(src: str, dst: str, dport: int, action: str = "allow", sent: int = 4000, app: str = "ssl") -> str:
    return pan("TRAFFIC", {4: "end", 7: src, 8: dst, 11: "outbound", 14: app, 16: "trust", 17: "untrust",
                           18: "ethernet1/2", 22: str(random.randint(1, 99999)), 24: str(random.randint(1024, 65000)),
                           25: str(dport), 29: "tcp", 30: action, 31: str(sent + 5000), 32: str(sent), 33: "5000",
                           37: "computer-and-internet-info", 46: "tcp-fin"})


def forti(**fields) -> str:
    now = datetime.now()
    head = {"date": f"{now:%Y-%m-%d}", "time": f"{now:%H:%M:%S}", "devname": FGT, "devid": "FGT60FTK20001234",
            "eventtime": str(int(now.timestamp() * 1e9)), "tz": "+0000", "logid": "0000000013", "vd": "root"}
    bare = {"date", "time", "srcip", "dstip", "srcport", "dstport", "proto", "sentbyte", "rcvdbyte", "policyid",
            "eventtime", "remip", "duration", "sessionid"}
    return "<189>" + " ".join(f"{k}={v}" if k in bare else f'{k}="{v}"' for k, v in {**head, **fields}.items())


def forti_traffic(src: str, dst: str, dport: int, action: str = "accept", proto: int = 6, sent: int = 1200) -> str:
    return forti(type="traffic", subtype="forward", level="notice", srcip=src, srcport=random.randint(1024, 65000),
                 srcintf="internal", dstip=dst, dstport=dport, dstintf="wan1", sessionid=random.randint(1, 999999),
                 proto=proto, action=action, policyid=1, service="HTTPS", duration=12, sentbyte=sent, rcvdbyte=4800)


def pan_flow(src: str, dst: str, dport: int, policy: str, zones: tuple[str, str], action: str = "allow",
             nat_dst: str = "", app: str = "incomplete") -> str:
    """A PAN-OS traffic log with a chosen rule, zones and (for inbound NAT) translated destination."""
    return pan("TRAFFIC", {4: "end", 7: src, 8: dst, 10: nat_dst, 11: policy, 14: app, 16: zones[0], 17: zones[1],
                           18: "ethernet1/1", 22: str(random.randint(1, 99999)), 24: str(random.randint(1024, 65000)),
                           25: str(dport), 29: "tcp", 30: action, 31: "9000", 32: "4000", 33: "5000",
                           37: "any", 46: "tcp-fin"})


def cisco(seq: int, text: str) -> str:
    return f"<189>{seq}: {SW}: {bsd_time()}.{random.randint(0, 999):03d}: {text}"


def baseline(n: int = 150):
    """Ordinary background traffic."""
    for _ in range(n):
        client = f"192.168.1.{random.randint(20, 60)}"
        yield filterlog("pass", client, f"142.250.{random.randint(0, 255)}.{random.randint(1, 254)}",
                        random.randint(1024, 65000), random.choice([443, 443, 443, 80, 53]))
        yield pan_traffic(client, f"151.101.{random.randint(0, 255)}.{random.randint(1, 254)}", 443)
        yield forti_traffic(f"192.168.3.{random.randint(20, 60)}", f"104.16.{random.randint(0, 255)}.{random.randint(1, 254)}", 443)
        if random.random() < 0.15:
            yield filterlog("block", f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.7",
                            "203.0.113.10", random.randint(1024, 65000), random.choice([22, 23, 445, 3389, 8080]),
                            iface="igb1")


def portscan():
    """An internal host walks 60 ports on a server (OPNsense filterlog)."""
    for port in random.sample(range(1, 1024), 60):
        yield filterlog("block", "192.168.1.77", "192.168.10.5", 51000, port)


def sweep():
    """An internal host tries SMB on 40 neighbours (worm-like)."""
    for host in range(1, 41):
        yield filterlog("block", "192.168.1.88", f"192.168.20.{host}", 52000 + host, 445)


def flood():
    """An external address hammers the WAN with blocked packets."""
    for _ in range(400):
        yield filterlog("block", "198.51.100.23", "203.0.113.10", random.randint(1024, 65000), 23, iface="igb1")


def bruteforce():
    """SSH password guessing against the switch, ending in a success."""
    for seq, user in enumerate(["admin", "root", "cisco", "admin", "support", "admin", "admin"]):
        yield cisco(300 + seq, f"%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: {user}] [Source: 192.168.1.66] "
                               f"[localport: 22] [Reason: Login Authentication Failed] at {bsd_time()}")
    yield cisco(320, "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 192.168.1.66] "
                     f"[localport: 22] at {bsd_time()}")
    yield cisco(321, "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.66)")
    for _ in range(6):
        yield f"<38>{bsd_time()} {FW} sshd[4411]: Failed password for invalid user oracle from 185.220.101.4 port 40022 ssh2"


def flap():
    """A switch port bouncing."""
    for seq in range(8):
        state = "down" if seq % 2 == 0 else "up"
        yield cisco(400 + seq, f"%LINK-3-UPDOWN: Interface GigabitEthernet1/0/12, changed state to {state}")
        yield cisco(450 + seq, f"%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/12, changed state to {state}")


def threat():
    """Palo Alto threat logs and a Suricata alert."""
    yield pan("THREAT", {4: "spyware", 7: "192.168.1.45", 8: "45.33.32.156", 11: "outbound", 14: "dns",
                         16: "trust", 17: "untrust", 24: "53211", 25: "53", 29: "udp", 30: "sinkhole",
                         31: "evil-c2.example.net", 32: "Suspicious DNS Query (generic:evil-c2.example.net)(109000001)",
                         33: "any", 34: "high", 35: "client-to-server"})
    yield pan("THREAT", {4: "vulnerability", 7: "203.0.113.99", 8: "192.168.10.5", 11: "inbound-web", 14: "web-browsing",
                         16: "untrust", 17: "dmz", 24: "44123", 25: "443", 29: "tcp", 30: "reset-both",
                         31: "index.php", 32: "Apache Log4j Remote Code Execution Vulnerability(91991)",
                         33: "code-execution", 34: "critical", 35: "client-to-server"})
    yield (f"<129>{bsd_time()} {FW} suricata[77210]: [1:2024897:3] ET USER_AGENTS Go HTTP Client User-Agent "
           "[Classification: Misc activity] [Priority: 2] {TCP} 192.168.1.52:49822 -> 93.184.216.34:80")


def switch():
    """Layer-2 trouble on the Cisco and RTL-Playground switches."""
    yield cisco(500, "%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address "
                     "0011.2233.4455 on port GigabitEthernet1/0/7.")
    yield cisco(501, "%SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.4455 in vlan 10 is flapping between port Gi1/0/3 and port Gi1/0/4")
    yield cisco(502, "%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port GigabitEthernet1/0/9 with BPDU Guard enabled. Disabling port.")
    yield f"<14>{RTL} STP: loop detected, blocking port 3"
    yield f"<14>{RTL} STP: BPDU guard tripped, disabling port 5"
    yield f"<14>{RTL} <new link: 0000000015, was 0000000055>"


def exfil():
    """An internal host uploads ~3 GB to the internet (Palo Alto byte counts)."""
    for _ in range(6):
        yield pan_traffic("192.168.1.31", "104.21.55.10", 443, sent=520 * 1024 * 1024, app="ssl")


def fortigate():
    """FortiGate: IPS and antivirus hits, a DoS anomaly, admin and VPN password guessing, a config change."""
    yield forti(type="utm", subtype="ips", eventtype="signature", level="alert", severity="critical",
                srcip="203.0.113.50", srcport=40112, dstip="192.168.3.10", dstport=8080, srcintf="wan1", proto=6,
                action="dropped", attack="Apache.Log4j.Error.Log.Remote.Code.Execution", attackid=51006,
                msg="applications3: Apache.Log4j.Error.Log.Remote.Code.Execution")
    yield forti(type="utm", subtype="virus", eventtype="infected", level="warning", srcip="192.168.3.44",
                srcport=50211, dstip="198.51.100.80", dstport=80, srcintf="internal", proto=6, action="blocked",
                virus="EICAR_TEST_FILE", filename="eicar.com", msg="File is infected.")
    yield forti(type="utm", subtype="anomaly", eventtype="anomaly", level="alert", severity="critical",
                srcip="198.51.100.99", srcport=1234, dstip="203.0.113.10", dstport=443, srcintf="wan1", proto=6,
                action="clear_session", attack="tcp_syn_flood", count=1, msg="anomaly: tcp_syn_flood, 2001 > threshold 2000")
    for user in ["admin", "admin", "root", "admin", "fortinet", "admin"]:
        yield forti(type="event", subtype="system", level="alert", logdesc="Admin login failed", user=user,
                    ui="ssh(192.168.3.90)", method="ssh", action="login", status="failed", reason="passwd_invalid",
                    msg=f"Administrator {user} login failed from ssh(192.168.3.90) because of invalid password")
    yield forti(type="event", subtype="system", level="information", logdesc="Admin login successful", user="admin",
                ui="ssh(192.168.3.90)", method="ssh", srcip="192.168.3.90", action="login", status="success",
                msg="Administrator admin logged in successfully from ssh(192.168.3.90)")
    yield forti(type="event", subtype="system", level="information", logdesc="Object attribute configured",
                user="admin", ui="GUI(192.168.3.90)", action="Edit", cfgpath="firewall.policy", cfgobj="1",
                cfgattr="action[deny->accept]", msg="Edit firewall.policy 1")
    for _ in range(6):
        yield forti(type="event", subtype="vpn", level="alert", logdesc="SSL VPN login fail", action="ssl-login-fail",
                    tunneltype="ssl-web", remip="185.220.101.77", user="jsmith", reason="sslvpn_login_permission_denied",
                    msg="SSL user failed to logged in")
    yield forti(type="event", subtype="system", level="warning", logdesc="Interface status changed",
                action="interface-stat-change", status="DOWN", msg="Link monitor: Interface wan2 was turned down")


def exposed():
    """Internet hosts reach RDP on an internal server through a port forward (Palo Alto, destination NAT)."""
    for last in (7, 21, 99):
        yield pan_flow(f"203.0.113.{last}", "198.51.100.10", 3389, "legacy-rdp-forward", ("untrust", "dmz"),
                       nat_dst="192.168.10.5", app="ms-rdp")


def egress():
    """Internal hosts go out on IRC, Tor and SMB."""
    yield filterlog("pass", "192.168.1.52", "45.9.148.3", 50123, 6667)
    yield forti_traffic("192.168.3.44", "185.220.101.5", 9001)
    yield pan_flow("192.168.1.33", "52.96.10.4", 445, "allow-all-out", ("trust", "untrust"), app="ms-ds-smb")


def lateral():
    """A workstation opens SMB to a dozen servers in another zone, and the firewall allows it."""
    for host in range(10, 22):
        yield pan_flow("192.168.1.77", f"192.168.10.{host}", 445, "trust-to-servers", ("trust", "servers"), app="ms-ds-smb")


def spray():
    """Password spraying against the switch, and one account guessed from many addresses."""
    for seq, user in enumerate(["admin", "administrator", "root", "cisco", "netadmin", "operator", "support", "backup"]):
        yield cisco(600 + seq, f"%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: {user}] [Source: 192.168.1.88] "
                               f"[localport: 22] [Reason: Login Authentication Failed] at {bsd_time()}")
    for last in range(1, 7):
        yield f"<38>{bsd_time()} {FW} sshd[4411]: Failed password for root from 141.98.10.{last} port 40022 ssh2"


def adminlogin():
    """Someone administers the FortiGate from an internet address."""
    yield forti(type="event", subtype="system", level="information", logdesc="Admin login successful", user="admin",
                ui="https(198.51.100.200)", method="https", srcip="198.51.100.200", action="login", status="success",
                msg="Administrator admin logged in successfully from https(198.51.100.200)")


def hostile():
    """An internet address scans the firewall, then is allowed through to an internal server."""
    for port in random.sample(range(1, 1024), 40):
        yield filterlog("block", "203.0.113.66", "192.168.10.5", 41000, port, iface="igb1")
    yield filterlog("pass", "203.0.113.66", "192.168.10.5", 41001, 8443, iface="igb1")


def compromised():
    """One workstation scans, spreads and calls out: three indicators that correlate into one critical alert."""
    yield from portscan()
    yield from lateral()
    yield filterlog("pass", "192.168.1.77", "45.9.148.9", 50999, 4444)


def beacon(count: int = 13, interval: float = 30.0):
    """A host checks in with one internet address on a fixed timer. Takes several minutes: the timing is the point."""
    for i in range(count):
        if i:
            time.sleep(interval)
        yield forti_traffic("192.168.3.61", "45.77.12.34", 8443)


def riskports():
    """A spread of traffic on high-risk ports, for the Risk ports page: Telnet and FTP in use
    inside, FTP and SMB allowed out, RDP reached from the internet, and blocked probes of the rest."""
    for i in range(30):
        yield filterlog("pass", f"192.168.1.{40 + i % 3}", "192.168.10.9", 51000 + i, 23)       # Telnet to a switch
        yield filterlog("pass", "192.168.1.45", "192.168.10.20", 52000 + i, 21)                # FTP to a file server
        yield forti_traffic("192.168.3.25", "198.51.100.77", 21)                               # FTP out
        yield filterlog("pass", f"192.168.1.{30 + i % 8}", "93.184.216.34", 53000 + i, 80)     # plain HTTP out
    for i in range(12):
        yield pan_flow("192.168.1.33", "52.96.10.4", 445, "allow-all-out", ("trust", "untrust"), app="ms-ds-smb")
        yield pan_flow(f"203.0.113.{10 + i}", "198.51.100.10", 3389, "legacy-rdp-forward", ("untrust", "dmz"),
                       nat_dst="192.168.10.5", app="ms-rdp")
    for i in range(150):
        port = (23, 3389, 445, 22, 5900, 1433, 6379)[i % 7]
        yield filterlog("block", f"{45 + i % 60}.{i % 250}.{(i * 7) % 250}.{1 + i % 200}", "203.0.113.10", 40000 + i, port,
                        iface="igb1")


SCENARIOS = {f.__name__: f for f in (baseline, portscan, sweep, flood, bruteforce, flap, threat, switch, exfil, fortigate,
                                     exposed, egress, lateral, spray, adminlogin, hostile, compromised, riskports, beacon)}
SLOW = {"beacon"}  # only run when asked for by name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenarios", nargs="*", help="which to run (default: all)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--delay", type=float, default=0.002, help="seconds between messages")
    parser.add_argument("--tcp", action="store_true", help="send over TCP (octet-counted framing) instead of UDP")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = parser.parse_args()
    if args.list:
        for name, fn in SCENARIOS.items():
            print(f"{name:11s} {fn.__doc__.strip()}")
        return
    unknown = [s for s in args.scenarios if s not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}. Try --list.")
    if args.tcp:
        sock = socket.create_connection((args.host, args.port), timeout=10)

        def send(data: bytes) -> None:
            sock.sendall(f"{len(data)} ".encode() + data)  # RFC 6587 octet counting
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def send(data: bytes) -> None:
            sock.sendto(data, (args.host, args.port))
    for name in args.scenarios or [s for s in SCENARIOS if s not in SLOW]:
        count = 0
        for line in SCENARIOS[name]():
            send(line.encode())
            count += 1
            time.sleep(args.delay)
        print(f"{name}: sent {count} messages")
    sock.close()


if __name__ == "__main__":
    main()
