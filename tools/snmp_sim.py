#!/usr/bin/env python3
"""Fake SNMP agents for trying the topology feature without real hardware.

    python tools/snmp_sim.py            # serves four devices on 127.0.0.1:16101-16104
    python tools/snmp_sim.py --sites 30 # a 302-device campus, for trying Cerberus at scale

Each agent answers SNMP v2c (community "public") with system, interface, LLDP
and CDP data describing one small network. Pair it with tools/simulate.py
(which sends syslog under the same hostnames) and, on the Devices page, set
each device's SNMP address to the one printed here.
"""
from __future__ import annotations

import asyncio
import bisect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.snmp import GET, GETBULK, RESPONSE, _int, _oid, _tlv, decode_message, oid  # noqa: E402

INTEGER, OCTETS, OBJECT_ID, IPADDR, COUNTER64, GAUGE, TICKS = 0x02, 0x04, 0x06, 0x40, 0x46, 0x42, 0x43


def encode_value(tag: int, value) -> bytes:
    if tag == INTEGER:
        return _int(value)
    if tag in (GAUGE, TICKS, COUNTER64):
        return _tlv(tag, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big"))
    if tag == OCTETS:
        return _tlv(tag, value.encode() if isinstance(value, str) else value)
    if tag == OBJECT_ID:
        return _oid(value)
    if tag == IPADDR:
        return _tlv(tag, bytes(int(p) for p in value.split(".")))
    raise ValueError(tag)


class FakeAgent(asyncio.DatagramProtocol):
    """Serves a static {oid: (tag, value)} table over SNMP v2c."""

    def __init__(self, mib: dict, community: str = "public"):
        self.mib = mib
        self.order = sorted(mib)
        self.community = community.encode()
        self.requests = 0
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def _bind(self, name) -> bytes:
        tag, value = self.mib[name]
        return _tlv(0x30, _oid(name) + encode_value(tag, value))

    def _next(self, name) -> tuple[tuple, bytes]:
        pos = bisect.bisect_right(self.order, name)
        if pos >= len(self.order):
            return name, _tlv(0x30, _oid(name) + b"\x82\x00")  # endOfMibView
        return self.order[pos], self._bind(self.order[pos])

    def datagram_received(self, data: bytes, addr) -> None:
        msg = decode_message(data)
        if msg["community"] != self.community:
            return  # real agents stay silent on a wrong community
        self.requests += 1
        out = b""
        if msg["pdu"] == GET:
            for name, _ in msg["varbinds"]:
                out += self._bind(name) if name in self.mib else _tlv(0x30, _oid(name) + b"\x81\x00")
        else:
            repeat = max(1, min(msg["b"], 50)) if msg["pdu"] == GETBULK else 1
            for name, _ in msg["varbinds"]:
                for _ in range(repeat):
                    name, bind = self._next(name)
                    out += bind
        body = _int(msg["request_id"]) + _int(0) + _int(0) + _tlv(0x30, out)
        self.transport.sendto(_tlv(0x30, _int(1) + _tlv(0x04, self.community) + _tlv(RESPONSE, body)), addr)


def mac_bytes(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def device_mib(name: str, descr: str, ip: str, chassis: str, ports: list[str], lldp: list[tuple] = (),
               cdp: list[tuple] = (), lldp_port_ids: bool = True) -> dict:
    """ports: interface names (ifIndex = position + 1).
    lldp: (local ifIndex, remote chassis MAC, remote port id, remote sys name, remote sys descr, remote mgmt ip)
    cdp:  (local ifIndex, remote device id, remote port, platform, remote ip)"""
    mib = {
        oid("1.3.6.1.2.1.1.1.0"): (OCTETS, descr),
        oid("1.3.6.1.2.1.1.2.0"): (OBJECT_ID, oid("1.3.6.1.4.1.99999.1")),
        oid("1.3.6.1.2.1.1.3.0"): (TICKS, 86400 * 100 * 12),
        oid("1.3.6.1.2.1.1.5.0"): (OCTETS, name),
        oid("1.3.6.1.2.1.1.6.0"): (OCTETS, "Rack 1"),
        oid("1.3.6.1.2.1.4.20.1.1") + oid(ip): (IPADDR, ip),
        oid("1.0.8802.1.1.2.1.3.1.0"): (INTEGER, 4),
        oid("1.0.8802.1.1.2.1.3.2.0"): (OCTETS, mac_bytes(chassis)),
    }
    base = mac_bytes(chassis)
    cabled = {row[0] for row in (*lldp, *cdp)}
    for i, port in enumerate(ports, start=1):
        up = i == 1 or i in cabled
        mib[oid("1.3.6.1.2.1.2.2.1.2") + (i,)] = (OCTETS, port)
        mib[oid("1.3.6.1.2.1.2.2.1.6") + (i,)] = (OCTETS, base[:5] + bytes([(base[5] + i) % 256]))
        mib[oid("1.3.6.1.2.1.2.2.1.8") + (i,)] = (INTEGER, 1 if up else 2)
        mib[oid("1.3.6.1.2.1.31.1.1.1.1") + (i,)] = (OCTETS, port)
        mib[oid("1.3.6.1.2.1.31.1.1.1.6") + (i,)] = (COUNTER64, 9_000_000_000 * i)
        mib[oid("1.3.6.1.2.1.31.1.1.1.10") + (i,)] = (COUNTER64, 4_000_000_000 * i)
        mib[oid("1.3.6.1.2.1.31.1.1.1.15") + (i,)] = (GAUGE, 1000)
        mib[oid("1.3.6.1.2.1.31.1.1.1.18") + (i,)] = (OCTETS, "")
        if lldp_port_ids:
            mib[oid("1.0.8802.1.1.2.1.3.7.1.2") + (i,)] = (INTEGER, 5)
            mib[oid("1.0.8802.1.1.2.1.3.7.1.3") + (i,)] = (OCTETS, port)
            mib[oid("1.0.8802.1.1.2.1.3.7.1.4") + (i,)] = (OCTETS, port)
    for n, (ifindex, r_chassis, r_port, r_name, r_descr, r_ip) in enumerate(lldp, start=1):
        index = (0, ifindex, n)
        rem = oid("1.0.8802.1.1.2.1.4.1.1")
        mib[rem + (4,) + index] = (INTEGER, 4)
        mib[rem + (5,) + index] = (OCTETS, mac_bytes(r_chassis))
        mib[rem + (6,) + index] = (INTEGER, 5)
        mib[rem + (7,) + index] = (OCTETS, r_port)
        mib[rem + (8,) + index] = (OCTETS, r_port)
        mib[rem + (9,) + index] = (OCTETS, r_name)
        mib[rem + (10,) + index] = (OCTETS, r_descr)
        if r_ip:
            mib[oid("1.0.8802.1.1.2.1.4.2.1.3") + index + (1, 4) + oid(r_ip)] = (INTEGER, 2)
    for n, (ifindex, r_name, r_port, platform, r_ip) in enumerate(cdp, start=1):
        cache = oid("1.3.6.1.4.1.9.9.23.1.2.1.1")
        mib[cache + (4, ifindex, n)] = (OCTETS, bytes(int(p) for p in r_ip.split(".")))
        mib[cache + (6, ifindex, n)] = (OCTETS, r_name)
        mib[cache + (7, ifindex, n)] = (OCTETS, r_port)
        mib[cache + (8, ifindex, n)] = (OCTETS, platform)
    return mib


FW_MAC, PA_MAC, FG_MAC, SW_MAC, RTL_MAC, AP_MAC = (f"02:00:00:00:{n:02x}:00" for n in (1, 2, 3, 4, 5, 6))
SW_DESCR = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E"


def network(with_rogue: bool = False) -> dict[str, dict]:
    """Hostname -> MIB. Hostnames match the ones tools/simulate.py logs under.
    core-sw1 sits in the middle; rtl-sw2 and ap-lobby do not answer SNMP and are
    only known through what core-sw1 hears from them."""
    core_ports = [f"GigabitEthernet1/0/{i}" for i in range(1, 13)]
    core_lldp = [
        (1, FW_MAC, "igb1", "OPNsense.lan", "OPNsense 25.1 FreeBSD firewall", "192.168.1.1"),
        (2, PA_MAC, "ethernet1/2", "PA-440", "Palo Alto Networks PA-440 firewall", "192.168.1.2"),
        (3, FG_MAC, "internal1", "FGT-60F", "FortiGate-60F v7.4.4", "192.168.1.3"),
        (4, RTL_MAC, "1", "rtl-sw2", "RTL8372 switch", ""),
        (5, AP_MAC, "eth0", "ap-lobby", "UniFi U6 access point", "192.168.1.60"),
    ]
    if with_rogue:
        core_lldp.append((9, "02:00:00:00:99:00", "port1", "netgear-gs108", "Unmanaged-looking switch", ""))
    return {
        "OPNsense.lan": device_mib("OPNsense.lan", "OPNsense 25.1 FreeBSD 14.2 firewall", "192.168.1.1", FW_MAC,
                                   ["igb0", "igb1", "igb2"],
                                   lldp=[(2, SW_MAC, "Gi1/0/1", "core-sw1", SW_DESCR, "192.168.1.4")]),
        "PA-440": device_mib("PA-440", "Palo Alto Networks PA-400 series firewall", "192.168.1.2", PA_MAC,
                             ["ethernet1/1", "ethernet1/2", "ethernet1/3"],
                             lldp=[(2, SW_MAC, "Gi1/0/2", "core-sw1", SW_DESCR, "192.168.1.4")]),
        "FGT-60F": device_mib("FGT-60F", "FortiGate-60F v7.4.4,build2662", "192.168.1.3", FG_MAC,
                              ["wan1", "wan2", "internal1"],
                              lldp=[(3, SW_MAC, "Gi1/0/3", "core-sw1", SW_DESCR, "192.168.1.4")]),
        # The switch abbreviates its own LLDP port IDs but uses full names in IF-MIB, and
        # also hears the FortiGate over CDP - both have to merge into single links.
        "core-sw1": {
            **device_mib("core-sw1.lan", SW_DESCR, "192.168.1.4", SW_MAC, core_ports, lldp=core_lldp,
                         cdp=[(3, "FGT-60F", "internal1", "FortiGate-60F", "192.168.1.3")], lldp_port_ids=False),
            **{oid("1.0.8802.1.1.2.1.3.7.1.3") + (i,): (OCTETS, f"Gi1/0/{i}") for i in range(1, 13)},
            **{oid("1.0.8802.1.1.2.1.3.7.1.4") + (i,): (OCTETS, f"GigabitEthernet1/0/{i}") for i in range(1, 13)},
        },
    }


def campus(sites: int = 30, access: int = 8, endpoints: int = 6) -> dict[str, dict]:
    """A larger network, hostname -> MIB: two core switches, and per site a firewall
    and a distribution switch with `access` access switches under it. Every access
    switch also hears `endpoints` phones and access points that answer nothing
    themselves. Every cable between two agents is reported from both ends."""
    def mac(site: int, unit: int) -> str:
        return f"02:00:{site // 256:02x}:{site % 256:02x}:{unit:02x}:00"

    def ip(site: int, unit: int) -> str:
        return f"10.{site // 250}.{site % 250}.{unit}"

    def ports(n: int) -> list[str]:
        return [f"GigabitEthernet1/0/{i}" for i in range(1, n + 1)]

    core_lldp: dict[int, list] = {0: [], 1: []}
    out: dict[str, dict] = {}
    for site in range(1, sites + 1):
        core = site % 2
        core_port = len(core_lldp[core]) + 1
        fw, dist = f"s{site:03d}-fw", f"s{site:03d}-dist"
        core_lldp[core].append((core_port, mac(site, 2), "Gi1/0/1", dist, SW_DESCR, ip(site, 2)))
        dist_lldp = [
            (1, mac(0, core + 1), f"Gi1/0/{core_port}", f"core-{core + 1}", SW_DESCR, ip(0, core + 1)),
            (2, mac(site, 1), "internal1", fw, "FortiGate-60F v7.4.4", ip(site, 1)),
        ]
        for unit in range(access):
            name = f"s{site:03d}-acc{unit + 1}"
            dist_lldp.append((3 + unit, mac(site, 10 + unit), "Gi1/0/1", name, SW_DESCR, ip(site, 10 + unit)))
            heard = [(1, mac(site, 2), f"Gi1/0/{3 + unit}", dist, SW_DESCR, ip(site, 2))]
            for e in range(endpoints):
                kind = ("SEP phone", "Cisco IP Phone 8845") if e % 3 else ("ap", "UniFi U6 access point")
                heard.append((2 + e, f"06:{site // 256:02x}:{site % 256:02x}:{unit:02x}:{e:02x}:00", "eth0",
                              f"{kind[0].split()[0].lower()}-{site:03d}-{unit + 1}-{e + 1}", kind[1], ""))
            out[name] = device_mib(name, SW_DESCR, ip(site, 10 + unit), mac(site, 10 + unit), ports(2 + endpoints), lldp=heard)
        out[fw] = device_mib(fw, "FortiGate-60F v7.4.4,build2662", ip(site, 1), mac(site, 1), ["wan1", "wan2", "internal1"],
                             lldp=[(3, mac(site, 2), "Gi1/0/2", dist, SW_DESCR, ip(site, 2))])
        out[dist] = device_mib(dist, SW_DESCR, ip(site, 2), mac(site, 2), ports(2 + access), lldp=dist_lldp)
    for core in (0, 1):
        peer = (len(core_lldp[core]) + 1, mac(0, 2 - core), f"Gi1/0/{len(core_lldp[1 - core]) + 1}", f"core-{2 - core}", SW_DESCR, ip(0, 2 - core))
        out[f"core-{core + 1}"] = device_mib(f"core-{core + 1}", SW_DESCR, ip(0, core + 1), mac(0, core + 1),
                                             ports(len(core_lldp[core]) + 1), lldp=[*core_lldp[core], peer])
    return out


async def serve(mibs: dict[str, dict], host: str = "127.0.0.1", first_port: int = 16101) -> dict[str, tuple]:
    """Start one agent per device. Returns {name: (transport, agent, port)}; port 0 picks free ports."""
    loop = asyncio.get_running_loop()
    out = {}
    for offset, (name, mib) in enumerate(mibs.items()):
        port = first_port + offset if first_port else 0
        transport, agent = await loop.create_datagram_endpoint(lambda m=mib: FakeAgent(m), local_addr=(host, port))
        out[name] = (transport, agent, transport.get_extra_info("sockname")[1])
    return out


async def main() -> None:
    rogue = "--rogue" in sys.argv
    sites = int(sys.argv[sys.argv.index("--sites") + 1]) if "--sites" in sys.argv else 0
    agents = await serve(campus(sites) if sites else network(with_rogue=rogue))
    print('Fake SNMP agents (community "public"):')
    for name, (_, _, port) in agents.items():
        print(f"  {name:14s} 127.0.0.1:{port}")
    if not sites:
        print("rtl-sw2 and ap-lobby have no agent on purpose." + (" A rogue switch is attached to core-sw1." if rogue else ""))
    print("Ctrl+C to stop.")
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
