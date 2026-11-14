"""Builds the network map from what each device reports about its neighbours.

Every polled device contributes "on my port X I see device Y, its port Z".
Y is matched to a device we already know (by management IP, MAC or name) or
becomes a discovered node, and the two directions of one cable are merged into
a single link.
"""
from __future__ import annotations

import re

from .models import SEVERITIES

_ABBREVIATIONS = [
    ("hundredgigabitethernet", "hu"), ("hundredgige", "hu"), ("fortygigabitethernet", "fo"),
    ("twentyfivegige", "twe"), ("tengigabitethernet", "te"), ("gigabitethernet", "gi"),
    ("fastethernet", "fa"), ("port-channel", "po"), ("ethernet", "eth"),
]
_FIREWALL = re.compile(r"firewall|fortigate|fortios|pan-os|palo alto|opnsense|pfsense|sonicwall|asa\b", re.I)
_SWITCH = re.compile(r"switch|catalyst|\bios\b|nx-os|procurve|aruba|rtl83|bridge", re.I)
_AP = re.compile(r"access point|\bap\b|unifi|wireless|aironet", re.I)
_KIND_BY_CONNECTOR = {"opnsense": "firewall", "paloalto": "firewall", "fortinet": "firewall",
                      "cisco_ios": "switch", "rtl_playground": "switch"}


def norm_port(name: str) -> str:
    """Canonical form of a port name, so 'GigabitEthernet1/0/1' equals 'Gi1/0/1'."""
    s = name.strip().lower().replace(" ", "")
    for long, short in _ABBREVIATIONS:
        if s.startswith(long):
            return short + s[len(long):]
    return s


def _short(name: str) -> str:
    """Hostname without its domain, lowercased - unless it is an IP address."""
    name = name.strip().lower()
    return name if re.fullmatch(r"[\d.]+", name) else name.split(".")[0]


def guess_kind(description: str, connector: str = "") -> str:
    if connector in _KIND_BY_CONNECTOR:
        return _KIND_BY_CONNECTOR[connector]
    if _FIREWALL.search(description):
        return "firewall"
    if _AP.search(description):
        return "ap"
    if _SWITCH.search(description):
        return "switch"
    return "device"


def build_topology(devices: list[dict], records: dict[str, dict], alerts: dict[str, dict] | None = None) -> dict:
    """devices: Device.as_dict() rows; records: SnmpPoller.records;
    alerts: device id -> {severity: open count}."""
    alerts = alerts or {}
    nodes: dict[str, dict] = {}
    by_ip: dict[str, str] = {}
    by_mac: dict[str, str] = {}
    by_name: dict[str, str] = {}

    for dev in devices:
        node_id = "dev:" + dev["id"]
        record = records.get(dev["id"]) or {}
        data = record.get("data") or {}
        system = data.get("system", {})
        counts = alerts.get(dev["id"], {})
        worst = next((s for s in reversed(SEVERITIES) if counts.get(s)), "")
        nodes[node_id] = {
            "id": node_id, "device": dev["id"], "managed": True,
            "label": dev.get("name") or system.get("name") or dev.get("hostname") or dev["id"],
            "ip": dev.get("ip", ""),
            "kind": guess_kind(system.get("descr", ""), dev.get("connector_pin") or dev.get("connector_seen", "")),
            "descr": system.get("descr", ""),
            "snmp": "ok" if record.get("ok") else ("error" if record.get("polled") else "none"),
            "alerts": sum(counts.values()), "severity": worst,
        }
        for ip in [dev.get("ip", ""), *data.get("ips", [])]:
            if ip:
                by_ip.setdefault(ip, node_id)
        for value in [data.get("chassis_id", ""), *(i.get("mac", "") for i in data.get("interfaces", {}).values())]:
            if value:
                by_mac.setdefault(value.lower(), node_id)
        for name in (dev["id"], dev.get("hostname", ""), dev.get("name", ""), system.get("name", "")):
            if name:
                by_name.setdefault(_short(name), node_id)

    def resolve(n: dict) -> str:
        """Find or create the node a neighbour entry refers to."""
        found = (by_ip.get(n["mgmt_ip"]) or by_mac.get(n["chassis_id"].lower())
                 or (by_name.get(_short(n["sys_name"])) if n["sys_name"] else None))
        if found:
            return found
        key = (n["chassis_id"] or n["sys_name"] or n["mgmt_ip"] or "unknown").lower()
        node_id = "nbr:" + key
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id, "device": "", "managed": False,
                "label": n["sys_name"] or n["mgmt_ip"] or n["chassis_id"] or "Unknown device",
                "ip": n["mgmt_ip"], "kind": guess_kind(n["sys_desc"]), "descr": n["sys_desc"],
                "snmp": "none", "alerts": 0, "severity": "",
            }
        # Later sightings of the same neighbour resolve to the same node.
        for table, value in ((by_ip, n["mgmt_ip"]), (by_mac, n["chassis_id"].lower()), (by_name, _short(n["sys_name"]))):
            if value:
                table.setdefault(value, node_id)
        return node_id

    links: list[dict] = []
    between: dict[tuple, list[dict]] = {}  # (node, node) -> links between that pair

    def add_link(a: str, a_names: list[str], a_port: str, b: str, b_names: list[str], b_port: str, info: dict) -> None:
        a_set, b_set = {norm_port(x) for x in a_names if x}, {norm_port(x) for x in b_names if x}
        pair = between.setdefault((a, b) if a < b else (b, a), [])
        for link in pair:
            # The same cable seen from the other end (or by a second protocol).
            same = link["a"] == a and link["b"] == b and (link["_a"] & a_set or link["_b"] & b_set)
            flipped = link["a"] == b and link["b"] == a and (link["_a"] & b_set or link["_b"] & a_set)
            if same or flipped:
                mine, theirs = ("a", "b") if same else ("b", "a")
                link["_" + mine] |= a_set
                link["_" + theirs] |= b_set
                link[mine + "_port"] = a_port or link[mine + "_port"]  # a device knows its own port best
                link[theirs + "_port"] = link[theirs + "_port"] or b_port
                for key, value in info.items():
                    if value and not link.get(key):
                        link[key] = value
                if info["proto"] not in link["proto"]:
                    link["proto"] = "+".join(sorted({*link["proto"].split("+"), info["proto"]}))
                return
        link = {"a": a, "b": b, "a_port": a_port, "b_port": b_port, "_a": a_set, "_b": b_set, **info}
        links.append(link)
        pair.append(link)

    for dev in devices:
        data = (records.get(dev["id"]) or {}).get("data") or {}
        interfaces = data.get("interfaces", {})
        for n in data.get("neighbors", []):
            other = resolve(n)
            me = "dev:" + dev["id"]
            if other == me:
                continue
            iface = interfaces.get(n.get("local_ifindex", ""), {})
            info = {"proto": n["proto"], "speed_mbps": iface.get("speed_mbps", 0), "oper": iface.get("oper", ""),
                    "in_bps": iface.get("in_bps"), "out_bps": iface.get("out_bps")}
            add_link(me, n.get("local_names") or [n["local_port"]], n["local_port"],
                     other, [n["port_id"], n["port_desc"]], n["port_id"] or n["port_desc"], info)

    for link in links:
        del link["_a"], link["_b"]
    degree: dict[str, int] = {}
    for link in links:
        degree[link["a"]] = degree.get(link["a"], 0) + 1
        degree[link["b"]] = degree.get(link["b"], 0) + 1
    for node in nodes.values():
        node["linked"] = node["id"] in degree
        node["links"] = degree.get(node["id"], 0)
    return {"nodes": list(nodes.values()), "links": links}
