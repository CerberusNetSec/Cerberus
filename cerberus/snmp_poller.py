"""Polls log-source devices over SNMP for identity, interfaces and LLDP/CDP
neighbours - the raw material for the topology map - and raises an alert when
a device's neighbours change.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time

from .models import Candidate
from .snmp import SnmpClient, SnmpError, mac, number, oid, text

log = logging.getLogger("cerberus.snmp")

MASK = "********"
MAX_BACKOFF = 3600  # a device that keeps failing is retried at most this rarely
DEFAULTS = {
    "enabled": False,
    "community": "",
    "interval": 300,
    "concurrency": 16,  # devices polled at the same time
    "networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
}

SYSTEM = {
    "descr": oid("1.3.6.1.2.1.1.1.0"),
    "object_id": oid("1.3.6.1.2.1.1.2.0"),
    "uptime": oid("1.3.6.1.2.1.1.3.0"),
    "name": oid("1.3.6.1.2.1.1.5.0"),
    "location": oid("1.3.6.1.2.1.1.6.0"),
}
INTERFACES = {
    "descr": oid("1.3.6.1.2.1.2.2.1.2"),
    "mac": oid("1.3.6.1.2.1.2.2.1.6"),
    "oper": oid("1.3.6.1.2.1.2.2.1.8"),
    "name": oid("1.3.6.1.2.1.31.1.1.1.1"),
    "in_octets": oid("1.3.6.1.2.1.31.1.1.1.6"),
    "out_octets": oid("1.3.6.1.2.1.31.1.1.1.10"),
    "speed": oid("1.3.6.1.2.1.31.1.1.1.15"),
    "alias": oid("1.3.6.1.2.1.31.1.1.1.18"),
}
IP_ADDRESSES = oid("1.3.6.1.2.1.4.20.1.1")
LLDP_LOCAL = {
    "chassis_subtype": oid("1.0.8802.1.1.2.1.3.1.0"),
    "chassis_id": oid("1.0.8802.1.1.2.1.3.2.0"),
}
LLDP_LOCAL_PORTS = {
    "subtype": oid("1.0.8802.1.1.2.1.3.7.1.2"),
    "id": oid("1.0.8802.1.1.2.1.3.7.1.3"),
    "desc": oid("1.0.8802.1.1.2.1.3.7.1.4"),
}
LLDP_REMOTE = {
    "chassis_subtype": oid("1.0.8802.1.1.2.1.4.1.1.4"),
    "chassis_id": oid("1.0.8802.1.1.2.1.4.1.1.5"),
    "port_subtype": oid("1.0.8802.1.1.2.1.4.1.1.6"),
    "port_id": oid("1.0.8802.1.1.2.1.4.1.1.7"),
    "port_desc": oid("1.0.8802.1.1.2.1.4.1.1.8"),
    "sys_name": oid("1.0.8802.1.1.2.1.4.1.1.9"),
    "sys_desc": oid("1.0.8802.1.1.2.1.4.1.1.10"),
}
LLDP_REMOTE_ADDR = oid("1.0.8802.1.1.2.1.4.2.1.3")
CDP = {
    "address": oid("1.3.6.1.4.1.9.9.23.1.2.1.1.4"),
    "device_id": oid("1.3.6.1.4.1.9.9.23.1.2.1.1.6"),
    "port": oid("1.3.6.1.4.1.9.9.23.1.2.1.1.7"),
    "platform": oid("1.3.6.1.4.1.9.9.23.1.2.1.1.8"),
}
OPER = {1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "not present", 7: "lower layer down"}


def _lldp_id(subtype, value) -> str:
    """Chassis and port IDs are typed: MAC and network-address forms are binary."""
    if isinstance(value, bytes):
        if subtype in (3, 4) and len(value) == 6:  # port MAC / chassis MAC
            return value.hex(":")
        if subtype == 5 and len(value) == 5 and value[0] == 1:  # network address, IPv4
            return ".".join(str(b) for b in value[1:])
    return text(value)


def parse_target(value: str) -> tuple[str, int]:
    """'10.0.0.1' or '10.0.0.1:1161' -> (host, port). Raises ValueError."""
    host, _, port = value.strip().partition(":")
    ipaddress.IPv4Address(host)
    number_ = int(port) if port else 161
    if not 0 < number_ < 65536:
        raise ValueError("bad port")
    return host, number_


async def poll_device(client: SnmpClient, host: str, port: int, community: str, previous: dict | None) -> dict:
    """Collect everything we want from one device. Raises SnmpError on failure."""
    now = time.time()
    sysinfo = await client.get(host, port, community, list(SYSTEM.values()))
    system = {
        "descr": text(sysinfo.get(SYSTEM["descr"]))[:300],
        "object_id": text(sysinfo.get(SYSTEM["object_id"])),
        "uptime_seconds": (number(sysinfo.get(SYSTEM["uptime"])) or 0) // 100,
        "name": text(sysinfo.get(SYSTEM["name"]))[:120],
        "location": text(sysinfo.get(SYSTEM["location"]))[:120],
    }

    prev_ifaces = (previous or {}).get("interfaces", {})
    elapsed = now - (previous or {}).get("collected", 0)
    interfaces: dict[str, dict] = {}
    for index, row in (await client.table(host, port, community, INTERFACES)).items():
        if len(index) != 1:
            continue
        key = str(index[0])
        iface = {
            "name": text(row.get("name")) or text(row.get("descr")) or key,
            "descr": text(row.get("descr")),
            "alias": text(row.get("alias")),
            "oper": OPER.get(number(row.get("oper")) or 0, "unknown"),
            "speed_mbps": number(row.get("speed")) or 0,
            "mac": mac(row.get("mac")),
            "in_octets": number(row.get("in_octets")),
            "out_octets": number(row.get("out_octets")),
        }
        before = prev_ifaces.get(key)
        for direction in ("in", "out"):
            cur, old = iface[f"{direction}_octets"], (before or {}).get(f"{direction}_octets")
            if cur is not None and old is not None and cur >= old and 0 < elapsed < 3600:
                iface[f"{direction}_bps"] = int((cur - old) * 8 / elapsed)
        interfaces[key] = iface

    ips = [value for _, value in await client.walk(host, port, community, IP_ADDRESSES)
           if isinstance(value, str) and not value.startswith("127.")]

    local = await client.get(host, port, community, list(LLDP_LOCAL.values()))
    chassis = _lldp_id(number(local.get(LLDP_LOCAL["chassis_subtype"])), local.get(LLDP_LOCAL["chassis_id"]))
    local_ports = await client.table(host, port, community, LLDP_LOCAL_PORTS)
    by_name = {}
    for key, iface in interfaces.items():
        for label in (iface["name"], iface["descr"]):
            if label:
                by_name.setdefault(label.lower(), key)

    def local_port(port_num: int) -> tuple[str, list[str], str]:
        """(display name, every name this port is known by, ifIndex or '')."""
        row = local_ports.get((port_num,), {})
        names = [n for n in (_lldp_id(number(row.get("subtype")), row.get("id")), text(row.get("desc"))) if n]
        ifindex = next((by_name[n.lower()] for n in names if n.lower() in by_name), "")
        if not ifindex and str(port_num) in interfaces:
            ifindex = str(port_num)  # most agents number LLDP ports by ifIndex
        if ifindex:
            names += [interfaces[ifindex]["name"], interfaces[ifindex]["descr"]]
        names = list(dict.fromkeys(n for n in names if n))
        display = interfaces[ifindex]["name"] if ifindex else (names[0] if names else str(port_num))
        return display, names or [str(port_num)], ifindex

    neighbors = []
    remote_ips: dict[tuple, str] = {}
    for index, _ in await client.walk(host, port, community, LLDP_REMOTE_ADDR):
        # index: timeMark, localPort, remIndex, addrSubtype, [length,] address...
        rest = index[4:]
        if len(index) >= 8 and index[3] == 1:
            octets = rest[1:] if len(rest) == 5 and rest[0] == 4 else rest
            if len(octets) == 4:
                remote_ips.setdefault(index[1:3], ".".join(str(o) for o in octets))
    for index, row in (await client.table(host, port, community, LLDP_REMOTE)).items():
        if len(index) != 3:
            continue
        display, names, ifindex = local_port(index[1])
        neighbors.append({
            "proto": "lldp", "local_port": display, "local_names": names, "local_ifindex": ifindex,
            "chassis_id": _lldp_id(number(row.get("chassis_subtype")), row.get("chassis_id")),
            "port_id": _lldp_id(number(row.get("port_subtype")), row.get("port_id")),
            "port_desc": text(row.get("port_desc"))[:120],
            "sys_name": text(row.get("sys_name"))[:120],
            "sys_desc": text(row.get("sys_desc"))[:200],
            "mgmt_ip": remote_ips.get(index[1:3], ""),
        })
    for index, row in (await client.table(host, port, community, CDP)).items():
        if len(index) != 2:
            continue
        ifindex = str(index[0]) if str(index[0]) in interfaces else ""
        iface = interfaces.get(ifindex, {})
        address = row.get("address")
        neighbors.append({
            "proto": "cdp", "local_port": iface.get("name") or str(index[0]),
            "local_names": [n for n in (iface.get("name"), iface.get("descr")) if n] or [str(index[0])],
            "local_ifindex": ifindex, "chassis_id": "",
            "port_id": text(row.get("port"))[:120], "port_desc": "",
            "sys_name": text(row.get("device_id"))[:120], "sys_desc": text(row.get("platform"))[:200],
            "mgmt_ip": ".".join(str(b) for b in address) if isinstance(address, bytes) and len(address) == 4 else "",
        })
    # A link reported by both LLDP and CDP is one neighbour; keep the LLDP view.
    lldp_ports = {n["local_port"] for n in neighbors if n["proto"] == "lldp"}
    neighbors = [n for n in neighbors if n["proto"] == "lldp" or n["local_port"] not in lldp_ports]
    return {"collected": now, "system": system, "interfaces": interfaces, "ips": ips,
            "chassis_id": chassis, "neighbors": neighbors, "pending_lost": {}}


def neighbor_key(n: dict) -> str:
    return f"{n['local_port']}|{(n['chassis_id'] or n['sys_name'] or n['mgmt_ip']).lower()}"


def neighbor_label(n: dict) -> str:
    return n["sys_name"] or n["mgmt_ip"] or n["chassis_id"] or "unknown device"


def diff_neighbors(previous: dict, current: dict) -> tuple[list[dict], list[dict]]:
    """Compare two polls of one device. Returns (new, lost) neighbours and records
    in current['pending_lost'] those missing for the first time: a neighbour must
    be absent from two consecutive polls before it counts as lost."""
    before = {neighbor_key(n): n for n in previous.get("neighbors", [])}
    pending = previous.get("pending_lost", {})
    now = {neighbor_key(n): n for n in current["neighbors"]}
    new = [n for k, n in now.items() if k not in before and k not in pending]
    lost = [n for k, n in pending.items() if k not in now]
    current["pending_lost"] = {k: n for k, n in before.items() if k not in now}
    return new, lost


class SnmpPoller:
    def __init__(self, engine, db):
        self.engine = engine
        self.db = db
        self.client = SnmpClient()
        self.settings = dict(DEFAULTS)
        self._networks: list = []
        self.records: dict[str, dict] = {}  # device id -> {polled, ok, error, last_ok, data}
        self._busy: set[str] = set()
        self._slots = asyncio.Semaphore(DEFAULTS["concurrency"])
        self._wake = asyncio.Event()
        self._sweep: asyncio.Task | None = None

    # --- settings ----------------------------------------------------------
    def load(self) -> None:
        self.apply_settings(self.db.get_setting("snmp", {}), save=False)
        for row in self.db.q("SELECT * FROM snmp_data"):
            try:
                data = json.loads(row["data"]) if row["data"] else None
            except ValueError:
                data = None
            self.records[row["device"]] = {"polled": row["polled"], "ok": bool(row["ok"]), "error": row["error"] or "",
                                           "last_ok": row["last_ok"], "data": data, "fails": 0 if row["ok"] else 1}

    def apply_settings(self, given: dict, save: bool = True) -> list[str]:
        """Merge and validate settings. Returns the network entries that were rejected."""
        merged = {**self.settings, **{k: given[k] for k in DEFAULTS if k in given}}
        if merged["community"] == MASK:
            merged["community"] = self.settings["community"]
        merged["community"] = str(merged["community"]).strip()[:128]
        merged["enabled"] = bool(merged["enabled"])
        try:
            merged["interval"] = min(86400, max(60, int(merged["interval"])))
        except (TypeError, ValueError):
            merged["interval"] = DEFAULTS["interval"]
        try:
            merged["concurrency"] = min(64, max(1, int(merged["concurrency"])))
        except (TypeError, ValueError):
            merged["concurrency"] = DEFAULTS["concurrency"]
        if merged["concurrency"] != self.settings["concurrency"] or not save:
            self._slots = asyncio.Semaphore(merged["concurrency"])  # polls in flight finish on the old one
        nets, kept, rejected = [], [], []
        entries = merged["networks"] if isinstance(merged["networks"], list) else []
        for item in entries:
            try:
                nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
                kept.append(str(item).strip())
            except ValueError:
                rejected.append(str(item))
        merged["networks"] = kept
        self.settings, self._networks = merged, nets
        if save:
            self.db.set_setting("snmp", merged)
            self._wake.set()
        return rejected

    def public_settings(self) -> dict:
        return {**self.settings, "community": MASK if self.settings["community"] else ""}

    # --- targeting -----------------------------------------------------------
    def target(self, dev) -> tuple[tuple[str, int, str] | None, str]:
        """((host, port, community), '') if this device should be polled, else (None, why not)."""
        if not self.settings["enabled"]:
            return None, "SNMP polling is switched off"
        if dev.snmp_mode == "off":
            return None, "Polling disabled for this device"
        community = dev.snmp_community if dev.snmp_mode == "custom" and dev.snmp_community else self.settings["community"]
        if not community:
            return None, "No community string set"
        if dev.snmp_host:
            try:
                host, port = parse_target(dev.snmp_host)
            except ValueError:
                return None, "Invalid SNMP address"
            return (host, port, community), ""
        # Syslog source addresses can be forged, and the community string is sent
        # to them in clear text, so only poll addresses inside the allowed networks.
        try:
            addr = ipaddress.ip_address(dev.ip)
        except ValueError:
            return None, "Device has no usable IP address"
        if addr.version != 4:
            return None, "IPv6 polling is not supported"
        if not any(addr in net for net in self._networks if net.version == 4):
            return None, "Address is outside the allowed networks"
        return (dev.ip, 161, community), ""

    # --- polling -------------------------------------------------------------
    async def poll(self, dev) -> None:
        target, _reason = self.target(dev)
        if not target or dev.id in self._busy:
            return
        self._busy.add(dev.id)
        try:
            async with self._slots:
                record = self.records.get(dev.id) or {"last_ok": None, "data": None}
                previous = record.get("data")
                now = time.time()
                try:
                    data = await poll_device(self.client, *target, previous)
                except SnmpError as exc:
                    record.update(polled=now, ok=False, error=str(exc)[:200], fails=record.get("fails", 0) + 1)
                except Exception as exc:  # a malformed agent must not stop the poller
                    log.exception("SNMP poll of %s failed", dev.id)
                    record.update(polled=now, ok=False, error=f"{type(exc).__name__}: {exc}"[:200],
                                  fails=record.get("fails", 0) + 1)
                else:
                    if previous:
                        self._report_changes(dev, previous, data)
                    record.update(polled=now, ok=True, error="", last_ok=now, data=data, fails=0)
                self.records[dev.id] = record
                await self.db.ax(
                    "INSERT INTO snmp_data(device, polled, ok, error, last_ok, data) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(device) DO UPDATE SET polled=excluded.polled, ok=excluded.ok, error=excluded.error, "
                    "last_ok=excluded.last_ok, data=excluded.data",
                    (dev.id, record["polled"], int(record["ok"]), record["error"], record["last_ok"],
                     json.dumps(record["data"]) if record["data"] else None))
        finally:
            self._busy.discard(dev.id)

    def _report_changes(self, dev, previous: dict, data: dict) -> None:
        new, lost = diff_neighbors(previous, data)
        detector = self.engine.by_id.get("topology_change")
        if not detector or not detector.enabled:
            return
        host = dev.name or data["system"]["name"] or dev.hostname or dev.id
        now = time.time()
        if detector.cfg["new_neighbors"]:
            for n in new:
                self.engine.raise_alert(Candidate(
                    "topology_change", f"{dev.id}|new|{neighbor_key(n)}", "medium",
                    f"New neighbour on {host} {n['local_port']}: {neighbor_label(n)}"[:160],
                    f"{host} now sees {neighbor_label(n)} on port {n['local_port']} (via {n['proto'].upper()}"
                    + (f", remote port {n['port_id']}" if n["port_id"] else "")
                    + "). If nobody plugged that in on purpose, it may be an unauthorised device.",
                    n["mgmt_ip"] or None, dev.id,
                    {k: n[k] for k in ("sys_name", "sys_desc", "chassis_id", "port_id", "mgmt_ip") if n[k]},
                ), now)
        if detector.cfg["lost_neighbors"]:
            for n in lost:
                self.engine.raise_alert(Candidate(
                    "topology_change", f"{dev.id}|lost|{neighbor_key(n)}", "low",
                    f"Neighbour gone from {host} {n['local_port']}: {neighbor_label(n)}"[:160],
                    f"{host} no longer sees {neighbor_label(n)} on port {n['local_port']} "
                    "(missing from two consecutive SNMP polls).",
                    n["mgmt_ip"] or None, dev.id,
                    {k: n[k] for k in ("sys_name", "chassis_id", "port_id", "mgmt_ip") if n[k]},
                ), now)

    def wait_for(self, record: dict | None) -> float:
        """Seconds between polls of this device. Each consecutive failure doubles it (up
        to an hour), so devices that will never answer do not use up the polling slots."""
        interval = self.settings["interval"]
        fails = (record or {}).get("fails", 0)
        if fails < 2:
            return interval
        return max(interval, min(MAX_BACKOFF, interval * 2 ** min(fails - 1, 10)))

    def due(self, now: float) -> list:
        out = []
        for dev in list(self.engine.devices.values()):
            record = self.records.get(dev.id)
            if self.target(dev)[0] and (not record or now - (record.get("polled") or 0) >= self.wait_for(record)):
                out.append(dev)
        return out

    async def poll_all(self, devices=None) -> None:
        devices = self.due(time.time()) if devices is None else devices
        if devices:
            await asyncio.gather(*(self.poll(d) for d in devices), return_exceptions=True)

    def start_sweep(self) -> int:
        """Poll every pollable device now, in the background. Returns how many were queued
        (0 if a sweep is already running)."""
        if self._sweep and not self._sweep.done():
            return 0
        devices = [d for d in self.engine.devices.values() if self.target(d)[0]]
        self._sweep = asyncio.create_task(self.poll_all(devices))
        return len(devices)

    def progress(self) -> dict:
        return {"sweeping": bool(self._sweep and not self._sweep.done()), "in_flight": len(self._busy)}

    async def run(self) -> None:
        await asyncio.to_thread(self.load)
        while True:
            try:
                await self.poll_all()
            except Exception:
                log.exception("SNMP poll cycle failed")
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), 15)
            except asyncio.TimeoutError:
                pass

    def forget(self, device_id: str) -> None:
        self.records.pop(device_id, None)

    def status(self, dev) -> dict:
        """What the UI shows about one device's polling."""
        record = self.records.get(dev.id) or {}
        target, reason = self.target(dev)
        retry = None
        if target and record.get("polled") and not record.get("ok"):
            retry = record["polled"] + self.wait_for(record)
        return {"pollable": bool(target), "reason": reason, "polled": record.get("polled"),
                "ok": record.get("ok"), "error": record.get("error", ""), "last_ok": record.get("last_ok"),
                "next_try": retry}
