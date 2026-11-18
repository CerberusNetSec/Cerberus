"""NetFlow v5, NetFlow v9 and IPFIX over UDP.

Routers, switches and firewalls that export flows describe every connection
they forward, allowed or not, without logging a line per firewall rule. Each
flow record becomes one message, handed to the same submit() as syslog:

    <14>1 - - netflow - - - {"src_ip": "10.0.0.5", "dst_ip": ..., "bytes": 1500, ...}

so the netflow connector, the detectors and storage treat it like any other
event, in a single instance and through collectors alike. The exporter's
address is the device.

v9 and IPFIX describe their records with templates, sent every so often. They
are kept per exporter and observation domain; records that arrive before their
template are counted and dropped, as every collector does. Behind a load
balancer, keep each exporter on one collector (hash on the source address).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import struct

log = logging.getLogger("cerberus.flows")

MAX_TEMPLATES = 10_000
MAX_FIELDS = 256

PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 132: "sctp"}
# Cisco NSEL / IPFIX firewallEvent: what the firewall did with the connection.
FW_EVENTS = {0: "", 1: "created", 2: "deleted", 3: "denied", 4: "alert", 5: "update"}

# Information elements (IPFIX numbering; NetFlow v9 uses the same numbers below 128).
_FIELDS = {
    1: "bytes", 2: "packets", 4: "proto", 6: "tcp_flags", 7: "src_port", 8: "src_ip", 10: "in_if", 11: "dst_port",
    12: "dst_ip", 14: "out_if", 21: "last_ms", 22: "first_ms", 27: "src_ip", 28: "dst_ip", 61: "direction",
    85: "bytes_total", 86: "packets_total", 89: "forwarding_status", 150: "start_s", 151: "end_s",
    152: "start_ms", 153: "end_ms", 231: "initiator_bytes", 232: "responder_bytes", 233: "fw_event",
    40005: "fw_event",  # NetFlow v9 NSEL (Cisco ASA)
}
_ADDRESSES = {8, 12, 27, 28}


def _uint(data: bytes) -> int:
    return int.from_bytes(data, "big") if data else 0


def _address(data: bytes) -> str:
    if len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if len(data) == 16:
        address = ipaddress.IPv6Address(data)
        return str(address.ipv4_mapped or address)
    return ""


def _finish(raw: dict, version: int) -> dict | None:
    """Raw field values to the message's fields; None for a record with no addresses."""
    if not raw.get("src_ip") or not raw.get("dst_ip"):
        return None
    out: dict = {"version": version, "src_ip": raw["src_ip"], "dst_ip": raw["dst_ip"]}
    proto = raw.get("proto")
    if proto is not None:
        out["proto"] = PROTOCOLS.get(proto, str(proto))
    for key in ("src_port", "dst_port"):
        if key in raw and out.get("proto") in ("tcp", "udp", "sctp"):
            out[key] = raw[key]
    sent = raw.get("initiator_bytes") or raw.get("bytes") or raw.get("bytes_total")
    if sent:
        out["bytes"] = sent
    if raw.get("responder_bytes"):
        out["bytes_received"] = raw["responder_bytes"]
    packets = raw.get("packets") or raw.get("packets_total")
    if packets:
        out["packets"] = packets
    for key in ("in_if", "out_if", "tcp_flags"):
        if raw.get(key):
            out[key] = raw[key]
    if "last_ms" in raw and "first_ms" in raw and raw["last_ms"] >= raw["first_ms"]:
        out["duration_ms"] = raw["last_ms"] - raw["first_ms"]
    elif "end_ms" in raw and "start_ms" in raw and raw["end_ms"] >= raw["start_ms"]:
        out["duration_ms"] = raw["end_ms"] - raw["start_ms"]
    elif "end_s" in raw and "start_s" in raw and raw["end_s"] >= raw["start_s"]:
        out["duration_ms"] = (raw["end_s"] - raw["start_s"]) * 1000
    event = FW_EVENTS.get(raw.get("fw_event", 0), "")
    if event:
        out["fw_event"] = event
    dropped = raw.get("forwarding_status", 0) >> 6 == 2  # IPFIX: 0b10xxxxxx is "dropped"
    out["action"] = "block" if event == "denied" or dropped else "allow"
    return out


class FlowDecoder:
    def __init__(self, max_templates: int = MAX_TEMPLATES):
        self.max_templates = max_templates
        # (exporter, version, domain, template id) -> [(field id, length)], or None for an options template
        self.templates: dict[tuple, list | None] = {}
        self.no_template = 0  # records that arrived before their template

    def decode(self, data: bytes, exporter: str) -> list[dict]:
        """Flow records in one datagram. Raises ValueError for one that is not NetFlow or IPFIX."""
        if len(data) < 4:
            raise ValueError("too short")
        version = struct.unpack_from("!H", data)[0]
        if version == 5:
            return self._v5(data)
        if version == 9:
            return self._v9(data, exporter)
        if version == 10:
            return self._ipfix(data, exporter)
        raise ValueError(f"version {version}")

    # --- NetFlow v5: fixed 48-byte records -------------------------------
    def _v5(self, data: bytes) -> list[dict]:
        count = struct.unpack_from("!H", data, 2)[0]
        out = []
        for i in range(min(count, 30)):
            offset = 24 + i * 48
            if offset + 48 > len(data):
                break
            (src, dst, _hop, in_if, out_if, packets, octets, first, last, sport, dport, _pad, flags, proto,
             _tos) = struct.unpack_from("!4s4s4sHHIIIIHHBBBB", data, offset)
            record = _finish({"src_ip": _address(src), "dst_ip": _address(dst), "in_if": in_if, "out_if": out_if,
                              "packets": packets, "bytes": octets, "first_ms": first, "last_ms": last,
                              "src_port": sport, "dst_port": dport, "tcp_flags": flags, "proto": proto}, 5)
            if record:
                out.append(record)
        return out

    # --- templates --------------------------------------------------------
    def _remember(self, key: tuple, fields: list | None) -> None:
        if key not in self.templates and len(self.templates) >= self.max_templates:
            self.templates.pop(next(iter(self.templates)))
        self.templates[key] = fields

    def _records(self, body: bytes, fields: list, version: int) -> list[dict]:
        out = []
        fixed = all(length != 0xFFFF for _, length in fields)
        min_length = sum(length for _, length in fields) if fixed else 1
        pos = 0
        while len(body) - pos >= max(min_length, 1):
            raw: dict = {}
            for field_id, length in fields:
                if length == 0xFFFF:  # IPFIX variable length
                    if pos >= len(body):
                        return out
                    length = body[pos]
                    pos += 1
                    if length == 255:
                        if pos + 2 > len(body):
                            return out
                        length = struct.unpack_from("!H", body, pos)[0]
                        pos += 2
                if pos + length > len(body):
                    return out
                value = body[pos:pos + length]
                pos += length
                name = _FIELDS.get(field_id)
                if name is None:
                    continue
                raw[name] = _address(value) if field_id in _ADDRESSES else _uint(value)
            record = _finish(raw, version)
            if record:
                out.append(record)
            if not fixed and pos >= len(body):
                break
        return out

    # --- NetFlow v9 -------------------------------------------------------
    def _v9(self, data: bytes, exporter: str) -> list[dict]:
        domain = struct.unpack_from("!I", data, 16)[0]
        return self._sets(data, 20, exporter, 9, domain)

    # --- IPFIX ------------------------------------------------------------
    def _ipfix(self, data: bytes, exporter: str) -> list[dict]:
        length, _export_time, _sequence, domain = struct.unpack_from("!HIII", data, 2)
        return self._sets(data[:length] if 16 <= length <= len(data) else data, 16, exporter, 10, domain)

    def _sets(self, data: bytes, pos: int, exporter: str, version: int, domain: int) -> list[dict]:
        template_set, options_set = (0, 1) if version == 9 else (2, 3)
        out = []
        while pos + 4 <= len(data):
            set_id, set_length = struct.unpack_from("!HH", data, pos)
            if set_length < 4 or pos + set_length > len(data):
                break
            body = data[pos + 4:pos + set_length]
            pos += set_length
            if set_id == template_set:
                self._read_templates(body, exporter, version, domain, options=False)
            elif set_id == options_set:
                self._read_templates(body, exporter, version, domain, options=True)
            elif set_id >= 256:
                key = (exporter, version, domain, set_id)
                if key not in self.templates:
                    self.no_template += 1
                    continue
                fields = self.templates[key]
                if fields:  # None: an options template (sampling rates and the like), not flows
                    out.extend(self._records(body, fields, version))
        return out

    def _read_templates(self, body: bytes, exporter: str, version: int, domain: int, options: bool) -> None:
        pos = 0
        while pos + 4 <= len(body):
            template_id, count = struct.unpack_from("!HH", body, pos)
            pos += 4
            if template_id < 256:
                return  # padding
            if options:
                if version == 9:  # scope length and option length, in bytes of field specifiers
                    scope_length = count
                    if pos + 2 > len(body):
                        return
                    option_length = struct.unpack_from("!H", body, pos)[0]
                    pos += 2
                    count = (scope_length + option_length) // 4
                else:
                    pos += 2  # scope field count; the scopes are among the `count` fields
            if count > MAX_FIELDS:
                return
            fields = []
            for _ in range(count):
                if pos + 4 > len(body):
                    return
                field_id, length = struct.unpack_from("!HH", body, pos)
                pos += 4
                if version == 10 and field_id & 0x8000:
                    pos += 4  # enterprise number: not an element we read
                    field_id = 0
                fields.append((field_id, length))
            self._remember((exporter, version, domain, template_id), None if options else fields)


def flow_message(record: dict) -> bytes:
    # RFC 5424: version, time, host, app, process id, message id, structured data, message.
    return b"<14>1 - - netflow - - - " + json.dumps(record, separators=(",", ":")).encode()


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: "FlowReceiver"):
        self.receiver = receiver

    def datagram_received(self, data: bytes, addr) -> None:
        self.receiver.received(data, addr[0][7:] if addr[0].startswith("::ffff:") else addr[0])

    def error_received(self, exc) -> None:
        pass


class FlowReceiver:
    """A UDP listener for NetFlow v5/v9 and IPFIX; each flow record goes to submit()."""

    def __init__(self, submit, bind: str, port: int):
        self.submit = submit
        self.bind = bind
        self.port = port
        self.decoder = FlowDecoder()
        self.flows = 0
        self.datagrams = 0
        self.errors = 0
        self.error = ""
        self._transport = None

    def received(self, data: bytes, exporter: str) -> None:
        self.datagrams += 1
        try:
            records = self.decoder.decode(data, exporter)
        except (ValueError, struct.error, IndexError) as exc:
            self.errors += 1
            if self.errors == 1 or self.errors % 1000 == 0:
                log.warning("unreadable flow datagram from %s (%s); %d so far", exporter, exc, self.errors)
            return
        for record in records:
            self.flows += 1
            self.submit(flow_message(record), exporter)

    async def start(self) -> None:
        if not self.port:
            return
        try:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _Protocol(self), local_addr=(self.bind, self.port))
        except OSError as exc:
            self.error = str(exc.strerror or exc)
            log.error("flow listener on UDP port %d could not start: %s", self.port, self.error)
            return
        sock = transport.get_extra_info("socket")
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        self._transport = transport
        log.info("NetFlow/IPFIX listening on %s:%d (UDP)", self.bind, self.port)

    def status(self) -> dict:
        return {"port": self.port, "listening": self._transport is not None, "error": self.error,
                "datagrams": self.datagrams, "flows": self.flows, "unreadable": self.errors,
                "before_template": self.decoder.no_template}

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
