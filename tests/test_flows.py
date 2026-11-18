"""NetFlow v5, v9 and IPFIX decoding, and flow records through the connector to events."""
import asyncio
import ipaddress
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.flows import FlowDecoder, FlowReceiver, flow_message  # noqa: E402
from cerberus.syslog_parser import parse_syslog  # noqa: E402

REG = ConnectorRegistry()
EXPORTER = "10.0.0.1"


def ip4(text: str) -> bytes:
    return ipaddress.IPv4Address(text).packed


def v5(*records) -> bytes:
    header = struct.pack("!HHIIIIBBH", 5, len(records), 1000, 1763114400, 0, 1, 0, 0, 0)
    body = b"".join(
        struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", ip4(src), ip4(dst), ip4("0.0.0.0"), 1, 2, packets, octets, 100, 900,
                    sport, dport, 0, 0x12, proto, 0, 0, 0, 24, 24, 0)
        for src, dst, sport, dport, proto, packets, octets in records)
    return header + body


def v9(*flowsets, domain=7) -> bytes:
    return struct.pack("!HHIIII", 9, len(flowsets), 1000, 1763114400, 1, domain) + b"".join(flowsets)


def ipfix(*sets, domain=7) -> bytes:
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, 16 + len(body), 1763114400, 1, domain) + body


def flowset(set_id: int, body: bytes) -> bytes:
    return struct.pack("!HH", set_id, 4 + len(body)) + body


def template(template_id: int, fields, enterprise=()) -> bytes:
    out = struct.pack("!HH", template_id, len(fields) + len(enterprise))
    out += b"".join(struct.pack("!HH", f, n) for f, n in fields)
    out += b"".join(struct.pack("!HHI", f | 0x8000, n, pen) for f, n, pen in enterprise)
    return out


V4_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (10, 2), (14, 2)]


def v4_record(src, dst, sport, dport, proto, octets, packets=10) -> bytes:
    return ip4(src) + ip4(dst) + struct.pack("!HHBIIHH", sport, dport, proto, octets, packets, 3, 4)


def test_v5():
    records = FlowDecoder().decode(v5(("10.0.0.5", "93.184.216.34", 50000, 443, 6, 10, 1500),
                                      ("10.0.0.5", "8.8.8.8", 0, 2048, 1, 1, 84)), EXPORTER)
    assert records[0] == {"version": 5, "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34", "proto": "tcp",
                          "src_port": 50000, "dst_port": 443, "bytes": 1500, "packets": 10, "in_if": 1, "out_if": 2,
                          "tcp_flags": 0x12, "duration_ms": 800, "action": "allow"}
    assert records[1]["proto"] == "icmp" and "dst_port" not in records[1]  # ICMP type/code is not a port


def test_v9_template_then_data_and_data_before_template():
    decoder = FlowDecoder()
    data = flowset(256, v4_record("10.0.0.5", "10.0.0.6", 51515, 445, 6, 900) + b"\0\0")  # padded
    assert decoder.decode(v9(data), EXPORTER) == []
    assert decoder.no_template == 1
    records = decoder.decode(v9(flowset(0, template(256, V4_FIELDS)), data), EXPORTER)
    assert len(records) == 1
    assert records[0]["dst_port"] == 445 and records[0]["bytes"] == 900 and records[0]["in_if"] == 3
    # Templates are per exporter and domain.
    assert decoder.decode(v9(data), "10.0.0.2") == [] and decoder.decode(v9(data, domain=8), EXPORTER) == []


def test_v9_nsel_firewall_events():
    """Cisco ASA NSEL: 40005 is the firewall event; 231/232 the bytes each way."""
    decoder = FlowDecoder()
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (40005, 1), (231, 4), (232, 4)]

    def rec(event, dport):
        return ip4("203.0.113.5") + ip4("10.0.0.5") + struct.pack("!HHBBII", 51515, dport, 6, event, 0, 0)

    records = decoder.decode(v9(flowset(0, template(260, fields))), EXPORTER)
    assert records == []
    records = decoder.decode(v9(flowset(260, rec(3, 22) + rec(1, 443))), EXPORTER)
    assert [(r["fw_event"], r["action"], r["dst_port"]) for r in records] == [("denied", "block", 22),
                                                                            ("created", "allow", 443)]


def test_ipfix_variable_length_enterprise_options_and_ipv6():
    decoder = FlowDecoder()
    fields = [(27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (1, 8), (89, 1), (82, 0xFFFF)]
    templates = flowset(2, template(300, fields, enterprise=[(1, 4, 9)]))
    options = flowset(3, struct.pack("!HHH", 301, 2, 1) + struct.pack("!HHHH", 149, 4, 34, 4))
    src, dst = ipaddress.IPv6Address("2001:db8::5").packed, ipaddress.IPv6Address("2001:db8::10").packed
    name = b"eth0"
    rec1 = src + dst + struct.pack("!HHBQB", 51515, 22, 6, 1200, 0x40) + bytes([len(name)]) + name + b"\0\0\0\0"
    rec2 = src + dst + struct.pack("!HHBQB", 51516, 23, 6, 60, 0x80) + bytes([0]) + b"\0\0\0\0"  # dropped
    option_data = flowset(301, struct.pack("!II", 1, 100))
    records = decoder.decode(ipfix(templates, options, flowset(300, rec1 + rec2), option_data), EXPORTER)
    assert [(r["src_ip"], r["dst_port"], r["bytes"], r["action"]) for r in records] == [
        ("2001:db8::5", 22, 1200, "allow"), ("2001:db8::5", 23, 60, "block")]
    assert decoder.templates[(EXPORTER, 10, 7, 301)] is None  # options: remembered, not read as flows


def test_garbage_is_rejected_not_raised():
    decoder = FlowDecoder()
    for data in (b"", b"\x00\x05", b"\x00\x07garbage", b"\x00\x09" + b"\xff" * 30, b"\x00\x0a\x00\x10" + b"\xff" * 40):
        try:
            decoder.decode(data, EXPORTER)
        except (ValueError, struct.error, IndexError):
            pass


def test_template_cache_is_bounded():
    decoder = FlowDecoder(max_templates=3)
    for template_id in range(256, 266):
        decoder.decode(v9(flowset(0, template(template_id, V4_FIELDS))), EXPORTER)
    assert len(decoder.templates) == 3


def build(record: dict):
    parsed = parse_syslog(flow_message(record))
    return REG.build_event(parsed, 1000.0, EXPORTER, EXPORTER)


def test_flow_records_become_traffic_events():
    record = FlowDecoder().decode(v5(("10.0.0.5", "93.184.216.34", 50000, 443, 6, 10, 1500)), EXPORTER)[0]
    ev = build(record)
    assert (ev.connector, ev.event_type, ev.action, ev.src_ip, ev.dst_ip, ev.dst_port, ev.proto, ev.bytes,
            ev.interface) == ("netflow", "traffic", "allow", "10.0.0.5", "93.184.216.34", 443, "tcp", 1500, "1")
    assert ev.extra["out_interface"] == "2"
    ev = build({**record, "fw_event": "denied", "action": "block"})
    assert (ev.event_type, ev.action) == ("traffic", "block")
    ev = build({**record, "fw_event": "deleted"})
    assert ev.event_type == "session_end"


def test_receiver_end_to_end():
    async def run():
        got = []
        receiver = FlowReceiver(lambda data, ip: got.append((data, ip)), "127.0.0.1", 0)
        receiver.port = _free_udp_port()
        await receiver.start()
        assert receiver.status()["listening"]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(v5(("10.0.0.5", "10.0.0.6", 51515, 22, 6, 1, 60)), ("127.0.0.1", receiver.port))
        sock.sendto(b"not a flow", ("127.0.0.1", receiver.port))
        for _ in range(100):
            if got and receiver.errors:
                break
            await asyncio.sleep(0.02)
        sock.close()
        await receiver.stop()
        return got, receiver.status()

    got, status = asyncio.run(run())
    assert len(got) == 1 and got[0][1] == "127.0.0.1"
    assert build_from_bytes(got[0][0]).dst_port == 22
    assert (status["flows"], status["unreadable"], status["datagrams"]) == (1, 1, 2)


def build_from_bytes(data: bytes):
    return REG.build_event(parse_syslog(data), 1000.0, EXPORTER, EXPORTER)


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
