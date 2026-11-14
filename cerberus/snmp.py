"""A small asyncio SNMP v2c client: GET and GETBULK table walks.

Just enough BER to read the handful of standard MIB tables the topology
feature needs, with no third-party dependency. SNMPv3 is not implemented.
"""
from __future__ import annotations

import asyncio
import ipaddress
import secrets

Oid = tuple[int, ...]

GET, GETNEXT, RESPONSE, GETBULK = 0xA0, 0xA1, 0xA2, 0xA5
_UNSIGNED = (0x41, 0x42, 0x43, 0x46, 0x47)  # Counter32, Gauge32, TimeTicks, Counter64, Unsigned32
_ERRORS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess", 16: "authorizationError"}


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


class _End:
    """endOfMibView marker."""

    def __repr__(self) -> str:
        return "END"


END = _End()


def oid(text: str) -> Oid:
    return tuple(int(part) for part in text.strip(".").split("."))


# --- BER encoding ---------------------------------------------------------------
def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _length(len(payload)) + payload


def _int(value: int) -> bytes:
    return _tlv(0x02, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


def _oid(value: Oid) -> bytes:
    if len(value) < 2:
        raise SnmpError("OID too short")
    out = bytearray([value[0] * 40 + value[1]])
    for arc in value[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def encode_request(pdu: int, request_id: int, community: str, oids: list[Oid], a: int = 0, b: int = 0) -> bytes:
    """Build a v2c message. For GETBULK, a = non-repeaters and b = max-repetitions."""
    varbinds = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    body = _int(request_id) + _int(a) + _int(b) + _tlv(0x30, varbinds)
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + _tlv(pdu, body))


# --- BER decoding ---------------------------------------------------------------
def _read(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, start, end) of the TLV at pos."""
    if pos + 2 > len(buf):
        raise SnmpError("truncated message")
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if not 0 < count <= 4 or pos + count > len(buf):
            raise SnmpError("bad length")
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    if pos + length > len(buf):
        raise SnmpError("truncated message")
    return tag, pos, pos + length


def _decode_oid(data: bytes) -> Oid:
    if not data:
        raise SnmpError("empty OID")
    first = min(data[0] // 40, 2)
    arcs = [first, data[0] - 40 * first]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return tuple(arcs)


def _value(tag: int, data: bytes):
    if tag == 0x02:
        return int.from_bytes(data, "big", signed=True)
    if tag in _UNSIGNED:
        return int.from_bytes(data, "big")
    if tag == 0x04 or tag == 0x44:
        return bytes(data)
    if tag == 0x06:
        return _decode_oid(data)
    if tag == 0x40:
        return ".".join(str(b) for b in data) if len(data) == 4 else bytes(data)
    if tag == 0x82:
        return END
    return None  # NULL, noSuchObject, noSuchInstance, anything unknown


def decode_message(buf: bytes) -> dict:
    """Parse any v1/v2c message into dict(version, community, pdu, request_id, a, b, varbinds)."""
    tag, pos, end = _read(buf, 0)
    if tag != 0x30:
        raise SnmpError("not an SNMP message")
    _, s, e = _read(buf, pos)
    version = int.from_bytes(buf[s:e], "big")
    _, s, e2 = _read(buf, e)
    community = bytes(buf[s:e2])
    pdu, pos, end = _read(buf, e2)
    numbers = []
    for _ in range(3):
        _, s, e = _read(buf, pos)
        numbers.append(int.from_bytes(buf[s:e], "big", signed=True))
        pos = e
    _, pos, end = _read(buf, pos)
    varbinds = []
    while pos < end:
        _, s, e = _read(buf, pos)
        _, os_, oe = _read(buf, s)
        vtag, vs, ve = _read(buf, oe)
        varbinds.append((_decode_oid(buf[os_:oe]), _value(vtag, buf[vs:ve])))
        pos = e
    return {"version": version, "community": community, "pdu": pdu, "request_id": numbers[0],
            "a": numbers[1], "b": numbers[2], "varbinds": varbinds}


# --- value helpers --------------------------------------------------------------
def text(value) -> str:
    """Render an OCTET STRING (or anything else) for display."""
    if value is None or value is END:
        return ""
    if isinstance(value, bytes):
        raw = value.rstrip(b"\x00")
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex(":")
        return decoded.strip() if decoded.isprintable() else raw.hex(":")
    if isinstance(value, tuple):
        return ".".join(str(v) for v in value)
    return str(value)


def mac(value) -> str:
    if isinstance(value, bytes) and len(value) == 6 and any(value):
        return value.hex(":")
    return ""


def number(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# --- client -----------------------------------------------------------------------
class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, pending: dict):
        self.pending = pending

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            msg = decode_message(data)
        except (SnmpError, IndexError, ValueError):
            return
        waiter = self.pending.get(msg["request_id"])
        # Only the device we asked may answer, and only with a response PDU.
        if waiter and msg["pdu"] == RESPONSE and addr[:2] == waiter[1] and not waiter[0].done():
            waiter[0].set_result(msg)

    def error_received(self, exc) -> None:
        pass


class SnmpClient:
    def __init__(self, timeout: float = 2.0, retries: int = 2):
        self.timeout = timeout
        self.retries = retries
        self._pending: dict[int, tuple[asyncio.Future, tuple]] = {}
        self._transport = None

    async def start(self) -> None:
        if self._transport is None:
            loop = asyncio.get_running_loop()
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: _Protocol(self._pending), local_addr=("0.0.0.0", 0))

    def close(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None

    async def _request(self, host: str, port: int, community: str, pdu: int, oids: list[Oid],
                       a: int = 0, b: int = 0) -> list[tuple[Oid, object]]:
        await self.start()
        try:
            if ipaddress.ip_address(host).version != 4:
                raise SnmpError("only IPv4 targets are supported")
        except ValueError:
            raise SnmpError(f"'{host}' is not an IP address") from None
        loop = asyncio.get_running_loop()
        for _attempt in range(self.retries + 1):
            request_id = secrets.randbelow(2**31 - 2) + 1
            future: asyncio.Future = loop.create_future()
            self._pending[request_id] = (future, (host, port))
            try:
                self._transport.sendto(encode_request(pdu, request_id, community, oids, a, b), (host, port))
                msg = await asyncio.wait_for(future, self.timeout)
            except asyncio.TimeoutError:
                continue
            except OSError as exc:
                raise SnmpError(f"cannot send to {host}: {exc}") from None
            finally:
                self._pending.pop(request_id, None)
            if msg["a"]:
                raise SnmpError(_ERRORS.get(msg["a"], f"error {msg['a']}"))
            return msg["varbinds"]
        raise SnmpTimeout("no response (wrong community, SNMP disabled, or blocked)")

    async def get(self, host: str, port: int, community: str, oids: list[Oid]) -> dict[Oid, object]:
        return dict(await self._request(host, port, community, GET, oids))

    async def walk(self, host: str, port: int, community: str, base: Oid, max_rows: int = 5000) -> list[tuple[Oid, object]]:
        """Walk one subtree with GETBULK. Returns (index suffix, value) pairs."""
        rows: list[tuple[Oid, object]] = []
        last = base
        size = len(base)
        repetitions = 20
        while len(rows) < max_rows:
            try:
                varbinds = await self._request(host, port, community, GETBULK, [last], 0, repetitions)
            except SnmpError as exc:
                if str(exc) == "tooBig" and repetitions > 1:
                    repetitions = max(1, repetitions // 2)
                    continue
                raise
            if not varbinds:
                break
            for name, value in varbinds:
                # Stop at the end of the subtree, and on agents that fail to advance.
                if value is END or name[:size] != base or name <= last:
                    return rows
                rows.append((name[size:], value))
                last = name
        return rows

    async def table(self, host: str, port: int, community: str, columns: dict[str, Oid]) -> dict[Oid, dict]:
        """Walk several columns of one table and join them by index."""
        out: dict[Oid, dict] = {}
        for name, base in columns.items():
            for index, value in await self.walk(host, port, community, base):
                out.setdefault(index, {})[name] = value
        return out
