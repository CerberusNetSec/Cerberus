"""Scale-out ingest without a message bus: PROXY protocol, syslog over TLS, the
collector's spool, and collectors parsing exactly as the single process does."""
import asyncio
import ipaddress
import json
import shutil
import socket
import ssl
import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import golden  # noqa: E402
from cerberus.bus import Publisher, Spool, encode_event  # noqa: E402
from cerberus.collector import Collector  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.receiver import V2_SIGNATURE, SyslogReceiver, read_proxy_header, tls_context  # noqa: E402
from tools import simulate  # noqa: E402

LINE = b"<134>1 2027-01-15T12:00:00Z fw1 filterlog - - - hello"


def v2_header(src: str, dst: str = "10.0.0.1", local: bool = False) -> bytes:
    if local:
        return V2_SIGNATURE + struct.pack("!BBH", 0x20, 0x00, 0)
    if ":" in src:
        body = ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address("::1").packed + struct.pack("!HH", 40000, 514)
        return V2_SIGNATURE + struct.pack("!BBH", 0x21, 0x21, len(body)) + body
    body = ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!HH", 40000, 514)
    return V2_SIGNATURE + struct.pack("!BBH", 0x21, 0x11, len(body)) + body


def header(data: bytes):
    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await read_proxy_header(reader)
    return asyncio.run(go())


def test_proxy_headers():
    assert header(b"PROXY TCP4 198.51.100.7 10.0.0.1 40000 514\r\nrest") == "198.51.100.7"
    assert header(b"PROXY TCP6 2001:db8::7 ::1 40000 514\r\n") == "2001:db8::7"
    assert header(b"PROXY UNKNOWN\r\n") is None
    assert header(v2_header("203.0.113.9")) == "203.0.113.9"
    assert header(v2_header("2001:db8::9")) == "2001:db8::9"
    assert header(v2_header("", local=True)) is None
    for junk in (b"PROXY TCP4 nonsense\r\n", b"GET / HTTP/1.1\r\n\r\n", b"<134>hello there\n", b"PROXY " + b"x" * 200 + b"\r\n"):
        with pytest.raises(Exception):
            header(junk)


async def send_tcp(port: int, payload: bytes, ssl_context=None) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=ssl_context)
    writer.write(payload)
    await writer.drain()
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, ssl.SSLError):
        pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_receiver_takes_the_device_address_only_from_a_trusted_proxy():
    async def go(proxy_from, payloads):
        got = []
        port = free_port()
        receiver = SyslogReceiver(lambda data, ip: got.append((data, ip)), "127.0.0.1", 0, port, proxy_from=proxy_from)
        await receiver.start()
        for payload in payloads:
            await send_tcp(port, payload)
        await asyncio.sleep(0.3)
        await receiver.stop()
        return got, receiver.bad_proxy
    framed = f"{len(LINE)} ".encode() + LINE
    # Trusted proxy: the device's address comes from the header, in both versions.
    got, bad = asyncio.run(go(["127.0.0.0/8"], [v2_header("203.0.113.9") + framed,
                                                b"PROXY TCP4 198.51.100.7 10.0.0.1 1 2\r\n" + LINE + b"\n",
                                                v2_header("", local=True),  # a health check: nothing to read
                                                LINE + b"\n"]))  # from the proxy, but no header: refused
    assert got == [(LINE, "203.0.113.9"), (LINE + b"\n", "198.51.100.7")] and bad == 1
    # Not a trusted proxy: a header is just bytes, and the address is the real peer's.
    got, bad = asyncio.run(go(["192.0.2.0/24"], [b"PROXY TCP4 198.51.100.7 10.0.0.1 1 2\r\n" + LINE + b"\n"]))
    assert [ip for _, ip in got] == ["127.0.0.1", "127.0.0.1"] and bad == 0


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    """A CA, a server certificate for 127.0.0.1 and a client certificate, made with openssl."""
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("pki")

    def run(*args):
        subprocess.run([openssl, *args], cwd=d, check=True, capture_output=True)
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2",
        "-subj", "/CN=test-ca")
    (d / "san.ext").write_text("subjectAltName=IP:127.0.0.1\n")
    for name in ("server", "client"):
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}")
        run("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", f"{name}.crt", "-days", "2", "-extfile", "san.ext")
    return d


def test_syslog_over_tls(certificates):
    d = certificates

    async def go(client_ca: str, with_client_cert: bool):
        got = []
        port = free_port()
        receiver = SyslogReceiver(lambda data, ip: got.append(data), "127.0.0.1", 0, 0, tls_port=port,
                                  tls=tls_context(str(d / "server.crt"), str(d / "server.key"), client_ca))
        await receiver.start()
        client = ssl.create_default_context(cafile=str(d / "ca.crt"))
        if with_client_cert:
            client.load_cert_chain(str(d / "client.crt"), str(d / "client.key"))
        try:
            await send_tcp(port, f"{len(LINE)} ".encode() + LINE, client)
        except (ssl.SSLError, ConnectionError, OSError):
            pass
        await asyncio.sleep(0.3)
        await receiver.stop()
        return got
    assert asyncio.run(go("", False)) == [LINE]
    assert asyncio.run(go(str(d / "ca.crt"), True)) == [LINE]  # mutual TLS
    assert asyncio.run(go(str(d / "ca.crt"), False)) == []  # a device without a certificate is refused


class FlakyProducer:
    """Stands in for the Kafka producer: refuses while `down`, records what it accepts."""

    def __init__(self):
        self.down = False
        self.sent = []

    async def start(self):
        if self.down:
            raise ConnectionError("bus down")

    async def stop(self):
        pass

    async def send(self, topic, value, key=None):
        if self.down:
            raise ConnectionError("bus down")
        self.sent.append(value)
        future = asyncio.get_running_loop().create_future()
        future.set_result(None)
        return future


def cfg_for(tmp_path, **extra) -> Config:
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity, cfg.kafka_topic, cfg.spool_mb = tmp_path, "hostname", "test", 1
    for k, v in extra.items():
        setattr(cfg, k, v)
    return cfg


def records(n: int, start: int = 0) -> list[tuple[bytes, bytes]]:
    return [(b"fw", json.dumps({"n": i}).encode()) for i in range(start, start + n)]


def test_spool_keeps_order_through_an_outage(tmp_path):
    producer = FlakyProducer()
    publisher = Publisher(cfg_for(tmp_path), tmp_path / "spool", producer, name="c1")

    async def go():
        await publisher.start()
        await publisher.publish(records(5))
        producer.down = True
        await publisher.publish(records(5, 5))  # fails: spooled
        await publisher.publish(records(5, 10))  # spool not empty: spooled behind it
        assert publisher.down and publisher.spooled == 10 and producer.sent and len(producer.sent) == 5
        assert await publisher.drain_spool() is False  # still down
        producer.down = False
        await publisher.publish(records(5, 15))  # the spool goes first, so this waits its turn
        assert await publisher.drain_spool() is True
        await publisher.publish(records(5, 20))
    asyncio.run(go())
    assert [json.loads(v)["n"] for v in producer.sent] == list(range(25))
    assert not publisher.spool and not publisher.down and publisher.published == 25


def test_spool_survives_a_restart_and_has_a_limit(tmp_path):
    spool = Spool(tmp_path / "spool", limit_bytes=60_000)
    spool.append([("events", k, v) for k, v in records(100)])
    spool.close()
    again = Spool(tmp_path / "spool", limit_bytes=60_000)  # a collector restarted while the bus was down
    assert again.events() == 100
    big = [("events", b"fw", b"x" * 500)] * 30_000  # far over the limit: whole oldest files go
    again.append(big)
    assert again.size() <= 60_000 + 30_000 * 600 and again.dropped > 0
    assert again.events() + again.dropped == 30_100


def test_collector_parses_exactly_like_the_single_process(tmp_path):
    cfg = cfg_for(tmp_path)
    collector = Collector(cfg, ConnectorRegistry(), Publisher(cfg, tmp_path / "spool", FlakyProducer(), name="c1"))
    db = Database(tmp_path / "c.db")
    engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    engine.load(now=golden.START)
    for offset, line in golden.timeline(simulate):
        ts = golden.START + offset
        mine = collector.parse(line.encode(), "10.255.0.1", ts)
        theirs = engine.parse(line.encode(), "10.255.0.1", ts)
        engine.record(theirs, ts)  # the engine learns each device's connector the same way
        assert mine == theirs
        key, value = encode_event(mine)
        assert key == mine.device.encode() and json.loads(value) == mine.as_dict()
    db.close()


def test_spool_left_by_a_collector_that_has_gone_is_sent_once(tmp_path):
    from cerberus import bus
    if bus.fcntl is None:
        pytest.skip("file locks are not available on this platform (collectors run on Linux)")
    cfg = cfg_for(tmp_path)
    root = tmp_path / "spool"

    async def go():
        down = FlakyProducer()
        down.down = True
        old = Publisher(cfg, root, down, name="old")  # a replica that is replaced while the bus is down
        await old.start()
        await old.publish(records(10))
        await old.stop()  # its lock is released
        busy = Publisher(cfg, root, FlakyProducer(), name="busy")  # a running replica keeps its own
        busy.down = True
        await busy.publish(records(3, 100))
        up = FlakyProducer()
        new = Publisher(cfg, root, up, name="new")
        await new.start()
        await new.adopt_orphans()
        await new.adopt_orphans()  # nothing twice
        return up.sent, new.adopted
    sent, adopted = asyncio.run(go())
    assert [json.loads(v)["n"] for v in sent] == list(range(10)) and adopted == 10
    assert not (root / "old").exists() and (root / "busy").exists()


def test_deduplicator_recognises_copies_and_forgets_slowly():
    from cerberus.bus import Deduplicator
    d = Deduplicator()
    assert all(d.fresh("run-a", n) for n in range(1, 1001))
    assert not any(d.fresh("run-a", n) for n in (1, 500, 1000)) and d.duplicates == 3
    assert d.fresh("run-b", 1) and d.fresh("run-a", 1500) and d.fresh("run-a", 1200)  # out of order: still new
    assert not d.fresh("run-a", 1200)
    far = 1500 + Deduplicator.WINDOW + 10  # a jump bigger than the window
    assert d.fresh("run-a", far) and d.fresh("run-a", 1500 + Deduplicator.WINDOW // 2 + 20)
    assert d.fresh("run-a", 5) and d.unverifiable == 1  # too old to tell: accepted
    # The window really slides: a number from just inside it is remembered, one pushed out is not.
    e = Deduplicator()
    e.fresh("r", 10)
    e.fresh("r", 10 + Deduplicator.WINDOW - 1)
    assert not e.fresh("r", 10)
    e.fresh("r", 10 + Deduplicator.WINDOW)
    assert e.fresh("r", 10) and e.unverifiable == 1


def test_spool_files_from_0_5_0_still_read(tmp_path):
    """0.5.0 spooled [key, value] lines, all for the event topic."""
    d = tmp_path / 'spool'
    d.mkdir()
    lines = [json.dumps(['fw', json.dumps({'n': n})]) for n in (1, 2)]
    (d / '000000000001.jsonl').write_bytes(''.join(line + chr(10) for line in lines).encode())
    path, rows = Spool(d, 10**6).oldest('cerberus.events')
    assert rows == [('cerberus.events', b'fw', json.dumps({'n': 1}).encode()),
                    ('cerberus.events', b'fw', json.dumps({'n': 2}).encode())]
