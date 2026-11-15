"""Syslog listeners chosen under Settings, changed while running."""
import asyncio
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from cerberus import listeners, web  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.receiver import SyslogReceiver  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def send_tcp(port: int, text: str) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(text.encode() + b"\n")
    await writer.drain()
    writer.close()


def test_receiver_moves_a_listener_while_running():
    got = []

    async def go():
        a, b = free_port(), free_port()
        r = SyslogReceiver(lambda data, ip: got.append(data), "127.0.0.1", 0, a)
        await r.start()
        assert r.status()["tcp"] == {"port": a, "listening": True, "error": ""}
        await send_tcp(a, "<13>one")
        await asyncio.sleep(0.2)
        assert await r.reconfigure({"tcp": b}) == {}
        await send_tcp(b, "<13>two")
        await asyncio.sleep(0.2)
        try:  # the old port is closed
            await asyncio.wait_for(send_tcp(a, "<13>lost"), 1)
            refused = False
        except OSError:
            refused = True
        # A port that cannot be opened leaves the listener where it was.
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        taken = blocker.getsockname()[1]
        failed = await r.reconfigure({"tcp": taken})
        status = r.status()["tcp"]
        blocker.close()
        # Off, then back on.
        assert await r.reconfigure({"tcp": 0}) == {} and r.status()["tcp"]["listening"] is False
        assert await r.reconfigure({"tcp": b}) == {} and r.status()["tcp"]["listening"] is True
        await r.stop()
        return refused, failed, status, b, taken
    refused, failed, status, b, taken = asyncio.run(go())
    assert [d.strip() for d in got] == [b"<13>one", b"<13>two"]
    assert refused
    assert failed == {"tcp": f"port {taken} is already in use"} or "tcp" in failed
    assert status["port"] == b and status["listening"]


def test_tls_cannot_be_switched_on_without_a_certificate():
    async def go():
        r = SyslogReceiver(lambda d, ip: None, "127.0.0.1", 0, 0)
        return await r.reconfigure({"tls": free_port()})
    assert "certificate" in asyncio.run(go())["tls"]


def test_saved_listeners_win_over_the_environment_at_start():
    cfg = Config.from_env()
    cfg.syslog_udp_port, cfg.syslog_tcp_port, cfg.syslog_tls_port = 5514, 5514, 0
    listeners.apply_saved(cfg, {"udp": {"enabled": False, "port": 514}, "tcp": {"enabled": True, "port": 1514},
                                "tls": {"enabled": True, "port": 6514}})
    assert (cfg.syslog_udp_port, cfg.syslog_tcp_port, cfg.syslog_tls_port) == (0, 1514, 0)  # no certificate: no TLS
    listeners.apply_saved(cfg, None)  # nothing saved: unchanged
    listeners.apply_saved(cfg, {"udp": {"enabled": True, "port": 99999}})  # invalid: ignored
    assert (cfg.syslog_udp_port, cfg.syslog_tcp_port) == (0, 1514)


def make_app(tmp_path, receiver, raw=False):
    cfg = Config.from_env()
    cfg.data_dir, cfg.auth_enabled, cfg.bind = tmp_path, False, "127.0.0.1"
    cfg.syslog_udp_port, cfg.syslog_tcp_port, cfg.syslog_tls_port = 0, receiver.tcp_port if receiver else 5514, 0
    db = Database(tmp_path / "c.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    engine.receiver = receiver
    app = web.create_app(cfg, db, engine, notifier, SnmpPoller(engine, db))
    return (app if raw else TestClient(app)), db, engine


def test_listener_api(tmp_path):
    """Through the HTTP API, on the same event loop as the listeners (as in the server)."""
    import httpx
    port, other = free_port(), free_port()

    async def go():
        r = SyslogReceiver(lambda d, ip: None, "127.0.0.1", 0, port)
        await r.start()
        app, db, _ = make_app(tmp_path, r, raw=True)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cerberus") as client:
            view = (await client.get("/api/listeners")).json()
            assert view["available"] and not view["saved"]
            assert view["listeners"]["tcp"] == {"enabled": True, "port": port, "listening": True,
                                                "listening_port": port, "error": ""}
            assert view["listeners"]["udp"]["enabled"] is False and view["tls_certificate"] is False
            bad = [({"tcp": {"enabled": True, "port": 0}}, "between 1 and 65535"),
                   ({"tcp": {"enabled": True, "port": "x"}}, "must be a number"),
                   ({"tcp": {"enabled": False, "port": port}, "udp": {"enabled": False, "port": 1}}, "at least one"),
                   ({"tls": {"enabled": True, "port": 6514}}, "certificate")]
            for body, message in bad:
                res = await client.put("/api/listeners", json={"listeners": body})
                assert res.status_code == 400 and message in res.json()["detail"], (body, res.json())
            res = (await client.put("/api/listeners", json={"listeners": {"tcp": {"enabled": True, "port": other}}})).json()
            assert res["saved"] and res["listeners"]["tcp"]["listening_port"] == other
            assert db.get_setting("listeners")["tcp"] == {"enabled": True, "port": other}
            # A port in use: reported, and what is saved stays what is running.
            blocker = socket.socket()
            blocker.bind(("127.0.0.1", 0))
            blocker.listen()
            res = (await client.put("/api/listeners", json={"listeners": {"tcp": {
                "enabled": True, "port": blocker.getsockname()[1]}}})).json()
            blocker.close()
            assert "in use" in res["listeners"]["tcp"]["error"]
            assert db.get_setting("listeners")["tcp"]["port"] == other and r.status()["tcp"]["port"] == other
        await r.stop()
        db.close()
    asyncio.run(go())


def test_no_listeners_on_a_processor(tmp_path):
    client, db, _ = make_app(tmp_path, None)
    assert client.get("/api/listeners").json()["available"] is False
    assert client.put("/api/listeners", json={"listeners": {}}).status_code == 409
    db.close()


def test_alert_counts_for_the_badge(tmp_path):
    client, db, engine = make_app(tmp_path, None)
    assert client.get("/api/alerts/counts").json() == {"open": {}, "total": 0}
    for i, sev in enumerate(("high", "high", "low")):
        engine.raise_alert(Candidate("port_scan", f"10.0.0.{i}", sev, "t", "d", f"10.0.0.{i}", ""), 1_800_000_000.0)
    asyncio.run(engine._flush())
    assert client.get("/api/alerts/counts").json() == {"open": {"high": 2, "low": 1}, "total": 3}
    db.close()
    json.dumps(listeners.from_config(Config.from_env()))
