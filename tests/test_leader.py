"""Active/standby: one processor active, the others waiting."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from cerberus import leader  # noqa: E402
from cerberus.db import Database  # noqa: E402


class FakeLock:
    def __init__(self, free_after: int = 0, fail_first: bool = False):
        self.tries = 0
        self.free_after = free_after
        self.fail_first = fail_first
        self.held = False
        self.released = 0

    def try_acquire(self):
        self.tries += 1
        if self.fail_first and self.tries == 1:
            raise OSError("connection refused")
        self.held = self.tries > self.free_after
        return self.held

    def still_held(self):
        return self.held

    def release(self):
        self.released += 1


def test_sqlite_has_one_process_which_always_leads(tmp_path):
    db = Database(tmp_path / "c.db")
    lock = db.leadership("processor:x")
    assert lock.try_acquire() and lock.still_held()
    db.close()


def test_a_standby_is_alive_but_not_ready():
    client = TestClient(leader.standby_app("p-2", {"since": 1.0}))
    assert client.get("/healthz").json()["role"] == "standby"
    assert client.get("/readyz").status_code == 503
    assert client.get("/api/summary").status_code == 503
    assert client.post("/api/login", json={}).status_code == 503


def test_waits_until_the_lock_is_free(monkeypatch):
    monkeypatch.setattr(leader, "TRY_SECONDS", 0.01)
    lock = FakeLock(free_after=3, fail_first=True)
    assert asyncio.run(leader.wait_for_leadership(lock)) is True
    assert lock.tries == 4 and lock.released == 1  # a failed attempt drops the connection


def test_a_standby_told_to_stop_stops(monkeypatch):
    monkeypatch.setattr(leader, "TRY_SECONDS", 0.01)

    async def go():
        stopped = asyncio.get_running_loop().create_future()
        stopped.set_result(None)

        class Server:
            should_exit = False
        return await leader.wait_for_leadership(FakeLock(free_after=10**9), lambda app: (Server(), stopped))
    assert asyncio.run(go()) is False


def test_losing_the_lock_stops_the_active_processor(monkeypatch):
    monkeypatch.setattr(leader, "CHECK_SECONDS", 0.01)
    lock = FakeLock()
    lock.held = False
    lost = []
    asyncio.run(leader.keep_leadership(lock, on_lost=lambda: lost.append(True)))
    assert lost == [True]


def test_api_ready_on_the_active_processor(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_api_contract import build  # noqa: E402
    client, db = build(tmp_path, monkeypatch)
    assert client.get("/readyz").json() == {"ok": True, "role": "active"}
    db.close()


def test_metrics_on_the_active_processor_and_a_standby(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_api_contract import build  # noqa: E402
    client, db = build(tmp_path, monkeypatch)
    text = client.get("/metrics").text
    assert "# TYPE cerberus_events_received_total counter" in text
    assert "cerberus_active 1" in text and "cerberus_outbox_pending 0" in text
    assert 'cerberus_info{version="' in text
    db.close()
    standby = TestClient(leader.standby_app("p-2", {"since": 1.0}, metrics_token="s3cret"))
    assert standby.get("/metrics").status_code == 401
    text = standby.get("/metrics", headers={"Authorization": "Bearer s3cret"}).text
    assert "cerberus_active 0" in text and 'name="p-2"' in text


def test_metrics_render_escapes_labels():
    from cerberus.metrics import render
    out = render([("m", "gauge", "help", True, {"name": "a\"b\\c"})])  # a"b\c
    assert out.splitlines()[-1] == 'm{name="a\\"b\\\\c"} 1'


def test_metrics_on_a_collector(tmp_path):
    from cerberus.bus import Publisher
    from cerberus.collector import Collector, status_app
    from cerberus.config import Config
    from cerberus.connectors import ConnectorRegistry

    cfg = Config.from_env()
    cfg.data_dir, cfg.collector_name = tmp_path, "edge-1"
    collector = Collector(cfg, ConnectorRegistry(), Publisher(cfg, tmp_path / "spool", object(), name="edge-1"))
    text = TestClient(status_app(collector)).get("/metrics").text
    assert 'role="collector"' in text and "cerberus_collector_messages_received_total 0" in text
    assert "cerberus_bus_down 0" in text
