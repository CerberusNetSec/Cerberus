"""Notifications go through an outbox: stored with their alert, then sent."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus import notifiers  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.storage import OUTBOX_ATTEMPTS  # noqa: E402


def setup(tmp_path, monkeypatch, fail=False):
    cfg = Config.from_env()
    cfg.data_dir = tmp_path
    db = Database(tmp_path / "c.db")
    db.add_channel({"type": "webhook", "name": "hook", "enabled": 1, "min_severity": "low",
                    "config": json.dumps({"url": "https://hooks.example/x"})})
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    sent = []

    async def fake_send(channel, subject, body, client, payload=None):
        if fail:
            raise RuntimeError("unreachable")
        sent.append(subject)
    monkeypatch.setattr(notifiers, "send", fake_send)
    return db, notifier, engine, sent


def alert(engine, entity="10.0.0.1"):
    engine.raise_alert(Candidate("port_scan", entity, "high", f"Port scan from {entity}", "d", entity, ""), 1_800_000_000.0)


def test_nothing_is_sent_until_the_alert_is_stored(tmp_path, monkeypatch):
    db, notifier, engine, sent = setup(tmp_path, monkeypatch)

    async def go():
        await notifier.reload()
        alert(engine)
        assert notifier.pending and await notifier.send_due() == 0  # not stored yet: nothing to send
        await engine._flush()  # the alert and its notification, in one write
        assert db.outbox_pending() == 1
        assert await notifier.send_due() == 1
        await asyncio.gather(*notifier._tasks)
        assert await notifier.send_due() == 0  # sent once
    asyncio.run(go())
    assert sent == ["[Cerberus HIGH] Port scan from 10.0.0.1"]
    assert db.outbox_pending() == 0
    db.close()


def test_a_crash_before_the_write_sends_nothing(tmp_path, monkeypatch):
    """The alert and its notification are lost together, and come back together when
    the new leader replays the events from its checkpoint."""
    db, notifier, engine, sent = setup(tmp_path, monkeypatch)

    async def go():
        await notifier.reload()
        alert(engine)
        # crash: no flush
        fresh = Notifier(db)
        await fresh.reload()
        assert await fresh.send_due() == 0
    asyncio.run(go())
    assert sent == [] and db.outbox_pending() == 0
    db.close()


def test_failures_are_retried_later_then_given_up(tmp_path, monkeypatch):
    db, notifier, engine, sent = setup(tmp_path, monkeypatch, fail=True)

    async def no_wait(_delay):
        return None

    async def go():
        await notifier.reload()
        monkeypatch.setattr(notifiers.asyncio, "sleep", no_wait)  # deliver()'s own quick retries
        alert(engine)
        await engine._flush()
        assert await notifier.send_due() == 1
        await asyncio.gather(*notifier._tasks)
        assert await notifier.send_due() == 0  # not due again for a minute
    asyncio.run(go())
    assert notifier.failed == 1 and db.outbox_pending() == 1
    row_id = db.outbox_due(10**12, 10)[0]["id"]
    for _ in range(OUTBOX_ATTEMPTS - 1):
        db.outbox_done(row_id, 2000.0, "still unreachable")
    assert db.outbox_pending() == 0 and db.outbox_due(10**12, 10) == []
    db.close()


def test_backoff_doubles():
    from cerberus.storage import outbox_retry_at
    assert [outbox_retry_at(0, n) for n in (1, 2, 3, 4)] == [60, 120, 240, 480]
