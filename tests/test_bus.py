"""Collectors, a real message bus, and the processor, against the single process.

Needs a Kafka-compatible broker; skipped unless this is set (CI sets it):

    CERBERUS_TEST_KAFKA_BOOTSTRAP=127.0.0.1:19092

Each test uses its own topic and consumer group.
"""
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import golden  # noqa: E402
from cerberus.bus import EventSource, Heartbeats, Publisher, ensure_topics, encode_event  # noqa: E402
from cerberus.collector import Collector  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Event  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from tools import simulate  # noqa: E402

KAFKA = os.environ.get("CERBERUS_TEST_KAFKA_BOOTSTRAP", "")
if os.environ.get("CERBERUS_REQUIRE_BACKENDS") and not KAFKA:
    raise RuntimeError("CERBERUS_REQUIRE_BACKENDS is set but CERBERUS_TEST_KAFKA_BOOTSTRAP is not")
pytestmark = pytest.mark.skipif(not KAFKA, reason="set CERBERUS_TEST_KAFKA_BOOTSTRAP")


def bus_config(tmp_path, partitions: int = 1) -> Config:
    cfg = Config.from_env()
    run = uuid.uuid4().hex[:10]
    cfg.data_dir, cfg.device_identity = tmp_path, "hostname"
    cfg.kafka_bootstrap, cfg.kafka_topic, cfg.kafka_group = KAFKA, f"cerberus-test-{run}", f"cerberus-test-{run}"
    cfg.kafka_partitions = partitions
    return cfg


async def collect(cfg, tmp_path, resend: bool = False) -> int:
    """Parse the reference traffic as a collector would and publish it. Returns the event count."""
    await ensure_topics(cfg)
    publisher = Publisher(cfg, tmp_path / "spool", name="test-collector")
    await publisher.start()
    collector = Collector(cfg, ConnectorRegistry(), publisher)
    batch, total, sent = [], 0, []
    for offset, line in golden.timeline(simulate):
        batch.append(collector.encode(collector.parse(line.encode(), "10.255.0.1", golden.START + offset)))
        if len(batch) == 2000:
            sent += batch
            await publisher.publish(batch)
            total, batch = total + len(batch), []
    await publisher.publish(batch)
    total += len(batch)
    if resend:
        # What a collector does after a bus outage it cannot be sure about: sends some again.
        await publisher.publish(sent[:: 7])
    assert not publisher.spool
    await publisher.stop()
    return total


def processor(cfg, store_path: Path, now: float):
    db = Database(store_path)
    engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    engine.load(now=now)
    engine.installed = golden.START - 86400
    watch = {d.id: d.settings() for d in engine.detectors}
    watch["watchlist"]["entries"] = "45.77.0.0/16"
    engine.apply_settings(watch, engine.general_settings())
    engine.source = EventSource(cfg)
    return db, engine


def done_extra(dedup, extra: int) -> bool:
    return dedup.duplicates >= extra


async def process(cfg, store_path: Path, total: int, restart_at: int = 0, extra: int = 0) -> None:
    """Consume everything as the processor does, ticking on the events' clock as the reference
    run does. With restart_at, stop cleanly after that many events and start a new processor."""
    from aiokafka.structs import TopicPartition

    from cerberus.bus import Deduplicator
    dedup = Deduplicator()
    db, engine = processor(cfg, store_path, golden.START)
    await engine.source.start()
    next_tick, seen, last = golden.START + golden.TICK, 0, golden.START
    while seen < total or not done_extra(dedup, extra):
        got = await engine.source.consumer.getmany(timeout_ms=2000, max_records=5000)
        for tp, records in got.items():
            for record in records:
                body = json.loads(record.value)
                if not dedup.fresh(*body["_uid"]):
                    engine.source.position[TopicPartition(tp.topic, tp.partition)] = record.offset + 1
                    continue
                ev = Event.from_dict(body)
                while next_tick <= ev.ts:
                    await engine._flush()  # also commits what has been written
                    engine.tick(next_tick)
                    next_tick += golden.TICK
                engine.received += 1
                if engine.record(ev, ev.ts):
                    engine.detect(ev, ev.ts)
                engine.source.position[TopicPartition(tp.topic, tp.partition)] = record.offset + 1
                seen, last = seen + 1, ev.ts
                if seen == restart_at:
                    await engine._flush()
                    engine.save_state(last)
                    await engine.source.stop()
                    db.close()
                    db, engine = processor(cfg, store_path, last)  # resumes at the committed offset
                    await engine.source.start()
                    break
            else:
                continue
            break
    await engine._flush()
    engine.tick(next_tick)
    await engine._flush()
    await engine.source.stop()
    db.close()


def reference(tmp_path) -> dict:
    (tmp_path / "ref").mkdir()
    return golden.run(None, tmp_path / "ref", store=lambda: Database(tmp_path / "ref" / "c.db"))


@pytest.mark.parametrize("restart,resend", [(False, False), (True, False), (False, True)])
def test_reference_traffic_through_collector_bus_and_processor(tmp_path, restart, resend):
    expected = reference(tmp_path)
    cfg = bus_config(tmp_path)

    async def go():
        total = await collect(cfg, tmp_path, resend)
        extra = len(range(0, (total // 2000) * 2000, 7)) if resend else 0
        await process(cfg, tmp_path / "processor.db", total, restart_at=total // 2 if restart else 0, extra=extra)
        return total
    total = asyncio.run(go())
    assert total == expected["events"]["rows"]
    assert golden.summarise_store(Database(tmp_path / "processor.db")) == expected


def test_collector_heartbeats_reach_the_processor(tmp_path):
    cfg = bus_config(tmp_path)

    async def go():
        from aiokafka import AIOKafkaProducer
        await ensure_topics(cfg)
        heartbeats = Heartbeats(cfg)
        watcher = asyncio.create_task(heartbeats.watch())
        await asyncio.sleep(3)  # let the watcher join before anything is sent
        producer = AIOKafkaProducer(bootstrap_servers=KAFKA)
        await producer.start()
        try:
            deadline = time.time() + 20
            while "edge-1" not in heartbeats.latest and time.time() < deadline:
                await heartbeats.send(producer, {"name": "edge-1", "received": 42, "sent": time.time()})
                await asyncio.sleep(1)
        finally:
            await producer.stop()
            watcher.cancel()
        return heartbeats.latest
    latest = asyncio.run(go())
    assert latest["edge-1"]["received"] == 42 and latest["edge-1"]["received_at"] > 0
