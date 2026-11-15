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
from cerberus.bus import EventSource, Heartbeats, Publisher, ensure_topics  # noqa: E402
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
        batch += collector.encode(collector.parse(line.encode(), "10.255.0.1", golden.START + offset))
        total += 1
        if len(batch) >= 2000:
            sent += batch
            await publisher.publish(batch)
            batch = []
    await publisher.publish(batch)
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
        extra = len(range(0, (total // 2000) * 2000, 7)) if resend else 0  # one record per event here
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


def test_reference_traffic_through_detection_workers(tmp_path):
    """Collectors route events to every family's topic; one detection worker per family
    runs it and sends candidates back; the processor runs the rest and the alert stage.
    The same alerts are found, and the same is stored, as in one process."""
    from aiokafka.structs import TopicPartition

    from cerberus.bus import Deduplicator, candidates_topic
    from cerberus.detectors import WORKER_FAMILIES
    from cerberus.models import Candidate
    from cerberus.worker import DetectionWorker

    expected = reference(tmp_path)
    cfg = bus_config(tmp_path)
    cfg.detection_workers = WORKER_FAMILIES

    async def work(family: str) -> int:
        """One worker for a family, driven on the events' clock like the reference run."""
        wcfg = bus_config(tmp_path)
        wcfg.kafka_topic, wcfg.kafka_group = cfg.kafka_topic, cfg.kafka_group
        wcfg.detection_workers, wcfg.detection_family = WORKER_FAMILIES, family
        db = Database(tmp_path / f"{family}.db")
        engine = Engine(wcfg, db, ConnectorRegistry(), Notifier(db))
        engine.families = {family}
        watch = {d.id: d.settings() for d in engine.detectors}
        watch["watchlist"]["entries"] = "45.77.0.0/16"
        engine.apply_settings(watch, engine.general_settings())
        worker = DetectionWorker(wcfg, db, engine, Publisher(wcfg, tmp_path / "spool", name=f"w-{family}"))
        await worker.publisher.start()
        await worker.source.start()
        next_tick, idle = golden.START + golden.TICK, 0
        while idle < 8:  # until the topic has been quiet for a while
            records = await worker.source.batch(timeout_ms=1000)
            idle = 0 if records else idle + 1
            for record in records:
                ts = json.loads(record.value)["ts"]
                while next_tick <= ts:
                    await worker.publisher.publish(worker.tick(next_tick))
                    next_tick += golden.TICK
                await worker.publisher.publish(worker.handle([record]))
            await worker.source.commit(worker.source.snapshot())
        await worker.publisher.publish(worker.tick(next_tick))
        await worker.publisher.stop()
        await worker.source.stop()
        if family == "port":
            ports = worker.engine.risk_ports.drain()
            db.close()
            return ports
        db.close()
        return []

    async def go():
        total = await collect(cfg, tmp_path)
        ports = (await asyncio.gather(*(work(f) for f in WORKER_FAMILIES)))[WORKER_FAMILIES.index("port")]
        # The candidates, then the processor: alerts raised at the time they were found.
        source = EventSource(cfg, topic=candidates_topic(cfg), group=cfg.kafka_group + "-alerts")
        await source.start()
        pending, dedup, idle = [], Deduplicator(), 0
        while idle < 4:
            records = await source.batch(timeout_ms=1000)
            idle = 0 if records else idle + 1
            for record in records:
                body = json.loads(record.value)
                if dedup.fresh(*body["_uid"]):
                    pending.append(body)
        await source.stop()
        pending.sort(key=lambda b: b["_ts"])

        db, engine = processor(cfg, tmp_path / "processor.db", golden.START)
        engine.families = {"device", "alerts"}
        await engine.source.start()

        def raise_until(ts, inclusive):
            while pending and (pending[0]["_ts"] <= ts if inclusive else pending[0]["_ts"] < ts):
                body = pending.pop(0)
                engine.raise_alert(Candidate.from_dict(body), body["_ts"])

        next_tick, seen = golden.START + golden.TICK, 0
        while seen < total:
            for tp, records in (await engine.source.consumer.getmany(timeout_ms=2000, max_records=5000)).items():
                for record in records:
                    ev = Event.from_dict(json.loads(record.value))
                    while next_tick <= ev.ts:
                        await engine._flush()
                        raise_until(next_tick, True)
                        engine.tick(next_tick)
                        next_tick += golden.TICK
                    raise_until(ev.ts, False)
                    if engine.record(ev, ev.ts):
                        engine.detect(ev, ev.ts)
                    engine.source.position[TopicPartition(tp.topic, tp.partition)] = record.offset + 1
                    seen += 1
        await engine._flush()
        raise_until(next_tick, True)
        engine.tick(next_tick)
        raise_until(float("inf"), True)
        from cerberus.storage import Batch
        db.write_batch(Batch(ports=ports))  # what the port worker writes
        await engine._flush()
        await engine.source.stop()
        db.close()
        return total

    total = asyncio.run(go())
    assert total == expected["events"]["rows"]
    actual = golden.summarise_store(Database(tmp_path / "processor.db"))

    def comparable(alerts):
        return sorted((a["created"], a["detector"], a["entity"], a["severity"], a["title"], a["count"],
                       a["description"], a["details"]) for a in alerts)
    assert comparable(actual.pop("alerts")) == comparable(expected.pop("alerts"))
    assert actual == expected


def test_a_new_leader_after_a_crash_finds_and_stores_exactly_the_same(tmp_path):
    """Processor A saves a checkpoint, carries on storing and committing, takes in more
    events without storing them, and dies without saving anything more. Processor B
    takes over: it goes back on the bus to the checkpoint, replays up to what A had
    stored (detection only) and carries on. The result is what one uninterrupted
    process stores: no event or alert lost, none twice."""
    from aiokafka.structs import TopicPartition

    from cerberus.bus import Deduplicator

    expected = reference(tmp_path)
    cfg = bus_config(tmp_path)
    store_path = tmp_path / "processor.db"

    async def run(engine, stop_after=None, checkpoint_at=None, flush_at=None, start_tick=None):
        """Feed records; returns (records seen, checkpoint time, last ts)."""
        await engine.source.start()
        next_tick, seen, last, saved = start_tick or golden.START + golden.TICK, 0, golden.START, None
        last_offset = -1
        while last_offset < stop_after:
            for tp, records in (await engine.source.consumer.getmany(timeout_ms=2000, max_records=500)).items():
                records = engine.source.after_seek(tp, records)  # as EventSource.batch() does
                for record in records:
                    ev_ts = json.loads(record.value)["ts"]
                    until = engine.source.replay_until.get(TopicPartition(tp.topic, tp.partition))
                    in_replay = until is not None and record.offset < until
                    while next_tick <= ev_ts:
                        if not in_replay:
                            await engine._flush()
                        engine.tick(next_tick, replay=in_replay)
                        next_tick += golden.TICK
                    engine.take(record)
                    engine.source.position[TopicPartition(tp.topic, tp.partition)] = record.offset + 1
                    seen, last, last_offset = seen + 1, ev_ts, record.offset
                    if record.offset == checkpoint_at:
                        engine.save_state(ev_ts)
                        saved = ev_ts
                    if record.offset == flush_at:
                        await engine._flush()
                    if record.offset >= stop_after:
                        break
                else:
                    continue
                break
        return next_tick, saved, last

    async def go():
        total = await collect(cfg, tmp_path)
        # A: checkpoint at 40%, everything stored and committed to 55%, crash at 60%.
        db, a = processor(cfg, store_path, golden.START)
        a.dedup = Deduplicator()
        _, saved, _ = await run(a, stop_after=int(total * 0.6), checkpoint_at=int(total * 0.4),
                                flush_at=int(total * 0.55))
        await a.source.consumer.stop()  # gone, without a flush or a save
        db.close()
        # B: starts from the checkpoint.
        db, b = processor(cfg, store_path, saved)
        b.dedup = Deduplicator()
        b.prepare_resume()
        next_tick, _, _ = await run(b, stop_after=total - 1, start_tick=(saved // golden.TICK + 1) * golden.TICK)
        assert b.source.replayed > 0
        await b._flush()
        b.tick(next_tick)
        await b._flush()
        await b.source.stop()
        db.close()
        return total

    total = asyncio.run(go())
    assert total == expected["events"]["rows"]
    assert golden.summarise_store(Database(store_path)) == expected


def test_a_replaced_worker_rebuilds_its_windows_from_the_bus(tmp_path):
    """Worker A runs the source family on the first half of the traffic and goes; a new
    worker B in the same group rebuilds its windows by replaying the partition up to
    what A committed, then carries on. A and B together raise exactly what one worker
    raises over the whole run: nothing missed, nothing twice."""
    from aiokafka.structs import TopicPartition

    from cerberus.worker import DetectionWorker

    cfg = bus_config(tmp_path)
    cfg.detection_workers = ("source",)

    async def run_worker(group: str, stop_ts: float | None = None) -> list:
        wcfg = bus_config(tmp_path)
        wcfg.kafka_topic, wcfg.kafka_group = cfg.kafka_topic, group
        wcfg.detection_workers, wcfg.detection_family = ("source",), "source"
        db = Database(tmp_path / f"{group}-{uuid.uuid4().hex[:6]}.db")
        engine = Engine(wcfg, db, ConnectorRegistry(), Notifier(db))
        engine.families = {"source"}
        watch = {d.id: d.settings() for d in engine.detectors}
        engine.apply_settings(watch, engine.general_settings())
        worker = DetectionWorker(wcfg, db, engine, publisher=None)
        await worker.source.start()
        found, next_tick, idle, done = [], golden.START + golden.TICK, 0, False
        while idle < 6 and not done:
            got = await worker.source.consumer.getmany(timeout_ms=1000, max_records=500)
            idle = 0 if got else idle + 1
            for tp, records in got.items():
                records = worker.source.after_seek(tp, records)  # as EventSource.batch() does
                key = TopicPartition(tp.topic, tp.partition)
                for record in records:
                    ts = json.loads(record.value)["ts"]
                    if stop_ts is not None and ts > stop_ts:
                        done = True  # gone: this record and the rest are left for the next worker
                        break
                    until = worker.source.replay_until.get(key)
                    in_replay = until is not None and record.offset < until
                    while next_tick <= ts:
                        found += worker.tick(next_tick, replay=in_replay)
                        next_tick += golden.TICK
                    found += worker.handle([record])
                    worker.source.position[key] = record.offset + 1
                await worker.source.commit(worker.source.snapshot())
                if done:
                    break
        if not done:
            found += worker.tick(next_tick)
        replayed, rebuilds = worker.source.replayed, worker.rebuilds
        await worker.source.stop()
        db.close()
        alerts = sorted((b["detector"], b["entity"], b["severity"], b["title"], b["_ts"])
                        for b in (json.loads(v) for _t, _k, v in found))
        return alerts, replayed, rebuilds

    async def go():
        await collect(cfg, tmp_path)
        whole, _, _ = await run_worker(cfg.kafka_group + "-whole")
        middle = whole[len(whole) // 2][4]  # A goes halfway through the alerts
        first, _, _ = await run_worker(cfg.kafka_group + "-ab", stop_ts=middle)
        second, replayed, rebuilds = await run_worker(cfg.kafka_group + "-ab")
        return whole, first, second, replayed, rebuilds

    whole, first, second, replayed, rebuilds = asyncio.run(go())
    assert whole and first and second
    assert replayed > 0 and rebuilds == 1
    assert sorted(first + second) == whole


@pytest.mark.parametrize("scenario", ["worker", "processor"])
def test_a_slow_assignment_still_replays_before_anything_live(tmp_path, monkeypatch, scenario):
    """The consumer can fetch from the committed position while the assignment callback is
    still deciding where to start. Taking two seconds there must change nothing: the new
    partitions are paused until the replay position is set. (Without that, records were
    processed live with empty state first, and their later copies ignored.)"""
    from cerberus.bus import EventSource
    original = EventSource._assigned

    async def slow(self, assigned):
        await asyncio.sleep(2)
        await original(self, assigned)
    monkeypatch.setattr(EventSource, "_assigned", slow)
    if scenario == "worker":
        test_a_replaced_worker_rebuilds_its_windows_from_the_bus(tmp_path)
    else:
        test_a_new_leader_after_a_crash_finds_and_stores_exactly_the_same(tmp_path)


SASL = os.environ.get("CERBERUS_TEST_KAFKA_SASL", "")  # host:port|user|password|mechanism
if os.environ.get("CERBERUS_REQUIRE_BACKENDS") and KAFKA and not SASL:
    raise RuntimeError("CERBERUS_REQUIRE_BACKENDS is set but CERBERUS_TEST_KAFKA_SASL is not")


@pytest.mark.skipif(not SASL, reason="set CERBERUS_TEST_KAFKA_SASL=host:port|user|password|mechanism")
def test_sasl_authentication(tmp_path):
    """Publishing and consuming through a broker that requires SASL (SCRAM), and refusing a
    wrong password."""
    from aiokafka.errors import KafkaError

    from cerberus.models import Event

    bootstrap, user, password, mechanism = SASL.split("|")
    cfg = bus_config(tmp_path)
    cfg.kafka_bootstrap, cfg.kafka_security = bootstrap, "SASL_PLAINTEXT"
    cfg.kafka_sasl_mechanism, cfg.kafka_username, cfg.kafka_password = mechanism, user, password

    async def go():
        await ensure_topics(cfg)
        publisher = Publisher(cfg, tmp_path / "spool", name="sasl")
        await publisher.start()
        ev = Event(ts=1.0, device="fw", source_ip="10.0.0.1", event_type="traffic", message="hello over SASL")
        from cerberus.bus import encode_event
        await publisher.publish([encode_event(ev, ("run", 1))])
        assert not publisher.spool and publisher.published == 1
        await publisher.stop()
        source = EventSource(cfg)
        await source.start()
        got = []
        for _ in range(20):
            got += await source.batch(timeout_ms=1000)
            if got:
                break
        await source.stop()
        return got
    got = asyncio.run(go())
    assert json.loads(got[0].value)["message"] == "hello over SASL"

    wrong = bus_config(tmp_path)
    wrong.kafka_bootstrap, wrong.kafka_security = bootstrap, "SASL_PLAINTEXT"
    wrong.kafka_sasl_mechanism, wrong.kafka_username, wrong.kafka_password = mechanism, user, "not-the-password"
    with pytest.raises(KafkaError):
        asyncio.run(ensure_topics(wrong))
    # Settings that cannot work stop the process with a message.
    from cerberus.bus import _common
    wrong.kafka_password = ""
    with pytest.raises(SystemExit, match="USERNAME"):
        _common(wrong)
