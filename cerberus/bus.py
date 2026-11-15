"""The message bus between collectors and the processor (Kafka or anything that
speaks its protocol, such as Redpanda).

Collectors publish every parsed event to one topic, keyed by device so each
device's events stay in order, plus a heartbeat every 15 seconds to a second
topic. The processor consumes both, and commits its position in the event
topic only after the events up to it have been written to storage (at least
once: after a crash it may see a few seconds of events again).

When the bus cannot be reached a collector keeps working: events go to a
spool on disk, oldest first, and are sent in order once the bus is back. The
spool has a size limit; past it the oldest spooled events are dropped and
counted.

Every collector spools into its own folder (spool/<collector name>/), which it
holds with an exclusive lock while it runs. Collectors may share one volume:
a folder whose lock nobody holds belongs to a collector that has gone (a
replaced container), and a running collector adopts it and sends what is in it.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import ssl
import time
from pathlib import Path

try:
    import fcntl  # file locks: Linux and other Unixes, which is where collectors run
except ImportError:  # Windows (development): no adoption of other collectors' spools
    fcntl = None

log = logging.getLogger("cerberus.bus")

HEARTBEAT_SECONDS = 15
SPOOL_FILE_EVENTS = 20_000  # events per spool file


def _ssl_context(cfg) -> ssl.SSLContext | None:
    if cfg.kafka_security != "SSL":
        return None
    context = ssl.create_default_context(cafile=cfg.kafka_ca or None)
    return context


def _common(cfg) -> dict:
    return {"bootstrap_servers": cfg.kafka_bootstrap, "security_protocol": cfg.kafka_security,
            "ssl_context": _ssl_context(cfg)}


async def ensure_topics(cfg) -> None:
    """Create the topics if the cluster does not have them (and allows it)."""
    from aiokafka.admin import AIOKafkaAdminClient, NewTopic
    from aiokafka.errors import KafkaError

    admin = AIOKafkaAdminClient(**_common(cfg))
    await admin.start()
    try:
        have = set(await admin.list_topics())
        wanted = [NewTopic(cfg.kafka_topic, cfg.kafka_partitions, cfg.kafka_replication),
                  NewTopic(cfg.kafka_topic + ".collectors", 1, cfg.kafka_replication)]
        if cfg.detection_workers:
            wanted += [NewTopic(family_topic(cfg, f), cfg.kafka_partitions, cfg.kafka_replication)
                       for f in cfg.detection_workers]
            wanted.append(NewTopic(candidates_topic(cfg), cfg.kafka_partitions, cfg.kafka_replication))
        missing = [t for t in wanted if t.name not in have]
        if missing:
            try:
                await admin.create_topics(missing)
                log.info("created topics: %s", ", ".join(t.name for t in missing))
            except KafkaError as exc:  # another node created it first, or no permission
                log.warning("could not create topics (%s); assuming they are managed elsewhere", exc)
    finally:
        await admin.close()


def encode_event(ev, uid: tuple[str, int] | None = None) -> tuple[bytes, bytes]:
    """(key, value) for one Event. uid (collector run, sequence number) lets the processor
    recognise a copy: after a bus outage a collector cannot always tell whether a send it
    was told had failed was delivered anyway, so it sends again and the processor decides."""
    body = ev.as_dict()
    if uid is not None:
        body["_uid"] = list(uid)
    return ev.device.encode("utf-8", "replace"), json.dumps(body, separators=(",", ":")).encode()


class Deduplicator:
    """Which (collector run, sequence number) pairs the processor has already seen: per
    run, a bitmap over the most recent WINDOW numbers. Older numbers than that cannot be
    told apart and are accepted."""

    WINDOW = 1 << 21  # numbers remembered per collector run (256 KB each)
    MAX_RUNS = 1000

    def __init__(self):
        self.runs: dict[str, list] = {}  # run -> [highest seen, bitmap, last used]
        self.duplicates = 0
        self.unverifiable = 0

    def fresh(self, run: str, seq: int, now: float = 0.0) -> bool:
        state = self.runs.get(run)
        if state is None:
            if len(self.runs) >= self.MAX_RUNS:
                oldest = min(self.runs, key=lambda r: self.runs[r][2])
                del self.runs[oldest]
            state = self.runs[run] = [-1, bytearray(self.WINDOW // 8), now]
        state[2] = now
        high, bits = state[0], state[1]
        if seq > high:
            # Slide the window forward, forgetting the numbers that fall out of it. Over a
            # run this clears each position once per number, so it costs O(1) per event.
            if seq - high >= self.WINDOW:
                bits[:] = bytes(len(bits))
            else:
                for n in range(high + 1, seq + 1):
                    bits[(n % self.WINDOW) >> 3] &= ~(1 << (n & 7)) & 0xFF
            state[0] = seq
        elif seq <= high - self.WINDOW:
            self.unverifiable += 1
            return True
        index, mask = (seq % self.WINDOW) >> 3, 1 << (seq & 7)
        if bits[index] & mask:
            self.duplicates += 1
            return False
        bits[index] |= mask
        return True


def _lock(directory: Path):
    """Hold directory/.lock exclusively; None if another process holds it."""
    directory.mkdir(parents=True, exist_ok=True)
    handle = open(directory / ".lock", "a+")
    if fcntl is not None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return None
    return handle


class Spool:
    """Events waiting on disk for the bus to come back: numbered files of
    JSON lines [key, value], read oldest first."""

    def __init__(self, directory: Path, limit_bytes: int, lock: bool = True):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.handle = _lock(directory) if lock else None
        if lock and self.handle is None:
            raise RuntimeError(f"spool {directory} is in use by another collector with the same name")
        self.limit = limit_bytes
        self.dropped = 0
        files = self.files()
        self._next = int(files[-1].stem) + 1 if files else 1
        self._open = None
        self._open_count = 0

    def files(self) -> list[Path]:
        return sorted(self.dir.glob("*.jsonl"))

    def size(self) -> int:
        return sum(f.stat().st_size for f in self.files())

    def events(self) -> int:
        total = 0
        for f in self.files():
            with open(f, "rb") as fh:
                total += sum(1 for _ in fh)
        return total

    def __bool__(self) -> bool:
        return bool(self.files())

    def append(self, records: list[tuple]) -> None:
        """records: (topic, key, value); a spool line is [topic, key, value]."""
        for topic, key, value in records:
            if self._open is None or self._open_count >= SPOOL_FILE_EVENTS:
                self._close_open()
                self._open = open(self.dir / f"{self._next:012d}.jsonl", "ab")
                self._next += 1
                self._open_count = 0
            self._open.write(json.dumps([topic, key.decode("utf-8", "replace"), value.decode()]).encode() + b"\n")
            self._open_count += 1
        self._open.flush()
        while self.size() > self.limit and len(self.files()) > 1:
            oldest = self.files()[0]
            with open(oldest, "rb") as fh:
                self.dropped += sum(1 for _ in fh)
            oldest.unlink()
            log.warning("spool over its limit: dropped the oldest %s", oldest.name)

    def _close_open(self) -> None:
        if self._open is not None:
            self._open.close()
            self._open = None

    def close(self) -> None:
        self._close_open()
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def oldest(self, default_topic: str = "") -> tuple[Path, list[tuple]] | None:
        files = self.files()
        if not files:
            return None
        if self._open is not None and Path(self._open.name) == files[0]:
            self._close_open()  # sending the file being written: start a new one for what follows
        with open(files[0], "rb") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        # 0.5.0 spooled [key, value], all for the event topic.
        return files[0], [(r[0], r[1].encode(), r[2].encode()) if len(r) == 3 else (default_topic, r[0].encode(), r[1].encode())
                          for r in rows]


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:100] or "collector"


class Publisher:
    """Sends events to the bus, or to the spool while the bus is unreachable."""

    def __init__(self, cfg, spool_root: Path, producer=None, name: str = ""):
        self.cfg = cfg
        self.topic = cfg.kafka_topic
        self.root = spool_root
        self.name = _safe_name(name or collector_name(cfg))
        self.spool = Spool(spool_root / self.name, cfg.spool_mb * 1024 * 1024)
        self.producer = producer
        self._made_producer = producer is None
        self.started = False
        self.published = 0
        self.spooled = 0
        self.adopted = 0  # events sent from the spools of collectors that have gone
        self.down = False
        self.last_error = ""

    def _new_producer(self):
        from aiokafka import AIOKafkaProducer
        return AIOKafkaProducer(**_common(self.cfg), acks="all", linger_ms=20, compression_type="lz4",
                                max_batch_size=1 << 20, request_timeout_ms=15000, enable_idempotence=True)

    async def _ensure_started(self) -> None:
        if self.started:
            return
        if self.producer is None:
            self.producer = self._new_producer()
        try:
            await self.producer.start()
            self.started = True
        except Exception:
            if self._made_producer:  # a producer that failed to start cannot be started again
                try:
                    await self.producer.stop()
                except Exception:
                    pass
                self.producer = None
            raise

    async def start(self) -> None:
        try:
            await self._ensure_started()
        except Exception as exc:  # the bus is down at start: spool until it is back
            self._went_down(exc)

    async def stop(self) -> None:
        self.spool.close()
        if self.producer is not None:
            try:
                await self.producer.stop()
            except Exception:
                pass

    def _went_down(self, exc: Exception) -> None:
        if not self.down:
            log.warning("message bus unreachable, spooling to disk: %s", exc)
        self.down = True
        self.last_error = str(exc)[:200] or type(exc).__name__

    def _with_topic(self, records: list[tuple]) -> list[tuple]:
        """(key, value) pairs go to the event topic; (topic, key, value) to their own."""
        return [r if len(r) == 3 else (self.topic, *r) for r in records]

    async def _send(self, records: list[tuple]) -> None:
        await self._ensure_started()
        futures = [await self.producer.send(topic, value, key=key) for topic, key, value in records]
        await asyncio.gather(*futures)

    async def publish(self, records: list[tuple]) -> None:
        """Send a batch, keeping order with anything already spooled."""
        if not records:
            return
        records = self._with_topic(records)
        if self.down or self.spool:
            self.spool.append(records)
            self.spooled += len(records)
            return
        try:
            await self._send(records)
            self.published += len(records)
        except Exception as exc:
            self._went_down(exc)
            self.spool.append(records)
            self.spooled += len(records)

    async def drain_spool(self) -> bool:
        """Send spooled events, oldest first. Returns True when the spool is empty."""
        while True:
            item = self.spool.oldest(self.topic)
            if item is None:
                if self.down:
                    log.info("message bus reachable again; spool sent")
                self.down, self.last_error = False, ""
                return True
            path, records = item
            try:
                await self._send(records)
            except Exception as exc:
                self._went_down(exc)
                return False
            path.unlink()
            self.published += len(records)

    async def adopt_orphans(self) -> None:
        """Send what collectors that have gone left in their spools on the shared volume."""
        if fcntl is None or self.down:
            return
        for directory in sorted(p for p in self.root.iterdir() if p.is_dir() and p.name != self.name):
            handle = _lock(directory)
            if handle is None:
                continue  # its collector is running
            orphan = Spool(directory, self.spool.limit, lock=False)
            try:
                while (item := orphan.oldest(self.topic)) is not None:
                    path, records = item
                    await self._send(records)
                    path.unlink()
                    self.adopted += len(records)
                    self.published += len(records)
                shutil.rmtree(directory, ignore_errors=True)
                log.info("sent the spool left by collector %s", directory.name)
            except Exception as exc:
                self._went_down(exc)
            finally:
                handle.close()

    async def run(self) -> None:
        """Keep trying to empty the spool, and pick up spools left by collectors that have gone."""
        last_adopt = 0.0
        while True:
            await asyncio.sleep(2)
            try:
                if self.spool or self.down:
                    await self.drain_spool()
                if time.monotonic() - last_adopt > 30:
                    last_adopt = time.monotonic()
                    await self.adopt_orphans()
            except Exception:
                log.exception("sending spooled events failed")


class Heartbeats:
    """Collector side: a status message every few seconds. Processor side: the latest
    status of every collector."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.topic = cfg.kafka_topic + ".collectors"
        self.latest: dict[str, dict] = {}
        self.consumer = None

    async def send(self, producer, status: dict) -> None:
        await producer.send_and_wait(self.topic, json.dumps(status).encode(), key=status["name"].encode())

    async def watch(self) -> None:
        from aiokafka import AIOKafkaConsumer
        while True:
            try:
                self.consumer = AIOKafkaConsumer(self.topic, **_common(self.cfg), group_id=None,
                                                 auto_offset_reset="latest", enable_auto_commit=False)
                await self.consumer.start()
                async for record in self.consumer:
                    try:
                        status = json.loads(record.value)
                        status["received_at"] = time.time()
                        self.latest[str(status.get("name"))[:100]] = status
                    except ValueError:
                        continue
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("collector heartbeats unavailable: %s", exc)
                await asyncio.sleep(5)
            finally:
                if self.consumer is not None:
                    try:
                        await self.consumer.stop()
                    except Exception:
                        pass


def family_topic(cfg, family: str) -> str:
    return f"{cfg.kafka_topic}.{family}"


def candidates_topic(cfg) -> str:
    return f"{cfg.kafka_topic}.candidates"


def encode_candidate(c, ts: float, uid: tuple[str, int]) -> tuple[str, bytes, bytes]:
    """(topic-less key, value) for an alert candidate from a detection worker."""
    body = {**c.as_dict(), "_ts": ts, "_uid": list(uid)}
    return f"{c.detector}|{c.entity}".encode("utf-8", "replace"), json.dumps(body, separators=(",", ":")).encode()


def _tp_key(tp) -> str:
    return f"{tp.topic}:{tp.partition}"


class EventSource:
    """Consuming one topic, and committing only what has been dealt with.

    Resuming from a checkpoint: resume holds, per partition, the position the saved
    detector state was taken at. When the partition is assigned and that is behind the
    committed position, the source goes back to it, and records before the committed
    position are a replay (replaying()): already stored, to be seen by the detectors only."""

    def __init__(self, cfg, consumer=None, topic: str = "", group: str = ""):
        self.cfg = cfg
        self.consumer = consumer
        self.topic = topic or cfg.kafka_topic
        self.group = group or cfg.kafka_group
        self.position: dict = {}  # TopicPartition -> offset of the next record to process
        self.resume: dict[str, int] = {}  # "topic:partition" -> where the checkpoint was taken
        self.replay_until: dict = {}  # TopicPartition -> committed offset: below it, a replay
        self.replayed = 0
        self.on_assign = None  # optional: async (consumer, assigned partitions) -> None, instead of resume

    async def start(self) -> None:
        if self.consumer is None:
            from aiokafka import AIOKafkaConsumer
            from aiokafka.abc import ConsumerRebalanceListener
            source = self

            class Listener(ConsumerRebalanceListener):
                async def on_partitions_revoked(self, revoked):
                    pass

                async def on_partitions_assigned(self, assigned):
                    await source.assigned(assigned)

            self.consumer = AIOKafkaConsumer(
                **_common(self.cfg), group_id=self.group,
                enable_auto_commit=False, auto_offset_reset="earliest", max_poll_records=5000,
                fetch_max_bytes=64 * 1024 * 1024)
            self.consumer.subscribe([self.topic], listener=Listener())
        await self.consumer.start()

    async def assigned(self, assigned) -> None:
        if self.on_assign is not None:
            await self.on_assign(assigned)
            return
        for tp in assigned:
            back = self.resume.pop(_tp_key(tp), None)
            if back is None:
                continue
            committed = await self.consumer.committed(tp)
            if committed is not None and back < committed:
                self.consumer.seek(tp, back)
                self.replay_until[tp] = committed
                log.info("%s partition %d: replaying %d records from the checkpoint to rebuild detector state",
                         tp.topic, tp.partition, committed - back)

    def replaying(self, record) -> bool:
        if not self.replay_until:
            return False
        from aiokafka.structs import TopicPartition
        tp = TopicPartition(record.topic, record.partition)
        until = self.replay_until.get(tp)
        if until is None:
            return False
        if record.offset < until:
            self.replayed += 1
            return True
        del self.replay_until[tp]
        return False

    async def rewind(self, assigned, seconds: float) -> int:
        """Go back seconds on each partition (by the time records were published), marking
        what lies before the committed position as a replay. Returns the records to replay."""
        self.replay_until = {}
        since = int((time.time() - seconds) * 1000)
        found = await self.consumer.offsets_for_times({tp: since for tp in assigned}) if assigned else {}
        total = 0
        for tp in assigned:
            committed = await self.consumer.committed(tp)
            at = found.get(tp)
            if committed is None or at is None or at.offset >= committed:
                continue
            self.consumer.seek(tp, at.offset)
            self.replay_until[tp] = committed
            total += committed - at.offset
        return total

    def positions(self) -> dict[str, int]:
        """The position, per partition, as stored with a checkpoint."""
        return {_tp_key(tp): offset for tp, offset in self.position.items()}

    async def stop(self) -> None:
        await self.consumer.stop()

    async def batch(self, timeout_ms: int = 500) -> list:
        """The next records, in order within each partition."""
        got = await self.consumer.getmany(timeout_ms=timeout_ms, max_records=5000)
        out = []
        for tp, records in got.items():
            out += records
            if records:
                self.position[tp] = records[-1].offset + 1
        return out

    def snapshot(self) -> dict:
        return dict(self.position)

    async def commit(self, offsets: dict) -> None:
        # Never move a partition's committed position back while it is being replayed.
        offsets = {tp: o for tp, o in offsets.items() if tp not in self.replay_until}
        if offsets:
            await self.consumer.commit(offsets)


def collector_name(cfg) -> str:
    return cfg.collector_name or os.environ.get("HOSTNAME", "") or "collector"
