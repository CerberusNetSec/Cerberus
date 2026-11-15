"""Detection worker: runs one family of detectors on its share of the events.

Collectors publish every event a family reads to that family's topic, keyed by
the family's key (source address, target host, address pair, port, account).
Workers of one family share the topic's partitions as a consumer group, so
every event for one key reaches the same worker, and each worker keeps the
state for its keys only. Alert candidates go to the candidates topic with the
time they were raised and a unique id; the processor folds them into alerts.

The worker reads detector settings and ignore lists from shared storage every
30 seconds, so changes made on the dashboard reach it. A port worker also
writes the high-risk port counters and publishes a summary of what it holds
for the Risk ports page.

State lives in memory: when a worker restarts, or partitions move between
workers, the sliding windows for the moved keys start again (the high-risk port
history is reloaded from storage).
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time

from . import __version__
from .bus import (HEARTBEAT_SECONDS, Deduplicator, EventSource, Heartbeats, Publisher, candidates_topic,
                  collector_name, encode_candidate, family_topic)
from .models import Event
from .storage import Batch

log = logging.getLogger("cerberus.worker")

SETTINGS_SECONDS = 30
VIEW_SECONDS = 30
RISKPORTS_VIEW = "riskports_view:"


class DetectionWorker:
    def __init__(self, cfg, store, engine, publisher: Publisher, source: EventSource | None = None):
        self.cfg = cfg
        self.family = cfg.detection_family
        self.name = f"{self.family}:{collector_name(cfg)}"
        self.store = store
        self.engine = engine  # runs only this family (engine.families)
        self.publisher = publisher
        self.source = source or EventSource(cfg, topic=family_topic(cfg, self.family),
                                            group=f"{cfg.kafka_group}-{self.family}")
        self.dedup = Deduplicator()
        self.run_id = secrets.token_hex(8)
        self.seq = 0
        self.received = self.candidates = self.errors = 0
        self.started = time.time()
        self.hostile = engine.by_id["hostile_allowed"] if self.family == "source" else None
        self._tasks: list[asyncio.Task] = []

    # --- detection ----------------------------------------------------------------------
    def handle(self, records) -> list[tuple]:
        """Detect on a batch of bus records; returns the candidate records to publish."""
        out: list[tuple] = []
        topic = candidates_topic(self.cfg)

        def emit_at(ts):
            def emit(c):
                self.seq += 1
                out.append((topic, *encode_candidate(c, ts, (self.run_id, self.seq))))
                self.candidates += 1
                # The source family's own alerts mark hostile addresses, as the processor
                # does in one process: every detector that marks one is in this family.
                if self.hostile is not None and self.hostile.enabled:
                    self.hostile.on_alert(c, ts)
            return emit

        for record in records:
            try:
                body = json.loads(record.value)
                uid = body.get("_uid")
                if uid and not self.dedup.fresh(str(uid[0]), int(uid[1]), time.time()):
                    continue
                self.received += 1
                ev = Event.from_dict(body)
                self.engine.detect(ev, ev.ts, emit=emit_at(ev.ts))
            except Exception:
                self.errors += 1
                if self.errors <= 20:
                    log.exception("failed to process an event")
        return out

    def tick(self, now: float) -> list[tuple]:
        out: list[tuple] = []
        topic = candidates_topic(self.cfg)

        def emit(c):
            self.seq += 1
            out.append((topic, *encode_candidate(c, now, (self.run_id, self.seq))))
            self.candidates += 1
        for det in self.engine.detectors:
            if self.engine.runs(det):
                try:
                    det.tick(now, emit if det.enabled else (lambda c: None))
                except Exception:
                    log.exception("detector %s tick failed", det.id)
        return out

    # --- loops ----------------------------------------------------------------------------
    async def _consume(self) -> None:
        while True:
            try:
                records = await self.source.batch()
                if not records:
                    continue
                await self.publisher.publish(self.handle(records))
                await self.source.commit(self.source.snapshot())  # sent, or safely spooled
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("detection batch failed")
                await asyncio.sleep(2)

    async def _ticks(self) -> None:
        while True:
            await asyncio.sleep(10)
            await self.publisher.publish(self.tick(time.time()))

    async def _settings(self) -> None:
        while True:
            await asyncio.sleep(SETTINGS_SECONDS)
            try:
                detectors = await asyncio.to_thread(self.store.get_setting, "detectors", {})
                general = await asyncio.to_thread(self.store.get_setting, "general", {})
                self.engine.apply_settings(detectors or {}, general or {})
            except Exception as exc:
                log.warning("could not reload settings: %s", exc)

    async def _ports(self) -> None:
        """Port family only: counters to storage every second, a summary every 30."""
        rp = self.engine.risk_ports
        last_view = 0.0
        while True:
            await asyncio.sleep(1)
            try:
                rows = rp.drain()
                if rows:
                    await asyncio.to_thread(self.store.write_batch, Batch(ports=rows))
                now = time.time()
                if now - last_view >= VIEW_SECONDS:
                    last_view = now
                    await asyncio.to_thread(self.store.set_setting, RISKPORTS_VIEW + self.name, riskports_view(rp, now))
            except Exception:
                log.exception("writing high-risk port data failed")

    async def _heartbeat(self) -> None:
        heartbeats = Heartbeats(self.cfg)
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            if not self.publisher.down:
                try:
                    await heartbeats.send(self.publisher.producer, self.status())
                except Exception as exc:
                    log.debug("heartbeat not sent: %s", exc)

    def status(self) -> dict:
        return {"name": self.name, "role": "detector", "family": self.family, "version": __version__,
                "sent": time.time(), "uptime": int(time.time() - self.started), "received": self.received,
                "candidates": self.candidates, "duplicates": self.dedup.duplicates, "errors": self.errors,
                "published": self.publisher.published, "spooled": self.publisher.spooled,
                "spool_bytes": self.publisher.spool.size(), "spool_dropped": self.publisher.spool.dropped,
                "bus_down": self.publisher.down, "bus_error": self.publisher.last_error}

    async def start(self) -> None:
        self.engine.apply_settings(self.store.get_setting("detectors", {}) or {},
                                   self.store.get_setting("general", {}) or {})
        if self.family == "port":
            now = time.time()
            self.engine.risk_ports.restore_rows(self.store.port_minutes_since(int(now - 27 * 3600)), now)
            self.engine.risk_ports._unsaved = {}  # what was just read back is already stored
        await self.publisher.start()
        await self.source.start()
        loops = [self._consume(), self._ticks(), self._settings(), self._heartbeat(), self.publisher.run()]
        if self.family == "port":
            loops.append(self._ports())
        self._tasks = [asyncio.create_task(c) for c in loops]
        log.info("detection worker %s: %s", self.name,
                 ", ".join(d.id for d in self.engine.detectors if self.engine.runs(d)))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.publisher.stop()
        await self.source.stop()


def riskports_view(rp, now: float) -> dict:
    """What the Risk ports page needs from a port worker's memory."""
    from .riskports import DIRECTIONS
    fresh: dict[str, int] = {}
    for (port, _way, _src), first in list(rp.first_seen.items()):
        if now - first < 86400 and first - rp.since > 6 * 3600:
            fresh[str(port)] = fresh.get(str(port), 0) + 1
    talkers = {}
    for port in sorted(rp.ports):
        tops = {way: rp.top(port, way, now) for way in DIRECTIONS}
        if any(t["sources"] or t["destinations"] for t in tops.values()):
            talkers[str(port)] = tops
    return {"at": now, "since": rp.since, "spikes": rp.spikes(now) if rp.enabled else [], "fresh": fresh,
            "talkers": talkers}
