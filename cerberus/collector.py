"""Collector: receive syslog, parse it, publish the events to the message bus.

Collectors hold no state worth keeping, so any number can run behind a load
balancer. Each keeps the connector its devices' last messages matched (so it
tries that connector first) and, when it can reach the shared storage, the
connectors devices are pinned to, refreshed every minute.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time

from . import __version__
from .bus import HEARTBEAT_SECONDS, Heartbeats, Publisher, collector_name, encode_event, family_topic
from .detectors import family_event_types, family_key
from .engine import QUEUE_SIZE, parse_message

log = logging.getLogger("cerberus.collector")

MAX_DEVICES = 20_000
BATCH = 2000


class _Seen:
    __slots__ = ("connector_pin", "connector_seen")

    def __init__(self, pin: str = "", seen: str = ""):
        self.connector_pin, self.connector_seen = pin, seen


class Collector:
    def __init__(self, cfg, connectors, publisher: Publisher, store=None):
        self.cfg = cfg
        self.name = collector_name(cfg)
        self.connectors = connectors
        self.publisher = publisher
        self.store = store
        self.devices: dict[str, _Seen] = {}
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.received = self.dropped = self.parse_errors = 0
        self.run = secrets.token_hex(8)  # this process's run: with seq, a unique id per event
        self.seq = 0
        # Families run by detection workers: (topic, family, event types read).
        self.routes = [(family_topic(cfg, f), f, family_event_types(f)) for f in cfg.detection_workers]
        self.started = time.time()
        self.receiver = None
        self._tasks: list[asyncio.Task] = []

    # --- intake ---------------------------------------------------------------------
    def submit(self, data: bytes, source_ip: str) -> None:
        try:
            self.queue.put_nowait((data, source_ip, time.time()))
        except asyncio.QueueFull:
            self.dropped += 1

    def encode(self, ev) -> list[tuple]:
        """The records for one event: the event topic, and each worker family that reads it,
        keyed by that family's key. Every copy carries the same unique id."""
        self.seq += 1
        key, value = encode_event(ev, (self.run, self.seq))
        out = [(self.publisher.topic, key, value)]
        for topic, family, types in self.routes:
            if ev.event_type in types or "*" in types:
                out.append((topic, family_key(family, ev).encode("utf-8", "replace"), value))
        return out

    def parse(self, data: bytes, source_ip: str, ts: float):
        ev = parse_message(self.cfg, self.connectors, self.devices, data, source_ip, ts)
        seen = self.devices.get(ev.device)
        if seen is None and len(self.devices) < MAX_DEVICES:
            seen = self.devices[ev.device] = _Seen()
        if seen is not None and ev.connector and (ev.connector != "generic" or not seen.connector_seen):
            seen.connector_seen = ev.connector
        return ev

    async def _pipeline(self) -> None:
        queue = self.queue
        while True:
            items = [await queue.get()]
            while len(items) < BATCH and not queue.empty():
                items.append(queue.get_nowait())
            records = []
            for data, source_ip, ts in items:
                self.received += 1
                try:
                    records += self.encode(self.parse(data, source_ip, ts))
                except Exception:
                    self.parse_errors += 1
                    if self.parse_errors <= 20:
                        log.exception("failed to parse a message from %s", source_ip)
            await self.publisher.publish(records)  # back-pressure: the queue fills while this waits

    # --- background --------------------------------------------------------------------
    async def _refresh_pins(self) -> None:
        """Every minute, from shared storage: device pins, and whether to scan for secrets."""
        while self.store is not None:
            try:
                for row in await asyncio.to_thread(self.store.devices_all):
                    seen = self.devices.get(row["id"])
                    if seen is None and len(self.devices) < MAX_DEVICES:
                        seen = self.devices[row["id"]] = _Seen(seen=row.get("connector_seen") or "")
                    if seen is not None:
                        seen.connector_pin = row.get("connector_pin") or ""
                from .secrets_scan import configure_from, ensure_key
                await asyncio.to_thread(ensure_key, self.store)
                configure_from(await asyncio.to_thread(self.store.get_setting, "detectors", {}))
            except Exception as exc:
                log.warning("could not read device pins from storage: %s", exc)
            await asyncio.sleep(60)

    async def _heartbeat(self, heartbeats: Heartbeats) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            if self.publisher.down:
                continue
            try:
                await heartbeats.send(self.publisher.producer, self.status())
            except Exception as exc:
                log.debug("heartbeat not sent: %s", exc)

    def status(self) -> dict:
        spool = self.publisher.spool
        return {"name": self.name, "version": __version__, "sent": time.time(), "uptime": int(time.time() - self.started),
                "received": self.received, "dropped": self.dropped, "parse_errors": self.parse_errors,
                "published": self.publisher.published, "spooled": self.publisher.spooled,
                "spool_bytes": spool.size(), "spool_dropped": spool.dropped, "bus_down": self.publisher.down,
                "bus_error": self.publisher.last_error, "queue": self.queue.qsize(),
                "devices": len(self.devices),
                "tcp_refused": self.receiver.refused if self.receiver else 0}

    async def start(self) -> None:
        await self.publisher.start()
        self._tasks += [asyncio.create_task(c) for c in (
            self._pipeline(), self.publisher.run(), self._refresh_pins(), self._heartbeat(Heartbeats(self.cfg)))]
        log.info("collector %s publishing to %s (topic %s)", self.name, self.cfg.kafka_bootstrap, self.cfg.kafka_topic)

    async def stop(self) -> None:
        # Whatever is still queued is parsed and sent (or spooled) before stopping.
        items = []
        while not self.queue.empty():
            items.append(self.queue.get_nowait())
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        records = []
        for data, source_ip, ts in items:
            try:
                records += self.encode(self.parse(data, source_ip, ts))
            except Exception:
                self.parse_errors += 1
        await self.publisher.publish(records)
        await self.publisher.stop()


def status_app(collector: Collector):
    """The collector's only HTTP endpoints: health and its counters (no data)."""
    from fastapi import FastAPI

    app = FastAPI(title="Cerberus collector", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    @app.get("/status")
    async def status():
        return json.loads(json.dumps(collector.status()))

    from .metrics import COLLECTOR, PUBLISHER, add_endpoint, common, from_status

    async def samples():
        return common("collector", collector.name) + from_status(collector.status(), COLLECTOR + PUBLISHER)
    add_endpoint(app, collector.cfg.metrics_token, samples)

    return app
