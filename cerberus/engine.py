"""The pipeline: raw datagrams -> events -> detectors -> alerts.

Receivers call submit(); one task drains the queue, and state that needs to
reach disk (events, per-minute stats, device records, alerts) is buffered and
written once a second in a single transaction.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections import Counter, deque
from dataclasses import dataclass

from .config import Config
from .connectors import ConnectorRegistry
from .db import Database
from .detectors import NewDevice, RateAnomaly, build_detectors
from .models import Candidate, Event, sev_rank
from .notifiers import Notifier
from .state import decode, encode
from .storage import TOTAL, Batch
from .syslog_parser import parse_syslog

log = logging.getLogger("cerberus.engine")

QUEUE_SIZE = 50_000
TOP_KEYS_PER_MINUTE = 20_000
MAX_DEVICES = 5000
MAX_PENDING_EVENTS = 200_000  # events waiting to be written; beyond this the disk is not keeping up
STATE_KEY = "engine_state"  # settings row holding the detectors' working state
STATE_VERSION = 1
STATE_SAVE_SECONDS = 300
CHECKPOINT_SECONDS = 60  # processor: how much a new leader replays from the bus at most
# Detectors keyed on a source address; the ignore list applies to these.
_SOURCE_KEYED = {"port_scan", "host_sweep", "deny_flood", "brute_force", "large_transfer", "threat",
                 "risky_egress", "lateral_movement", "beaconing", "password_spray", "distributed_guessing",
                 "hostile_allowed", "correlation",
                 "risk_ports"}
# Detectors about a destination; the ignored-destinations list applies to these.
_DEST_KEYED = {"exposed_service", "risky_egress", "beaconing", "large_transfer"}


def parse_message(cfg: Config, connectors: ConnectorRegistry, devices: dict, data: bytes | str, source_ip: str,
                  ts: float, pin: str | None = None) -> Event:
    """Syslog bytes to a normalised Event. devices maps device id to anything with
    connector_pin and connector_seen (a device pinned to a connector, and the connector
    its last message matched); pin overrides both."""
    parsed = parse_syslog(data)
    device_id = source_ip
    if cfg.device_identity == "hostname" and parsed["hostname"]:
        device_id = parsed["hostname"]
    hint = ""
    if pin is None:
        dev = devices.get(device_id)
        pin, hint = (dev.connector_pin, dev.connector_seen) if dev else ("", "")
    ev = connectors.build_event(parsed, ts, device_id, source_ip, pin, hint)
    if cfg.device_identity == "hostname" and ev.hostname and ev.device != ev.hostname:
        ev.device = ev.hostname  # the connector found a hostname the envelope did not have
    return ev


def migrate_detector_settings(detectors: dict) -> dict:
    """Settings saved before 0.6.0, when password spraying and distributed guessing were
    one detector (credential_attacks) and correlation included hostile_allowed."""
    detectors = dict(detectors or {})
    old = detectors.get("credential_attacks")
    if isinstance(old, dict):
        on = old.get("enabled", True)
        detectors.setdefault("password_spray", {"enabled": on, **{k: old[k] for k in ("users", "window") if k in old}})
        detectors.setdefault("distributed_guessing",
                             {"enabled": on, **{k: old[k] for k in ("sources", "window") if k in old}})
    corr = detectors.get("correlation")
    if isinstance(corr, dict) and "hostile_allowed" not in detectors:
        detectors["hostile_allowed"] = {"enabled": corr.get("enabled", True),
                                        **{k: corr[k] for k in ("window_hours",) if k in corr}}
    return detectors


def migrate_snapshot(snap: dict) -> dict:
    """Detector state saved before 0.6.0: split the old combined detectors' state."""
    dets = dict(snap.get("detectors") or {})
    old = dets.pop("credential_attacks", None)
    if old is not None and "password_spray" not in dets:
        try:
            state = decode(old.get("_state"))
            emitted = decode(old.get("_emitted"))
            for new, tag in (("password_spray", "spray"), ("distributed_guessing", "dist")):
                dets[new] = {"_state": encode({k: v for k, v in state.items() if k[0] == tag}),
                             "_emitted": encode({k: v for k, v in emitted.items() if k[0] == tag})}
        except (TypeError, ValueError, KeyError, AttributeError, IndexError):
            pass
    corr = dets.get("correlation")
    if corr is not None and "hostile" in corr and "hostile_allowed" not in dets:
        try:
            emitted = decode(corr.get("_emitted"))
            dets["hostile_allowed"] = {"_state": encode({}), "hostile": corr["hostile"],
                                       "_emitted": encode({k: v for k, v in emitted.items() if k[0] == "hostile"})}
            dets["correlation"] = {"_state": corr.get("_state"), "hosts": corr.get("hosts"),
                                   "_emitted": encode({k: v for k, v in emitted.items() if k[0] == "host"})}
        except (TypeError, ValueError, KeyError, AttributeError, IndexError):
            pass
    return {**snap, "detectors": dets}


@dataclass
class Device:
    id: str
    ip: str
    hostname: str = ""
    name: str = ""
    connector_pin: str = ""
    connector_seen: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    events: int = 0
    snmp_mode: str = "default"  # "default" (global community), "custom" or "off"
    snmp_community: str = ""
    snmp_host: str = ""  # poll this address[:port] instead of `ip`
    dirty: bool = False

    def as_dict(self) -> dict:
        """Public view: the community string never leaves the server."""
        out = {k: v for k, v in self.__dict__.items() if k not in ("dirty", "snmp_community")}
        out["snmp_has_community"] = bool(self.snmp_community)
        return out


@dataclass
class _Active:
    id: int
    severity: str
    last_seen: float
    count: int
    status: str
    description: str
    details: dict
    dirty: bool = False


class AlertManager:
    """Folds repeated candidates for the same entity into one alert."""

    def __init__(self, db: Database, notifier: Notifier):
        self.db = db
        self.notifier = notifier
        self.cooldown = 1800.0
        self.active: dict[str, _Active] = {}
        self.next_id = 1
        self.new_rows: list[tuple] = []

    def load(self, now: float | None = None) -> None:
        self.next_id = self.db.alert_next_id()
        rows = self.db.alerts_active_since((time.time() if now is None else now) - self.cooldown)
        for row in rows:
            self.active[f"{row['detector']}|{row['entity']}"] = _Active(
                row["id"], row["severity"], row["last_seen"], row["count"], row["status"],
                row["description"], json.loads(row["details"] or "{}"),
            )

    def raise_(self, c: Candidate, now: float) -> None:
        key = f"{c.detector}|{c.entity}"
        cur = self.active.get(key)
        if cur and now - cur.last_seen <= self.cooldown:
            cur.last_seen = now
            cur.count += 1
            cur.description = c.description
            cur.details = c.details
            cur.dirty = True
            if sev_rank(c.severity) > sev_rank(cur.severity):
                cur.severity = c.severity
                self.notifier.notify(self._as_alert(cur.id, c, now))
            return
        alert_id = self.next_id
        self.next_id += 1
        self.active[key] = _Active(alert_id, c.severity, now, 1, "open", c.description, c.details)
        self.new_rows.append((
            alert_id, now, now, c.detector, c.severity, c.title[:200], c.description[:1000],
            c.entity[:300], c.src_ip, c.device, 1, "open", json.dumps(c.details)[:4000],
        ))
        log.info("ALERT [%s] %s", c.severity, c.title)
        self.notifier.notify(self._as_alert(alert_id, c, now))

    @staticmethod
    def _as_alert(alert_id: int, c: Candidate, now: float) -> dict:
        return {"id": alert_id, "created": now, "severity": c.severity, "title": c.title,
                "description": c.description, "device": c.device, "src_ip": c.src_ip,
                "detector": c.detector, "details": c.details}

    def drain(self) -> tuple[list[tuple], list[tuple]]:
        """New alerts and changed alerts since the last flush, as Batch rows."""
        stamp = time.time()  # wall clock, so a site's report cursor only moves forward
        updates = []
        for cur in self.active.values():
            if cur.dirty:
                cur.dirty = False
                updates.append((cur.last_seen, cur.count, cur.severity, cur.description[:1000],
                                json.dumps(cur.details)[:4000], stamp, cur.id))
        new_rows, self.new_rows = self.new_rows, []
        return [(*row, stamp) for row in new_rows], updates

    def set_status(self, ids: list[int], status: str) -> None:
        wanted = set(ids)
        for key, cur in list(self.active.items()):
            if cur.id in wanted:
                if status == "resolved":
                    del self.active[key]  # a recurrence becomes a fresh alert
                else:
                    cur.status = status

    def expire(self, now: float) -> None:
        # An alert with a change not yet written stays until the next flush has written it.
        for key in [k for k, v in self.active.items() if now - v.last_seen > self.cooldown and not v.dirty]:
            del self.active[key]


class Engine:
    def __init__(self, cfg: Config, db: Database, connectors: ConnectorRegistry, notifier: Notifier):
        self.cfg = cfg
        self.db = db
        self.connectors = connectors
        self.notifier = notifier
        self.alerts = AlertManager(db, notifier)
        self.detectors = build_detectors()
        self.by_id = {d.id: d for d in self.detectors}
        self._for_type: dict[str, list] = {}  # event type -> detectors that read it, in order
        self.baselines = next(d for d in self.detectors if isinstance(d, RateAnomaly)).baselines
        self.new_device: NewDevice = self.by_id["new_device"]  # type: ignore[assignment]
        self.correlation = self.by_id["correlation"]
        self.hostile = self.by_id["hostile_allowed"]
        self.admin_access = self.by_id["admin_access"]
        self.risk_ports = self.by_id["risk_ports"]
        self.ignore_destinations: list[str] = []
        self._ignore_dst_nets: list = []
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.devices: dict[str, Device] = {}
        self.ignore_sources: list[str] = []
        self._ignore_nets: list = []
        self._ignore_cache: dict[str, bool] = {}
        self.started = time.time()
        self.installed = self.started
        self.received = 0
        self.dropped = 0
        self.unstored = 0  # allowed-traffic events analysed but not written (CERBERUS_TRAFFIC_SAMPLE)
        self.unwritten = 0  # events analysed but not written because the disk fell behind
        self.refused_devices = 0  # messages from sources beyond MAX_DEVICES
        self.flush_seconds = 0.0  # how long the last write to disk took
        self._sample = 0
        self.parse_errors = 0
        self._events: list[tuple] = []
        self._stats: dict[tuple[int, str], list[int]] = {}
        self._tops: deque = deque(maxlen=60)  # (minute, Counter(src), Counter(port))
        self._rate: deque = deque(maxlen=7)
        self._tasks: list[asyncio.Task] = []
        self.receiver = None  # set by __main__, for the health figures on the dashboard
        # Which detector partitions this engine runs: None for all. The processor leaves out the
        # families detection workers run; a worker runs only its own.
        self.families: set | None = None
        self.candidates = None  # processor with workers: a bus.EventSource of their alert candidates
        self.candidate_dedup = None
        self.source = None  # processor mode: a bus.EventSource; events come from collectors
        self.dedup = None  # processor mode: a bus.Deduplicator
        self._committed: dict = {}
        self._committed_candidates: dict = {}
        self._replaying = False  # the event or candidate in hand was already stored before a takeover

    # --- lifecycle -------------------------------------------------------
    def load(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        for row in self.db.devices_all():
            self.devices[row["id"]] = Device(**{k: ("" if v is None else v) for k, v in row.items()})
        self.installed = self.db.get_setting("installed")
        if not self.installed:
            self.installed = time.time()
            self.db.set_setting("installed", self.installed)
        self.db.ensure_stats_totals()  # databases from before the all-devices counter row
        self.apply_settings(self.db.get_setting("detectors", {}), self.db.get_setting("general", {}))
        restored = self.restore(self.db.get_setting(STATE_KEY) or {}, now)
        if "admin_access" not in restored:
            self.admin_access.restore_legacy(self.db.get_setting("admin_sources", {}))
        if "risk_ports" not in restored:
            self.risk_ports.restore_rows(self.db.port_minutes_since(int(now - 27 * 3600)), now)
        self.alerts.load(now)

    def apply_settings(self, detectors: dict, general: dict) -> None:
        detectors = migrate_detector_settings(detectors)
        for det in self.detectors:
            det.configure(detectors.get(det.id, {}))
        def networks(items) -> tuple[list[str], list]:
            nets, kept = [], []
            for item in items if isinstance(items, list) else []:
                try:
                    nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
                    kept.append(str(item).strip())
                except ValueError:
                    continue
            return kept, nets

        self.ignore_sources, self._ignore_nets = networks(general.get("ignore_sources", []))
        self.ignore_destinations, self._ignore_dst_nets = networks(general.get("ignore_destinations", []))
        self._ignore_cache = {}
        try:
            self.alerts.cooldown = max(60.0, float(general.get("cooldown_minutes", 30)) * 60)
        except (TypeError, ValueError):
            self.alerts.cooldown = 1800.0

    def general_settings(self) -> dict:
        return {"ignore_sources": self.ignore_sources, "ignore_destinations": self.ignore_destinations,
                "cooldown_minutes": int(self.alerts.cooldown // 60)}

    def runs(self, det) -> bool:
        return self.families is None or det.partition in self.families

    def raise_alert(self, c: Candidate, now: float) -> None:
        """The alert stage: fold the candidate into an alert, and let the correlator see it.
        In a replay the alert is already stored (and notified): only the detectors that
        read the alert stream learn from it again."""
        if not self._replaying:
            self.alerts.raise_(c, now)
        if self.hostile.enabled and self.runs(self.hostile):  # with a source worker, it marks there
            self.hostile.on_alert(c, now)
        if self.correlation.enabled:
            self.correlation.on_alert(c, now, lambda found: None if self._replaying else self.alerts.raise_(found, now))

    # --- working state ---------------------------------------------------
    def snapshot(self, now: float | None = None) -> dict:
        """Everything the detectors have learned and are counting, as JSON-compatible data,
        with the bus position it matches (processor). Call on the event-loop thread: it
        reads state the pipeline is changing."""
        snap = {"version": STATE_VERSION, "saved": time.time() if now is None else now,
                "detectors": {d.id: d.snapshot() for d in self.detectors},
                "baselines": encode(self.baselines), "tops": encode(self._tops)}
        if self.source:
            snap["bus"] = {"events": self.source.positions(),
                           "candidates": self.candidates.positions() if self.candidates else {}}
        return snap

    def prepare_resume(self) -> None:
        """Processor, before its sources start: go back on the bus to where the saved state
        was taken, so a new leader's detectors see every event the old one's had seen."""
        bus = (self.db.get_setting(STATE_KEY) or {}).get("bus") or {}
        if self.source:
            self.source.resume = dict(bus.get("events") or {})
        if self.candidates:
            self.candidates.resume = dict(bus.get("candidates") or {})

    def restore(self, snap: dict, now: float) -> set[str]:
        """Load a snapshot; returns the ids of the detectors restored. A detector whose
        state does not load starts empty, as it would have without a snapshot."""
        if not snap or snap.get("version") != STATE_VERSION:
            return set()
        snap = migrate_snapshot(snap)
        restored = set()
        for det in self.detectors:
            data = snap.get("detectors", {}).get(det.id)
            if data is None:
                continue
            try:
                det.restore(data)
                restored.add(det.id)
            except (TypeError, ValueError, KeyError, AttributeError):
                log.warning("could not restore the state of detector %s; it starts empty", det.id)
        try:
            # In place: RateAnomaly and DeviceSilent share this object.
            loaded = decode(snap.get("baselines"))
            self.baselines.devices, self.baselines.minute = loaded.devices, loaded.minute
            if now - float(snap.get("saved", now)) > 60:
                # Cerberus itself was down: devices were not silent, it was not listening.
                for base in self.baselines.devices.values():
                    base.last_seen = max(base.last_seen, now)
            self._tops = decode(snap.get("tops"))
        except (TypeError, ValueError, KeyError, AttributeError):
            log.warning("could not restore rate baselines; they warm up again")
        return restored

    def save_state(self, now: float | None = None) -> None:
        """Snapshot and store, synchronously (tests and shutdown)."""
        self.db.set_setting(STATE_KEY, self.snapshot(now))

    async def save_state_async(self) -> None:
        snap = self.snapshot()  # here, on the loop; the write goes to a thread
        await asyncio.to_thread(self.db.set_setting, STATE_KEY, snap)

    async def start(self) -> None:
        await asyncio.to_thread(self.load)
        intake = self._consume() if self.source else self._pipeline()
        loops = [intake, self._flush_loop(), self._tick_loop(), self._prune_loop()]
        if self.candidates:
            loops.append(self._consume_candidates())
        for coro in loops:
            self._tasks.append(asyncio.create_task(coro))

    async def _consume_candidates(self) -> None:
        """Processor with detection workers: their alert candidates, into the alert stage."""
        while True:
            try:
                records = await self.candidates.batch()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("reading alert candidates from the message bus failed")
                await asyncio.sleep(2)
                continue
            for record in records:
                self.take_candidate(record)
            await asyncio.sleep(0)

    def take_candidate(self, record) -> None:
        try:
            body = json.loads(record.value)
            uid = body.get("_uid")
            if uid and not self.candidate_dedup.fresh(str(uid[0]), int(uid[1]), time.time()):
                return
            self._replaying = self.candidates.replaying(record)
            self.raise_alert(Candidate.from_dict(body), float(body["_ts"]))
        except Exception:
            self.parse_errors += 1
            if self.parse_errors <= 20:
                log.exception("failed to process an alert candidate")
        finally:
            self._replaying = False

    async def _consume(self) -> None:
        """Processor mode: parsed events from the collectors, through the bus."""
        while True:
            try:
                records = await self.source.batch()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("reading from the message bus failed")
                await asyncio.sleep(2)
                continue
            for record in records:
                self.take(record)
            await asyncio.sleep(0)

    def take(self, record) -> None:
        """Processor: one event from the bus through record and detect, or, in a replay
        after a takeover, through detection only (it is already stored)."""
        try:
            body = json.loads(record.value)
            uid = body.get("_uid")
            if uid and self.dedup is not None and not self.dedup.fresh(str(uid[0]), int(uid[1]), time.time()):
                return  # a copy of an event already processed
            ev = Event.from_dict(body)
            if self.source.replaying(record):
                self._replaying = self.risk_ports.replaying = True
                if ev.device in self.devices:
                    self._count_blocked(ev, ev.ts)
                    self.detect(ev, ev.ts)
                return
            self.received += 1
            if self.record(ev, ev.ts):
                self.detect(ev, ev.ts)
        except Exception:
            self.parse_errors += 1
            if self.parse_errors <= 20:
                log.exception("failed to process an event from the bus")
        finally:
            self._replaying = self.risk_ports.replaying = False

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        while not self.queue.empty():
            self._process(*self.queue.get_nowait())
        await self._flush()
        await self.save_state_async()

    # --- intake ----------------------------------------------------------
    def submit(self, data: bytes, source_ip: str) -> None:
        try:
            self.queue.put_nowait((data, source_ip, time.time()))
        except asyncio.QueueFull:
            self.dropped += 1

    async def _pipeline(self) -> None:
        queue = self.queue
        while True:
            item = await queue.get()
            self._safe_process(item)
            for _ in range(2000):
                if queue.empty():
                    break
                self._safe_process(queue.get_nowait())
            await asyncio.sleep(0)  # let the web server and receivers breathe under load

    def _safe_process(self, item) -> None:
        try:
            self._process(*item)
        except Exception:
            self.parse_errors += 1
            if self.parse_errors <= 20:
                log.exception("failed to process message from %s", item[1])

    def _ignored(self, ip: str | None, destination: bool = False) -> bool:
        nets = self._ignore_dst_nets if destination else self._ignore_nets
        if not ip or not nets:
            return False
        key = (ip, destination)
        hit = self._ignore_cache.get(key)
        if hit is None:
            try:
                addr = ipaddress.ip_address(ip)
                hit = any(addr.version == net.version and addr in net for net in nets)
            except ValueError:
                hit = False
            if len(self._ignore_cache) > 100_000:
                self._ignore_cache.clear()
            self._ignore_cache[key] = hit
        return hit

    def build_event(self, data: bytes | str, source_ip: str, ts: float, pin: str | None = None) -> Event:
        return parse_message(self.cfg, self.connectors, self.devices, data, source_ip, ts, pin)

    # --- the per-message pipeline -----------------------------------------
    # Three stages, kept apart so that clustering can run them in different
    # processes: parse (bytes -> Event), record (device registry, counters,
    # storage), detect (Event -> alert candidates). Candidates go to the alert
    # stage, raise_alert(). Everything a stage needs travels in the Event.
    def _process(self, data: bytes, source_ip: str, ts: float) -> None:
        ev = self.parse(data, source_ip, ts)
        if self.record(ev, ts):
            self.detect(ev, ts)

    def parse(self, data: bytes | str, source_ip: str, ts: float) -> Event:
        """Stage 1: syslog bytes to a normalised Event."""
        self.received += 1
        return parse_message(self.cfg, self.connectors, self.devices, data, source_ip, ts)

    def record(self, ev: Event, ts: float) -> bool:
        """Stage 2: the device registry, per-minute counters and the storage buffer.
        Returns False for a message from a source beyond MAX_DEVICES, which goes no further."""
        dev = self.devices.get(ev.device)
        if dev is None:
            if len(self.devices) >= MAX_DEVICES:
                self.refused_devices += 1
                return False  # refuse to track an unbounded number of (possibly spoofed) sources
            dev = self.devices[ev.device] = Device(ev.device, ev.source_ip, first_seen=ts)
            learning = ts - self.installed < self.new_device.cfg["learning_minutes"] * 60
            if self.new_device.enabled and not learning:
                self.raise_alert(self.new_device.seen(ev.device, ev.source_ip, ev.hostname, ts), ts)
        dev.ip = ev.source_ip
        dev.last_seen = ts
        dev.events += 1
        if ev.hostname:
            dev.hostname = ev.hostname
        if ev.connector and (ev.connector != "generic" or not dev.connector_seen):
            dev.connector_seen = ev.connector
        dev.dirty = True

        blocked = ev.action == "block"
        minute = int(ts // 60) * 60
        stat = self._stats.get((minute, ev.device))
        if stat is None:
            stat = self._stats[(minute, ev.device)] = [0, 0]
        stat[0] += 1
        if blocked:
            stat[1] += 1
            self._count_blocked(ev, ts)

        # Every event is analysed; routine allowed traffic may be thinned out on disk,
        # because at scale it is nearly all of the volume and the least looked at.
        keep = True
        sample = self.cfg.traffic_sample
        if sample != 1 and ev.event_type == "traffic" and not blocked:
            self._sample += 1
            keep = sample > 1 and self._sample % sample == 0
        if keep and len(self._events) >= MAX_PENDING_EVENTS:
            self.unwritten += 1  # memory stays bounded; detection has already seen the event
        elif keep:
            self._events.append((
                ts, ev.device, ev.hostname, ev.connector, ev.app, ev.severity, ev.event_type, ev.action,
                ev.src_ip, ev.dst_ip, ev.src_port, ev.dst_port, ev.proto, ev.bytes, ev.user, ev.interface,
                ev.message[:2000], json.dumps(ev.extra, separators=(",", ":")) if ev.extra else None,
            ))
        else:
            self.unstored += 1
        return True

    def _count_blocked(self, ev: Event, ts: float) -> None:
        """Top blocked sources and ports (kept in memory, in the saved state)."""
        if ev.action != "block":
            return
        minute = int(ts // 60) * 60
        if not self._tops or self._tops[-1][0] != minute:
            self._tops.append((minute, Counter(), Counter()))
        _, sources, ports = self._tops[-1]
        if ev.src_ip and (ev.src_ip in sources or len(sources) < TOP_KEYS_PER_MINUTE):
            sources[ev.src_ip] += 1
        if ev.dst_port is not None:
            ports[(ev.proto, ev.dst_port)] += 1

    def detect(self, ev: Event, ts: float, emit=None) -> None:
        """Stage 3: every detector that reads this kind of event. Candidates go to
        emit, by default the alert stage."""
        emit = emit or (lambda c: self.raise_alert(c, ts))
        if self.families is None or "device" in self.families:
            self.baselines.observe(ev, ts)
        ignored = self._ignored(ev.src_ip)
        ignored_dst = self._ignore_dst_nets and (
            self._ignored(ev.dst_ip, True) or self._ignored(ev.extra.get("nat_dst_ip"), True))
        readers = self._for_type.get(ev.event_type)
        if readers is None:
            readers = self._for_type[ev.event_type] = [
                d for d in self.detectors
                if (d.event_types is None or ev.event_type in d.event_types) and self.runs(d)]
        for det in readers:
            if det.enabled and not (ignored and det.id in _SOURCE_KEYED) and not (ignored_dst and det.id in _DEST_KEYED):
                det.process(ev, ts, emit)

    # --- background loops ------------------------------------------------
    async def _flush(self) -> None:
        # The bus position that matches what is about to be written: nothing below
        # awaits before the buffers are swapped, so no event slips between the two.
        offsets = self.source.snapshot() if self.source else {}
        candidate_offsets = self.candidates.snapshot() if self.candidates else {}
        events, self._events = self._events, []
        stats, self._stats = self._stats, {}
        devices = [d for d in self.devices.values() if d.dirty]
        for d in devices:
            d.dirty = False
        totals: dict[int, list[int]] = {}
        for (minute, _device), v in stats.items():
            total = totals.setdefault(minute, [0, 0])
            total[0] += v[0]
            total[1] += v[1]
        for minute, v in totals.items():
            stats[(minute, TOTAL)] = v
        started = time.perf_counter()
        new_alerts, alert_updates = self.alerts.drain()
        batch = Batch(
            events=events,
            stats=[(m, dev, v[0], v[1]) for (m, dev), v in stats.items()],
            devices=[(d.id, d.ip, d.hostname, d.connector_seen, d.first_seen, d.last_seen, d.events) for d in devices],
            ports=self.risk_ports.drain(),
            new_alerts=new_alerts, alert_updates=alert_updates,
        )
        if batch:
            await asyncio.to_thread(self.db.write_batch, batch)
            self.flush_seconds = time.perf_counter() - started
        if offsets and offsets != self._committed:
            # Only now that the events are stored may the bus forget them.
            await self.source.commit(offsets)
            self._committed = offsets
        if candidate_offsets and candidate_offsets != self._committed_candidates:
            await self.candidates.commit(candidate_offsets)  # the alerts they became are stored
            self._committed_candidates = candidate_offsets

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                await self._flush()
            except Exception:
                log.exception("flush failed")

    async def _tick_loop(self) -> None:
        while True:
            await asyncio.sleep(10)
            now = time.time()
            self._rate.append((now, self.received))
            self.tick(now)
            self.notifier.tick()

    def tick(self, now: float, replay: bool = False) -> None:
        """Time-based work: windows expire, baselines roll, silent devices are noticed.
        replay: a tick at a time a previous leader already covered (tests that tick on
        the events' clock); what it finds was already raised."""
        emit = lambda c: self.raise_alert(c, now)  # noqa: E731
        self._replaying = replay
        try:
            for det in self.detectors:
                if not self.runs(det):
                    continue
                try:
                    det.tick(now, emit if det.enabled else (lambda c: None))
                except Exception:
                    log.exception("detector %s tick failed", det.id)
        finally:
            self._replaying = False
        self.alerts.expire(now)

    async def _prune_loop(self) -> None:
        saved = time.monotonic()
        while True:
            try:
                await asyncio.to_thread(
                    self.db.prune, time.time(), self.cfg.retention_days,
                    self.cfg.max_events, self.cfg.alert_retention_days,
                )
            except Exception:
                log.exception("prune failed")
            if time.monotonic() - saved >= (CHECKPOINT_SECONDS if self.source else STATE_SAVE_SECONDS):
                saved = time.monotonic()
                try:
                    await self.save_state_async()
                except Exception:
                    log.exception("saving detector state failed")
            await asyncio.sleep(60)

    # --- read side for the web UI ----------------------------------------
    def rate(self) -> float:
        """Messages per second over the last minute or so."""
        if len(self._rate) < 2:
            return 0.0
        (t0, n0), (t1, n1) = self._rate[0], self._rate[-1]
        return (n1 - n0) / max(t1 - t0, 1e-6)

    def top_blocked(self, limit: int = 8) -> tuple[list, list]:
        sources: Counter = Counter()
        ports: Counter = Counter()
        cutoff = time.time() - 3600
        for minute, src, prt in self._tops:
            if minute >= cutoff:
                sources.update(src)
                ports.update(prt)
        return (
            [{"ip": ip, "count": n} for ip, n in sources.most_common(limit)],
            [{"proto": p, "port": port, "count": n} for (p, port), n in ports.most_common(limit)],
        )

    def forget_device(self, device_id: str) -> None:
        self.devices.pop(device_id, None)
        self.baselines.forget(device_id)
