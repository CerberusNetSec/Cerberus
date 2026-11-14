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
from .syslog_parser import parse_syslog

log = logging.getLogger("cerberus.engine")

QUEUE_SIZE = 50_000
TOP_KEYS_PER_MINUTE = 20_000
MAX_DEVICES = 5000
MAX_PENDING_EVENTS = 200_000  # events waiting to be written; beyond this the disk is not keeping up
TOTAL = "*"  # stats_minute row holding the sum over all devices, so charts read one row per minute
STATE_KEY = "engine_state"  # settings row holding the detectors' working state
STATE_VERSION = 1
STATE_SAVE_SECONDS = 300
# Detectors keyed on a source address; the ignore list applies to these.
_SOURCE_KEYED = {"port_scan", "host_sweep", "deny_flood", "brute_force", "large_transfer", "threat",
                 "risky_egress", "lateral_movement", "beaconing", "credential_attacks", "correlation",
                 "risk_ports"}
# Detectors about a destination; the ignored-destinations list applies to these.
_DEST_KEYED = {"exposed_service", "risky_egress", "beaconing", "large_transfer"}


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
        self.next_id = (self.db.q("SELECT MAX(id) AS m FROM alerts")[0]["m"] or 0) + 1
        rows = self.db.q(
            "SELECT * FROM alerts WHERE status != 'resolved' AND last_seen > ?",
            ((time.time() if now is None else now) - self.cooldown,),
        )
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

    def drain(self) -> list[tuple[str, list]]:
        """SQL to persist new alerts and updates since the last flush."""
        stamp = time.time()  # wall clock, so a site's report cursor only moves forward
        updates = []
        for cur in self.active.values():
            if cur.dirty:
                cur.dirty = False
                updates.append((cur.last_seen, cur.count, cur.severity, cur.description[:1000],
                                json.dumps(cur.details)[:4000], stamp, cur.id))
        new_rows, self.new_rows = self.new_rows, []
        return [
            ("INSERT OR REPLACE INTO alerts(id, created, last_seen, detector, severity, title, description, "
             "entity, src_ip, device, count, status, details, updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             [(*row, stamp) for row in new_rows]),
            ("UPDATE alerts SET last_seen=?, count=?, severity=?, description=?, details=?, updated=? WHERE id=?", updates),
        ]

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
        self.baselines = next(d for d in self.detectors if isinstance(d, RateAnomaly)).baselines
        self.new_device: NewDevice = self.by_id["new_device"]  # type: ignore[assignment]
        self.correlation = self.by_id["correlation"]
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

    # --- lifecycle -------------------------------------------------------
    def load(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        for row in self.db.q("SELECT * FROM devices"):
            self.devices[row["id"]] = Device(**{k: ("" if v is None else v) for k, v in row.items()})
        self.installed = self.db.get_setting("installed")
        if not self.installed:
            self.installed = time.time()
            self.db.set_setting("installed", self.installed)
        if not self.db.get_setting("stats_totals"):
            # Databases from before the all-devices row existed: fill it in once.
            self.db.x("INSERT OR IGNORE INTO stats_minute(minute, device, events, blocked) "
                      "SELECT minute, ?, SUM(events), SUM(blocked) FROM stats_minute WHERE device != ? GROUP BY minute",
                      (TOTAL, TOTAL))
            self.db.set_setting("stats_totals", True)
        self.apply_settings(self.db.get_setting("detectors", {}), self.db.get_setting("general", {}))
        restored = self.restore(self.db.get_setting(STATE_KEY) or {}, now)
        if "admin_access" not in restored:
            self.admin_access.restore_legacy(self.db.get_setting("admin_sources", {}))
        if "risk_ports" not in restored:
            self.risk_ports.restore_rows(self.db.q("SELECT * FROM port_minute WHERE minute >= ? ORDER BY minute",
                                                   (int(now - 27 * 3600),)), now)
        self.alerts.load(now)

    def apply_settings(self, detectors: dict, general: dict) -> None:
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

    def raise_alert(self, c: Candidate, now: float) -> None:
        """Raise an alert and let the correlator see it."""
        self.alerts.raise_(c, now)
        if self.correlation.enabled:
            self.correlation.on_alert(c, now, lambda found: self.alerts.raise_(found, now))

    # --- working state ---------------------------------------------------
    def snapshot(self, now: float | None = None) -> dict:
        """Everything the detectors have learned and are counting, as JSON-compatible data.
        Call on the event-loop thread: it reads state the pipeline is changing."""
        return {"version": STATE_VERSION, "saved": time.time() if now is None else now,
                "detectors": {d.id: d.snapshot() for d in self.detectors},
                "baselines": encode(self.baselines), "tops": encode(self._tops)}

    def restore(self, snap: dict, now: float) -> set[str]:
        """Load a snapshot; returns the ids of the detectors restored. A detector whose
        state does not load starts empty, as it would have without a snapshot."""
        if not snap or snap.get("version") != STATE_VERSION:
            return set()
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
        for coro in (self._pipeline(), self._flush_loop(), self._tick_loop(), self._prune_loop()):
            self._tasks.append(asyncio.create_task(coro))

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
        parsed = parse_syslog(data)
        device_id = source_ip
        if self.cfg.device_identity == "hostname" and parsed["hostname"]:
            device_id = parsed["hostname"]
        hint = ""
        if pin is None:
            dev = self.devices.get(device_id)
            pin, hint = (dev.connector_pin, dev.connector_seen) if dev else ("", "")
        return self.connectors.build_event(parsed, ts, device_id, source_ip, pin, hint)

    def _process(self, data: bytes, source_ip: str, ts: float) -> None:
        self.received += 1
        ev = self.build_event(data, source_ip, ts)
        if self.cfg.device_identity == "hostname" and ev.hostname and ev.device != ev.hostname:
            ev.device = ev.hostname  # the connector found a hostname the envelope did not have

        emit = lambda c: self.raise_alert(c, ts)  # noqa: E731

        dev = self.devices.get(ev.device)
        if dev is None:
            if len(self.devices) >= MAX_DEVICES:
                self.refused_devices += 1
                return  # refuse to track an unbounded number of (possibly spoofed) sources
            dev = self.devices[ev.device] = Device(ev.device, source_ip, first_seen=ts)
            learning = ts - self.installed < self.new_device.cfg["learning_minutes"] * 60
            if self.new_device.enabled and not learning:
                emit(self.new_device.seen(ev.device, source_ip, ev.hostname, ts))
        dev.ip = source_ip
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
            if not self._tops or self._tops[-1][0] != minute:
                self._tops.append((minute, Counter(), Counter()))
            _, sources, ports = self._tops[-1]
            if ev.src_ip and (ev.src_ip in sources or len(sources) < TOP_KEYS_PER_MINUTE):
                sources[ev.src_ip] += 1
            if ev.dst_port is not None:
                ports[(ev.proto, ev.dst_port)] += 1

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

        self.baselines.observe(ev, ts)
        ignored = self._ignored(ev.src_ip)
        ignored_dst = self._ignore_dst_nets and (
            self._ignored(ev.dst_ip, True) or self._ignored(ev.extra.get("nat_dst_ip"), True))
        for det in self.detectors:
            if det.enabled and not (ignored and det.id in _SOURCE_KEYED) and not (ignored_dst and det.id in _DEST_KEYED):
                det.process(ev, ts, emit)

    # --- background loops ------------------------------------------------
    async def _flush(self) -> None:
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
        statements = [
            ("INSERT INTO stats_minute(minute, device, events, blocked) VALUES(?,?,?,?) "
             "ON CONFLICT(minute, device) DO UPDATE SET events=events+excluded.events, "
             "blocked=blocked+excluded.blocked",
             [(m, dev, v[0], v[1]) for (m, dev), v in stats.items()]),
            ("INSERT INTO devices(id, ip, hostname, connector_seen, first_seen, last_seen, events) "
             "VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET ip=excluded.ip, hostname=excluded.hostname, "
             "connector_seen=excluded.connector_seen, last_seen=excluded.last_seen, events=excluded.events",
             [(d.id, d.ip, d.hostname, d.connector_seen, d.first_seen, d.last_seen, d.events) for d in devices]),
            ("INSERT INTO port_minute(minute, port, direction, allowed, blocked) VALUES(?,?,?,?,?) "
             "ON CONFLICT(minute, port, direction) DO UPDATE SET allowed=allowed+excluded.allowed, "
             "blocked=blocked+excluded.blocked", self.risk_ports.drain()),
            *self.alerts.drain(),
        ]
        if events or any(rows for _, rows in statements):
            await asyncio.to_thread(self.db.write, events, statements)
            self.flush_seconds = time.perf_counter() - started

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

    def tick(self, now: float) -> None:
        """Time-based work: windows expire, baselines roll, silent devices are noticed."""
        emit = lambda c: self.raise_alert(c, now)  # noqa: E731
        for det in self.detectors:
            try:
                det.tick(now, emit if det.enabled else (lambda c: None))
            except Exception:
                log.exception("detector %s tick failed", det.id)
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
            if time.monotonic() - saved >= STATE_SAVE_SECONDS:
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
