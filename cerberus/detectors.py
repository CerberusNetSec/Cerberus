"""Anomaly detectors.

Each detector keeps a small amount of in-memory state, looks at every event
via process(), and may do periodic work in tick(). They report by calling
emit(Candidate); the alert manager folds repeats into one alert.
"""
from __future__ import annotations

import math
from collections import deque
from typing import Callable

from .models import Candidate, Event, is_internal, sev_rank
from .state import decode, encode, persistent

Emit = Callable[[Candidate], None]

MAX_TRACKED = 50_000  # cap on keys per detector, so spoofed floods cannot eat memory
EMIT_INTERVAL = 5.0  # seconds between repeat emits for one entity


# How a detector's state is keyed, which decides how events can be divided between
# several copies of it (clustering): every event with the same key must reach the
# same copy. "split" marks a detector that keys on two things at once and must be
# divided into two detectors before it can be sharded; "none" reads no events.
PARTITIONS = {
    # Events without a source address go by device: the brute-force detector counts
    # failed logins with no address per device; the others ignore such events.
    "source": lambda ev: ev.src_ip or f"device {ev.device}",
    "device": lambda ev: ev.device,
    "pair": lambda ev: "|".join(sorted((ev.src_ip or "", ev.dst_ip or ""))),
    "port": lambda ev: "" if ev.dst_port is None else str(ev.dst_port),
    "account": lambda ev: f"{ev.device}|{(ev.user or '')[:64]}",
}


def _clip(text: str, limit: int = 80) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@persistent
class SlidingSet:
    """Distinct items seen within a time window."""

    __slots__ = ("items",)

    def __init__(self):
        self.items: dict = {}

    def add(self, item, now: float, window: float) -> int:
        items = self.items
        items.pop(item, None)
        items[item] = now
        cutoff = now - window
        while items:
            oldest = next(iter(items))
            if items[oldest] >= cutoff:
                break
            del items[oldest]
        return len(items)


@persistent
class Buckets:
    """Sum of amounts within a time window, in coarse buckets."""

    __slots__ = ("data",)

    def __init__(self):
        self.data: dict[int, int] = {}

    def add(self, now: float, window: float, amount: int = 1, size: int = 10) -> int:
        data = self.data
        key = int(now // size)
        data[key] = data.get(key, 0) + amount
        low = int((now - window) // size)
        if len(data) > window // size + 2:
            for old in [k for k in data if k < low]:
                del data[old]
        return sum(v for k, v in data.items() if k >= low)


class Detector:
    id = ""
    name = ""
    description = ""
    # (key, default, label) - the default's type decides how the UI edits it
    params: list[tuple[str, object, str]] = []
    # Attributes holding working state: saved across restarts by snapshot()/restore().
    # Settings and anything derived from them are not state.
    _persist: tuple[str, ...] = ("_state", "_emitted")
    # The event types process() acts on (None: any). The engine does not call
    # process() for others. Must include every type the detector reacts to.
    event_types: frozenset | None = None
    # What the detector's state is keyed by: a key of PARTITIONS (or "target", see
    # ExposedService), "alerts" for the alert stream, or "none".
    partition = "none"

    def partition_key(self, ev: Event) -> str:
        """Events with equal keys must be seen by the same copy of this detector."""
        return PARTITIONS[self.partition](ev)

    def __init__(self):
        self.enabled = True
        self.cfg = {key: default for key, default, _ in self.params}
        self._state: dict = {}  # key -> [last_touch, object]
        self._emitted: dict = {}

    def schema(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "params": [
                {"key": k, "label": label, "default": d, "value": self.cfg[k],
                 "type": "text" if k in getattr(self, "multiline", ()) else type(d).__name__}
                for k, d, label in self.params
            ],
        }

    def configure(self, settings: dict) -> None:
        self.enabled = bool(settings.get("enabled", True))
        for key, default, _ in self.params:
            if key not in settings:
                continue
            value = settings[key]
            try:
                if isinstance(default, bool):
                    self.cfg[key] = bool(value)
                elif isinstance(default, int):
                    self.cfg[key] = max(0, int(value))
                elif isinstance(default, float):
                    self.cfg[key] = max(0.0, float(value))
                else:
                    self.cfg[key] = str(value)[:20000]
            except (TypeError, ValueError):
                pass

    def settings(self) -> dict:
        return {"enabled": self.enabled, **self.cfg}

    # --- persistence -----------------------------------------------------
    def snapshot(self) -> dict:
        """Working state as JSON-compatible data."""
        return {name: encode(getattr(self, name)) for name in self._persist}

    def restore(self, data: dict) -> None:
        """Load a snapshot. All or nothing: a snapshot that does not decode changes nothing."""
        decoded = {name: decode(data[name]) for name in self._persist if name in data}
        for name, value in decoded.items():
            setattr(self, name, value)

    # --- state helpers -------------------------------------------------
    def _get(self, key, factory, now: float):
        entry = self._state.get(key)
        if entry is None:
            if len(self._state) >= MAX_TRACKED:
                return None
            entry = self._state[key] = [now, factory()]
        entry[0] = now
        return entry[1]

    def _may_emit(self, key, now: float) -> bool:
        last = self._emitted.get(key)
        if last is not None and now - last < EMIT_INTERVAL:
            return False
        if len(self._emitted) >= MAX_TRACKED:
            self._emitted.clear()
        self._emitted[key] = now
        return True

    def _prune(self, now: float, ttl: float) -> None:
        cutoff = now - ttl
        for key in [k for k, v in self._state.items() if v[0] < cutoff]:
            del self._state[key]
        for key in [k for k, t in self._emitted.items() if t < cutoff]:
            del self._emitted[key]

    def process(self, ev: Event, now: float, emit: Emit) -> None:
        pass

    def tick(self, now: float, emit: Emit) -> None:
        self._prune(now, float(self.cfg.get("window", 600)) + 60)


def _origin(ip: str) -> str:
    return "internal host" if is_internal(ip) else "external host"


class PortScan(Detector):
    event_types = frozenset({"traffic"})
    partition = "source"
    id = "port_scan"
    name = "Port scan"
    description = "One source probing many different ports on a single destination."
    params = [
        ("ports", 25, "Distinct destination ports"),
        ("window", 60, "Within (seconds)"),
        ("blocked_only", False, "Count only blocked connections"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type != "traffic" or not ev.src_ip or not ev.dst_ip or ev.dst_port is None:
            return
        if self.cfg["blocked_only"] and ev.action != "block":
            return
        key = (ev.src_ip, ev.dst_ip)
        seen = self._get(key, SlidingSet, now)
        if seen is None:
            return
        count = seen.add(ev.dst_port, now, self.cfg["window"])
        if count >= self.cfg["ports"] and self._may_emit(key, now):
            emit(Candidate(
                self.id, f"{ev.src_ip}>{ev.dst_ip}",
                "high" if is_internal(ev.src_ip) else "low",
                f"Port scan from {ev.src_ip}",
                f"{_origin(ev.src_ip).capitalize()} {ev.src_ip} hit {count} different ports on "
                f"{ev.dst_ip} within {self.cfg['window']}s.",
                ev.src_ip, ev.device,
                {"target": ev.dst_ip, "distinct_ports": count,
                 "sample_ports": sorted(list(seen.items)[-20:])},
            ))


class HostSweep(Detector):
    event_types = frozenset({"traffic"})
    partition = "source"
    id = "host_sweep"
    name = "Host sweep"
    description = "One source trying the same port across many destinations (worm-like or reconnaissance)."
    params = [
        ("hosts", 20, "Distinct destination hosts"),
        ("window", 60, "Within (seconds)"),
        ("blocked_only", True, "Count only blocked connections"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type != "traffic" or not ev.src_ip or not ev.dst_ip or ev.dst_port is None:
            return
        if self.cfg["blocked_only"] and ev.action != "block":
            return
        key = (ev.src_ip, ev.dst_port, ev.proto)
        seen = self._get(key, SlidingSet, now)
        if seen is None:
            return
        count = seen.add(ev.dst_ip, now, self.cfg["window"])
        if count >= self.cfg["hosts"] and self._may_emit(key, now):
            port = f"{ev.proto or 'port'}/{ev.dst_port}"
            emit(Candidate(
                self.id, f"{ev.src_ip}:{port}",
                "high" if is_internal(ev.src_ip) else "low",
                f"Host sweep from {ev.src_ip} on {port}",
                f"{_origin(ev.src_ip).capitalize()} {ev.src_ip} tried {port} on {count} different "
                f"hosts within {self.cfg['window']}s.",
                ev.src_ip, ev.device,
                {"port": ev.dst_port, "proto": ev.proto, "distinct_hosts": count,
                 "sample_hosts": list(seen.items)[-10:]},
            ))


class DenyFlood(Detector):
    event_types = frozenset({"traffic"})
    partition = "source"
    id = "deny_flood"
    name = "Blocked-traffic flood"
    description = "One source generating a large volume of blocked connections."
    params = [
        ("count", 300, "Blocked connections"),
        ("window", 60, "Within (seconds)"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type != "traffic" or ev.action != "block" or not ev.src_ip:
            return
        counter = self._get(ev.src_ip, Buckets, now)
        if counter is None:
            return
        total = counter.add(now, self.cfg["window"])
        if total >= self.cfg["count"] and self._may_emit(ev.src_ip, now):
            emit(Candidate(
                self.id, ev.src_ip,
                "medium" if is_internal(ev.src_ip) else "low",
                f"Flood of blocked traffic from {ev.src_ip}",
                f"{_origin(ev.src_ip).capitalize()} {ev.src_ip} had {total} connections blocked "
                f"within {self.cfg['window']}s.",
                ev.src_ip, ev.device, {"blocked": total},
            ))


@persistent
class _AuthState:
    __slots__ = ("times", "users")

    def __init__(self):
        self.times: deque = deque(maxlen=1000)
        self.users: dict = {}


class BruteForce(Detector):
    event_types = frozenset({"auth_failure", "auth_success"})
    partition = "source"
    id = "brute_force"
    name = "Login brute force"
    description = "Repeated failed logins from one source, and a successful login that follows them."
    params = [
        ("failures", 5, "Failed logins"),
        ("window", 300, "Within (seconds)"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type not in ("auth_failure", "auth_success"):
            return
        key = ev.src_ip or f"device {ev.device}"
        if ev.event_type == "auth_success":
            entry = self._state.get(key)
            if not entry:
                return
            state = entry[1]
            while state.times and state.times[0] < now - self.cfg["window"]:
                state.times.popleft()
            if len(state.times) >= self.cfg["failures"]:
                emit(Candidate(
                    "brute_force_success", f"{key}@{ev.device}", "critical",
                    f"Successful login after {len(state.times)} failures from {key}",
                    f"{key} logged in to {ev.hostname or ev.device} as '{_clip(ev.user, 40) or 'unknown'}' "
                    f"after {len(state.times)} failed attempts. This can mean a password was guessed.",
                    ev.src_ip, ev.device, {"user": ev.user, "failures": len(state.times)},
                ))
                state.times.clear()
            return
        state = self._get(key, _AuthState, now)
        if state is None:
            return
        state.times.append(now)
        if ev.user and len(state.users) < 20:
            state.users[ev.user[:64]] = True
        while state.times and state.times[0] < now - self.cfg["window"]:
            state.times.popleft()
        count = len(state.times)
        if count >= self.cfg["failures"] and self._may_emit(key, now):
            users = list(state.users)
            emit(Candidate(
                self.id, f"{key}@{ev.device}",
                "high" if ev.src_ip and is_internal(ev.src_ip) else "medium",
                f"Repeated login failures from {key}",
                f"{count} failed logins on {ev.hostname or ev.device} from {key} within "
                f"{self.cfg['window']}s" + (f", trying: {_clip(', '.join(users), 120)}." if users else "."),
                ev.src_ip, ev.device, {"failures": count, "users": users},
            ))


class LinkFlap(Detector):
    event_types = frozenset({"link_state"})
    partition = "device"
    id = "link_flap"
    name = "Link flapping"
    description = "An interface changing state repeatedly (bad cable, failing optic, or a loop)."
    params = [
        ("changes", 6, "State changes"),
        ("window", 300, "Within (seconds)"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type != "link_state":
            return
        key = (ev.device, ev.interface)
        times = self._get(key, deque, now)
        if times is None:
            return
        times.append(now)
        while times and times[0] < now - self.cfg["window"]:
            times.popleft()
        if len(times) >= self.cfg["changes"] and self._may_emit(key, now):
            where = f"{ev.interface} on {ev.hostname or ev.device}" if ev.interface else (ev.hostname or ev.device)
            emit(Candidate(
                self.id, f"{ev.device}|{ev.interface}", "medium",
                f"Link flapping: {_clip(where, 60)}",
                f"{len(times)} link state changes on {_clip(where, 60)} within {self.cfg['window']}s.",
                None, ev.device, {"interface": ev.interface, "changes": len(times)},
            ))


class PlaintextSecret(Detector):
    """Alerts for the secrets the parse stage found (see secrets_scan.py). Its settings
    also switch the scanning and the redaction of stored events on and off."""
    id = "plaintext_secret"
    name = "Plaintext passwords and secrets"
    description = ("Passwords, API keys, tokens and private keys that appear in clear in your devices' logs: "
                   "credentials in URLs (user:password@, ?password=), HTTP Basic and bearer headers quoted by an IDS "
                   "or proxy, and cloud and SaaS keys. Found secrets are removed from the stored event, and the "
                   "alert shows only a fingerprint. Switching this off stops the scanning and the redaction.")
    params = [
        ("redact", True, "Remove found secrets from stored events (recommended)"),
    ]
    event_types = None  # any message may carry one
    partition = "device"

    def configure(self, settings: dict) -> None:
        super().configure(settings)
        from .secrets_scan import SCANNER
        SCANNER.configure(self.enabled, self.cfg["redact"])

    def process(self, ev, now, emit):
        for s in ev.extra.get("secrets") or ():
            if not isinstance(s, dict) or not s.get("fingerprint"):
                continue
            key = (s.get("kind"), s["fingerprint"])
            if not self._may_emit(key, now):
                continue
            who = ev.hostname or ev.device
            route = (f" from {ev.src_ip}" if ev.src_ip else "") + (
                f" to {ev.dst_ip}{f':{ev.dst_port}' if ev.dst_port is not None else ''}" if ev.dst_ip else "")
            where = "a URL" if s.get("kind") == "url_credentials" else f"the {s.get('parameter') or s.get('field', 'message')}"
            emit(Candidate(
                self.id, f"{s.get('kind')}|{s['fingerprint']}", s.get("severity", "medium"),
                f"Plaintext {s.get('label', 'secret')} in logs from {who}",
                f"{who} logged a {s.get('label', 'secret')} in clear{route}, in {where}. "
                + ("It was removed from the stored event; " if "[REDACTED" in (ev.message or "") or any(
                    "[REDACTED" in str(v) for v in ev.extra.values()) else "")
                + "anyone who can read these logs, or the traffic they describe, could use it.",
                ev.src_ip, ev.device,
                {"kind": s.get("kind"), "fingerprint": s["fingerprint"], "preview": s.get("preview"),
                 "field": s.get("field"), "target": ev.dst_ip, "port": ev.dst_port,
                 **{k: s[k] for k in ("user", "parameter") if s.get(k)}},
            ))


class ThreatEvent(Detector):
    event_types = frozenset({"threat"})
    partition = "source"
    id = "threat"
    name = "IDS / threat log"
    description = "Threats the device itself reported (Palo Alto threat logs, Suricata alerts)."
    params = [
        ("min_level", "low", "Minimum vendor severity (info, low, medium, high, critical)"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type != "threat":
            return
        level = ev.level or "low"
        if sev_rank(level) < sev_rank(self.cfg["min_level"]):
            return
        name = _clip(ev.extra.get("threat_name") or ev.extra.get("category") or "Threat", 90)
        key = (name, ev.src_ip, ev.dst_ip)
        if not self._may_emit(key, now):
            return
        blocked = ev.action == "block"
        emit(Candidate(
            self.id, f"{name}|{ev.src_ip}|{ev.dst_ip}", level,
            name if blocked else f"Not blocked: {name}",
            f"{ev.hostname or ev.device} reported '{name}' for {ev.src_ip or '?'} → {ev.dst_ip or '?'}"
            + (f":{ev.dst_port}" if ev.dst_port is not None else "")
            + (f" (traffic was {'blocked' if ev.action == 'block' else 'allowed'})." if ev.action else "."),
            ev.src_ip, ev.device,
            {"blocked": blocked, "target": ev.dst_ip,
             **{k: v for k, v in ev.extra.items() if k in ("threat_name", "category", "detail", "sid", "classification",
                                                           "application", "policy", "policyid", "src_zone", "dst_zone")}},
        ))


_NOTABLE = {
    "security_violation": ("high", "Security violation"),
    "stp_guard": ("high", "Spanning-tree guard tripped"),
    "loop_detected": ("high", "Network loop detected"),
    "mac_flap": ("medium", "MAC address flapping"),
    "system_restart": ("low", "Device restarted"),
    "stp_change": ("low", "Spanning-tree topology change"),
    "config_change": ("low", "Configuration changed"),
}


class NotableEvent(Detector):
    event_types = frozenset({*_NOTABLE, "system", "other"})
    partition = "device"
    id = "notable"
    name = "Notable device events"
    description = ("Port-security and DHCP/ARP inspection violations, loops, spanning-tree guards, MAC flaps, "
                   "restarts, plus anything a device logs at a critical level.")
    params = [
        ("config_changes", True, "Alert on configuration changes"),
        ("stp_changes", False, "Alert on ordinary spanning-tree topology changes"),
        ("syslog_severity", 2, "Alert on syslog severity at or below (0-7, 0 = emergencies only)"),
        ("vendor_levels", True, "Alert on system logs the vendor marks high or critical"),
    ]

    def process(self, ev, now, emit):
        known = _NOTABLE.get(ev.event_type)
        if known:
            if ev.event_type == "config_change" and not self.cfg["config_changes"]:
                return
            if ev.event_type == "stp_change" and not self.cfg["stp_changes"]:
                return
            severity, label = known
        elif ev.event_type == "system" and self.cfg["vendor_levels"] and sev_rank(ev.level) >= 3:
            severity, label = ev.level, "Device reported a problem"
        elif ev.severity <= self.cfg["syslog_severity"] and ev.event_type in ("other", "system"):
            severity, label = "medium", "Critical syslog message"
        else:
            return
        key = (ev.device, ev.event_type, ev.interface, label)
        if not self._may_emit(key, now):
            return
        host = ev.hostname or ev.device
        where = f" ({ev.interface})" if ev.interface else ""
        who = f" by {_clip(ev.user, 40)}" if ev.user else ""
        emit(Candidate(
            self.id, f"{ev.device}|{ev.event_type}|{ev.interface}|{label}", severity,
            f"{label}: {_clip(host + where, 80)}",
            f"{host}{where}{who}: {_clip(ev.extra.get('detail') or ev.message, 300)}",
            ev.src_ip, ev.device, dict(list(ev.extra.items())[:10]),
        ))


class LargeTransfer(Detector):
    event_types = frozenset({"traffic"})
    partition = "source"
    id = "large_transfer"
    name = "Large outbound transfer"
    description = ("An internal host sending an unusual amount of data to the internet. "
                   "Needs byte counts in the traffic log (e.g. Palo Alto).")
    params = [
        ("megabytes", 2048, "Megabytes sent"),
        ("window", 600, "Within (seconds)"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type != "traffic" or not ev.src_ip or not ev.dst_ip:
            return
        sent = ev.extra.get("bytes_sent")
        amount = int(sent) if sent and sent.isdigit() else ev.bytes
        if not amount or not is_internal(ev.src_ip) or is_internal(ev.dst_ip):
            return
        counter = self._get(ev.src_ip, Buckets, now)
        if counter is None:
            return
        total = counter.add(now, self.cfg["window"], amount, 60)
        if total >= self.cfg["megabytes"] * 1_048_576 and self._may_emit(ev.src_ip, now):
            mb = total // 1_048_576
            emit(Candidate(
                self.id, ev.src_ip, "medium",
                f"Large outbound transfer from {ev.src_ip}",
                f"{ev.src_ip} sent about {mb:,} MB to the internet within {self.cfg['window'] // 60} minutes "
                f"(most recently to {ev.dst_ip}).",
                ev.src_ip, ev.device, {"megabytes": mb, "last_destination": ev.dst_ip},
            ))


@persistent
class _Baseline:
    """Per-device per-minute counts with an exponentially weighted mean/variance."""

    __slots__ = ("current", "mean", "var", "samples", "last_seen", "silent", "hostname")

    def __init__(self):
        self.current = [0, 0]  # events, blocked - in the minute being collected
        self.mean = [0.0, 0.0]
        self.var = [0.0, 0.0]
        self.samples = 0
        self.last_seen = 0.0
        self.silent = False
        self.hostname = ""


@persistent
class Baselines:
    """Shared between RateAnomaly and DeviceSilent."""

    ALPHA = 0.05

    def __init__(self):
        self.devices: dict[str, _Baseline] = {}
        self.minute = 0

    def observe(self, ev: Event, now: float) -> None:
        base = self.devices.get(ev.device)
        if base is None:
            if len(self.devices) >= 5000:
                return
            base = self.devices[ev.device] = _Baseline()
        base.current[0] += 1
        if ev.action == "block":
            base.current[1] += 1
        base.last_seen = now
        base.hostname = ev.hostname

    def forget(self, device: str) -> None:
        self.devices.pop(device, None)

    def roll(self, now: float):
        """Once a minute: yield (device, baseline, metric, count, mean, std) for
        each closed minute, then fold it into the baseline."""
        minute = int(now // 60)
        if self.minute == 0:
            self.minute = minute
            return
        if minute == self.minute:
            return
        self.minute = minute
        for device, base in self.devices.items():
            for metric in (0, 1):
                x = base.current[metric]
                mean = base.mean[metric]
                std = max(math.sqrt(base.var[metric]), math.sqrt(mean), 1.0)
                yield device, base, metric, x, mean, std
                # Clamp so a single spike does not drag the baseline up with it.
                if base.samples >= 5:
                    x = min(x, mean + 3 * std)
                if base.samples == 0:
                    base.mean[metric] = float(x)
                else:
                    delta = x - mean
                    base.mean[metric] = mean + self.ALPHA * delta
                    base.var[metric] = (1 - self.ALPHA) * (base.var[metric] + self.ALPHA * delta * delta)
            base.current = [0, 0]
            base.samples += 1


class RateAnomaly(Detector):
    event_types = frozenset()  # fed by the engine (or the SNMP poller), not by process()
    partition = "device"
    id = "rate_anomaly"
    name = "Traffic rate anomaly"
    description = ("A device suddenly logging far more than its learned baseline, overall or in blocked "
                   "traffic. The baseline is a moving average that needs a warm-up after each restart.")
    params = [
        ("sigma", 4.0, "Standard deviations above baseline"),
        ("min_ratio", 3.0, "And at least this multiple of the baseline"),
        ("min_events", 120, "And at least this many events per minute"),
        ("warmup", 30, "Warm-up (minutes of data)"),
    ]

    def __init__(self, baselines: Baselines):
        super().__init__()
        self.baselines = baselines

    def tick(self, now, emit):
        cfg = self.cfg
        for device, base, metric, x, mean, std in self.baselines.roll(now):
            if not self.enabled or base.samples < cfg["warmup"] or x < cfg["min_events"]:
                continue
            if x > mean + cfg["sigma"] * std and x >= cfg["min_ratio"] * max(mean, 1.0):
                what = "blocked traffic" if metric else "log volume"
                host = base.hostname or device
                emit(Candidate(
                    self.id, f"{device}|{metric}", "medium",
                    f"Spike in {what} on {_clip(host, 40)}",
                    f"{host} logged {x:,} {'blocked connections' if metric else 'messages'} in the last "
                    f"minute; its baseline is about {mean:,.0f} per minute.",
                    None, device, {"per_minute": x, "baseline": round(mean, 1), "std": round(std, 1)},
                ))


class DeviceSilent(Detector):
    event_types = frozenset()  # fed by the engine (or the SNMP poller), not by process()
    partition = "device"
    id = "device_silent"
    name = "Device went silent"
    description = "A device that normally logs steadily has stopped sending (down, unplugged, or logging disabled)."
    params = [
        ("minutes", 15, "Silent for (minutes)"),
        ("min_rate", 1.0, "Only devices that normally send at least (messages/minute)"),
        ("warmup", 30, "Warm-up (minutes of data)"),
        ("group", 5, "Report as one outage when this many devices go silent within 10 minutes"),
    ]

    def __init__(self, baselines: Baselines):
        super().__init__()
        self.baselines = baselines
        self.recent: deque = deque(maxlen=2000)  # (when, host) of devices that just went silent

    _persist = (*Detector._persist, "recent")

    def tick(self, now, emit):
        cfg = self.cfg
        while self.recent and now - self.recent[0][0] > 600:
            self.recent.popleft()
        for device, base in self.baselines.devices.items():
            quiet = now - base.last_seen
            if quiet < cfg["minutes"] * 60:
                base.silent = False
                continue
            if base.silent or base.samples < cfg["warmup"]:
                continue
            # The mean decays while the device is quiet, so judge it generously.
            if base.mean[0] * (1 + quiet / 60 * Baselines.ALPHA * 2) < cfg["min_rate"]:
                continue
            base.silent = True
            host = base.hostname or device
            self.recent.append((now, host))
            if cfg["group"] and len(self.recent) >= cfg["group"]:
                # Many devices stopping together share a cause. One alert that keeps
                # counting is more use than a page per device.
                hosts = [h for _, h in self.recent]
                emit(Candidate(
                    self.id, "group", "high",
                    "Several devices went silent together",
                    f"{len(hosts)} devices stopped sending syslog within 10 minutes: {', '.join(hosts[:12])}"
                    + (f" and {len(hosts) - 12} more" if len(hosts) > 12 else "")
                    + ". When devices stop together the cause is usually shared: a site, an uplink, "
                    "or the path to Cerberus itself.",
                    None, "", {"devices": hosts[:200], "count": len(hosts)},
                ))
                continue
            emit(Candidate(
                self.id, device, "high",
                f"Device went silent: {_clip(host, 40)}",
                f"No syslog from {host} for {int(quiet // 60)} minutes. It normally sends steadily.",
                None, device, {"silent_minutes": int(quiet // 60)},
            ))


class NewDevice(Detector):
    event_types = frozenset()  # fed by the engine (or the SNMP poller), not by process()
    partition = "device"
    id = "new_device"
    name = "New log source"
    description = "A device that has never sent logs before started sending."
    params = [
        ("learning_minutes", 30, "Stay quiet for this long after first install (minutes)"),
        ("group", 10, "Report as one alert when more than this many appear within 10 minutes"),
    ]

    _persist = (*Detector._persist, "recent")

    def __init__(self):
        super().__init__()
        self.recent: deque = deque(maxlen=2000)  # (when, label)

    def seen(self, device: str, source_ip: str, hostname: str, now: float) -> Candidate:
        label = f"{hostname} ({source_ip})" if hostname and hostname != source_ip else source_ip
        while self.recent and now - self.recent[0][0] > 600:
            self.recent.popleft()
        self.recent.append((now, label))
        if self.cfg["group"] and len(self.recent) > self.cfg["group"]:
            # A rollout, or forged source addresses: either way, one alert that counts.
            labels = [name for _, name in self.recent]
            return Candidate(
                self.id, "group", "low",
                "Many new log sources at once",
                f"{len(labels)} devices sent syslog for the first time within 10 minutes: {', '.join(labels[:12])}"
                + (f" and {len(labels) - 12} more" if len(labels) > 12 else "")
                + ". Expected during a rollout; otherwise check whether the source addresses are real.",
                None, "", {"devices": labels[:200], "count": len(labels)},
            )
        return Candidate(
            self.id, device, "info",
            f"New log source: {_clip(label, 60)}",
            f"{label} sent syslog for the first time.",
            None, device, {},
        )


class TopologyChange(Detector):
    event_types = frozenset()  # fed by the engine (or the SNMP poller), not by process()
    partition = "device"
    id = "topology_change"
    name = "Topology change"
    description = ("A device gained or lost an LLDP/CDP neighbour between SNMP polls - for example an "
                   "unexpected switch or access point being plugged in. Needs SNMP polling (Topology page).")
    params = [
        ("new_neighbors", True, "Alert when a new neighbour appears"),
        ("lost_neighbors", True, "Alert when a neighbour disappears"),
    ]


# Families of detectors that share a key and can run in detection workers. The
# "device" family (baselines, silence, new devices, link flaps, notable events,
# admin access) stays with the processor, which already sees every event by device;
# correlation reads the alert stream there too.
WORKER_FAMILIES = ("source", "target", "pair", "port", "account")


def family_detectors(family: str) -> list[Detector]:
    return [d for d in build_detectors() if d.partition == family]


def family_event_types(family: str) -> frozenset:
    """The event types a family's detectors read: what collectors send to its topic."""
    types: set = set()
    for det in family_detectors(family):
        if det.event_types is None:
            return frozenset({"*"})
        types |= det.event_types
    return frozenset(types)


def family_key(family: str, ev: Event) -> str:
    """The key events of a family's topic are divided by."""
    return family_detectors_cached(family)[0].partition_key(ev)


_FAMILY_CACHE: dict = {}


def family_detectors_cached(family: str) -> list[Detector]:
    if family not in _FAMILY_CACHE:
        _FAMILY_CACHE[family] = family_detectors(family)
    return _FAMILY_CACHE[family]


def build_detectors() -> list[Detector]:
    from .security import build_security_detectors  # imported here: security.py builds on this module

    baselines = Baselines()
    return [
        *build_security_detectors(),
        PortScan(), HostSweep(), DenyFlood(), BruteForce(), ThreatEvent(), PlaintextSecret(), NotableEvent(),
        LinkFlap(), LargeTransfer(), RateAnomaly(baselines), DeviceSilent(baselines), NewDevice(),
        TopologyChange(),
    ]
