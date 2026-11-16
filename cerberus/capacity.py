"""Storage on collectors and detection workers: how full it is, and when to say so.

A collector keeps events on disk (its spool) while the message bus is
unreachable. Two things can run out: the spool's own allowance
(CERBERUS_SPOOL_MB; past it the oldest events are dropped) and the volume the
spool is on (past it nothing more can be kept at all). Each process reports
both with its heartbeat; the processor compares them with two thresholds, set
under Settings -> General, and raises an alert when one is crossed.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from .models import Candidate

SETTING = "collector_storage"
DEFAULTS = {"enabled": True, "warn": 70, "critical": 90, "volume": True}
HYSTERESIS = 5  # points below a threshold before it can alert again
LEVELS = ("", "warning", "critical")


def clean(given: dict | None, base: dict | None = None) -> dict:
    """Settings as stored: `given` over `base` (or the defaults). Raises ValueError with a
    message for the person who typed them."""
    out = {**DEFAULTS, **{k: v for k, v in (base or {}).items() if k in DEFAULTS}}
    given = given if isinstance(given, dict) else {}
    for key in ("enabled", "volume"):
        if key in given:
            out[key] = bool(given[key])
    for key in ("warn", "critical"):
        if key in given:
            try:
                out[key] = int(given[key])
            except (TypeError, ValueError):
                raise ValueError("thresholds are whole percentages") from None
    if not 1 <= out["warn"] <= 99:
        raise ValueError("the warning threshold must be between 1 and 99 percent")
    if not out["warn"] < out["critical"] <= 100:
        raise ValueError("the critical threshold must be above the warning threshold, and at most 100 percent")
    return out


def stored(value) -> dict:
    """Whatever is in storage, made safe to use (bad or missing values fall back to the defaults)."""
    try:
        return clean(value if isinstance(value, dict) else {})
    except ValueError:
        return dict(DEFAULTS)


class Peak:
    """The most a spool has held since this process's last heartbeat got through. A spool
    fills while the bus is down, when no heartbeat can be sent, and may have emptied
    again by the first one that can: the peak is what tells the processor it happened."""

    def __init__(self, spool):
        self.spool = spool
        self.bytes = 0

    def sample(self) -> int:
        self.bytes = max(self.bytes, self.spool.size())
        return self.bytes

    def reported(self) -> None:
        self.bytes = 0


def usage(spool, directory: Path, peak: Peak | None = None) -> dict:
    """What a process reports about its spool and the volume under it."""
    size, limit = spool.size(), spool.limit
    percent = (lambda n: round(min(100.0, n * 100 / limit), 1)) if limit else (lambda n: 0.0)
    out = {"spool_bytes": size, "spool_limit": limit, "spool_percent": percent(size)}
    if peak is not None:
        top = max(peak.sample(), size)
        out.update(spool_peak_bytes=top, spool_peak_percent=percent(top))
    try:
        disk = shutil.disk_usage(directory)
        out.update(volume_bytes=disk.total, volume_free=disk.free,
                   volume_percent=round((disk.total - disk.free) * 100 / disk.total, 1) if disk.total else 0.0)
    except OSError:
        pass  # not every platform or mount can say; the spool figures stand on their own
    return out


def level(percent: float, settings: dict) -> str:
    if percent >= settings["critical"]:
        return "critical"
    return "warning" if percent >= settings["warn"] else ""


def measures(status: dict, settings: dict) -> list[tuple[str, float]]:
    """(what, percent) for each thing watched on one process, fullest first."""
    found = []
    if status.get("spool_limit"):
        found.append(("spool", max(float(status.get("spool_percent") or 0),
                                   float(status.get("spool_peak_percent") or 0))))
    if settings["volume"] and status.get("volume_bytes"):
        found.append(("volume", float(status.get("volume_percent") or 0)))
    return sorted(found, key=lambda m: -m[1])


def assess(status: dict, settings: dict) -> dict:
    """For the dashboard: this process's fullest measure and the level it is at."""
    found = measures(status, settings)
    if not found:
        return {"storage_percent": None, "storage_level": "", "storage_what": ""}
    what, percent = found[0]
    return {"storage_percent": percent, "storage_what": what,
            "storage_level": level(percent, settings) if settings["enabled"] else ""}


def _size(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("bytes", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class StorageWatch:
    """Processor side. Turns heartbeats into alerts when a process's storage crosses a
    threshold: once on the way up to each level, and again only after it has fallen
    HYSTERESIS points below that level's threshold."""

    def __init__(self):
        self.levels: dict[tuple[str, str], str] = {}  # (process, what) -> level last alerted

    def check(self, statuses: list[dict], settings: dict) -> list[Candidate]:
        if not settings["enabled"]:
            self.levels.clear()
            return []
        out = []
        names = set()
        for status in statuses:
            name = str(status.get("name") or "")
            names.add(name)
            for what, percent in measures(status, settings):
                key = (name, what)
                was, now = self.levels.get(key, ""), level(percent, settings)
                if LEVELS.index(now) > LEVELS.index(was):
                    self.levels[key] = now
                    out.append(self._candidate(status, what, percent, now, settings))
                elif LEVELS.index(now) < LEVELS.index(was):
                    # Step down only once clear of the threshold, so a figure hovering at it alerts once.
                    if was == "critical" and percent < settings["critical"] - HYSTERESIS:
                        self.levels[key] = now if percent < settings["warn"] - HYSTERESIS else "warning"
                    elif was == "warning" and percent < settings["warn"] - HYSTERESIS:
                        self.levels[key] = ""
        for key in [k for k in self.levels if k[0] not in names]:
            del self.levels[key]  # a process that is gone starts afresh if it returns
        return out

    @staticmethod
    def _candidate(status: dict, what: str, percent: float, lvl: str, settings: dict) -> Candidate:
        name = str(status.get("name") or "")
        worker = status.get("role") == "detector"
        kind = "Detection worker" if worker else "Collector"
        threshold = settings["critical"] if lvl == "critical" else settings["warn"]
        if what == "spool":
            title = f"{kind} spool {percent:.0f}% full: {name}"
            held = "alert candidates" if worker else "events"
            now_percent = float(status.get("spool_percent") or 0)
            if percent > now_percent:  # it filled while out of touch, and has been emptying since
                title = f"{kind} spool reached {percent:.0f}%: {name}"
                text = (f"{kind} {name}'s spool reached {_size(status.get('spool_peak_bytes') or 0)} of {held} on "
                        f"disk, {percent:.0f}% of the {_size(status.get('spool_limit') or 0)} it may keep "
                        f"({lvl} threshold: {threshold}%), while it could not reach the message bus. It is sending "
                        f"them now and holds {_size(status.get('spool_bytes') or 0)} ({now_percent:.0f}%). "
                        "When the spool is full the oldest are dropped.")
            else:
                text = (f"{kind} {name} is holding {_size(status.get('spool_bytes') or 0)} of {held} on disk, "
                        f"{percent:.0f}% of the {_size(status.get('spool_limit') or 0)} it may keep "
                        f"({lvl} threshold: {threshold}%). It keeps them while it cannot reach the message bus"
                        + (" (unreachable now)" if status.get("bus_down") else "")
                        + "; when the spool is full the oldest are dropped.")
        else:
            title = f"{kind} volume {percent:.0f}% full: {name}"
            text = (f"The volume holding {kind.lower()} {name}'s spool is {percent:.0f}% full: "
                    f"{_size(status.get('volume_free') or 0)} free of {_size(status.get('volume_bytes') or 0)} "
                    f"({lvl} threshold: {threshold}%). When it is full, nothing more can be kept while the "
                    "message bus is unreachable.")
        if status.get("spool_dropped"):
            text += f" {status['spool_dropped']} have been dropped already."
        details = {"collector": name, "what": what, "percent": round(percent, 1), "threshold": threshold,
                   "spool_bytes": status.get("spool_bytes"), "spool_limit": status.get("spool_limit")}
        if status.get("volume_bytes"):
            details.update(volume_free=status.get("volume_free"), volume_bytes=status.get("volume_bytes"))
        if worker:
            details["family"] = status.get("family", "")
        return Candidate("collector_storage", f"collector_storage|{name}|{what}|{lvl}",
                         "high" if lvl == "critical" else "medium", title, text, None, "", details)
