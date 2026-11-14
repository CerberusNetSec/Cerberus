"""Equivalence harness: a fixed, deterministic run through the whole pipeline.

Refactoring for clustering must not change what Cerberus detects or stores.
This module drives an Engine through two simulated hours of traffic (baseline
load, every attack scenario, a burst, a device going silent, a beacon) with
fixed timestamps and seeds, then summarises everything it produced: every
alert row in full, and digests of every stored event, counter and device.

    python tests/golden.py --code <checkout> --out tests/golden/v0.2.0.json

records a reference from another checkout (for example a worktree of a
release tag); tests/test_equivalence.py checks the current code against it.
Only the standard library and the code under test are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sqlite3
import sys
import tempfile
from pathlib import Path

START = 1_800_000_000.0  # simulated clock; far from "now" so nothing depends on the wall clock
TICK = 10.0


def freeze(simulate) -> None:
    """The simulator writes the wall-clock time into log text; freeze it, in UTC,
    so the timeline is the same on any machine in any time zone."""
    import datetime as _dt

    class Frozen(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2027, 1, 15, 12, 0, 0, tzinfo=_dt.timezone.utc)

        def astimezone(self, tz=None):
            return self

    simulate.datetime = Frozen


def timeline(simulate) -> list[tuple[float, str]]:
    """(seconds after START, syslog line), in order."""
    freeze(simulate)
    random.seed(20261114)
    out: list[tuple[float, str]] = []
    t = 0.0
    # 40 minutes of ordinary traffic: warms the rate baselines past their 30-minute warm-up.
    while t < 2400:
        for line in simulate.baseline(4):
            out.append((t, line))
            t += 0.25
        t = (int(t // TICK) + 1) * TICK
    # Every scenario, back to back.
    for name, scenario in simulate.SCENARIOS.items():
        if name in simulate.SLOW:
            continue
        for line in scenario():
            out.append((t, line))
            t += 0.05
        t += 30
    # A beacon: thirteen check-ins thirty seconds apart, interleaved with background traffic.
    for i in range(13):
        out.append((t, simulate.forti_traffic("192.168.3.61", "45.77.12.34", 8443)))
        for line in simulate.baseline(1):
            out.append((t + 1, line))
        t += 30
    # A burst well above baseline, inside one minute.
    for i, line in enumerate(simulate.baseline(500)):
        out.append((t + i * 0.03, line))
    t += 120
    # Then the Palo Alto goes quiet while the other devices carry on for 25 minutes.
    end = t + 1500
    while t < end:
        for line in simulate.baseline(2):
            if " PA-440 " not in line:
                out.append((t, line))
        t += TICK
    out.sort(key=lambda item: item[0])
    return out


def run(code: Path | None, data_dir: Path, restarts: tuple[float, ...] = (), wire: bool = False) -> dict:
    """restarts: fractions of the way through the timeline at which to save the
    engine's state, shut it down and start a new one on the same database.
    wire: pass every event between the parse and the later stages, and every alert
    candidate to the alert stage, through JSON, as a message bus between processes would."""
    if code is not None:
        sys.path.insert(0, str(code))
    from cerberus.config import Config
    from cerberus.connectors import ConnectorRegistry
    from cerberus.db import Database
    from cerberus.engine import Engine
    from cerberus.notifiers import Notifier
    from tools import simulate

    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity = data_dir, "hostname"

    def start(now: float | None):
        db = Database(data_dir / "cerberus.db")
        engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
        engine.load() if now is None else engine.load(now)
        engine.installed = START - 86400  # long installed: new-device alerts are live
        watch = {d.id: d.settings() for d in engine.detectors}
        watch["watchlist"]["entries"] = "45.77.0.0/16"
        engine.apply_settings(watch, engine.general_settings())
        return db, engine

    db, engine = start(None)

    def tick(now: float) -> None:
        if hasattr(engine, "tick"):
            engine.tick(now)
            return
        emit = lambda c: engine.raise_alert(c, now)  # noqa: E731
        for det in engine.detectors:
            det.tick(now, emit if det.enabled else (lambda c: None))
        engine.alerts.expire(now)

    import asyncio
    loop = asyncio.new_event_loop()
    next_tick = START + TICK
    lines = timeline(simulate)
    stops = {int(len(lines) * f) for f in restarts}
    last = START
    for index, (offset, line) in enumerate(lines):
        if index in stops:
            loop.run_until_complete(engine._flush())
            engine.save_state(last)
            db.close()
            db, engine = start(last)
        ts = START + offset
        last = ts
        while next_tick <= ts:
            # Production writes to disk every second and ticks every ten; write before
            # each tick so nothing is held only in memory across a tick.
            loop.run_until_complete(engine._flush())
            tick(next_tick)
            next_tick += TICK
        if not wire:
            engine._process(line.encode(), "10.255.0.1", ts)
            continue
        from cerberus.models import Candidate, Event
        ev = Event.from_dict(json.loads(json.dumps(engine.parse(line.encode(), "10.255.0.1", ts).as_dict())))
        if engine.record(ev, ts):
            engine.detect(ev, ts, emit=lambda c, t=ts, e=engine: e.raise_alert(
                Candidate.from_dict(json.loads(json.dumps(c.as_dict()))), t))
    loop.run_until_complete(engine._flush())
    tick(next_tick)
    loop.run_until_complete(engine._flush())
    loop.close()
    db.close()
    return summarise(data_dir / "cerberus.db")


def _digest(conn, sql: str) -> dict:
    rows = conn.execute(sql).fetchall()
    h = hashlib.sha256()
    for row in rows:
        h.update(json.dumps(list(row), default=str).encode())
    return {"rows": len(rows), "sha256": h.hexdigest()}


def summarise(path: Path) -> dict:
    conn = sqlite3.connect(path)
    alert_columns = ["id", "created", "last_seen", "detector", "severity", "title", "description", "entity",
                     "src_ip", "device", "count", "status", "details"]
    alerts = [dict(zip(alert_columns, row)) for row in conn.execute(
        f"SELECT {', '.join(alert_columns)} FROM alerts ORDER BY id")]
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND (name = 'events' OR name GLOB 'events_[0-9]*') "
        "ORDER BY name")]
    columns = ("ts, device, hostname, connector, app, sev, event_type, action, src_ip, dst_ip, src_port, dst_port, "
               "proto, bytes, user, interface, message, extra")
    union = " UNION ALL ".join(f"SELECT id, {columns} FROM {t}" for t in tables)
    out = {
        "alerts": alerts,
        "events": _digest(conn, f"SELECT * FROM ({union}) ORDER BY id"),
        "stats_minute": _digest(conn, "SELECT minute, device, events, blocked FROM stats_minute ORDER BY minute, device"),
        "port_minute": _digest(conn, "SELECT minute, port, direction, allowed, blocked FROM port_minute "
                                     "ORDER BY minute, port, direction"),
        "devices": _digest(conn, "SELECT id, ip, hostname, connector_seen, first_seen, last_seen, events FROM devices "
                                 "ORDER BY id"),
    }
    conn.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--code", type=Path, help="checkout to run (default: this one)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        result = run(args.code.resolve() if args.code else Path(__file__).resolve().parent.parent, Path(tmp))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    kinds = sorted({a["detector"] for a in result["alerts"]})
    print(f"{len(result['alerts'])} alerts ({len(kinds)} kinds), {result['events']['rows']} events -> {args.out}")
    print(", ".join(kinds))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
