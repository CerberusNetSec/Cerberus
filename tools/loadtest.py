#!/usr/bin/env python3
"""Measure how Cerberus copes with a large estate, without needing one.

Runs the real pipeline in this process (parser, connectors, every detector,
SQLite) against generated logs from many devices and reports throughput,
storage and query times.

    python tools/loadtest.py                          # 300 devices, 500,000 messages
    python tools/loadtest.py --devices 800 --messages 2000000
    python tools/loadtest.py --profile                # where the time goes

Nothing is sent over the network and the database is a temporary file.
"""
from __future__ import annotations

import argparse
import asyncio
import cProfile
import pstats
import random
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database, segment_rows_for  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from tools import simulate  # noqa: E402


def estate(devices: int) -> list[tuple[str, str, str]]:
    """(kind, hostname, source ip) for a plausible mix: one firewall in ten, the rest switches."""
    out = []
    for i in range(devices):
        ip = f"10.{200 + i // 62500}.{(i // 250) % 250}.{i % 250 + 1}"
        if i % 10 == 0:
            kind = ("opnsense", "paloalto", "fortinet")[(i // 10) % 3]
            out.append((kind, f"fw-{i:04d}", ip))
        else:
            out.append(("cisco" if i % 3 else "rtl", f"sw-{i:04d}", ip))
    return out


def messages(devices: list[tuple[str, str, str]], count: int, seed: int = 7):
    """Yield (bytes, source ip). Firewalls produce ~95% of the volume, as they do in practice."""
    rnd = random.Random(seed)
    random.seed(seed)
    firewalls = [d for d in devices if d[0] in ("opnsense", "paloalto", "fortinet")]
    switches = [d for d in devices if d[0] in ("cisco", "rtl")] or firewalls
    seq = 0
    for _ in range(count):
        if rnd.random() < 0.95:
            kind, host, ip = rnd.choice(firewalls)
            site = int(host[3:]) % 250
            client = f"10.{site}.{rnd.randint(0, 20)}.{rnd.randint(2, 250)}"
            remote = f"{rnd.choice((142, 151, 104, 13, 52))}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
            port = rnd.choice((443, 443, 443, 443, 80, 53, 123, 993))
            blocked = rnd.random() < 0.12
            if blocked:  # internet background noise hitting the WAN side
                client, remote = f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}", f"203.0.113.{site}"
                port = rnd.choice((22, 23, 445, 3389, 8080, 5060))
            if kind == "opnsense":
                line = simulate.filterlog("block" if blocked else "pass", client, remote, rnd.randint(1024, 65000), port)
                line = line.replace(simulate.FW, host, 1)
            elif kind == "paloalto":
                line = simulate.pan_traffic(client, remote, port, "deny" if blocked else "allow").replace(simulate.PA, host, 1)
            else:
                line = simulate.forti_traffic(client, remote, port, "deny" if blocked else "accept").replace(simulate.FGT, host, 1)
        else:
            kind, host, ip = rnd.choice(switches)
            seq += 1
            if kind == "cisco":
                line = simulate.cisco(seq, rnd.choice((
                    "%DHCPD-6-ADDRESS_ASSIGN: Interface Vlan10 assigned DHCP address",
                    "%SYS-6-CLOCKUPDATE: System clock has been updated",
                    "%SPANTREE-6-PORT_STATE: Port Gi1/0/7 instance 0 moving from learning to forwarding",
                    f"%ILPOWER-5-POWER_GRANTED: Interface Gi1/0/{rnd.randint(1, 48)}: Power granted",
                ))).replace(simulate.SW, host, 1)
            else:
                line = f"<14>{host} STP: port forwarding {rnd.randint(1, 8)}"
        yield line.encode(), ip


def percentile(values: list[float], p: float) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


async def run(args) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="cerberus-load-"))
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity = tmp, "ip"
    if args.max_events:
        cfg.max_events = args.max_events
    db = Database(tmp / "cerberus.db", segment_rows_for(cfg.max_events))
    engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    engine.load()
    engine.installed -= 86400  # past the learning period, as a running system would be

    devices = estate(args.devices)
    print(f"generating {args.messages:,} messages from {len(devices)} devices ...")
    feed = list(messages(devices, args.messages))

    profiler = cProfile.Profile() if args.profile else None
    start = time.time() - args.messages / args.rate  # spread over simulated time at the target rate
    step = 1 / args.rate
    cpu = flush = 0.0
    flushes: list[float] = []
    prunes: list[float] = []
    if profiler:
        profiler.enable()
    for i, (data, ip) in enumerate(feed):
        t0 = time.perf_counter()
        engine._process(data, ip, start + i * step)
        cpu += time.perf_counter() - t0
        if i % args.rate == args.rate - 1:  # one flush per simulated second, as in production
            t0 = time.perf_counter()
            await engine._flush()
            flushes.append(time.perf_counter() - t0)
            flush += flushes[-1]
            for det in engine.detectors:
                det.tick(start + i * step, lambda c: engine.raise_alert(c, start + i * step))
            if len(flushes) % 60 == 0:  # expire old events once a simulated minute, as in production
                t0 = time.perf_counter()
                if db.prune(start + i * step, cfg.retention_days, cfg.max_events, cfg.alert_retention_days):
                    prunes.append(time.perf_counter() - t0)
    if profiler:
        profiler.disable()
    await engine._flush()

    size = sum(f.stat().st_size for f in tmp.iterdir() if f.is_file()) / 1e6
    alerts = db.q("SELECT COUNT(*) AS n FROM alerts")[0]["n"]
    print(f"\npipeline      {args.messages / cpu:>10,.0f} messages/s on one core (parse + detect)")
    print(f"with storage  {args.messages / (cpu + flush):>10,.0f} messages/s sustained")
    print(f"flush         {1000 * percentile(flushes, 0.5):>10.0f} ms median, {1000 * percentile(flushes, 0.99):.0f} ms p99 "
          f"per second of traffic at {args.rate:,}/s")
    tenth = max(1, len(flushes) // 10)
    stored = db.events_stored()
    print(f"              {1000 * sum(flushes[:tenth]) / tenth:>10.0f} ms at the start, "
          f"{1000 * sum(flushes[-tenth:]) / tenth:.0f} ms at the end")
    if prunes:
        print(f"expiry        {1000 * max(prunes):>10.0f} ms at worst to drop old events ({len(prunes)} times)")
    print(f"database      {size:>10,.0f} MB holding {stored:,} events ({1e6 * size / max(stored, 1):,.0f} bytes each, "
          f"cap {cfg.max_events:,})")
    print(f"devices       {len(engine.devices):>10,}   alerts raised {alerts:,}   parse errors {engine.parse_errors}")

    searches = {
        "events, newest 200": ([], []),
        "events for one device": (["device = ?"], [devices[-1][2]]),
        "events for one address": (["(src_ip = ? OR dst_ip = ?)"], ["10.0.3.77", "10.0.3.77"]),
        "events on a rare port": (["dst_port = ?"], [5061]),
        "events, text search (no match)": (["message LIKE ?"], ["%no-such-text%"]),
    }
    print("\nquery times over everything stored")
    t0 = time.perf_counter()
    db.q("SELECT (minute / 900) * 900 AS t, SUM(events) AS e, SUM(blocked) AS b FROM stats_minute "
         "WHERE minute >= 0 AND device = '*' GROUP BY t")
    print(f"  {'dashboard chart':<32}{1000 * (time.perf_counter() - t0):>8.0f} ms")
    for name, (where, params) in searches.items():
        t0 = time.perf_counter()
        rows = db.search_events(where, params)
        print(f"  {name:<32}{1000 * (time.perf_counter() - t0):>8.0f} ms   ({len(rows)} rows)")

    if profiler:
        print()
        pstats.Stats(profiler).sort_stats("cumulative").print_stats(28)
    db.close()
    for f in tmp.iterdir():
        f.unlink()
    tmp.rmdir()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--devices", type=int, default=300)
    ap.add_argument("--messages", type=int, default=500_000)
    ap.add_argument("--rate", type=int, default=5000, help="simulated messages per second (sets flush size and detector windows)")
    ap.add_argument("--max-events", type=int, default=0, help="event cap to test with (default: CERBERUS_MAX_EVENTS)")
    ap.add_argument("--profile", action="store_true", help="print where the CPU time goes")
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
