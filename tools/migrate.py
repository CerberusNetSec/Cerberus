#!/usr/bin/env python3
"""Copy a Cerberus SQLite database into clustered storage (PostgreSQL + ClickHouse).

Stop Cerberus first, so nothing is written while the copy runs, then:

    python tools/migrate.py --from data/cerberus.db \\
        --postgres postgresql://cerberus:PASSWORD@db-host:5432/cerberus \\
        --clickhouse http://cerberus:PASSWORD@ch-host:8123/cerberus

Everything moves: settings (with the detectors' saved state and the dashboard
password), devices, alerts, notification channels, SNMP data, sessions, central
console sites and their alerts, every stored event and every counter. Events
keep their order; their ids are renumbered from 1. The target must be empty.
Afterwards start Cerberus with CERBERUS_POSTGRES_URL and CERBERUS_CLICKHOUSE_URL
set. The SQLite file is only read, never changed.

Inside the container image the same tool runs as:

    docker run --rm -v cerberus_cerberus-data:/data:ro ghcr.io/cerberusnetsec/cerberus:<version> \\
        python tools/migrate.py --from /data/cerberus.db --postgres ... --clickhouse ...
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.db import EVENT_COLUMNS  # noqa: E402
from cerberus.storage import Batch, Store  # noqa: E402

CHUNK = 50_000


def read(conn: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    return [dict(row) for row in conn.execute(sql, params)]


def migrate(source: Path, target: Store, log=print) -> dict:
    """Copy everything from the SQLite file at source into target. Returns counts per table."""
    conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    counts: dict[str, int] = {}
    tables = {r["name"] for r in read(conn, "SELECT name FROM sqlite_master WHERE type = 'table'")}

    if target.events_stored() or target.alert_next_id() > 1 or target.devices_all():
        raise SystemExit("The target already holds data. Migrate into empty databases.")

    for table, columns in Store.IMPORTABLE.items():
        if table not in tables:
            continue
        have = {r["name"] for r in read(conn, f"PRAGMA table_info({table})")}
        rows = read(conn, f"SELECT {', '.join(c for c in columns if c in have)} FROM {table}")
        target.import_table(table, rows)
        counts[table] = len(rows)
        log(f"{table:12s} {len(rows):>12,}")

    # Events, oldest first, segment by segment (or the single table of older databases).
    if "event_segments" in tables:
        segments = [r["name"] for r in read(conn, "SELECT name FROM event_segments ORDER BY n")]
    else:
        segments = ["events"] if "events" in tables else []
    moved = 0
    started = time.time()
    for name in segments:
        last = 0
        while True:
            rows = conn.execute(f"SELECT id, {', '.join(EVENT_COLUMNS)} FROM {name} WHERE id > ? ORDER BY id LIMIT ?",
                                (last, CHUNK)).fetchall()
            if not rows:
                break
            last = rows[-1][0]
            target.write_batch(Batch(events=[tuple(r)[1:] for r in rows]))
            moved += len(rows)
            log(f"events       {moved:>12,}  ({moved / max(time.time() - started, 0.001):,.0f}/s)")
    counts["events"] = moved

    for table, field in (("stats_minute", "stats"), ("port_minute", "ports")):
        if table not in tables:
            continue
        columns = ("minute, device, events, blocked" if table == "stats_minute"
                   else "minute, port, direction, allowed, blocked")
        rows = [tuple(r) for r in conn.execute(f"SELECT {columns} FROM {table} ORDER BY minute")]
        for start in range(0, len(rows), CHUNK):
            target.write_batch(Batch(**{field: rows[start:start + CHUNK]}))
        counts[table] = len(rows)
        log(f"{table:12s} {len(rows):>12,}")
    conn.close()

    stored = target.events_stored()
    if stored != moved:
        raise SystemExit(f"Copied {moved:,} events but the target holds {stored:,}. Check the target and retry.")
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="source", type=Path, required=True, help="the SQLite database (cerberus.db)")
    ap.add_argument("--postgres", default=os.environ.get("CERBERUS_POSTGRES_URL", ""))
    ap.add_argument("--clickhouse", default=os.environ.get("CERBERUS_CLICKHOUSE_URL", ""))
    args = ap.parse_args()
    if not args.source.is_file():
        ap.error(f"{args.source} does not exist")
    if not (args.postgres and args.clickhouse):
        ap.error("give --postgres and --clickhouse (or set CERBERUS_POSTGRES_URL and CERBERUS_CLICKHOUSE_URL)")
    from cerberus.ch import ClickHouseEvents
    from cerberus.pg import PostgresStore

    target = PostgresStore(args.postgres, ClickHouseEvents(args.clickhouse))
    try:
        counts = migrate(args.source, target)
    finally:
        target.close()
    print("done:", ", ".join(f"{k} {v:,}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
