"""Events and per-minute counters in ClickHouse (clustered storage).

Paired with PostgreSQL (pg.py), which holds everything else. ClickHouse suits
the event stream: columnar compression, fast scans for text search, and
whole-hour partitions that expire by dropping a partition.

- events: one row per stored event, ids assigned here in arrival order, so
  "newest first" and paging by id work as with SQLite. Partitioned by hour.
- stats_minute, port_minute: SummingMergeTree. The pipeline inserts deltas and
  ClickHouse folds them; every query sums, because folding happens in the
  background.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from urllib.parse import unquote, urlparse, urlunparse

from .storage import TOTAL, QueryTimeout

log = logging.getLogger("cerberus.clickhouse")

EVENT_COLUMNS = ("id", "ts", "device", "hostname", "connector", "app", "sev", "event_type", "action", "src_ip",
                 "dst_ip", "src_port", "dst_port", "proto", "bytes", "user", "interface", "message", "extra")
_SELECT_EVENTS = ", ".join(f"`{c}`" for c in EVENT_COLUMNS)

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS events (
        id UInt64, ts Float64, device String, hostname String, connector String, app String, sev Int16,
        event_type LowCardinality(String), action LowCardinality(String),
        src_ip Nullable(String), dst_ip Nullable(String), src_port Nullable(Int32), dst_port Nullable(Int32),
        proto LowCardinality(String), bytes Nullable(Int64), `user` String, interface String,
        message String, extra Nullable(String),
        INDEX src_idx src_ip TYPE bloom_filter GRANULARITY 4,
        INDEX dst_idx dst_ip TYPE bloom_filter GRANULARITY 4,
        INDEX device_idx device TYPE bloom_filter GRANULARITY 4,
        INDEX port_idx dst_port TYPE minmax GRANULARITY 4
    ) ENGINE = MergeTree PARTITION BY intDiv(toUInt64(ts), 3600) ORDER BY id""",
    """CREATE TABLE IF NOT EXISTS stats_minute (
        minute Int64, device String, events UInt64, blocked UInt64
    ) ENGINE = SummingMergeTree((events, blocked)) ORDER BY (device, minute)""",
    """CREATE TABLE IF NOT EXISTS port_minute (
        minute Int64, port Int32, direction LowCardinality(String), allowed UInt64, blocked UInt64
    ) ENGINE = SummingMergeTree((allowed, blocked)) ORDER BY (minute, port, direction)""",
]

TIMEOUT_EXCEEDED = 159  # ClickHouse error code


def _client_for(url: str):
    import clickhouse_connect  # optional dependency: only clustered storage needs it

    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("CERBERUS_CLICKHOUSE_URL must be http(s)://user:password@host:8123/database")
    return clickhouse_connect.get_client(
        host=parts.hostname, port=parts.port or (8443 if parts.scheme == "https" else 8123),
        username=unquote(parts.username or "default"), password=unquote(parts.password or ""),
        database=(parts.path or "/").lstrip("/") or "default", secure=parts.scheme == "https",
        settings={"insert_deduplicate": 0}, connect_timeout=10, send_receive_timeout=300)


def _ensure_database(url: str) -> None:
    """Create the database the URL names if it does not exist yet (an operator-managed
    ClickHouse has users, not databases). Needs the CREATE DATABASE grant, or an existing one."""
    parts = urlparse(url)
    name = (parts.path or "/").lstrip("/")
    if not name or name == "default" or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
        return
    admin = _client_for(urlunparse(parts._replace(path="/default")))
    try:
        if not admin.command(f"EXISTS DATABASE {name}"):
            admin.command(f"CREATE DATABASE IF NOT EXISTS {name}")
    finally:
        admin.close()


class ClickHouseEvents:
    def __init__(self, url: str):
        self.url = url
        self._local = threading.local()  # one HTTP client per thread: the client is not thread-safe
        _ensure_database(url)
        for statement in SCHEMA:
            for attempt in range(5):
                try:
                    self.client.command(statement)
                    break
                except Exception as exc:  # another process creating the same table at the same moment
                    if attempt == 4 or "already exists" not in str(exc).lower():
                        raise
                    time.sleep(0.5)
        self._id_lock = threading.Lock()
        self._next_id = int(self.client.command("SELECT max(id) FROM events") or 0) + 1

    @property
    def client(self):
        client = getattr(self._local, "client", None)
        if client is None:
            client = self._local.client = _client_for(self.url)
        return client

    def _rows(self, sql: str, params: dict | None = None, settings: dict | None = None) -> list[dict]:
        result = self.client.query(sql, parameters=params or {}, settings=settings, use_none=True)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    # --- writes ------------------------------------------------------------------------------
    def write(self, events: list[tuple], stats: list[tuple], ports: list[tuple]) -> None:
        if events:
            with self._id_lock:
                first = self._next_id
                self._next_id += len(events)
            self.client.insert("events", [(first + i, *row) for i, row in enumerate(events)],
                               column_names=list(EVENT_COLUMNS))
        if stats:
            self.client.insert("stats_minute", stats, column_names=["minute", "device", "events", "blocked"])
        if ports:
            self.client.insert("port_minute", ports, column_names=["minute", "port", "direction", "allowed", "blocked"])

    def prune(self, cutoff: float, max_events: int) -> int:
        """Drop whole hours: those older than cutoff, then the oldest while more than
        max_events remain (the current hour is never dropped). Returns events removed."""
        parts = self._rows(
            "SELECT partition, sum(rows) AS n FROM system.parts WHERE database = currentDatabase() "
            "AND table = 'events' AND active GROUP BY partition ORDER BY toUInt64(partition)")
        total = sum(p["n"] for p in parts)
        removed = 0
        for part in parts[:-1]:
            hour = int(part["partition"])
            if (hour + 1) * 3600 <= cutoff or total - removed - part["n"] >= max_events:
                self.client.command(f"ALTER TABLE events DROP PARTITION {hour}")
                removed += part["n"]
            else:
                break
        minute = int(cutoff)
        for table in ("stats_minute", "port_minute"):
            if self._rows(f"SELECT 1 AS x FROM {table} WHERE minute < {{m:Int64}} LIMIT 1", {"m": minute}):
                self.client.command(f"DELETE FROM {table} WHERE minute < {{m:Int64}}", parameters={"m": minute})
        return removed

    # --- events -----------------------------------------------------------------------------------
    def search_events(self, since: float = 0, before: int = 0, limit: int = 200, timeout: float = 0, *,
                      device: str = "", event_type: str = "", action: str = "", ip: str = "",
                      port: int | None = None, text: str = "") -> list[dict]:
        where, params = ["ts >= {since:Float64}"], {"since": float(since)}
        if before:
            where.append("id < {before:UInt64}")
            params["before"] = before
        for column, value in (("device", device), ("event_type", event_type), ("action", action)):
            if value:
                where.append(f"{column} = {{{column}:String}}")
                params[column] = value
        if ip:
            where.append("(src_ip = {ip:String} OR dst_ip = {ip:String})")
            params["ip"] = ip
        if port is not None:
            where.append("dst_port = {port:Int32}")
            params["port"] = port
        if text:
            where.append("message ILIKE {pattern:String}")  # SQLite's LIKE ignores case too
            params["pattern"] = f"%{text}%"
        params["limit"] = limit
        settings = {"max_execution_time": max(1, int(timeout)), "timeout_overflow_mode": "throw"} if timeout else None
        try:
            return self._rows(f"SELECT {_SELECT_EVENTS} FROM events WHERE {' AND '.join(where)} "
                              "ORDER BY id DESC LIMIT {limit:UInt32}", params, settings)
        except Exception as exc:
            if getattr(exc, "code", None) == TIMEOUT_EXCEEDED or "TIMEOUT_EXCEEDED" in str(exc):
                raise QueryTimeout() from None
            raise

    def events_stored(self) -> int:
        return int(self.client.command("SELECT count() FROM events") or 0)

    def oldest_event_ts(self) -> float | None:
        rows = self._rows("SELECT minOrNull(ts) AS t FROM events")
        return rows[0]["t"] if rows else None

    # --- counters --------------------------------------------------------------------------------
    def traffic_series(self, start: int, bucket: int) -> list[dict]:
        return self._rows(
            "SELECT intDiv(minute, {b:Int64}) * {b:Int64} AS t, toInt64(sum(events)) AS e, toInt64(sum(blocked)) AS b "
            "FROM stats_minute WHERE minute >= {start:Int64} AND device = {total:String} GROUP BY t",
            {"b": bucket, "start": start, "total": TOTAL})

    def traffic_totals(self, since: int) -> tuple[int, int]:
        row = self._rows("SELECT toInt64(sum(events)) AS e, toInt64(sum(blocked)) AS b FROM stats_minute "
                         "WHERE minute >= {since:Int64} AND device = {total:String}", {"since": since, "total": TOTAL})[0]
        return row["e"] or 0, row["b"] or 0

    def port_series(self, start: int, bucket: int) -> list[dict]:
        return self._rows(
            "SELECT intDiv(minute, {b:Int64}) * {b:Int64} AS t, port, direction, toInt64(sum(allowed)) AS a, "
            "toInt64(sum(blocked)) AS b FROM port_minute WHERE minute >= {start:Int64} GROUP BY t, port, direction",
            {"b": bucket, "start": start})

    def port_minutes_since(self, minute: int) -> list[dict]:
        return self._rows(
            "SELECT minute, port, direction, toInt64(sum(allowed)) AS allowed, toInt64(sum(blocked)) AS blocked "
            "FROM port_minute WHERE minute >= {m:Int64} GROUP BY minute, port, direction ORDER BY minute, port, direction",
            {"m": minute})

    def counters_by_device(self) -> list[dict]:
        """Every per-minute counter row: for migration checks and tests."""
        return self._rows("SELECT minute, device, toInt64(sum(events)) AS events, toInt64(sum(blocked)) AS blocked "
                          "FROM stats_minute GROUP BY minute, device ORDER BY minute, device")

    def close(self) -> None:
        client = getattr(self._local, "client", None)
        if client is not None:
            client.close()
