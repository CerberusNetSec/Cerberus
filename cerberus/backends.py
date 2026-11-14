"""Opening the configured storage backend."""
from __future__ import annotations

import logging

from .config import Config
from .storage import Store

log = logging.getLogger("cerberus.storage")


def open_store(cfg: Config) -> Store:
    """SQLite in the data directory, or PostgreSQL plus ClickHouse when both URLs are set."""
    if cfg.postgres_url or cfg.clickhouse_url:
        if not (cfg.postgres_url and cfg.clickhouse_url):
            raise SystemExit("Clustered storage needs both CERBERUS_POSTGRES_URL and CERBERUS_CLICKHOUSE_URL.")
        from .ch import ClickHouseEvents
        from .pg import PostgresStore

        store = PostgresStore(cfg.postgres_url, ClickHouseEvents(cfg.clickhouse_url))
        log.info("storage: PostgreSQL and ClickHouse")
        return store
    from .db import Database, segment_rows_for

    return Database(cfg.data_dir / "cerberus.db", segment_rows_for(cfg.max_events))
