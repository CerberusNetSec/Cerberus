"""Clustered storage (PostgreSQL + ClickHouse) against the SQLite backend.

Needs servers; skipped unless both of these are set (CI sets them):

    CERBERUS_TEST_POSTGRES_URL=postgresql://user:pass@host:5432/db
    CERBERUS_TEST_CLICKHOUSE_URL=http://user:pass@host:8123/db

Each test gets fresh databases on those servers, dropped afterwards.
"""
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import golden  # noqa: E402
import test_api_contract  # noqa: E402
import test_federation  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.storage import Batch  # noqa: E402
from tools import migrate as migrate_tool  # noqa: E402

PG = os.environ.get("CERBERUS_TEST_POSTGRES_URL", "")
CH = os.environ.get("CERBERUS_TEST_CLICKHOUSE_URL", "")
if os.environ.get("CERBERUS_REQUIRE_BACKENDS") and not (PG and CH):
    raise RuntimeError("CERBERUS_REQUIRE_BACKENDS is set but the server URLs are not")  # CI must not skip silently
pytestmark = pytest.mark.skipif(not (PG and CH), reason="set CERBERUS_TEST_POSTGRES_URL and CERBERUS_TEST_CLICKHOUSE_URL")


def with_database(url: str, name: str) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(path="/" + name))


def database_pair():
    """Create a fresh PostgreSQL + ClickHouse database pair. Returns (open, drop): open()
    connects a new store to the pair (any number of times), drop() closes them all and
    removes the databases."""
    import psycopg

    from cerberus.ch import ClickHouseEvents, _client_for
    from cerberus.pg import PostgresStore

    name = "cerberus_test_" + uuid.uuid4().hex[:12]
    with psycopg.connect(PG, autocommit=True) as admin:
        admin.execute(f"CREATE DATABASE {name}")
    _client_for(CH).command(f"CREATE DATABASE {name}")
    opened = []

    def open_store():
        store = PostgresStore(with_database(PG, name), ClickHouseEvents(with_database(CH, name)))
        opened.append(store)
        return store

    def drop():
        for store in opened:
            try:
                store.close()
            except Exception:
                pass
        with psycopg.connect(PG, autocommit=True) as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        _client_for(CH).command(f"DROP DATABASE IF EXISTS {name}")

    return open_store, drop


@pytest.fixture
def cluster():
    open_store, drop = database_pair()
    yield open_store
    drop()


def sqlite_reference(tmp_path, **kwargs) -> dict:
    return golden.run(None, tmp_path / "sqlite", store=lambda: Database(tmp_path / "sqlite" / "c.db"), **kwargs)


def test_reference_run_stores_the_same_as_sqlite(tmp_path, cluster):
    (tmp_path / "sqlite").mkdir()
    expected = sqlite_reference(tmp_path)
    assert golden.run(None, tmp_path, store=cluster) == expected
    assert len(expected["alerts"]) == 52 and expected["events"]["rows"] == 6785


def test_restarting_on_clustered_storage_changes_nothing(tmp_path, cluster):
    (tmp_path / "sqlite").mkdir()
    expected = sqlite_reference(tmp_path)
    assert golden.run(None, tmp_path, store=cluster, restarts=(0.4, 0.75)) == expected


def test_api_answers_match_the_recording_on_clustered_storage(tmp_path, monkeypatch, cluster):
    monkeypatch.setattr(test_api_contract, "Database", lambda _path: cluster())
    test_api_contract.test_api_answers_match_the_recording(tmp_path, monkeypatch)


@pytest.mark.parametrize("name", [
    "test_sites_report_alerts_and_health", "test_alert_changes_flow_and_catch_up_in_batches",
    "test_acknowledging_at_the_console_reaches_the_site", "test_tokens_and_rebuilt_sites",
    "test_sites_from_configuration", "test_silent_site_alert",
    "test_sessions_survive_a_restart_and_logout_reaches_every_replica",
])
def test_federation_on_clustered_storage(name, tmp_path, monkeypatch, request):
    """The console and each site on their own pair of databases."""
    pairs: dict[str, object] = {}

    def database(path, *_args, **_kwargs):
        key = str(path)  # the same file name reopens the same pair
        if key not in pairs:
            open_store, drop = database_pair()
            request.addfinalizer(drop)
            pairs[key] = open_store
        return pairs[key]()

    monkeypatch.setattr(test_federation, "Database", database)
    fn = getattr(test_federation, name)
    params = fn.__code__.co_varnames[:fn.__code__.co_argcount]
    fn(**{k: v for k, v in (("tmp_path", tmp_path), ("monkeypatch", monkeypatch)) if k in params})


def test_migrating_a_sqlite_database(tmp_path, cluster):
    source = tmp_path / "sqlite" / "c.db"
    source.parent.mkdir()
    expected = golden.run(None, tmp_path / "sqlite", store=lambda: Database(source))
    db = Database(source)  # extras a real installation has: a channel, a session, SNMP data, a console site
    db.add_channel({"type": "telegram", "name": "SOC", "enabled": 1, "min_severity": "high", "config": "{}"})
    db.session_add("ab" * 32, time.time() + 3600)
    db.save_snmp_record("PA-440", 1.0, True, "", 1.0, '{"system": {}}')
    site_id = db.site_create("north", "cd" * 32, 5.0)
    db.close()
    target = cluster()
    counts = migrate_tool.migrate(source, target, log=lambda *_: None)
    assert counts["events"] == expected["events"]["rows"] and counts["alerts"] == 52
    assert golden.summarise_store(target) == expected
    assert [c["name"] for c in target.channels()] == ["SOC"] and target.session_expires("ab" * 32)
    assert target.snmp_records()[0]["device"] == "PA-440" and target.site(site_id)["name"] == "north"
    assert target.site_create("south", "ef" * 32, 6.0) == site_id + 1  # identity continues after imported ids
    with pytest.raises(SystemExit):
        migrate_tool.migrate(source, target, log=lambda *_: None)  # refuses a target that holds data
    # The source was only read.
    assert sqlite3.connect(source).execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 52


def test_clickhouse_prune_drops_whole_hours(cluster):
    store = cluster()
    base = 1_800_000_000.0 - 1_800_000_000.0 % 3600
    events = [(base + h * 3600 + i, "fw", "", "generic", "", 6, "traffic", "allow", "10.0.0.1", "8.8.8.8",
               1, 53, "udp", None, "", "", f"m{h}-{i}", None) for h in range(5) for i in range(10)]
    store.write_batch(Batch(events=events, stats=[(int(base) + h * 3600, "*", 10, 0) for h in range(5)]))
    assert store.events_stored() == 50
    # Older than the retention period: the first two hours go.
    assert store.events.prune(base + 2 * 3600, 10**9) == 20 and store.events_stored() == 30
    # Over the cap: whole hours go, oldest first, while at least the cap remains (as with SQLite)...
    assert store.events.prune(0, 15) == 10 and store.events_stored() == 20
    # ...and never the newest hour.
    assert store.events.prune(0, 1) == 10 and store.events_stored() == 10
    assert store.events.prune(0, 1) == 0
    assert store.oldest_event_ts() == base + 4 * 3600
    assert store.traffic_totals(0) == (30, 0)  # counters older than the cutoff went too
    newest = store.search_events(limit=3)
    assert [e["message"] for e in newest] == ["m4-9", "m4-8", "m4-7"]
    assert store.search_events(text="M4-1")[0]["message"] == "m4-1"  # case-insensitive, like SQLite


def test_settings_by_prefix_on_clustered_storage(tmp_path, cluster):
    """What the processor reads the port workers' summaries with, the same on both backends."""
    from cerberus.db import Database

    stores = [cluster(), Database(tmp_path / "c.db")]
    for store in stores:
        store.set_setting("riskports_view:port:a", {"at": 1})
        store.set_setting("riskports_view:port:b", [2])
        store.set_setting("riskports_viewer", 3)
        store.set_setting("detectors", {})
    assert stores[0].settings_with_prefix("riskports_view:") == stores[1].settings_with_prefix("riskports_view:") == {
        "riskports_view:port:a": {"at": 1}, "riskports_view:port:b": [2]}
    stores[1].close()
