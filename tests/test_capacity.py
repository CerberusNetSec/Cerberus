"""Collector storage: what is reported, the thresholds, and the alerts they raise."""
import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from cerberus import capacity, web  # noqa: E402
from cerberus.__main__ import watch_collectors  # noqa: E402
from cerberus.bus import Spool  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.playbooks import PLAYBOOKS  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402

MB = 1024 * 1024
SETTINGS = dict(capacity.DEFAULTS)  # warn 70, critical 90


def status(name="edge-1", spool=0.0, volume=10.0, **extra):
    """A heartbeat from a process whose spool and volume are that many percent full."""
    return {"name": name, "spool_bytes": int(spool * MB), "spool_limit": 100 * MB, "spool_percent": spool,
            "volume_bytes": 1000 * MB, "volume_free": int((100 - volume) * 10 * MB), "volume_percent": volume,
            "received_at": time.time(), **extra}


def test_usage_reports_the_spool_and_its_volume(tmp_path):
    spool = Spool(tmp_path / "spool", 10_000, lock=False)
    empty = capacity.usage(spool, spool.dir)
    assert empty["spool_bytes"] == 0 and empty["spool_limit"] == 10_000 and empty["spool_percent"] == 0
    assert empty["volume_bytes"] > 0 and 0 <= empty["volume_percent"] <= 100
    assert empty["volume_free"] <= empty["volume_bytes"]
    spool.append([("t", b"k", b'"' + b"x" * 2400 + b'"')])
    assert 20 < capacity.usage(spool, spool.dir)["spool_percent"] < 30
    # A folder that is gone: the spool figures still come back.
    blind = capacity.usage(spool, tmp_path / "nowhere" / "at" / "all")
    assert "volume_bytes" not in blind and blind["spool_bytes"] > 0
    spool.limit = 0
    assert capacity.usage(spool, spool.dir)["spool_percent"] == 0  # no division by zero


def test_settings_are_validated():
    assert capacity.clean({}) == capacity.DEFAULTS
    assert capacity.clean({"warn": "60", "critical": 85, "volume": 0}) == {
        "enabled": True, "warn": 60, "critical": 85, "volume": False}
    assert capacity.clean({"critical": 100})["critical"] == 100
    assert capacity.clean({"warn": 80}, {"warn": 50, "critical": 95, "junk": 1}) == {
        "enabled": True, "warn": 80, "critical": 95, "volume": True}
    for bad in ({"warn": 0}, {"warn": 100}, {"warn": 90, "critical": 90}, {"warn": 95}, {"critical": 101},
                {"warn": "lots"}, {"critical": None}):
        with pytest.raises(ValueError):
            capacity.clean(bad)
    # Whatever is in storage never breaks the watcher.
    assert capacity.stored({"warn": 99, "critical": 5}) == capacity.DEFAULTS
    assert capacity.stored("nonsense") == capacity.DEFAULTS


def test_alerts_once_per_level_on_the_way_up():
    watch = capacity.StorageWatch()
    assert watch.check([status(spool=69.9)], SETTINGS) == []
    (warn,) = watch.check([status(spool=70)], SETTINGS)
    assert (warn.detector, warn.severity, warn.title) == ("collector_storage", "medium", "Collector spool 70% full: edge-1")
    assert warn.details["what"] == "spool" and warn.details["threshold"] == 70
    assert watch.check([status(spool=75)], SETTINGS) == []  # still at warning: said already
    (crit,) = watch.check([status(spool=93, bus_down=True, spool_dropped=12)], SETTINGS)
    assert crit.severity == "high" and crit.entity != warn.entity
    assert "unreachable now" in crit.description and "12 have been dropped" in crit.description
    assert watch.check([status(spool=100)], SETTINGS) == []


def test_straight_to_critical_raises_one_alert():
    (only,) = capacity.StorageWatch().check([status(spool=96)], SETTINGS)
    assert only.severity == "high"


def test_hovering_at_a_threshold_alerts_once_and_recovery_rearms():
    watch = capacity.StorageWatch()
    assert len(watch.check([status(spool=71)], SETTINGS)) == 1
    for percent in (69, 71, 66, 72):  # dips, but never 5 points clear
        assert watch.check([status(spool=percent)], SETTINGS) == []
    assert watch.check([status(spool=64)], SETTINGS) == []  # clear of it: re-armed
    assert len(watch.check([status(spool=70)], SETTINGS)) == 1
    # Down from critical to warning does not repeat the warning; back up does repeat critical.
    assert len(watch.check([status(spool=95)], SETTINGS)) == 1
    assert watch.check([status(spool=80)], SETTINGS) == []
    assert len(watch.check([status(spool=91)], SETTINGS)) == 1
    # From critical to empty in one step re-arms both.
    assert watch.check([status(spool=0)], SETTINGS) == []
    assert [c.severity for c in watch.check([status(spool=75)], SETTINGS)] == ["medium"]


def test_the_volume_is_watched_too_unless_switched_off():
    watch = capacity.StorageWatch()
    (alert,) = watch.check([status(spool=1, volume=92)], SETTINGS)
    assert alert.title == "Collector volume 92% full: edge-1" and alert.details["what"] == "volume"
    assert "80.0 MB free of 1000.0 MB" in alert.description
    # Spool and volume are told apart: each alerts for itself.
    assert [c.details["what"] for c in watch.check([status(spool=75, volume=92)], SETTINGS)] == ["spool"]
    assert capacity.StorageWatch().check([status(spool=1, volume=99)], {**SETTINGS, "volume": False}) == []
    # A process that cannot say how big its volume is, is judged on its spool.
    blind = {k: v for k, v in status(spool=80).items() if not k.startswith("volume")}
    assert [c.details["what"] for c in capacity.StorageWatch().check([blind], SETTINGS)] == ["spool"]


def test_each_process_is_tracked_separately_and_workers_are_named():
    watch = capacity.StorageWatch()
    found = watch.check([status("edge-1", spool=75), status("edge-2", spool=10),
                         status("w-source-0", spool=95, role="detector", family="source")], SETTINGS)
    assert sorted(c.title for c in found) == ["Collector spool 75% full: edge-1",
                                              "Detection worker spool 95% full: w-source-0"]
    worker = next(c for c in found if "worker" in c.title)
    assert worker.details["family"] == "source" and "alert candidates" in worker.description
    assert len({c.entity for c in found}) == 2
    # A process that went away and came back still full is reported again.
    assert watch.check([status("edge-2", spool=10)], SETTINGS) == []
    assert len(watch.check([status("edge-1", spool=75), status("edge-2", spool=10)], SETTINGS)) == 1


def test_switched_off_raises_nothing_and_forgets():
    watch = capacity.StorageWatch()
    assert len(watch.check([status(spool=95)], SETTINGS)) == 1
    assert watch.check([status(spool=99)], {**SETTINGS, "enabled": False}) == []
    assert len(watch.check([status(spool=99)], SETTINGS)) == 1  # back on: says where things stand


def test_changed_thresholds_apply_at_once():
    watch = capacity.StorageWatch()
    assert watch.check([status(spool=55)], SETTINGS) == []
    (alert,) = watch.check([status(spool=55)], {**SETTINGS, "warn": 50})
    assert alert.details["threshold"] == 50 and alert.severity == "medium"


def test_assess_for_the_dashboard():
    assert capacity.assess(status(spool=20, volume=85), SETTINGS) == {
        "storage_percent": 85, "storage_what": "volume", "storage_level": "warning"}
    assert capacity.assess(status(spool=95, volume=85), SETTINGS)["storage_level"] == "critical"
    assert capacity.assess(status(spool=95), {**SETTINGS, "enabled": False})["storage_level"] == ""
    assert capacity.assess({"name": "old-collector"}, SETTINGS)["storage_percent"] is None  # a 1.0 collector


def test_there_is_guidance_for_the_alert():
    book = PLAYBOOKS["collector_storage"]
    assert book["stage"] == "Network health" and len(book["actions"]) >= 3


class FakeHeartbeats:
    def __init__(self, *statuses):
        self.latest = {s["name"]: s for s in statuses}


def rig(tmp_path, heartbeats=None):
    cfg = Config.from_env()
    cfg.data_dir, cfg.auth_enabled = tmp_path, False
    db = Database(tmp_path / "c.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    app = web.create_app(cfg, db, engine, notifier, SnmpPoller(engine, db), heartbeats=heartbeats)
    return cfg, db, engine, TestClient(app)


def test_api_reads_and_saves_thresholds(tmp_path):
    beats = FakeHeartbeats(status("edge-1", spool=75), status("edge-2", spool=5),
                           {**status("edge-3", spool=99), "received_at": time.time() - 3600})
    _cfg, db, _engine, client = rig(tmp_path, beats)
    d = client.get("/api/collector-storage").json()
    assert d["settings"] == capacity.DEFAULTS and d["available"] is True
    rows = {c["name"]: c for c in d["collectors"]}
    assert rows["edge-1"]["storage_level"] == "warning" and rows["edge-1"]["storage_what"] == "spool"
    assert rows["edge-2"]["storage_level"] == "" and rows["edge-2"]["state"] == "reporting"
    assert rows["edge-3"]["state"] == "silent"

    r = client.put("/api/collector-storage", json={"settings": {"warn": 80, "critical": 95}})
    assert r.status_code == 200 and r.json()["settings"] == {"enabled": True, "warn": 80, "critical": 95, "volume": True}
    assert db.get_setting(capacity.SETTING)["warn"] == 80
    assert client.get("/api/collector-storage").json()["collectors"][0]["storage_level"] == ""  # 75 < 80 now
    # One field at a time keeps the rest.
    assert client.put("/api/collector-storage", json={"enabled": False}).json()["settings"]["warn"] == 80
    for bad in ({"warn": 96}, {"critical": 101}, {"warn": "x"}):
        r = client.put("/api/collector-storage", json={"settings": bad})
        assert r.status_code == 400 and "threshold" in r.json()["detail"]
    assert db.get_setting(capacity.SETTING)["critical"] == 95  # refused changes are not saved

    # The dashboard's collector list carries the level.
    client.put("/api/collector-storage", json={"enabled": True, "warn": 70, "critical": 90})
    collectors = {c["name"]: c for c in client.get("/api/summary").json()["collectors"]}
    assert collectors["edge-1"]["storage_level"] == "warning" and collectors["edge-1"]["storage_percent"] == 75


def test_api_on_a_standalone_instance(tmp_path):
    _cfg, _db, _engine, client = rig(tmp_path)
    d = client.get("/api/collector-storage").json()
    assert d["available"] is False and d["collectors"] == []
    assert client.get("/api/summary").json()["collectors"] is None


def test_only_admins_change_thresholds(tmp_path):
    from cerberus.accounts import required_role
    assert required_role("PUT", "/api/collector-storage") == "admin"
    assert required_role("GET", "/api/collector-storage") == "viewer"


def test_the_processor_raises_the_alert_from_heartbeats(tmp_path, monkeypatch):
    """watch_collectors, as the processor runs it: thresholds from storage, alerts through the engine."""
    beats = FakeHeartbeats(status("edge-1", spool=75), status("edge-2", spool=96),
                           {**status("edge-gone", spool=99), "received_at": time.time() - 3600})
    cfg, db, engine, client = rig(tmp_path, beats)
    raised = []
    monkeypatch.setattr(engine, "raise_alert", lambda c, now: raised.append(c))
    real_sleep = asyncio.sleep

    async def run(rounds):
        ticks = 0

        async def fast(_seconds):
            nonlocal ticks
            ticks += 1
            if ticks > rounds:
                raise asyncio.CancelledError
            await real_sleep(0)
        monkeypatch.setattr(asyncio, "sleep", fast)
        with pytest.raises(asyncio.CancelledError):
            await watch_collectors(cfg, engine, beats, db)
        monkeypatch.setattr(asyncio, "sleep", real_sleep)

    asyncio.run(run(3))
    storage = [c for c in raised if c.detector == "collector_storage"]
    # Three rounds, one alert each; the silent collector's old figures are left alone.
    assert sorted((c.details["collector"], c.severity) for c in storage) == [("edge-1", "medium"), ("edge-2", "high")]
    assert [c.title for c in raised if c.detector == "collector_silent"] == ["Collector stopped reporting: edge-gone"]

    # Thresholds raised in the dashboard: a fresh watcher (a new leader, say) uses them. 75% is fine now,
    # and 96% is only a warning.
    client.put("/api/collector-storage", json={"warn": 80, "critical": 97})
    raised.clear()
    asyncio.run(run(1))
    assert [(c.details["collector"], c.severity) for c in raised if c.detector == "collector_storage"] == [
        ("edge-2", "medium")]


def test_a_spool_that_filled_during_an_outage_is_still_reported(tmp_path):
    """The bus was down, the spool filled, the bus came back and the spool emptied before the
    next heartbeat: the peak since the last heartbeat that got through tells the processor."""
    spool = Spool(tmp_path / "spool", 10_000, lock=False)
    peak = capacity.Peak(spool)
    spool.append([("t", b"k", b'"' + b"x" * 8000 + b'"')])
    peak.sample()  # a heartbeat tick while the bus is down
    for f in spool.files():  # sent once the bus is back
        spool._close_open()
        f.unlink()
    beat = {"name": "edge-1", **capacity.usage(spool, spool.dir, peak)}
    assert beat["spool_bytes"] == 0 and beat["spool_percent"] == 0 and 80 < beat["spool_peak_percent"] < 82

    spool_only = {**SETTINGS, "volume": False}  # this test machine's own disk is not the subject
    (alert,) = capacity.StorageWatch().check([beat], spool_only)
    assert alert.severity == "medium" and alert.title == "Collector spool reached 80%: edge-1"
    assert "while it could not reach the message bus" in alert.description and "(0%)" in alert.description
    assert capacity.assess(beat, spool_only)["storage_level"] == "warning"

    peak.reported()  # that heartbeat got through: the next one starts again from what is held now
    assert capacity.usage(spool, spool.dir, peak)["spool_peak_percent"] == 0
