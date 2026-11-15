"""Serialisable events and detector state."""
import json
import sys
import time
from collections import Counter, deque
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.detectors import SlidingSet, build_detectors  # noqa: E402
from cerberus.engine import STATE_KEY, Engine  # noqa: E402
from cerberus.models import Candidate, Event  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.state import decode, encode  # noqa: E402
from tools import simulate  # noqa: E402


def roundtrip(value):
    return decode(json.loads(json.dumps(encode(value))))


def test_codec_keeps_types_and_order():
    s = SlidingSet()
    for i, item in enumerate(["c", "a", "b"]):
        s.add(item, 100.0 + i, 60)
    value = {
        ("10.0.0.1", 445): [1.5, s], "plain": {"x": (1, None)}, 7: deque([1, 2], maxlen=5),
        "tags": {"a"}, "counts": Counter({("1.2.3.4", 0): 3}), "nothing": None, "flag": True,
    }
    back = roundtrip(value)
    assert back.keys() == value.keys() and list(back) == list(value)
    assert back[("10.0.0.1", 445)][0] == 1.5 and list(back[("10.0.0.1", 445)][1].items) == ["c", "a", "b"]
    assert back["plain"] == {"x": (1, None)} and back[7] == deque([1, 2]) and back[7].maxlen == 5
    assert back["tags"] == {"a"} and back["counts"] == Counter({("1.2.3.4", 0): 3})
    assert isinstance(back["counts"], Counter) and back["flag"] is True


def test_codec_refuses_unknown_types():
    class Stranger:
        pass
    with pytest.raises(TypeError):
        encode(Stranger())
    with pytest.raises(ValueError):
        decode({"O": "os.system", "a": {}})  # only registered classes are ever built
    with pytest.raises(ValueError):
        decode({"Z": 1})


def test_events_and_candidates_round_trip():
    ev = Event(ts=1.0, device="fw", source_ip="10.0.0.1", event_type="traffic", action="allow",
               src_ip="10.0.0.5", dst_ip="8.8.8.8", dst_port=53, extra={"policy": "out"})
    assert Event.from_dict(json.loads(json.dumps(ev.as_dict()))) == ev
    assert Event.from_dict({**ev.as_dict(), "from_a_newer_version": 1}) == ev
    c = Candidate("port_scan", "a>b", "high", "t", "d", "10.0.0.5", "fw", {"n": 1})
    assert Candidate.from_dict(json.loads(json.dumps(c.as_dict()))) == c


def test_every_detector_snapshots_to_json_after_real_traffic():
    detectors = build_detectors()
    found = []
    reg = ConnectorRegistry()
    from cerberus.syslog_parser import parse_syslog
    now = 1_000_000.0
    for name, scenario in simulate.SCENARIOS.items():
        if name in simulate.SLOW:
            continue
        for line in scenario():
            now += 0.05
            ev = reg.build_event(parse_syslog(line.encode()), now, "fw", "10.0.0.1")
            for det in detectors:
                det.process(ev, now, found.append)
    for det in detectors:
        det.tick(now, found.append)
        text = json.dumps(det.snapshot())
        fresh = next(d for d in build_detectors() if d.id == det.id)
        fresh.restore(json.loads(text))
        assert json.dumps(fresh.snapshot()) == text, det.id
    assert found


def engine(tmp_path):
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity = tmp_path, "hostname"
    db = Database(tmp_path / "cerberus.db")
    e = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    return e, db


def test_downtime_does_not_make_every_device_silent(tmp_path):
    e, db = engine(tmp_path)
    e.load(now=0.0)
    t = 50_000.0
    for minute in range(40):  # a steady device, well past the warm-up
        for i in range(10):
            e._process(b"<13>Nov 13 10:00:00 sw1 app: tick", "10.0.0.2", t + i)
        t += 60
        e.tick(t)
    e.save_state(t)
    db.close()
    # Cerberus is down for an hour, then starts again.
    e2, db2 = engine(tmp_path)
    e2.load(now=t + 3600)
    found = []
    silent = e2.by_id["device_silent"]
    silent.tick(t + 3600 + 60, found.append)
    assert found == []  # the outage was ours, not the device's
    silent.tick(t + 3600 + 16 * 60, found.append)
    assert [c.detector for c in found] == ["device_silent"]  # real silence after the restart still counts
    db2.close()


def test_damaged_snapshot_starts_that_detector_empty(tmp_path):
    e, db = engine(tmp_path)
    e.load(now=0.0)
    snap = e.snapshot(now=10.0)
    snap["detectors"]["port_scan"]["_state"] = {"O": "NoSuchClass", "a": {}}
    db.set_setting(STATE_KEY, snap)
    db.close()
    e2, db2 = engine(tmp_path)
    e2.load(now=20.0)  # does not raise
    assert e2.by_id["port_scan"]._state == {}
    db2.close()


def test_legacy_admin_sources_are_still_read(tmp_path):
    e, db = engine(tmp_path)
    db.set_setting("admin_sources", {"known": {"core-sw1": {"192.168.1.10": 5.0}}, "first": {"core-sw1": 1.0}})
    e.load(now=time.time())
    assert e.admin_access.known == {"core-sw1": {"192.168.1.10": 5.0}}
    db.close()


def test_settings_and_state_from_before_the_split_carry_over(tmp_path):
    """0.5.0 saved credential_attacks and correlation as single detectors."""
    from cerberus.engine import migrate_detector_settings
    from cerberus.state import encode
    old = {"credential_attacks": {"enabled": False, "users": 9, "sources": 7, "window": 300},
           "correlation": {"enabled": True, "indicators": 4, "window_hours": 12}}
    new = migrate_detector_settings(old)
    assert new["password_spray"] == {"enabled": False, "users": 9, "window": 300}
    assert new["distributed_guessing"] == {"enabled": False, "sources": 7, "window": 300}
    assert new["hostile_allowed"] == {"enabled": True, "window_hours": 12}

    e, db = engine(tmp_path)
    e.load(now=0.0)
    s = SlidingSet()
    s.add("alice", 100.0, 600)
    snap = e.snapshot(now=100.0)
    snap["detectors"].pop("password_spray")
    snap["detectors"].pop("distributed_guessing")
    snap["detectors"].pop("hostile_allowed")
    snap["detectors"]["credential_attacks"] = {
        "_state": encode({("spray", "1.2.3.4", "fw"): [100.0, s], ("dist", "fw", "alice"): [100.0, SlidingSet()]}),
        "_emitted": encode({("spray", "1.2.3.4", "fw"): 100.0})}
    snap["detectors"]["correlation"] = {
        "_state": encode({}), "_emitted": encode({("host", "10.0.0.5"): 90.0, ("hostile", "9.9.9.9", "10.0.0.6"): 95.0}),
        "hosts": encode({"10.0.0.5": {"network scanning": 90.0}}), "hostile": encode({"9.9.9.9": (95.0, "port scanning")})}
    db.set_setting(STATE_KEY, snap)
    db.close()
    e2, db2 = engine(tmp_path)
    e2.load(now=110.0)
    spray, dist = e2.by_id["password_spray"], e2.by_id["distributed_guessing"]
    assert list(spray._state) == [("spray", "1.2.3.4", "fw")] and list(dist._state) == [("dist", "fw", "alice")]
    assert list(spray._state[("spray", "1.2.3.4", "fw")][1].items) == ["alice"]
    assert e2.by_id["hostile_allowed"].hostile == {"9.9.9.9": (95.0, "port scanning")}
    assert e2.by_id["correlation"].hosts == {"10.0.0.5": {"network scanning": 90.0}}
    assert list(e2.by_id["correlation"]._emitted) == [("host", "10.0.0.5")]
    db2.close()
