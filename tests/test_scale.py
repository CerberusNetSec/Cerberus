"""Behaviour that only matters with many devices or a lot of traffic."""
import asyncio
import ipaddress
import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database, QueryTimeout  # noqa: E402
from cerberus.detectors import build_detectors  # noqa: E402
from cerberus.engine import TOTAL, Device, Engine  # noqa: E402
from cerberus.models import _INTERNAL, clean_ip, is_internal  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402
from cerberus.syslog_parser import parse_syslog  # noqa: E402
from cerberus.topology import build_topology  # noqa: E402
from tools import loadtest, simulate, snmp_sim  # noqa: E402


def make_engine(tmp_path, **cfg_overrides):
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity = tmp_path, "ip"
    for key, value in cfg_overrides.items():
        setattr(cfg, key, value)
    db = Database(tmp_path / "cerberus.db")
    engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    engine.load()
    return engine, db


def alerts(engine) -> list[tuple]:
    """(detector, entity, title) of everything raised so far, written to disk or not yet."""
    stored = [(r["detector"], r["entity"], r["title"]) for r in engine.db.q("SELECT * FROM alerts ORDER BY id")]
    return stored + [(row[3], row[7], row[5]) for row in engine.alerts.new_rows]


# --- ingest hot path ------------------------------------------------------------------
def test_fast_ip_path_agrees_with_ipaddress():
    rnd = random.Random(1)
    samples = [".".join(str(rnd.randint(0, 255)) for _ in range(4)) for _ in range(3000)]
    samples += ["10.0.0.1", "172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0", "192.168.0.1", "192.169.0.1",
                "100.63.255.255", "100.64.0.0", "100.127.255.255", "100.128.0.0", "169.254.1.1", "127.0.0.1", "0.0.0.0",
                "255.255.255.255", "198.51.100.7", "fe80::1", "fd00::5", "2001:db8::1", "::1"]
    for text in samples:
        addr = ipaddress.ip_address(text)
        assert clean_ip(text) == str(addr)
        assert is_internal(text) == any(addr.version == n.version and addr in n for n in _INTERNAL), text
    for junk in ("", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.-4", "a.b.c.d", "1.2.3.4 ; rm", "١.٢.٣.٤", "1..2.3"):
        assert clean_ip(junk) is None and is_internal(junk) is False, junk
    assert clean_ip(" 10.1.2.3 ") == "10.1.2.3" and clean_ip("[2001:DB8::1]") == "2001:db8::1"


def test_connector_hint_is_tried_first_but_never_trusted():
    registry = ConnectorRegistry()
    forti = parse_syslog(simulate.forti_traffic("192.168.3.20", "104.16.1.1", 443).encode())
    cisco = parse_syslog(simulate.cisco(1, "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)").encode())
    for hint in ("", "fortinet", "cisco_ios", "generic", "no-such-connector"):
        assert registry.build_event(forti, 1.0, "d", "10.0.0.1", "", hint).connector == "fortinet"
        assert registry.build_event(cisco, 1.0, "d", "10.0.0.1", "", hint).connector == "cisco_ios"
    # A pin still wins over everything.
    assert registry.build_event(forti, 1.0, "d", "10.0.0.1", "generic", "fortinet").connector == "generic"


def test_many_devices_through_the_pipeline(tmp_path):
    engine, db = make_engine(tmp_path)
    engine.installed = 0  # long past the learning period
    devices = loadtest.estate(400)
    start = 2_000_000.0
    for i, (data, ip) in enumerate(loadtest.messages(devices, 20_000)):
        engine._process(data, ip, start + i / 2000)
    asyncio.run(engine._flush())
    assert engine.parse_errors == 0
    assert len(engine.devices) > 350  # nearly every device got a word in
    seen = {d.connector_seen for d in engine.devices.values()}
    assert seen == {"opnsense", "paloalto", "fortinet", "cisco_ios", "rtl_playground"}
    # Ordinary traffic from a big estate raises nothing except the news that the estate appeared - once.
    assert {a[0] for a in alerts(engine)} == {"new_device"}
    assert sum(1 for a in alerts(engine) if a[1] == "group") == 1 and len(alerts(engine)) == 11
    assert db.events_stored() == 20_000 == len(db.search_events(limit=10**6))
    # The all-devices row equals the sum of the per-device rows, minute by minute.
    per_device = db.q("SELECT minute, SUM(events) AS e, SUM(blocked) AS b FROM stats_minute WHERE device != ? GROUP BY minute", (TOTAL,))
    total = db.q("SELECT minute, events AS e, blocked AS b FROM stats_minute WHERE device = ? ORDER BY minute", (TOTAL,))
    assert total == per_device and sum(r["e"] for r in total) == 20_000
    db.close()


def test_new_devices_one_at_a_time_still_alert_individually(tmp_path):
    engine, db = make_engine(tmp_path)
    engine.installed = 0  # long past the learning period
    for i in range(5):
        engine._process(b"<13>Nov 13 10:00:00 sw app: hello", f"10.9.9.{i + 1}", 3_000_000.0 + i * 700)
    assert [a[1] for a in alerts(engine)] == [f"10.9.9.{i + 1}" for i in range(5)]
    db.close()


def test_traffic_sampling_thins_storage_not_detection(tmp_path):
    engine, db = make_engine(tmp_path, traffic_sample=10, device_identity="hostname")
    engine.installed = 0
    now = 4_000_000.0
    lines = [*simulate.baseline(300), *simulate.lateral(), *simulate.portscan()]
    for i, line in enumerate(lines):
        engine._process(line.encode(), "10.255.0.1", now + i * 0.05)
    asyncio.run(engine._flush())
    kinds = {a[0] for a in alerts(engine)}
    assert {"lateral_movement", "port_scan"} <= kinds  # lateral movement is made of *allowed* traffic
    count = {"allow": 0, "block": 0}
    for row in db.search_events(event_type="traffic", limit=10**6):
        count[row["action"]] += 1
    allowed = sum(1 for line in lines if "pass" in line or "allow" in line or "accept" in line)
    assert abs(count["allow"] - allowed / 10) <= 2 and engine.unstored == allowed - count["allow"]
    assert count["block"] == len(lines) - allowed  # blocked traffic is always kept
    db.close()

    engine, db = make_engine(tmp_path / "none", traffic_sample=0, device_identity="hostname")
    for i, line in enumerate(simulate.baseline(50)):
        engine._process(line.encode(), "10.255.0.1", now + i)
    asyncio.run(engine._flush())
    assert db.search_events(action="allow") == [] and db.events_stored() > 0
    db.close()


def test_devices_going_silent_together_make_one_alert():
    detectors = {d.id: d for d in build_detectors()}
    rate, silent = detectors["rate_anomaly"], detectors["device_silent"]
    found = []
    registry = ConnectorRegistry()
    now = 60_000.0

    def hear(device: str, ts: float):
        parsed = parse_syslog(b"<13>Nov 13 10:00:00 host app: tick")
        rate.baselines.observe(registry.build_event(parsed, ts, device, device), ts)

    for _minute in range(45):
        for d in range(40):
            for i in range(3):
                hear(f"10.1.0.{d}", now + i)
        now += 60
        rate.tick(now, found.append)
        silent.tick(now, found.append)
    assert found == []
    for _minute in range(20):  # 30 of them stop; ten carry on
        for d in range(30, 40):
            hear(f"10.1.0.{d}", now)
        now += 60
        rate.tick(now, found.append)
        silent.tick(now, found.append)
    assert len(found) == 30  # every device is reported ...
    entities = [c.entity for c in found]
    assert entities.count("group") == 26 and len(set(entities)) == 5  # ... but as four alerts and one outage
    last = [c for c in found if c.entity == "group"][-1]
    assert last.details["count"] == 30 and "30 devices" in last.description


# --- storage ----------------------------------------------------------------------------
def event(ts: float, i: int) -> tuple:
    """One row in EVENT_COLUMNS order."""
    return (ts, f"dev{i % 7}", "", "generic", "", 6, "traffic", "allow", f"10.0.0.{i % 50}", f"8.8.{i % 3}.{i % 9}",
            40000, 443 if i % 5 else 22, "tcp", None, "", "", f"m{i}", None)


def fill(db: Database, rows: int, start: float = 1000.0, step: float = 1.0, batch: int = 250) -> None:
    for lo in range(0, rows, batch):
        db.write([event(start + i * step, i) for i in range(lo, min(lo + batch, rows))])


def test_events_are_stored_in_segments_and_read_back_in_order(tmp_path):
    db = Database(tmp_path / "s.db", segment_rows=1000)
    fill(db, 5300)
    assert [(s["name"], s["first_id"], s["rows"]) for s in db._segments] == [
        ("events_000001", 1, 1000), ("events_000002", 1001, 1000), ("events_000003", 2001, 1000),
        ("events_000004", 3001, 1000), ("events_000005", 4001, 1000), ("events_000006", 5001, 300)]
    assert db.events_stored() == 5300 and db.oldest_event_ts() == 1000.0
    # One page spans a segment boundary, newest first, and paging continues where it stopped.
    page = db.search_events(limit=500)
    assert [r["id"] for r in page] == list(range(5300, 4800, -1))
    older = db.search_events(before=page[-1]["id"], limit=500)
    assert [r["id"] for r in older] == list(range(4800, 4300, -1))
    # Filters, across every segment.
    ssh = db.search_events(port=22, limit=10**6)
    assert len(ssh) == 5300 // 5 and all(r["dst_port"] == 22 for r in ssh)
    assert [r["id"] for r in ssh] == sorted((r["id"] for r in ssh), reverse=True)
    one = db.search_events(ip="10.0.0.7", limit=10**6)
    assert len(one) == 5300 // 50
    # A time range: only events at or after it, and old segments are not even opened.
    recent = db.search_events(since=1000.0 + 5000, limit=10**6)
    assert [r["id"] for r in recent] == list(range(5300, 5000, -1))
    opened = []
    real = db.q
    db.q = lambda sql, params=(), timeout=0: (opened.append(sql.split()[3]), real(sql, params, timeout))[1]
    assert len(db.search_events(since=1000.0 + 4500, limit=10**6)) == 800
    assert opened == ["events_000006", "events_000005"]
    db.q = real
    # Reopening the file finds the segments and carries on numbering.
    db.close()
    db = Database(tmp_path / "s.db", segment_rows=1000)
    db.write([event(9999.0, 1)])
    assert db.search_events(limit=1)[0]["id"] == 5301 and db.events_stored() == 5301
    db.close()


def test_segment_indexes_serve_every_events_filter(tmp_path):
    db = Database(tmp_path / "i.db")
    fill(db, 2000)
    for column, value in (("device", "dev3"), ("src_ip", "10.0.0.7"), ("dst_ip", "8.8.1.4"), ("dst_port", 22)):
        plan = db.q(f"EXPLAIN QUERY PLAN SELECT * FROM events_000001 WHERE ts >= ? AND {column} = ? ORDER BY id DESC LIMIT 200", (0, value))
        detail = " ".join(row["detail"] for row in plan)
        assert "USING INDEX events_000001_" in detail and "TEMP B-TREE" not in detail, (column, detail)
    db.close()


def test_prune_drops_whole_segments(tmp_path):
    db = Database(tmp_path / "p.db", segment_rows=500)
    fill(db, 5000)  # ten segments of 500, one second per event
    assert len(db._segments) == 10
    # Row cap: at least 1,200 stay, so the three newest segments (1,500 rows) are kept.
    assert db.prune(now=1000.0 + 5000, retention_days=7, max_events=1200, alert_days=90) == 3500
    assert db.events_stored() == 1500 and db.search_events(limit=10**6)[-1]["id"] == 3501
    tables = {r["name"] for r in db.q("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'events_%'")}
    assert tables == {"events_000008", "events_000009", "events_000010"}
    # Age: a segment goes once everything in it is older than the retention period.
    day = 86400
    assert db.prune(now=1000.0 + 4000 + day - 1, retention_days=1, max_events=10**9, alert_days=90) == 0
    assert db.prune(now=1000.0 + 4000 + day + 1, retention_days=1, max_events=10**9, alert_days=90) == 500
    # The segment being written is never dropped, however old.
    assert db.prune(now=1000.0 + 10 * day, retention_days=1, max_events=1, alert_days=90) == 500
    assert db.events_stored() == 500 and len(db._segments) == 1
    # ... but a quiet system still expires: the next event, a day on, starts a new segment.
    db.write([event(1000.0 + 5000 + 2 * day, 1)])
    assert len(db._segments) == 2
    assert db.prune(now=1000.0 + 5000 + 4 * day, retention_days=1, max_events=10**9, alert_days=90) == 500
    assert [r["message"] for r in db.search_events(limit=10)] == ["m1"]
    db.close()
    empty = Database(tmp_path / "e.db")
    assert empty.prune(now=0.0, retention_days=1, max_events=10, alert_days=90) == 0 and empty.search_events() == []
    empty.close()


def test_database_from_before_segments_keeps_its_events(tmp_path):
    import sqlite3
    old = sqlite3.connect(tmp_path / "old.db")
    old.executescript("""CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL NOT NULL, device TEXT, hostname TEXT,
        connector TEXT, app TEXT, sev INTEGER, event_type TEXT, action TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER,
        dst_port INTEGER, proto TEXT, bytes INTEGER, user TEXT, interface TEXT, message TEXT, extra TEXT);
        CREATE INDEX events_ts ON events(ts);""")
    old.executemany("INSERT INTO events(ts, device, src_ip, message) VALUES(?,?,?,?)",
                    [(500.0 + i, "fw", "10.0.0.9", f"old{i}") for i in range(40)])
    old.commit()
    old.close()
    for _reopen in range(2):  # adopting it is done once, not on every start
        db = Database(tmp_path / "old.db", segment_rows=100)
        assert db.events_stored() == 40 and db.oldest_event_ts() == 500.0
        db.close()
    db = Database(tmp_path / "old.db", segment_rows=100)
    db.write([event(2000.0, 3)])
    found = db.search_events(ip="10.0.0.9")
    assert len(found) == 40 and found[0]["message"] == "old39"
    assert [r["id"] for r in db.search_events(limit=3)] == [41, 40, 39]
    db.close()


def test_write_buffer_is_bounded(tmp_path, monkeypatch):
    from cerberus import engine as engine_module
    monkeypatch.setattr(engine_module, "MAX_PENDING_EVENTS", 50)
    engine, db = make_engine(tmp_path)
    for i in range(80):  # nothing flushes: the disk has "stalled"
        engine._process(b"<13>Nov 13 10:00:00 sw app: hello", "10.9.9.1", 5_000_000.0 + i)
    assert len(engine._events) == 50 and engine.unwritten == 30 and engine.received == 80
    asyncio.run(engine._flush())
    assert db.events_stored() == 50
    db.close()


def test_slow_read_is_cancelled_and_readers_run_side_by_side(tmp_path):
    db = Database(tmp_path / "t.db")
    endless = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT COUNT(*) FROM n"
    started = time.monotonic()
    with pytest.raises(QueryTimeout):
        db.q(endless, timeout=0.3)
    assert time.monotonic() - started < 3
    assert db.q("SELECT 1 AS one") == [{"one": 1}]  # the connection went back to the pool, usable

    async def together():
        slow = asyncio.create_task(db.aq(endless, timeout=1.5))
        await asyncio.sleep(0.1)
        t0 = time.monotonic()
        quick = await db.aq("SELECT 2 AS two")  # must not queue behind the slow one
        waited = time.monotonic() - t0
        with pytest.raises(QueryTimeout):
            await slow
        return quick, waited
    quick, waited = asyncio.run(together())
    assert quick == [{"two": 2}] and waited < 0.5
    db.close()


# --- SNMP and topology ---------------------------------------------------------------------
def test_failing_devices_are_polled_less_often(tmp_path):
    engine, db = make_engine(tmp_path)
    poller = SnmpPoller(engine, db)
    poller.apply_settings({"enabled": True, "community": "public", "interval": 300}, save=False)
    waits = [poller.wait_for({"fails": n}) for n in range(8)]
    assert waits == [300, 300, 600, 1200, 2400, 3600, 3600, 3600] and poller.wait_for(None) == 300
    poller.apply_settings({"interval": 7200}, save=False)
    assert poller.wait_for({"fails": 9}) == 7200  # never more often than the configured interval
    assert poller.apply_settings({"concurrency": 500}, save=False) == [] and poller.settings["concurrency"] == 64
    db.close()


def test_campus_polled_concurrently_and_mapped(tmp_path):
    sites, access, endpoints = 6, 4, 3
    mibs = snmp_sim.campus(sites, access, endpoints)
    assert len(mibs) == 2 + sites * (2 + access)
    engine, db = make_engine(tmp_path)

    async def go():
        agents = await snmp_sim.serve(mibs, first_port=0)
        poller = SnmpPoller(engine, db)
        poller.client.timeout, poller.client.retries = 1, 1
        poller.apply_settings({"enabled": True, "community": "public", "concurrency": 8}, save=False)
        for name, (_, _, port) in agents.items():
            engine.devices[name] = Device(name, "192.0.2.1", hostname=name, snmp_host=f"127.0.0.1:{port}")
        # One device that will never answer must not hold the rest up.
        # (A socket nobody reads from, like a device behind a firewall that drops SNMP.)
        mute, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0))
        engine.devices["dead"] = Device("dead", "192.0.2.2",
                                        snmp_host=f"127.0.0.1:{mute.get_extra_info('sockname')[1]}")
        try:
            assert poller.start_sweep() == len(mibs) + 1 and poller.start_sweep() == 0  # no second sweep on top
            assert poller.progress()["sweeping"]
            await poller._sweep
        finally:
            poller.client.close()
            mute.close()
            for transport, _, _ in agents.values():
                transport.close()
        return poller
    poller = asyncio.run(go())
    assert sum(1 for r in poller.records.values() if r["ok"]) == len(mibs)
    assert poller.records["dead"]["ok"] is False and poller.records["dead"]["fails"] == 1
    assert poller.status(engine.devices["dead"])["next_try"] is not None

    graph = build_topology([d.as_dict() for d in engine.devices.values()], poller.records, {})
    managed = [n for n in graph["nodes"] if n["managed"]]
    ends = [n for n in graph["nodes"] if not n["managed"]]
    assert len(managed) == len(mibs) + 1 and len(ends) == sites * access * endpoints
    # Every cable once: core-core, and per site dist-core, dist-fw, dist-access and access-endpoint.
    assert len(graph["links"]) == 1 + sites * (2 + access + access * endpoints)
    assert all(n["links"] == 1 for n in ends)
    by_label = {n["label"]: n for n in graph["nodes"]}
    assert by_label["s001-dist"]["links"] == 2 + access and by_label["core-1"]["links"] == sites // 2 + 1
    assert not by_label["dead"]["linked"]
    db.close()


def test_topology_merge_is_linear():
    # 2,000 devices in a chain, each link reported from both ends: quick only if links are looked up, not searched.
    devices, records = [], {}
    for i in range(2000):
        name = f"sw{i}"
        devices.append({"id": name, "ip": f"10.{i // 250}.{i % 250}.1", "hostname": name, "name": "", "connector_seen": "cisco_ios"})
        neighbors = [{"proto": "lldp", "local_port": port, "local_names": [port], "local_ifindex": "", "chassis_id": "",
                      "port_id": other_port, "port_desc": "", "sys_name": f"sw{j}", "sys_desc": "", "mgmt_ip": ""}
                     for j, port, other_port in ((i - 1, "Gi1/0/1", "Gi1/0/2"), (i + 1, "Gi1/0/2", "Gi1/0/1")) if 0 <= j < 2000]
        records[name] = {"ok": True, "polled": 1.0, "data": {"system": {}, "interfaces": {}, "ips": [], "chassis_id": "",
                                                             "neighbors": neighbors}}
    started = time.perf_counter()
    graph = build_topology(devices, records, {})
    assert len(graph["nodes"]) == 2000 and len(graph["links"]) == 1999
    assert time.perf_counter() - started < 2.0
