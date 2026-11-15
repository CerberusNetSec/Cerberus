"""Detection divided between workers finds what one process does.

The reference traffic from tests/golden.py goes through a processor that runs
only the device family and the alert stage, plus two detection workers for
every other family, each event routed to a worker by its family's key the way
a collector does, and every event and alert candidate passed as JSON. The
alerts and everything stored must match the single-process reference.
"""
import asyncio
import json
import sys
import zlib
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import golden  # noqa: E402
from cerberus.bus import encode_event  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.detectors import WORKER_FAMILIES, family_event_types, family_key  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate, Event  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.storage import Batch  # noqa: E402
from cerberus.worker import DetectionWorker, riskports_view  # noqa: E402
from tools import simulate  # noqa: E402

REFERENCE = Path(__file__).resolve().parent / "golden" / "v0.2.0.json"
SHARDS = 2


def settings(engine):
    watch = {d.id: d.settings() for d in engine.detectors}
    watch["watchlist"]["entries"] = "45.77.0.0/16"
    engine.apply_settings(watch, engine.general_settings())


def run_with_workers(data_dir: Path) -> tuple[dict, list]:
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity = data_dir, "hostname"
    cfg.detection_workers = WORKER_FAMILIES
    db = Database(data_dir / "cerberus.db")
    engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    engine.load()
    engine.installed = golden.START - 86400
    engine.families = {"device", "alerts"}
    settings(engine)

    workers: dict[str, list[DetectionWorker]] = {}
    for family in WORKER_FAMILIES:
        wcfg = Config.from_env()
        wcfg.detection_workers, wcfg.detection_family = WORKER_FAMILIES, family
        shards = []
        for _ in range(SHARDS):
            e = Engine(wcfg, db, ConnectorRegistry(), Notifier(db))
            e.families = {family}
            settings(e)
            shards.append(DetectionWorker(wcfg, db, e, publisher=None, source=SimpleNamespace()))
        workers[family] = shards
    types = {f: family_event_types(f) for f in WORKER_FAMILIES}

    def deliver(candidates):
        for _topic, _key, value in candidates:
            body = json.loads(value)
            engine.raise_alert(Candidate.from_dict(body), float(body["_ts"]))

    def tick(now):
        for shards in workers.values():
            for w in shards:
                deliver(w.tick(now))
        for w in workers["port"]:
            rows = w.engine.risk_ports.drain()
            if rows:
                db.write_batch(Batch(ports=rows))
        engine.tick(now)

    loop = asyncio.new_event_loop()
    seq = 0
    next_tick = golden.START + golden.TICK
    for offset, line in golden.timeline(simulate):
        ts = golden.START + offset
        while next_tick <= ts:
            loop.run_until_complete(engine._flush())
            tick(next_tick)
            next_tick += golden.TICK
        seq += 1
        _key, value = encode_event(engine.parse(line.encode(), "10.255.0.1", ts), ("collector", seq))
        ev = Event.from_dict(json.loads(value))
        if not engine.record(ev, ts):
            continue
        engine.detect(ev, ts)
        for family, shards in workers.items():
            if ev.event_type in types[family]:
                w = shards[zlib.crc32(family_key(family, ev).encode()) % SHARDS]
                deliver(w.handle([SimpleNamespace(value=value)]))
    loop.run_until_complete(engine._flush())
    tick(next_tick)
    loop.run_until_complete(engine._flush())
    loop.close()
    views = [riskports_view(w.engine.risk_ports, next_tick) for w in workers["port"]]
    db.close()
    return golden.summarise(data_dir / "cerberus.db"), views


def comparable(alerts):
    return sorted((a["created"], a["detector"], a["entity"], a["severity"], a["title"], a["count"], a["status"],
                   a["description"], a["details"]) for a in alerts)


def test_workers_find_the_same_alerts_and_store_the_same(tmp_path):
    expected = json.loads(REFERENCE.read_text(encoding="utf-8"))
    actual, views = run_with_workers(tmp_path)
    actual = json.loads(json.dumps(actual))
    # Workers' candidates reach the alert stage in a different order, so alert ids may differ.
    assert comparable(actual["alerts"]) == comparable(expected["alerts"])
    for table in ("events", "stats_minute", "port_minute", "devices"):
        assert actual[table] == expected[table], table
    assert json.loads(json.dumps(views))  # the Risk ports summary is plain JSON


def test_collector_routes_each_event_to_the_families_that_read_it(tmp_path):
    from cerberus.collector import Collector

    cfg = Config.from_env()
    cfg.data_dir = tmp_path
    cfg.detection_workers = ("source", "account")
    collector = Collector.__new__(Collector)
    collector.cfg, collector.run, collector.seq = cfg, "r", 0
    collector.publisher = SimpleNamespace(topic=cfg.kafka_topic)
    collector.routes = [(f"{cfg.kafka_topic}.{f}", f, family_event_types(f)) for f in cfg.detection_workers]
    traffic = Event(ts=1.0, device="fw", source_ip="10.255.0.1", event_type="traffic", src_ip="203.0.113.9", dst_ip="10.0.0.5",
                    dst_port=22, action="deny")
    login = Event(ts=1.0, device="fw", source_ip="10.255.0.1", event_type="auth_failure", src_ip="203.0.113.9", user="admin")
    other = Event(ts=1.0, device="fw", source_ip="10.255.0.1", event_type="system")
    topics = lambda ev: [(t, k) for t, k, _v in collector.encode(ev)]  # noqa: E731
    assert topics(traffic) == [(cfg.kafka_topic, b"fw"), (cfg.kafka_topic + ".source", b"203.0.113.9")]
    assert topics(login) == [(cfg.kafka_topic, b"fw"), (cfg.kafka_topic + ".source", b"203.0.113.9"),
                             (cfg.kafka_topic + ".account", b"fw|admin")]
    assert topics(other) == [(cfg.kafka_topic, b"fw")]
    # Every copy of one event carries the same unique id, so duplicates are recognised anywhere.
    uids = {json.loads(v)["_uid"][1] for _t, _k, v in collector.encode(login)}
    assert len(uids) == 1


def test_risk_ports_page_merges_the_port_workers_summaries(tmp_path):
    from cerberus.worker import RISKPORTS_VIEW, merge_views

    db = Database(tmp_path / "cerberus.db")
    top = {"sources": [{"ip": "10.0.0.9", "allowed": 3, "blocked": 0, "internal": True, "new": False}],
           "destinations": []}
    db.set_setting(RISKPORTS_VIEW + "port:a", {"at": 1000.0, "since": 500.0, "fresh": {"3389": 2},
                                               "spikes": [{"port": 3389, "direction": "inbound"}],
                                               "talkers": {"3389": {"inbound": top}}})
    db.set_setting(RISKPORTS_VIEW + "port:b", {"at": 1010.0, "since": 400.0, "fresh": {"23": 1},
                                               "spikes": [], "talkers": {"23": {"internal": top}}})
    db.set_setting(RISKPORTS_VIEW + "port:gone", {"at": 1.0, "since": 1.0, "fresh": {"21": 9}, "spikes": [],
                                                  "talkers": {}})
    db.set_setting("riskports_other", {"at": 1000.0})
    views = db.settings_with_prefix(RISKPORTS_VIEW)
    assert sorted(views) == [RISKPORTS_VIEW + n for n in ("port:a", "port:b", "port:gone")]
    merged = merge_views(views.values(), 1020.0)
    assert merged["since"] == 400.0
    assert merged["fresh"] == {3389: 2, 23: 1}  # the summary from a worker long gone is left out
    assert merged["spikes"] == [{"port": 3389, "direction": "inbound"}]
    assert set(merged["talkers"]) == {3389, 23}
    db.close()
