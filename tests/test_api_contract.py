"""Every HTTP endpoint's answer on a fixed dataset, compared with a recording.

Refactors below the web layer (storage especially) must not change what the
API returns. This loads the reference traffic from tests/golden.py, pins the
clock, calls every endpoint (reads, then writes, then reads again) and compares
the answers with tests/golden/api.json.

    RECORD_API_CONTRACT=1 python -m pytest tests/test_api_contract.py

re-records it, for a deliberate change.
"""
import asyncio
import json
import os
import sys
import time
import types
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import golden  # noqa: E402
from cerberus import web  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402
from tools import simulate  # noqa: E402

RECORDING = Path(__file__).resolve().parent / "golden" / "api.json"
NOW = golden.START + 6000  # just after the reference traffic ends
VOLATILE = {"uptime", "flush_ms", "rate", "queue", "updated"}  # depend on the machine or the wall clock


def scrub(value):
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def build(tmp_path, monkeypatch):
    clock = types.SimpleNamespace(time=lambda: NOW, monotonic=time.monotonic, perf_counter=time.perf_counter)
    monkeypatch.setattr(web, "time", clock)
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity, cfg.auth_enabled = tmp_path, "hostname", False
    db = Database(tmp_path / "cerberus.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load(now=golden.START)
    engine.installed = golden.START - 86400
    engine.started = NOW - 100
    loop = asyncio.new_event_loop()
    next_tick = golden.START + golden.TICK
    for offset, line in golden.timeline(simulate):
        ts = golden.START + offset
        while next_tick <= ts:
            loop.run_until_complete(engine._flush())
            engine.tick(next_tick)
            next_tick += golden.TICK
        engine._process(line.encode(), "10.255.0.1", ts)
    loop.run_until_complete(engine._flush())
    loop.close()
    return TestClient(web.create_app(cfg, db, engine, notifier, SnmpPoller(engine, db))), db


def exchange(http) -> dict:
    out = {}

    def call(name, method, path, **kw):
        r = http.request(method, path, **kw)
        out[name] = {"status": r.status_code, "body": scrub(r.json())}

    reads = [
        ("me", "/api/me"), ("summary_1h", "/api/summary?range=1h"), ("summary_24h", "/api/summary?range=24h"),
        ("summary_7d", "/api/summary?range=7d"),
        ("alerts_open", "/api/alerts"), ("alerts_all", "/api/alerts?status=all"),
        ("alerts_high", "/api/alerts?status=active&severity=high"), ("alerts_search", "/api/alerts?status=all&q=192.168.1.77"),
        ("alert_one", "/api/alerts?id=5"),
        ("events", "/api/events?hours=8760"), ("events_device", "/api/events?hours=8760&device=PA-440"),
        ("events_ip", "/api/events?hours=8760&ip=192.168.1.77"), ("events_port", "/api/events?hours=8760&port=3389"),
        ("events_type", "/api/events?hours=8760&type=auth_failure&action="),
        ("events_blocked", "/api/events?hours=8760&action=block&limit=50"),
        ("events_text", "/api/events?hours=8760&q=Configured"), ("events_older", "/api/events?hours=8760&before=3000&limit=20"),
        ("events_recent_window", "/api/events?hours=0.5"),
        ("devices", "/api/devices"), ("topology", "/api/topology"), ("topology_device", "/api/topology/device?id=PA-440"),
        ("riskports_24h", "/api/riskports?range=24h"), ("riskports_1h", "/api/riskports?range=1h"),
        ("riskport_3389", "/api/riskports/port?port=3389"),
        ("connectors", "/api/connectors"), ("detectors", "/api/detectors"), ("channels", "/api/channels"),
    ]
    for name, path in reads:
        call(name, "GET", path)
    # Writes.
    call("ack", "POST", "/api/alerts/status", json={"ids": [1, 2, 3], "status": "ack"})
    call("resolve", "POST", "/api/alerts/status", json={"ids": [4], "status": "resolved"})
    call("ack_all", "POST", "/api/alerts/status", json={"all_open": True, "status": "ack"})
    call("ignore", "POST", "/api/ignore", json={"ip": "203.0.113.66", "kind": "source"})
    call("device_put", "PUT", "/api/devices", json={"id": "PA-440", "name": "Edge firewall", "connector_pin": "paloalto",
                                                     "snmp_mode": "custom", "snmp_community": "s3cret", "snmp_host": "10.0.0.9:161"})
    call("device_bad", "PUT", "/api/devices", json={"id": "PA-440", "snmp_mode": "nonsense"})
    call("detectors_put", "PUT", "/api/detectors", json={"detectors": {"port_scan": {"ports": 30}},
                                                          "general": {"cooldown_minutes": 45, "ignore_destinations": ["198.51.100.10"]}})
    call("snmp_put", "PUT", "/api/snmp", json={"enabled": False, "community": "public", "networks": ["10.0.0.0/8", "bogus"]})
    call("channel_add", "POST", "/api/channels", json={"type": "telegram", "name": "SOC", "min_severity": "high",
                                                       "config": {"token": "123:abc", "chat_id": "42"}})
    call("channel_bad", "POST", "/api/channels", json={"type": "smtp", "name": "x", "config": {}})
    call("channel_put", "PUT", "/api/channels/1", json={"name": "SOC team", "enabled": False, "min_severity": "medium",
                                                         "config": {"token": "********", "chat_id": "43"}})
    call("channel_add2", "POST", "/api/channels", json={"type": "pushbullet", "name": "Phone", "config": {"access_token": "o.x"}})
    call("channel_delete", "DELETE", "/api/channels/2")
    call("connector_test", "POST", "/api/connectors/test", json={"raw": simulate.cisco(1, "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)")})
    call("forget", "POST", "/api/devices/forget", json={"id": "FGT-60F"})
    # Reads after the writes.
    for name, path in [("alerts_after", "/api/alerts?status=all"), ("summary_after", "/api/summary?range=24h"),
                       ("devices_after", "/api/devices"), ("channels_after", "/api/channels"),
                       ("detectors_after", "/api/detectors"), ("topology_after", "/api/topology")]:
        call(name, "GET", path)
    return out


def test_api_answers_match_the_recording(tmp_path, monkeypatch):
    http, db = build(tmp_path, monkeypatch)
    actual = json.loads(json.dumps(exchange(http)))
    db.close()
    if os.environ.get("RECORD_API_CONTRACT"):
        RECORDING.write_text(json.dumps(actual, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(RECORDING.read_text(encoding="utf-8"))
    assert actual.keys() == expected.keys()
    for name in expected:
        assert actual[name] == expected[name], name
