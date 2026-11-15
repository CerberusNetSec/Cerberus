"""Webhook and custom API call notification channels."""
import asyncio
import hashlib
import hmac
import json
import sqlite3
import sys
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate  # noqa: E402
from cerberus.notifiers import (MASK, SAMPLE, Notifier, payload_for, public_channel, render, send,  # noqa: E402
                                validate_channel)

TRICKY = {**SAMPLE, "title": 'Quote " and back\\slash\nnew line & amp', "src_ip": "192.0.2.10"}


def capture():
    got = []

    def handler(request: httpx.Request):
        got.append(request)
        return httpx.Response(200, json={"ok": True})
    return got, httpx.AsyncClient(transport=httpx.MockTransport(handler))


def channel(kind, **config):
    return {"id": 1, "name": kind, "type": kind, "config": json.dumps(validate_channel(
        {"type": kind, "config": config})["config"] and json.loads(validate_channel({"type": kind, "config": config})["config"]))}


def test_webhook_sends_the_alert_signed():
    got, client = capture()
    ch = channel("webhook", url="https://hooks.example/cerberus", secret="s3cret",
                 headers="X-Team: netsec\nX-Title: {{title}}")
    payload = payload_for(TRICKY, "subject", "text", "https://cerberus.lan/#/alerts?id=0")
    asyncio.run(send(ch, "subject", "text", client, payload))
    req = got[0]
    body = json.loads(req.content)
    assert body["event"] == "alert" and body["title"] == TRICKY["title"] and body["severity"] == "high"
    assert body["technique"] == "T1046 Network Service Discovery" and body["stage"] == "Discovery"
    assert body["link"].endswith("#/alerts?id=0") and body["details"] == {"test": True}
    # Alert text with a line break cannot start a header of its own.
    assert req.headers["X-Team"] == "netsec" and "\n" not in req.headers["X-Title"]
    assert req.headers["X-Title"].startswith("Quote") and not any(k.lower().startswith("new line") for k in req.headers)
    stamp = req.headers["X-Cerberus-Timestamp"]
    want = hmac.new(b"s3cret", stamp.encode() + b"." + req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-Cerberus-Signature"] == f"sha256={want}"


def test_custom_api_call_fills_its_templates_safely():
    got, client = capture()
    ch = channel("api", method="POST", url="https://api.example/notify?title={{title}}&sev={{severity}}",
                 headers="Authorization: Bearer abc\nX-Alert: {{title}}",
                 content_type="application/json",
                 body='{"text": "{{subject}}: {{title}}", "ip": "{{src_ip}}", "all": {{payload}}}')
    payload = payload_for(TRICKY, "[Cerberus HIGH] x", "text")
    asyncio.run(send(ch, "[Cerberus HIGH] x", "text", client, payload))
    req = got[0]
    body = json.loads(req.content)  # stays valid JSON whatever the alert says
    assert body["text"] == "[Cerberus HIGH] x: " + TRICKY["title"] and body["ip"] == "192.0.2.10"
    assert body["all"]["title"] == TRICKY["title"]
    assert parse_qs(req.url.query.decode())["title"] == [TRICKY["title"]] and req.method == "POST"
    assert req.headers["Authorization"] == "Bearer abc" and "\n" not in req.headers["X-Alert"]


def test_form_and_get_calls():
    got, client = capture()
    form = channel("api", method="PUT", url="https://api.example/x", content_type="application/x-www-form-urlencoded",
                   body="msg={{title}}&level={{severity}}")
    get = channel("api", method="GET", url="https://api.example/ping?msg={{subject}}")
    payload = payload_for(TRICKY, "a b&c", "text")
    asyncio.run(send(form, "a b&c", "text", client, payload))
    asyncio.run(send(get, "a b&c", "text", client, payload))
    assert parse_qs(got[0].content.decode()) == {"msg": [TRICKY["title"]], "level": ["high"]}
    assert got[0].method == "PUT" and got[1].method == "GET" and got[1].content == b""
    assert parse_qs(got[1].url.query.decode())["msg"] == ["a b&c"]


def test_an_empty_body_sends_the_standard_payload():
    got, client = capture()
    asyncio.run(send(channel("api", url="https://api.example/x"), "s", "t", client, payload_for(SAMPLE, "s", "t")))
    assert json.loads(got[0].content)["detector"] == "port_scan"


@pytest.mark.parametrize("kind,config,message", [
    ("webhook", {"url": "ftp://x"}, "http"),
    ("webhook", {"url": "hooks.example/x"}, "http"),
    ("api", {"url": "https://x", "body": '{"text": {{title}}}'}, "not valid JSON"),
    ("api", {"url": ""}, "missing"),
])
def test_bad_channels_are_refused(kind, config, message):
    with pytest.raises(ValueError, match=message):
        validate_channel({"type": kind, "config": config})


def test_secrets_are_masked_and_kept():
    row = validate_channel({"type": "webhook", "config": {"url": "https://x", "secret": "s", "headers": "A: b"}})
    shown = public_channel({**row, "id": 1, "enabled": 1})
    assert shown["config"]["secret"] == MASK and shown["config"]["headers"] == MASK
    again = validate_channel({"type": "webhook", "config": {"url": "https://y", "secret": MASK, "headers": MASK}},
                             existing=row)
    assert json.loads(again["config"]) == {"url": "https://y", "secret": "s", "headers": "A: b"}
    assert validate_channel({"type": "api", "config": {"url": "https://x", "method": "DELETE"}})["config"].count('"POST"')


def test_render_escaping():
    p = payload_for(TRICKY, "s", "t")
    assert render("{{title}}", p, "json") == json.dumps(TRICKY["title"])[1:-1]
    assert render("{{title|raw}}", p, "json") == TRICKY["title"]
    assert render("{{severity|url}} {{unknown}}", p, "raw") == "high {{unknown}}"


def test_alerts_reach_a_webhook_through_the_outbox(tmp_path, monkeypatch):
    cfg = Config.from_env()
    cfg.data_dir = tmp_path
    db = Database(tmp_path / "c.db")
    db.add_channel({"type": "webhook", "name": "hook", "enabled": 1, "min_severity": "low",
                    "config": json.dumps({"url": "https://hooks.example/x", "secret": "", "headers": ""})})
    notifier = Notifier(db, "https://cerberus.lan")
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    got, client = capture()
    notifier._client = client

    async def go():
        await notifier.reload()
        engine.raise_alert(Candidate("port_scan", "10.0.0.9", "high", "Port scan from 10.0.0.9", "d", "10.0.0.9", "fw"),
                           1_800_000_000.0)
        await engine._flush()
        await notifier.send_due()
        await asyncio.gather(*notifier._tasks)
    asyncio.run(go())
    body = json.loads(got[0].content)
    assert (body["event"], body["title"], body["src_ip"], body["device"]) == ("alert", "Port scan from 10.0.0.9",
                                                                              "10.0.0.9", "fw")
    assert body["id"] == 1 and body["link"] == "https://cerberus.lan/#/alerts?id=1"
    db.close()


def test_an_older_outbox_gets_the_payload_column(tmp_path):
    path = tmp_path / "old.db"
    Database(path).close()
    conn = sqlite3.connect(path)
    conn.executescript("DROP TABLE outbox; CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL NOT NULL,"
                       " channel_id INTEGER NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, attempts INTEGER DEFAULT 0,"
                       " next_try REAL NOT NULL, done INTEGER DEFAULT 0, error TEXT);")
    conn.close()
    db = Database(path)
    from cerberus.storage import Batch
    db.write_batch(Batch(notices=[(1.0, 1, "s", "b", '{"a": 1}'), (2.0, 1, "s2", "b2")]))
    assert [r["payload"] for r in db.outbox_due(10.0, 10)] == ['{"a": 1}', None]
    db.close()
