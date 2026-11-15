"""Agents and scripts: API tokens, and the MCP server at /mcp."""
import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from cerberus import web  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402

T = 1_800_000_000.0


@pytest.fixture
def rig(tmp_path):
    cfg = Config.from_env()
    cfg.data_dir, cfg.auth_enabled, cfg.password = tmp_path, True, "dashboard-password"
    db = Database(tmp_path / "c.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    for i, det in enumerate(("port_scan", "brute_force")):
        engine.raise_alert(Candidate(det, f"10.0.0.{i}", "high", f"Alert {i}", "d", f"10.0.0.{i}", "fw"), T)
    asyncio.run(engine._flush())
    client = TestClient(web.create_app(cfg, db, engine, notifier, SnmpPoller(engine, db)))
    session = TestClient(client.app)
    assert session.post("/api/login", json={"password": "dashboard-password"}).status_code == 200
    yield client, session, db
    db.close()


def token(session, scope):
    res = session.post("/api/tokens", json={"name": f"{scope} agent", "scope": scope}).json()
    assert res["token"].startswith("cerb_")
    return res


def bearer(t):
    return {"Authorization": f"Bearer {t['token']}"}


def test_tokens_read_triage_and_never_administer(rig):
    client, session, db = rig
    read, write = token(session, "read"), token(session, "write")
    listed = session.get("/api/tokens").json()["tokens"]
    assert {t["name"] for t in listed} == {"read agent", "write agent"}
    assert all("token" not in t and "token_hash" not in t for t in listed)  # shown once, then never

    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts", headers={"Authorization": "Bearer cerb_wrong"}).status_code == 401
    assert len(client.get("/api/alerts", headers=bearer(read)).json()["alerts"]) == 2
    first = client.get("/api/alerts", headers=bearer(read)).json()["alerts"][0]["id"]
    assert client.post("/api/alerts/status", headers=bearer(read), json={"ids": [first], "status": "ack"}).status_code == 403
    for t in (read, write):  # settings, channels and tokens need the dashboard
        assert client.get("/api/tokens", headers=bearer(t)).status_code == 403
        assert client.put("/api/detectors", headers=bearer(t), json={}).status_code == 403
        assert client.post("/api/channels", headers=bearer(t), json={}).status_code == 403

    assert client.post("/api/alerts/status", headers=bearer(write), json={"ids": [first], "status": "ack"}).status_code == 200
    r = client.post("/api/alerts/false-positive", headers=bearer(write),
                    json={"id": first, "analyst": "Sam", "justification": "Known scanner, ticket SEC-9."})
    assert r.status_code == 200
    audit = session.get("/api/audit").json()["audit"]
    actions = {(e["action"], e["analyst"]) for e in audit}
    assert ("POST /api/alerts/status", "API token 'write agent'") in actions  # every change is recorded
    assert ("false_positive", "Sam (API token 'write agent')") in actions
    assert ("token_created", "admin (built-in)") in actions
    assert db.tokens()[0]["last_used"]

    assert session.post(f"/api/tokens/{read['id']}/revoke").status_code == 200
    assert client.get("/api/alerts", headers=bearer(read)).status_code == 401
    assert session.post(f"/api/tokens/{read['id']}/revoke").status_code == 404
    assert ("token_revoked", "admin (built-in)") in {(e["action"], e["analyst"]) for e in session.get("/api/audit").json()["audit"]}


def rpc(client, t, method, params=None, mid=1, **headers):
    body = {"jsonrpc": "2.0", "method": method, **({"id": mid} if mid is not None else {}),
            **({"params": params} if params is not None else {})}
    return client.post("/mcp", headers={**(bearer(t) if t else {}), **headers}, json=body)


def call(client, t, name, arguments=None):
    res = rpc(client, t, "tools/call", {"name": name, "arguments": arguments or {}}).json()["result"]
    if not res["isError"]:
        assert json.loads(res["content"][0]["text"]) == json.loads(json.dumps(res["structuredContent"], default=str))
    return res


def test_mcp_handshake_and_tools(rig):
    client, session, _ = rig
    read = token(session, "read")
    init = rpc(client, read, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                             "clientInfo": {"name": "test", "version": "1"}}).json()["result"]
    assert init["protocolVersion"] == "2025-06-18" and init["serverInfo"]["name"] == "cerberus"
    assert "untrusted" in init["instructions"] and init["capabilities"]["tools"] == {"listChanged": False}
    assert rpc(client, read, "initialize", {"protocolVersion": "1999-01-01"}).json()["result"]["protocolVersion"] == "2025-06-18"
    assert rpc(client, read, "notifications/initialized", mid=None).status_code == 202
    assert rpc(client, read, "ping").json()["result"] == {}

    tools = {t["name"]: t for t in rpc(client, read, "tools/list").json()["result"]["tools"]}
    assert set(tools) == {"get_status", "list_alerts", "get_alert", "search_events", "list_devices", "get_attack_matrix",
                          "get_high_risk_ports", "set_alert_status", "mark_false_positive"}
    assert tools["get_status"]["annotations"]["readOnlyHint"] is True
    assert tools["set_alert_status"]["annotations"]["readOnlyHint"] is False

    status = call(client, read, "get_status")["structuredContent"]
    assert status["open_alerts_total"] == 2 and status["devices"] == 0
    alerts = call(client, read, "list_alerts", {"limit": 5})["structuredContent"]["alerts"]
    assert {a["detector"] for a in alerts} == {"port_scan", "brute_force"}
    assert {a["technique"] for a in alerts} == {"T1046 Network Service Discovery", "T1110 Brute Force"}
    one = call(client, read, "get_alert", {"id": alerts[0]["id"]})["structuredContent"]["alert"]
    assert one["advice"]["actions"]
    assert call(client, read, "get_alert", {"id": 999})["isError"]
    assert "events" in call(client, read, "search_events", {"hours": 1, "port": 22})["structuredContent"]
    assert call(client, read, "list_devices")["structuredContent"] == {"devices": []}
    matrix = call(client, read, "get_attack_matrix", {"range": "all"})["structuredContent"]
    assert matrix["total"] == 2 and {t["tactic"] for t in matrix["tactics"]} >= {"Discovery", "Credential Access"}
    assert "ports" in call(client, read, "get_high_risk_ports")["structuredContent"]

    # Write tools need write scope.
    denied = call(client, read, "set_alert_status", {"ids": [alerts[0]["id"]], "status": "ack"})
    assert denied["isError"] and "write scope" in denied["content"][0]["text"]
    write = token(session, "write")
    assert call(client, write, "set_alert_status", {"ids": [alerts[0]["id"]], "status": "ack"})["structuredContent"] == {"updated": 1}
    short = call(client, write, "mark_false_positive", {"id": alerts[1]["id"], "justification": "no"})
    assert short["isError"] and "justification" in short["content"][0]["text"]
    fp = call(client, write, "mark_false_positive", {"id": alerts[1]["id"], "justification": "Lab traffic, approved in CHG-1."})
    assert fp["structuredContent"]["suppression"]["analyst"] == "agent (API token 'write agent')"

    # Bad arguments and requests.
    assert "unknown argument" in call(client, read, "list_alerts", {"bogus": 1})["content"][0]["text"]
    assert "must be one of" in call(client, read, "list_alerts", {"status": "maybe"})["content"][0]["text"]
    assert "missing argument" in call(client, read, "get_alert", {})["content"][0]["text"]
    assert rpc(client, read, "tools/call", {"name": "nope"}).json()["error"]["code"] == -32602
    assert rpc(client, read, "resources/list").json()["error"]["code"] == -32601


def test_mcp_transport_rules(rig):
    client, session, _ = rig
    read = token(session, "read")
    assert rpc(client, None, "ping").status_code == 401
    assert rpc(client, None, "ping").headers["www-authenticate"].startswith("Bearer")
    assert client.post("/mcp", headers=bearer(read), content=b"{nope").status_code == 400
    assert client.post("/mcp", headers=bearer(read), json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]).status_code == 400
    assert client.get("/mcp", headers=bearer(read)).status_code == 405
    assert rpc(client, read, "ping", Origin="https://evil.example").status_code == 403
    assert rpc(client, read, "ping", Origin="http://testserver").status_code == 200
    assert rpc(client, read, "ping", **{"MCP-Protocol-Version": "1999-01-01"}).status_code == 400
    assert rpc(client, read, "ping", **{"MCP-Protocol-Version": "2025-06-18"}).status_code == 200
    # The dashboard session works too.
    assert rpc(session, None, "ping").status_code == 200
