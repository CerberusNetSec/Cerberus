"""Stage 6: user accounts, roles, single sign-on and the audit trail."""
import asyncio
import base64
import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from cerberus import web  # noqa: E402
from cerberus.accounts import mask, required_role  # noqa: E402
from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Candidate  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.snmp_poller import SnmpPoller  # noqa: E402

ISSUER = "https://idp.example"
PASSWORD = "correct horse battery"


def make(tmp_path, **cfg_extra):
    cfg = Config.from_env()
    cfg.data_dir, cfg.auth_enabled, cfg.password = tmp_path, True, "shared-dashboard-password"
    cfg.public_url = "https://cerberus.example"
    for k, v in cfg_extra.items():
        setattr(cfg, k, v)
    db = Database(tmp_path / "c.db")
    notifier = Notifier(db)
    engine = Engine(cfg, db, ConnectorRegistry(), notifier)
    engine.load()
    for i in range(2):
        engine.raise_alert(Candidate("port_scan", f"10.0.0.{i}", "high", f"Alert {i}", "d", f"10.0.0.{i}", "fw"),
                           1_800_000_000.0)
    asyncio.run(engine._flush())
    app = web.create_app(cfg, db, engine, notifier, SnmpPoller(engine, db))
    return app, db


def client(app, username="", password="shared-dashboard-password"):
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.json()
    return c


@pytest.fixture
def rig(tmp_path):
    app, db = make(tmp_path)
    admin = client(app)  # the built-in admin
    for name, role in (("vera", "viewer"), ("ana", "analyst"), ("adam", "admin")):
        r = admin.post("/api/users", json={"username": name, "display_name": name.title(), "role": role, "password": PASSWORD})
        assert r.status_code == 200, r.json()
    yield app, db, admin
    db.close()


def test_role_policy():
    assert required_role("GET", "/api/alerts") == "viewer"
    assert required_role("GET", "/api/channels") == "admin" and required_role("GET", "/api/users") == "admin"
    assert required_role("GET", "/api/audit") == "analyst"
    assert required_role("POST", "/api/alerts/status") == "analyst"
    assert required_role("PUT", "/api/detectors") == "admin" and required_role("POST", "/api/anything-new") == "admin"
    assert required_role("POST", "/api/me/password") == "viewer"


def test_each_role_can_do_what_it_should(rig):
    app, db, admin = rig
    vera, ana, adam = (client(app, n, PASSWORD) for n in ("vera", "ana", "adam"))
    first = vera.get("/api/alerts").json()["alerts"][0]["id"]
    assert vera.get("/api/me").json()["user"] == {"username": "vera", "name": "Vera", "role": "viewer", "kind": "session",
                                                  "local": True, "source": "local"}
    # Viewer: reads, nothing more.
    assert vera.post("/api/alerts/status", json={"ids": [first], "status": "ack"}).status_code == 403
    for path in ("/api/channels", "/api/audit", "/api/users", "/api/tokens"):
        assert vera.get(path).status_code == 403, path
    # Analyst: triage, and reads the audit log; no settings.
    assert ana.post("/api/alerts/status", json={"ids": [first], "status": "ack"}).status_code == 200
    r = ana.post("/api/alerts/false-positive", json={"id": first, "justification": "Known scanner, ticket SEC-1."})
    assert r.status_code == 200 and r.json()["suppression"]["analyst"] == "Ana (ana)"  # named by the account
    assert ana.get("/api/audit").status_code == 200
    assert ana.put("/api/detectors", json={}).status_code == 403 and ana.get("/api/users").status_code == 403
    # Admin: settings too.
    assert adam.put("/api/detectors", json={}).status_code == 200 and adam.get("/api/users").status_code == 200
    # Everything that changed is on the record, under who did it.
    actions = {(e["action"], e["analyst"]) for e in adam.get("/api/audit?limit=100").json()["audit"]}
    assert ("POST /api/alerts/status", "Ana (ana)") in actions and ("PUT /api/detectors", "Adam (adam)") in actions
    assert ("login", "Vera (vera)") in actions and ("POST /api/users", "admin (built-in)") in actions


def test_logins_are_checked_throttled_and_recorded(rig):
    app, db, admin = rig
    c = TestClient(app, base_url="https://testserver")
    assert c.post("/api/login", json={"username": "ana", "password": "nope"}).status_code == 401
    assert c.post("/api/login", json={"username": "nobody", "password": PASSWORD}).status_code == 401
    for _ in range(3):
        c.post("/api/login", json={"username": "ana", "password": "nope"})
    assert c.post("/api/login", json={"username": "ana", "password": PASSWORD}).status_code == 429
    failed = [e for e in admin.get("/api/audit?limit=100").json()["audit"] if e["action"] == "login_failed"]
    assert {e["analyst"] for e in failed} == {"ana", "nobody"}


def test_disabling_or_demoting_takes_effect(rig):
    app, db, admin = rig
    adam = client(app, "adam", PASSWORD)
    ana = client(app, "ana", PASSWORD)
    ana_id = next(u["id"] for u in admin.get("/api/users").json()["users"] if u["username"] == "ana")
    assert adam.put(f"/api/users/{ana_id}", json={"disabled": True}).status_code == 200
    assert ana.get("/api/alerts").status_code == 401  # signed out at once
    assert TestClient(app).post("/api/login", json={"username": "ana", "password": PASSWORD}).status_code == 401
    adam_id = next(u["id"] for u in admin.get("/api/users").json()["users"] if u["username"] == "adam")
    assert adam.put(f"/api/users/{adam_id}", json={"role": "viewer"}).status_code == 400  # not yourself
    assert adam.delete(f"/api/users/{adam_id}").status_code == 400


def test_the_built_in_admin_can_be_switched_off_but_not_lock_everyone_out(tmp_path):
    app, db = make(tmp_path)
    admin = client(app)
    assert admin.put("/api/auth/builtin", json={"allowed": False}).status_code == 409  # no other admin yet
    admin.post("/api/users", json={"username": "adam", "role": "admin", "password": PASSWORD})
    assert admin.put("/api/auth/builtin", json={"allowed": False}).status_code == 200
    assert admin.get("/api/alerts").status_code == 401  # the shared-password session is over
    assert TestClient(app).post("/api/login", json={"password": "shared-dashboard-password"}).status_code == 401
    adam = client(app, "adam", PASSWORD)
    adam_id = adam.get("/api/users").json()["users"][0]["id"]
    eve = adam.post("/api/users", json={"username": "eve", "role": "admin", "password": PASSWORD}).json()["user"]
    eve_client = client(app, "eve", PASSWORD)
    assert eve_client.put(f"/api/users/{adam_id}", json={"disabled": True}).status_code == 200
    # Eve is now the only admin: she cannot be demoted by anyone, nor demote herself.
    assert eve_client.put(f"/api/users/{eve['id']}", json={"role": "analyst"}).status_code == 400
    assert eve_client.post("/api/users", json={"username": "admin", "role": "admin", "password": PASSWORD}).status_code == 200
    db.close()


def test_own_password(rig):
    app, db, admin = rig
    ana = client(app, "ana", PASSWORD)
    assert ana.post("/api/me/password", json={"current": "wrong", "new": "x" * 20}).status_code == 403
    assert ana.post("/api/me/password", json={"current": PASSWORD, "new": "short"}).status_code == 400
    assert ana.post("/api/me/password", json={"current": PASSWORD, "new": "a much better passphrase"}).status_code == 200
    assert TestClient(app).post("/api/login", json={"username": "ana", "password": "a much better passphrase"}).status_code == 200
    assert admin.post("/api/me/password", json={"current": "x", "new": "y" * 20}).status_code == 400  # built-in: not here
    weak = admin.post("/api/users", json={"username": "weak", "role": "viewer", "password": "aaaaaaaaaaaaaaa"})
    assert weak.status_code == 400


def test_audit_masks_secrets(rig):
    app, db, admin = rig
    admin.post("/api/channels", json={"type": "telegram", "name": "t", "config": {"token": "123:SECRET", "chat_id": "1"}})
    entry = next(e for e in admin.get("/api/audit").json()["audit"] if e["action"] == "POST /api/channels")
    assert "SECRET" not in json.dumps(entry) and entry["detail"]["request"]["config"]["token"] == "********"
    assert mask({"password": "p", "nested": [{"client_secret": "s", "ok": 1}]}) == {
        "password": "********", "nested": [{"client_secret": "********", "ok": 1}]}


# --- single sign-on -------------------------------------------------------------------------------
def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.c2lnbmF0dXJl"


class Idp:
    """A mock OpenID Connect provider."""

    def __init__(self):
        self.claims = {}
        self.nonce = ""
        self.token_requests = []

    def handler(self, request: httpx.Request):
        url = str(request.url)
        if url == ISSUER + "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize",
                                             "token_endpoint": ISSUER + "/token", "userinfo_endpoint": ISSUER + "/userinfo",
                                             "token_endpoint_auth_methods_supported": ["client_secret_basic"]})
        if url == ISSUER + "/token":
            self.token_requests.append(request)
            claims = {"iss": ISSUER, "aud": "cerberus", "exp": time.time() + 300, "iat": time.time(),
                      "nonce": self.nonce, "sub": "u-123", "preferred_username": "Sam", "name": "Sam Smith",
                      "email": "sam@example.com", **self.claims}
            return httpx.Response(200, json={"id_token": jwt(claims), "access_token": "at", "token_type": "Bearer"})
        if url == ISSUER + "/userinfo":
            return httpx.Response(200, json={"sub": "u-123", "groups": ["netsec-admins"]})
        return httpx.Response(404)


def sso_app(tmp_path, **extra):
    app, db = make(tmp_path, oidc_issuer=ISSUER, oidc_client_id="cerberus", oidc_client_secret="client-secret",
                   oidc_admin_groups="netsec-admins", oidc_analyst_groups="soc", **extra)
    idp = Idp()
    app.state.oidc().client = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    return app, db, idp


def sign_in(app, idp, state_override=None):
    c = TestClient(app, base_url="https://cerberus.example", follow_redirects=False)
    start = c.get("/api/auth/oidc/login")
    assert start.status_code == 303
    query = parse_qs(urlsplit(start.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"] and query["redirect_uri"] == [
        "https://cerberus.example/api/auth/oidc/callback"]
    idp.nonce = idp.nonce or query["nonce"][0]
    done = c.get("/api/auth/oidc/callback", params={"code": "the-code", "state": state_override or query["state"][0]})
    return c, done


def test_single_sign_on(tmp_path):
    app, db, idp = sso_app(tmp_path)
    assert TestClient(app).get("/api/me").json()["sso"] == {"enabled": True, "label": "single sign-on"}
    c, done = sign_in(app, idp)
    assert done.status_code == 303 and done.headers["location"] == "/"
    me = c.get("/api/me").json()["user"]
    assert me["username"] == "sam" and me["role"] == "admin" and me["source"] == "sso"  # groups from userinfo
    token_request = idp.token_requests[0]
    assert token_request.headers["authorization"].startswith("Basic ")
    form = parse_qs(token_request.content.decode())
    assert form["code"] == ["the-code"] and form["code_verifier"][0]
    # The next sign-in follows the groups the provider sends then.
    idp.nonce, idp.claims = "", {"groups": ["soc"]}
    c2, _ = sign_in(app, idp)
    assert c2.get("/api/me").json()["user"]["role"] == "analyst"
    assert len([u for u in db.users() if u["source"] == "sso"]) == 1
    audit = [e for e in db.audit_log(20) if e["action"] == "login"]
    assert json.loads(audit[0]["detail"])["method"] == "single sign-on"
    db.close()


@pytest.mark.parametrize("problem,message", [
    ("nonce", "nonce"), ("state", "state"), ("audience", "another application"), ("issuer", "another issuer"),
    ("expired", "expired"), ("groups", "not in a group"),
])
def test_single_sign_on_refusals(tmp_path, problem, message):
    app, db, idp = sso_app(tmp_path)
    if problem == "nonce":
        idp.nonce = "something-else"
    elif problem == "audience":
        idp.claims = {"aud": "another-app"}
    elif problem == "issuer":
        idp.claims = {"iss": "https://evil.example"}
    elif problem == "expired":
        idp.claims = {"exp": time.time() - 3600}
    elif problem == "groups":
        idp.claims = {"groups": ["marketing"]}
    c, done = sign_in(app, idp, state_override="forged" if problem == "state" else None)
    assert done.status_code == 303 and done.headers["location"].startswith("/?sso_error=")
    assert message in parse_qs(urlsplit(done.headers["location"]).query)["sso_error"][0]
    assert c.get("/api/me").json()["signed_in"] is False
    db.close()


def test_a_default_role_admits_everyone_else(tmp_path):
    app, db, idp = sso_app(tmp_path, oidc_default_role="viewer")
    idp.claims = {"groups": ["marketing"]}
    c, _ = sign_in(app, idp)
    assert c.get("/api/me").json()["user"]["role"] == "viewer"
    db.close()
