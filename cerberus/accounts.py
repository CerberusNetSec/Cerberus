"""User accounts, roles, single sign-on (OpenID Connect) and the audit trail's masking.

Roles, each including the one before:

  viewer   sees everything the dashboard shows.
  analyst  also triages: acknowledges and resolves alerts, marks false positives,
           removes suppressions, stops alerting on a source.
  admin    also changes settings, channels, users and tokens.

Who can sign in: local users (username and password, Settings -> Users), users
of an OpenID Connect provider (single sign-on, configured with
CERBERUS_OIDC_*), and the built-in admin, which is the shared dashboard password
of earlier versions (it can be switched off once there is another admin).
API tokens act as a viewer (read) or an analyst (write).

Single sign-on uses the authorization code flow with PKCE, state and nonce. The
ID token comes straight from the provider's token endpoint over a verified
HTTPS connection, which OpenID Connect Core (3.1.3.7, rule 6) accepts in place
of checking its signature; its issuer, audience, expiry and nonce are checked.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import httpx

ROLES = ("viewer", "analyst", "admin")
RANK = {role: i for i, role in enumerate(ROLES)}

# What each request needs. Reading is for everyone signed in, except these.
ADMIN_READ = ("/api/tokens", "/api/users", "/api/channels", "/api/auth/settings")
ANALYST_READ = ("/api/audit",)
# Changes an analyst may make; every other change needs an admin.
TRIAGE = {"/api/alerts/status", "/api/alerts/false-positive", "/api/suppressions/remove", "/api/ignore",
          "/api/site-alerts/status"}
SELF = {"/api/me/password"}  # every signed-in user, for their own account


def required_role(method: str, path: str) -> str:
    if method in ("GET", "HEAD"):
        if path.startswith(ADMIN_READ):
            return "admin"
        if path.startswith(ANALYST_READ):
            return "analyst"
        return "viewer"
    if path in TRIAGE:
        return "analyst"
    if path in SELF:
        return "viewer"
    return "admin"


def allows(role: str, needed: str) -> bool:
    return RANK.get(role, -1) >= RANK[needed]


# --- passwords ------------------------------------------------------------------------------------
PASSWORD_MIN = 12
USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,63}$")


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return digest.hex(), salt.hex()


def check_password(password: str, password_hash: str | None, salt: str | None) -> bool:
    if not password_hash or not salt:
        return False
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt))[0], password_hash)


def password_problem(password: str) -> str | None:
    if len(password) < PASSWORD_MIN:
        return f"use at least {PASSWORD_MIN} characters"
    if len(set(password)) < 5:
        return "use more different characters"
    return None


# --- the audit trail: what was asked for, without secrets -------------------------------------------
SECRET_NAMES = re.compile(r"(?i)pass|secret|token|community|headers|private|credential|cookie|api_?key")


def mask(value, depth: int = 0):
    """A copy of a request body for the audit log, secrets replaced."""
    if depth > 6:
        return "…"
    if isinstance(value, dict):
        return {k: ("********" if SECRET_NAMES.search(str(k)) and v not in ("", None) else mask(v, depth + 1))
                for k, v in list(value.items())[:100]}
    if isinstance(value, list):
        return [mask(v, depth + 1) for v in value[:100]]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "…"
    return value


# --- single sign-on (OpenID Connect) -----------------------------------------------------------------
@dataclass
class OidcSettings:
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_url: str = ""
    scopes: str = "openid email profile"
    label: str = "single sign-on"
    role_claim: str = "groups"
    admin_groups: list = field(default_factory=list)
    analyst_groups: list = field(default_factory=list)
    viewer_groups: list = field(default_factory=list)
    default_role: str = ""  # "" refuses users in none of the groups

    @property
    def enabled(self) -> bool:
        return bool(self.issuer and self.client_id and self.redirect_url)

    def role_for(self, groups: list[str]) -> str:
        have = {g.lower() for g in groups}
        for role, wanted in (("admin", self.admin_groups), ("analyst", self.analyst_groups),
                             ("viewer", self.viewer_groups)):
            if have & {w.lower() for w in wanted}:
                return role
        return self.default_role

    def public(self) -> dict:
        return {"enabled": self.enabled, "issuer": self.issuer, "client_id": self.client_id,
                "redirect_url": self.redirect_url, "label": self.label, "role_claim": self.role_claim,
                "admin_groups": self.admin_groups, "analyst_groups": self.analyst_groups,
                "viewer_groups": self.viewer_groups, "default_role": self.default_role or "none (refused)"}


def _groups(text: str) -> list[str]:
    return [g.strip() for g in str(text or "").split(",") if g.strip()]


def oidc_settings(cfg) -> OidcSettings:
    redirect = cfg.oidc_redirect_url or (cfg.public_url.rstrip("/") + "/api/auth/oidc/callback" if cfg.public_url else "")
    default = cfg.oidc_default_role if cfg.oidc_default_role in ROLES else ""
    return OidcSettings(cfg.oidc_issuer.rstrip("/"), cfg.oidc_client_id, cfg.oidc_client_secret, redirect,
                        cfg.oidc_scopes or "openid email profile", cfg.oidc_label or "single sign-on",
                        cfg.oidc_role_claim or "groups", _groups(cfg.oidc_admin_groups), _groups(cfg.oidc_analyst_groups),
                        _groups(cfg.oidc_viewer_groups), default)


class SsoError(Exception):
    """Single sign-on did not work; the message is shown to the user."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _secure(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"))


class Oidc:
    STATE_SECONDS = 600

    def __init__(self, settings: OidcSettings, key: bytes, client: httpx.AsyncClient | None = None):
        self.s = settings
        self.key = key  # signs the short-lived state cookie, so any replica can finish a sign-in
        self.client = client
        self._meta: dict | None = None
        self._meta_at = 0.0

    def _http(self) -> httpx.AsyncClient:
        if self.client is None:
            self.client = httpx.AsyncClient(timeout=15, follow_redirects=False)
        return self.client

    async def metadata(self) -> dict:
        if self._meta and time.time() - self._meta_at < 3600:
            return self._meta
        if not _secure(self.s.issuer):
            raise SsoError("the identity provider must use HTTPS")
        resp = await self._http().get(self.s.issuer + "/.well-known/openid-configuration")
        if resp.status_code != 200:
            raise SsoError(f"the identity provider's configuration could not be read ({resp.status_code})")
        meta = resp.json()
        if meta.get("issuer", "").rstrip("/") != self.s.issuer:
            raise SsoError("the identity provider reports a different issuer than configured")
        for key in ("authorization_endpoint", "token_endpoint"):
            if not _secure(meta.get(key, "")):
                raise SsoError(f"the identity provider's {key.replace('_', ' ')} must use HTTPS")
        self._meta, self._meta_at = meta, time.time()
        return meta

    # The state cookie: what the callback must match, signed so it cannot be forged.
    def _seal(self, data: dict) -> str:
        body = _b64url(json.dumps(data, separators=(",", ":")).encode())
        return body + "." + _b64url(hmac.new(self.key, body.encode(), hashlib.sha256).digest())

    def _open(self, sealed: str) -> dict:
        body, _, sig = (sealed or "").partition(".")
        want = _b64url(hmac.new(self.key, body.encode(), hashlib.sha256).digest())
        if not body or not hmac.compare_digest(sig, want):
            raise SsoError("the sign-in could not be checked; start again")
        data = json.loads(_unb64url(body))
        if data.get("exp", 0) < time.time():
            raise SsoError("the sign-in took too long; start again")
        return data

    async def start(self) -> tuple[str, str]:
        """(URL to send the browser to, state cookie value)."""
        meta = await self.metadata()
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        query = urlencode({"response_type": "code", "client_id": self.s.client_id, "redirect_uri": self.s.redirect_url,
                           "scope": self.s.scopes, "state": state, "nonce": nonce, "code_challenge": challenge,
                           "code_challenge_method": "S256"})
        sep = "&" if "?" in meta["authorization_endpoint"] else "?"
        cookie = self._seal({"state": state, "nonce": nonce, "verifier": verifier, "exp": time.time() + self.STATE_SECONDS})
        return f"{meta['authorization_endpoint']}{sep}{query}", cookie

    async def finish(self, code: str, state: str, cookie: str) -> dict:
        """Exchange the code; returns the user's claims (sub, groups, ...)."""
        saved = self._open(cookie)
        if not hmac.compare_digest(str(state), saved["state"]):
            raise SsoError("the sign-in could not be checked (state); start again")
        meta = await self.metadata()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.s.redirect_url,
                "code_verifier": saved["verifier"], "client_id": self.s.client_id}
        auth = None
        methods = meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        if self.s.client_secret:
            if "client_secret_basic" in methods:
                auth = (self.s.client_id, self.s.client_secret)
            else:
                form["client_secret"] = self.s.client_secret
        resp = await self._http().post(meta["token_endpoint"], data=form, auth=auth,
                                       headers={"Accept": "application/json"})
        if resp.status_code != 200:
            raise SsoError(f"the identity provider refused the sign-in ({resp.status_code})")
        tokens = resp.json()
        id_token = tokens.get("id_token")
        if not id_token or id_token.count(".") != 2:
            raise SsoError("the identity provider sent no ID token")
        try:
            claims = json.loads(_unb64url(id_token.split(".")[1]))
        except ValueError:
            raise SsoError("the ID token could not be read")
        now = time.time()
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if claims.get("iss", "").rstrip("/") != self.s.issuer:
            raise SsoError("the ID token is from another issuer")
        if self.s.client_id not in audiences or (len(audiences) > 1 and claims.get("azp") not in (None, self.s.client_id)):
            raise SsoError("the ID token is for another application")
        if float(claims.get("exp", 0)) < now - 60:
            raise SsoError("the ID token has expired")
        if not hmac.compare_digest(str(claims.get("nonce", "")), saved["nonce"]):
            raise SsoError("the ID token does not match this sign-in (nonce)")
        if not claims.get("sub"):
            raise SsoError("the ID token names no user")
        if self.s.role_claim not in claims and meta.get("userinfo_endpoint") and tokens.get("access_token"):
            info = await self._http().get(meta["userinfo_endpoint"],
                                          headers={"Authorization": f"Bearer {tokens['access_token']}"})
            if info.status_code == 200:
                extra = info.json()
                if extra.get("sub") == claims["sub"]:
                    claims = {**extra, **claims}
        return claims

    def identity(self, claims: dict) -> dict:
        """subject, username, display name, email and role from the claims ('' role: refused)."""
        groups = claims.get(self.s.role_claim) or []
        if isinstance(groups, str):
            groups = [g for g in re.split(r"[,\s]+", groups) if g]
        username = str(claims.get("preferred_username") or claims.get("email") or claims["sub"]).lower()[:64]
        return {"subject": f"{self.s.issuer}|{claims['sub']}", "username": username,
                "display_name": str(claims.get("name") or username)[:100], "email": str(claims.get("email") or "")[:200],
                "role": self.s.role_for([str(g) for g in groups]), "groups": [str(g) for g in groups][:50]}
