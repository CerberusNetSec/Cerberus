"""Plaintext secrets in the logs: find them, keep them out of storage, raise alerts.

Cerberus sees what devices log, not packets, but devices log a lot: proxy and
URL-filtering logs carry whole URLs (with user:password@ and ?password= in
them), IDS alerts quote HTTP headers (Authorization: Basic ...), and
misconfigured applications log tokens and keys. Every message is scanned as it
is parsed, before it is stored:

- what is found is replaced in the stored event by [REDACTED kind fingerprint],
  so Cerberus does not become a store of other people's passwords (unless
  redaction is switched off);
- the event carries a description of each find (kind, where, a fingerprint,
  a preview that does not reveal the secret), which the plaintext_secret
  detector turns into an alert.

The fingerprint is an HMAC keyed per installation, so the same secret seen
again folds into the same alert, but a fingerprint cannot be brute-forced back
into a short password by anyone without the key.

Scanning is configured by the plaintext_secret detector's settings (on by
default; Settings -> Detection), in every process that parses syslog.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets as _random
from dataclasses import dataclass

# kind -> label, severity
KINDS: dict[str, tuple[str, str]] = {
    "private_key": ("private key", "critical"),
    "aws_access_key": ("AWS access key", "high"),
    "github_token": ("GitHub token", "high"),
    "slack_token": ("Slack token", "high"),
    "google_api_key": ("Google API key", "high"),
    "stripe_key": ("Stripe secret key", "high"),
    "url_credentials": ("password in a URL", "high"),
    "basic_auth": ("HTTP Basic credentials", "high"),
    "bearer_token": ("bearer token", "medium"),
    "jwt": ("JSON Web Token", "medium"),
    "password_field": ("password or secret parameter", "medium"),
}

# (kind, pattern, group holding the secret, prefix kept in the preview)
_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
                               r"(?P<s>[A-Za-z0-9+/=\s\\n]{0,4000}?)(?:-----END[^-]*-----|$)"), "s", ""),
    ("aws_access_key", re.compile(r"(?<![A-Za-z0-9])(?P<s>(?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Za-z0-9])"), "s", 4),
    ("github_token", re.compile(r"(?<![A-Za-z0-9_])(?P<s>gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})"),
     "s", 4),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])(?P<s>xox[abposr]-[A-Za-z0-9-]{10,200})"), "s", 5),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9])(?P<s>AIza[0-9A-Za-z_\-]{35})(?![A-Za-z0-9_\-])"), "s", 4),
    ("stripe_key", re.compile(r"(?<![A-Za-z0-9])(?P<s>(?:sk|rk)_live_[0-9A-Za-z]{20,99})"), "s", 8),
    ("url_credentials", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,15}://(?P<user>[^\s:/@\"'<>]{1,64}):"
                                   r"(?P<s>[^\s/@\"'<>]{1,128})@[\w.-]+"), "s", 0),
    ("basic_auth", re.compile(r"(?i)\bauthorization\s*[:=]\s*\"?basic\s+(?P<s>[A-Za-z0-9+/]{6,300}={0,2})"), "s", 0),
    ("bearer_token", re.compile(r"(?i)\bauthorization\s*[:=]\s*\"?bearer\s+(?P<s>[A-Za-z0-9._~+/=-]{16,2000})"), "s", 0),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])(?P<s>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"),
     "s", 0),
    ("password_field", re.compile(
        r"(?i)(?:^|[?&;\s,{(\"'])(?P<key>pass(?:word|wd|code)?|pwd|passphrase|secret|client_secret|api[_-]?key|apikey|token|"
        r"access[_-]?token|auth[_-]?token|private[_-]?key)[\"']?\s*[=:]\s*(?P<q>[\"']?)(?P<s>[^\s&\"',;}<>)]{4,256})"),
     "s", 0),
]

# Values that are already masked, or are not secrets at all.
_NOT_SECRET = re.compile(r"(?i)^(?:[*x#.•]+|<[^>]*>|\[[^\]]*\]|%2a.*|\{\{.*|\$\{.*|redacted.*|hidden|masked|none|null|"
                         r"nil|true|false|yes|no|on|off|empty|unset|undefined|required|optional|changeme_?|\*+\w*|"
                         r"\d{1,3})$")
REDACTED = "[REDACTED {kind} {fp}]"
FIELD_MAX = 4096


@dataclass
class Settings:
    enabled: bool = True
    redact: bool = True


class SecretScanner:
    def __init__(self):
        self.settings = Settings()
        self._key = _random.token_bytes(32)  # replaced by the installation's key when storage is known
        self.found = 0

    def configure(self, enabled: bool, redact: bool) -> None:
        self.settings = Settings(bool(enabled), bool(redact))

    def set_key(self, key: str) -> None:
        self._key = bytes.fromhex(key)

    def fingerprint(self, secret: str) -> str:
        return hmac.new(self._key, secret.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]

    def scan_text(self, text: str) -> list[dict]:
        """Every secret in text: [{kind, secret, start, end, user?, key?}] (secret included)."""
        out: list[dict] = []
        taken: list[tuple[int, int]] = []
        for kind, pattern, group, _keep in _PATTERNS:
            for m in pattern.finditer(text):
                start, end = m.span(group)
                secret = m.group(group)
                if any(start < b and end > a for a, b in taken):
                    continue  # already found as something more specific
                if kind == "private_key":
                    start, end = m.span(0)
                    secret = m.group(0)
                elif kind == "basic_auth":
                    try:
                        decoded = base64.b64decode(secret + "=" * (-len(secret) % 4), validate=True).decode("utf-8")
                    except (binascii.Error, UnicodeDecodeError, ValueError):
                        continue
                    if ":" not in decoded or not decoded.split(":", 1)[1]:
                        continue
                elif kind in ("password_field", "url_credentials"):
                    if _NOT_SECRET.match(secret) or (kind == "password_field" and secret.lower() == m.group("key").lower()):
                        continue
                found = {"kind": kind, "secret": secret, "start": start, "end": end}
                if kind == "url_credentials":
                    found["user"] = m.group("user")
                if kind == "password_field":
                    found["key"] = m.group("key")
                out.append(found)
                taken.append((start, end))
        return sorted(out, key=lambda f: f["start"])

    def preview(self, kind: str, secret: str) -> str:
        """Enough to recognise which credential it was, never enough to use it."""
        keep = next((k for kd, _p, _g, k in _PATTERNS if kd == kind), 0)
        shown = secret[:keep] if keep else ""
        return f"{shown}… ({len(secret)} characters)" if shown else f"{len(secret)} characters"

    def scan_event(self, ev) -> None:
        """Find secrets in an event's message and text fields, redact them (if set to) and
        record each find in ev.extra["secrets"]."""
        if not self.settings.enabled:
            return
        finds: list[dict] = []
        fields = [("message", ev.message)] + [(f"extra.{k}", v) for k, v in ev.extra.items()
                                              if isinstance(v, str) and k != "secrets"]
        for name, text in fields:
            if not text or len(text) < 8:
                continue
            hits = self.scan_text(text[:FIELD_MAX])
            if not hits:
                continue
            redacted = text
            for hit in reversed(hits):
                fp = self.fingerprint(hit["secret"])
                label, severity = KINDS[hit["kind"]]
                if not any(f["fingerprint"] == fp and f["kind"] == hit["kind"] for f in finds):
                    record = {"kind": hit["kind"], "label": label, "severity": severity, "field": name,
                              "fingerprint": fp, "preview": self.preview(hit["kind"], hit["secret"])}
                    if hit.get("user"):
                        record["user"] = hit["user"][:64]
                    if hit.get("key"):
                        record["parameter"] = hit["key"][:40]
                    finds.append(record)
                if self.settings.redact:
                    redacted = redacted[:hit["start"]] + REDACTED.format(kind=hit["kind"], fp=fp) + redacted[hit["end"]:]
            if self.settings.redact and redacted != text:
                if name == "message":
                    ev.message = redacted
                else:
                    ev.extra[name[6:]] = redacted
        if finds:
            self.found += len(finds)
            ev.extra["secrets"] = list(reversed(finds))[:10]


SCANNER = SecretScanner()  # one per process: configured from the plaintext_secret detector's settings
KEY_SETTING = "secret_fingerprint_key"


def ensure_key(store) -> None:
    """Use the installation's fingerprint key (created on first use), so every process
    folds the same secret into the same alert."""
    key = store.get_setting(KEY_SETTING)
    if not key:
        key = _random.token_hex(32)
        store.set_setting(KEY_SETTING, key)
    SCANNER.set_key(key)


def configure_from(detector_settings: dict | None) -> None:
    cfg = (detector_settings or {}).get("plaintext_secret") or {}
    SCANNER.configure(cfg.get("enabled", True), cfg.get("redact", True))
