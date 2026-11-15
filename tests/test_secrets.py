"""Plaintext secrets in logs: found, kept out of storage, alerted on once per secret."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.config import Config  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.db import Database  # noqa: E402
from cerberus.engine import Engine  # noqa: E402
from cerberus.models import Event  # noqa: E402
from cerberus.notifiers import Notifier  # noqa: E402
from cerberus.secrets_scan import SCANNER, SecretScanner  # noqa: E402

FOUND = [
    ("GET http://bob:Summer2026!@intranet.example/reports HTTP/1.1", "url_credentials", "Summer2026!"),
    ("url=https://shop.example/login?user=jo&password=Tr0ub4dor%263 status=200", "password_field", "Tr0ub4dor%263"),
    ('request "POST /api" body {"api_key": "q8Zt3mKx9Lw2Rv7P"}', "password_field", "q8Zt3mKx9Lw2Rv7P"),
    ("HTTP header Authorization: Basic YWRtaW46UzNjcjN0IQ== seen", "basic_auth", "YWRtaW46UzNjcjN0IQ=="),
    ("Authorization: Bearer abcDEF0123456789ghiJKLmnop", "bearer_token", "abcDEF0123456789ghiJKLmnop"),
    ("aws key AKIAIOSFODNN7EXAMPLE used", "aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
    ("token ghp_" + "a" * 36 + " leaked", "github_token", "ghp_" + "a" * 36),
    ("slack xoxb-123456789012-abcdefABCDEF posted", "slack_token", "xoxb-123456789012-abcdefABCDEF"),
    ("key=AIza" + "B" * 35 + " in url", "google_api_key", "AIza" + "B" * 35),
    ("stripe sk_live_" + "c" * 24 + " charge", "stripe_key", "sk_live_" + "c" * 24),
    ("cookie session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
     "jwt", None),
    ("-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA0-----END RSA PRIVATE KEY-----", "private_key", None),
]

NOT_SECRETS = [
    "Failed password for root from 203.0.113.5 port 51515 ssh2",
    "Invalid password for user admin on vty0",
    "Accepted password for admin from 10.0.0.9 port 50000 ssh2",
    "url=https://shop.example/login?user=jo&password=****** status=200",
    "password=<hidden> pwd=[redacted] secret=REDACTED token=none apikey=null",
    "config: password=true passwd=xxx",
    "Administrator admin login failed from ssh(203.0.113.5) because of invalid password",
    "GET https://example.com/search?q=password+reset HTTP/1.1",
    "ftp://anonymous@ftp.example/pub",
    '1,2026/11/13 10:00:00,0123,TRAFFIC,end,2560,2026/11/13 10:00:00,192.168.1.5,93.184.216.34,0.0.0.0,0.0.0.0,allow-web',
]


@pytest.fixture
def scanner():
    s = SecretScanner()
    s.set_key("00" * 32)
    return s


@pytest.mark.parametrize("text,kind,secret", FOUND, ids=[k for _, k, _ in FOUND])
def test_each_kind_is_found(scanner, text, kind, secret):
    hits = scanner.scan_text(text)
    assert [h["kind"] for h in hits] == [kind]
    if secret:
        assert hits[0]["secret"] == secret


@pytest.mark.parametrize("text", NOT_SECRETS)
def test_ordinary_log_lines_are_left_alone(scanner, text):
    assert scanner.scan_text(text) == []


def event(message, **extra):
    return Event(ts=1.0, device="proxy01", source_ip="10.0.0.2", message=message, src_ip="10.0.0.5",
                 dst_ip="198.51.100.7", dst_port=80, extra=dict(extra))


def test_events_are_redacted_and_described(scanner):
    ev = event("GET http://bob:Summer2026!@intranet.example/ ok", url="https://x.example/?token=Zx81kQ2mPa")
    scanner.scan_event(ev)
    assert "Summer2026!" not in ev.message and "[REDACTED url_credentials " in ev.message
    assert "Zx81kQ2mPa" not in ev.extra["url"] and "[REDACTED password_field " in ev.extra["url"]
    finds = {f["kind"]: f for f in ev.extra["secrets"]}
    assert set(finds) == {"url_credentials", "password_field"}
    assert finds["url_credentials"]["user"] == "bob" and finds["password_field"]["parameter"] == "token"
    for f in finds.values():  # nothing in the description gives the secret away
        assert "Summer2026" not in str(f) and "Zx81kQ2mPa" not in str(f) and len(f["fingerprint"]) == 12


def test_fingerprints_are_keyed(scanner):
    other = SecretScanner()
    other.set_key("11" * 32)
    assert scanner.fingerprint("hunter2") == scanner.fingerprint("hunter2") != other.fingerprint("hunter2")


def test_off_and_no_redaction(scanner):
    scanner.configure(enabled=True, redact=False)
    ev = event("GET http://bob:Summer2026!@intranet.example/ ok")
    scanner.scan_event(ev)
    assert "Summer2026!" in ev.message and ev.extra["secrets"]
    scanner.configure(enabled=False, redact=True)
    ev = event("GET http://bob:Summer2026!@intranet.example/ ok")
    scanner.scan_event(ev)
    assert "Summer2026!" in ev.message and "secrets" not in ev.extra


def test_end_to_end(tmp_path):
    cfg = Config.from_env()
    cfg.data_dir, cfg.device_identity = tmp_path, "hostname"
    db = Database(tmp_path / "c.db")
    engine = Engine(cfg, db, ConnectorRegistry(), Notifier(db))
    engine.load()
    engine.installed = 0
    line = ("<134>Nov 14 10:00:00 proxy01 squid[12]: 1731578400.000 15 10.0.0.5 TCP_MISS/200 512 GET "
            "http://bob:Summer2026!@intranet.example/reports - HIER_DIRECT/198.51.100.7 text/html")
    try:
        for ts in (1_800_000_000.0, 1_800_000_060.0):
            engine._process(line.encode(), "10.0.0.2", ts)
        asyncio.run(engine._flush())
        [alert] = [a for a in db.alerts_find(limit=10) if a["detector"] == "plaintext_secret"]
        assert alert["detector"] == "plaintext_secret" and alert["severity"] == "high"
        assert alert["title"] == "Plaintext password in a URL in logs from proxy01"
        assert "removed from the stored event" in alert["description"] and "Summer2026" not in str(alert)
        stored = [e["message"] for e in db.search_events(limit=10)]
        assert len(stored) == 2 and all("Summer2026" not in m and "[REDACTED url_credentials" in m for m in stored)
        key = db.get_setting("secret_fingerprint_key")
        assert key and len(key) == 64
        # Switched off under Settings -> Detection: no scanning, no redaction.
        settings = {d.id: d.settings() for d in engine.detectors}
        settings["plaintext_secret"]["enabled"] = False
        engine.apply_settings(settings, engine.general_settings())
        engine._process(line.replace("Summer2026", "Winter2027").encode(), "10.0.0.2", 1_800_000_120.0)
        asyncio.run(engine._flush())
        assert any("Winter2027" in e["message"] for e in db.search_events(limit=10))
        assert len([a for a in db.alerts_find(limit=10) if a["detector"] == "plaintext_secret"]) == 1
    finally:
        SCANNER.configure(True, True)  # the process-wide default for other tests
        db.close()
