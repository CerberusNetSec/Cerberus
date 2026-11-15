"""Alert delivery: SMTP, Telegram, Pushbullet, webhooks and custom API calls.

Channels live in the database and are edited from the web UI. Each has a
minimum severity and a per-minute rate limit; alerts over the limit are
counted and reported in one summary message instead of being sent one by one.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import uuid
from urllib.parse import quote, urlsplit
import smtplib
import ssl
import time
from collections import deque
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import httpx

from .models import SEVERITIES, sev_rank
from .playbooks import advice

log = logging.getLogger("cerberus.notify")

SECRET_KEYS = ("password", "token", "access_token", "secret", "headers")
TEXT_MAX, TEMPLATE_MAX = 500, 8000  # a text field; a header list or body template
MASK = "********"

# type -> list of (key, label, kind, default)
CHANNEL_TYPES: dict[str, dict] = {
    "smtp": {
        "label": "Email (SMTP)",
        "fields": [
            ("host", "SMTP server", "text", ""),
            ("port", "Port", "number", "587"),
            ("security", "Encryption", "select:starttls,ssl,none", "starttls"),
            ("username", "Username (optional)", "text", ""),
            ("password", "Password", "secret", ""),
            ("from_addr", "From address", "text", ""),
            ("to_addrs", "Recipients (comma-separated)", "text", ""),
        ],
        "required": ["host", "from_addr", "to_addrs"],
    },
    "telegram": {
        "label": "Telegram",
        "fields": [
            ("token", "Bot token (from @BotFather)", "secret", ""),
            ("chat_id", "Chat IDs (comma-separated)", "text", ""),
        ],
        "required": ["token", "chat_id"],
    },
    "pushbullet": {
        "label": "Pushbullet",
        "fields": [
            ("access_token", "Access token", "secret", ""),
            ("email", "Send to email (optional; default: all your devices)", "text", ""),
            ("channel_tag", "Channel tag (optional)", "text", ""),
        ],
        "required": ["access_token"],
    },
    "webhook": {
        "label": "Webhook",
        "fields": [
            ("url", "URL (https:// recommended)", "text", ""),
            ("secret", "Signing secret (optional): adds an HMAC-SHA256 signature header", "secret", ""),
            ("headers", "Extra headers (optional), one per line: Name: value", "secret-textarea", ""),
        ],
        "required": ["url"],
        "help": ("POSTs each alert as JSON (see docs/API.md, \"Webhook payload\"). With a signing secret, "
                 "X-Cerberus-Signature is sha256=HMAC(secret, timestamp + \".\" + body) and "
                 "X-Cerberus-Timestamp the Unix time it was sent: check both, and reject old timestamps."),
    },
    "api": {
        "label": "Custom API call",
        "fields": [
            ("method", "Method", "select:POST,PUT,PATCH,GET", "POST"),
            ("url", "URL (placeholders allowed, URL-encoded)", "text", ""),
            ("headers", "Headers, one per line: Name: value (placeholders allowed)", "secret-textarea", ""),
            ("content_type", "Body type", "select:application/json,application/x-www-form-urlencoded,text/plain",
             "application/json"),
            ("body", "Body template (empty: the standard JSON payload)", "textarea", ""),
        ],
        "required": ["url"],
        "help": ("Placeholders: {{title}} {{description}} {{severity}} {{detector}} {{device}} {{src_ip}} {{id}} "
                 "{{created}} {{stage}} {{technique}} {{link}} {{subject}} {{text}}, and {{payload}} for the whole "
                 "alert as JSON. They are escaped for where they are: JSON-escaped in a JSON body (write "
                 "\"{{title}}\" inside quotes), URL-encoded in the URL and form bodies. Add |raw, |json or |url to "
                 "choose."),
    },
}

PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*(?:\|\s*(raw|json|url)\s*)?\}\}")
FIELDS = ("id", "title", "description", "severity", "detector", "device", "src_ip", "created", "stage", "technique",
          "link", "subject", "text")


def payload_for(alert: dict | None, subject: str, body: str, link: str = "", event: str = "alert") -> dict:
    """The JSON a webhook receives, and what custom API templates fill from."""
    from . import __version__
    a = alert or {}
    guide = advice(a) if a.get("detector") else {"stage": "", "technique": None, "actions": []}
    created = a.get("created")
    return {
        "event": event, "source": "cerberus", "version": __version__,
        "id": a.get("id"), "title": a.get("title", subject), "description": a.get("description", ""),
        "severity": a.get("severity", ""), "detector": a.get("detector", ""), "device": a.get("device", ""),
        "src_ip": a.get("src_ip") or "",
        "created": datetime.fromtimestamp(created).astimezone().isoformat() if created else "",
        "created_epoch": created, "details": a.get("details") or {},
        "stage": guide["stage"] or "",
        "technique": (f"{guide['technique']['id']} {guide['technique']['name']}" if guide["technique"] else ""),
        "actions": guide["actions"][:4], "link": link, "subject": subject, "text": body,
    }


def render(template: str, payload: dict, default: str) -> str:
    """Fill {{placeholders}}: default escaping is 'json' (inside a JSON string), 'url' or 'raw'."""
    def value(m):
        name, how = m.group(1), m.group(2) or default
        if name == "payload":
            raw = json.dumps(payload, separators=(",", ":"), default=str)
            return quote(raw, safe="") if how == "url" else raw
        if name not in FIELDS:
            return m.group(0)
        text = "" if payload.get(name) is None else str(payload[name])
        if how == "json":
            return json.dumps(text)[1:-1]
        if how == "url":
            return quote(text, safe="")
        return text
    return PLACEHOLDER.sub(value, template)


def _headers(text: str, payload: dict) -> dict[str, str]:
    out = {}
    for line in str(text or "").splitlines():
        name, sep, val = line.partition(":")
        name = name.strip()
        if not sep or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
            continue
        # Alert text in a header must not start a new header.
        out[name] = " ".join(render(val.strip(), payload, "raw").split())[:2000]
    return out


SAMPLE = {"id": 0, "created": 1_800_000_000.0, "severity": "high", "title": "Test notification from Cerberus",
          "description": "A sample alert, to check this channel works.", "detector": "port_scan",
          "device": "fw01", "src_ip": "192.0.2.10", "details": {"test": True}}


def _check_url(url: str) -> None:
    parts = urlsplit(url.replace("{{", "x").replace("}}", "x"))
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("the URL must start with http:// or https://")

RATE_LIMIT_PER_MINUTE = 10


def _split(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def validate_channel(body: dict, existing: dict | None = None) -> dict:
    """Return a clean channel row dict from API input, or raise ValueError."""
    ctype = (existing or body).get("type")
    spec = CHANNEL_TYPES.get(ctype)
    if not spec:
        raise ValueError("unknown channel type")
    name = str(body.get("name", "")).strip()[:80] or spec["label"]
    severity = body.get("min_severity", "medium")
    if severity not in SEVERITIES:
        raise ValueError("invalid minimum severity")
    old = json.loads(existing["config"]) if existing else {}
    given = body.get("config") or {}
    config = {}
    for key, _label, kind, default in spec["fields"]:
        limit = TEMPLATE_MAX if kind.endswith("textarea") else TEXT_MAX
        value = str(given.get(key, old.get(key, default)) or "").strip()[:limit]
        if kind in ("secret", "secret-textarea") and value == MASK:
            value = old.get(key, "")
        if kind.startswith("select:") and value not in kind[7:].split(","):
            value = default
        config[key] = value
    missing = [k for k in spec["required"] if not config.get(k)]
    if missing:
        raise ValueError("missing: " + ", ".join(missing))
    if ctype in ("webhook", "api"):
        _check_url(config["url"])
    if ctype == "api" and config["body"] and config["content_type"] == "application/json":
        filled = render(config["body"], payload_for(SAMPLE, "subject", "text"), "json")
        try:
            json.loads(filled)
        except ValueError as exc:
            raise ValueError(f"the body template is not valid JSON once filled in ({exc.msg} at character "
                             f"{exc.pos}); put text placeholders inside quotes, e.g. \"{{{{title}}}}\"")
    return {
        "type": ctype,
        "name": name,
        "enabled": 1 if body.get("enabled", True) else 0,
        "min_severity": severity,
        "config": json.dumps(config),
    }


def public_channel(row: dict) -> dict:
    config = json.loads(row["config"] or "{}")
    for key in SECRET_KEYS:
        if config.get(key):
            config[key] = MASK  # never sent back; saving MASK keeps the stored value
    return {**row, "config": config, "enabled": bool(row["enabled"])}


def _smtp_send(c: dict, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = c["from_addr"]
    msg["To"] = ", ".join(_split(c["to_addrs"]))
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="cerberus.local")
    msg.set_content(body)
    port = int(c.get("port") or 587)
    security = c.get("security", "starttls")
    context = ssl.create_default_context()
    if security == "ssl":
        server = smtplib.SMTP_SSL(c["host"], port, timeout=20, context=context)
    else:
        server = smtplib.SMTP(c["host"], port, timeout=20)
    try:
        if security == "starttls":
            server.starttls(context=context)
        if c.get("username"):
            server.login(c["username"], c.get("password", ""))
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass


async def _raise_for(resp: httpx.Response, service: str) -> None:
    if resp.status_code >= 400:
        try:
            data = resp.json()
            detail = data.get("description") or (data.get("error") or {}).get("message") or resp.text
        except ValueError:
            detail = resp.text
        raise RuntimeError(f"{service} returned {resp.status_code}: {str(detail)[:200]}")


async def send(channel: dict, subject: str, body: str, client: httpx.AsyncClient, payload: dict | None = None) -> None:
    """Deliver one message. Raises on failure."""
    c = json.loads(channel["config"]) if isinstance(channel["config"], str) else channel["config"]
    subject = " ".join(subject.split())[:200]
    kind = channel["type"]
    payload = payload or payload_for(None, subject, body, event="message")
    if kind == "smtp":
        await asyncio.to_thread(_smtp_send, c, subject, body)
    elif kind == "telegram":
        for chat in _split(c["chat_id"]):
            resp = await client.post(
                f"https://api.telegram.org/bot{c['token']}/sendMessage",
                json={"chat_id": chat, "text": f"{subject}\n\n{body}"[:4000],
                      "disable_web_page_preview": True},
            )
            await _raise_for(resp, "Telegram")
    elif kind == "pushbullet":
        payload = {"type": "note", "title": subject, "body": body[:4000]}
        if c.get("email"):
            payload["email"] = c["email"]
        if c.get("channel_tag"):
            payload["channel_tag"] = c["channel_tag"]
        resp = await client.post(
            "https://api.pushbullet.com/v2/pushes",
            headers={"Access-Token": c["access_token"]},
            json=payload,
        )
        await _raise_for(resp, "Pushbullet")
    elif kind == "webhook":
        data = json.dumps(payload, separators=(",", ":"), default=str).encode()
        headers = {**_headers(c.get("headers", ""), payload), "Content-Type": "application/json",
                   "User-Agent": "Cerberus", "X-Cerberus-Event": payload.get("event", "alert"),
                   "X-Cerberus-Delivery": str(uuid.uuid4())}
        if c.get("secret"):
            stamp = str(int(time.time()))
            digest = hmac.new(c["secret"].encode(), stamp.encode() + b"." + data, hashlib.sha256).hexdigest()
            headers.update({"X-Cerberus-Timestamp": stamp, "X-Cerberus-Signature": f"sha256={digest}"})
        resp = await client.post(c["url"], content=data, headers=headers)
        await _raise_for(resp, "The webhook")
    elif kind == "api":
        url = render(c["url"], payload, "url")
        content_type = c.get("content_type") or "application/json"
        if c.get("body"):
            text = render(c["body"], payload, {"application/json": "json", "text/plain": "raw"}.get(content_type, "url"))
        else:
            text = json.dumps(payload, separators=(",", ":"), default=str)
            content_type = "application/json"
        headers = {"Content-Type": content_type, "User-Agent": "Cerberus", **_headers(c.get("headers", ""), payload)}
        method = c.get("method") or "POST"
        resp = await client.request(method, url, headers=headers,
                                    content=None if method == "GET" else text.encode())
        await _raise_for(resp, "The API")
    else:
        raise RuntimeError(f"unknown channel type {kind}")


PENDING_MAX = 5000


class Notifier:
    def __init__(self, db, public_url: str = ""):
        self.db = db
        self.public_url = public_url
        self.channels: list[dict] = []
        # Formatted notifications waiting for the engine's next write, which puts them in
        # the outbox with the alerts they are about: (created, channel_id, subject, body).
        self.pending: list[tuple] = []
        self._inflight: set[int] = set()  # outbox ids being sent now
        self.sent = self.failed = 0
        self._sent: dict[int, deque] = {}
        self._suppressed: dict[int, int] = {}
        self._client: httpx.AsyncClient | None = None
        self._slots = asyncio.Semaphore(4)
        self._tasks: set = set()

    async def reload(self) -> None:
        self.channels = await asyncio.to_thread(self.db.channels)

    def format(self, alert: dict) -> tuple[str, str]:
        subject = f"[Cerberus {alert['severity'].upper()}] {alert['title']}"
        when = datetime.fromtimestamp(alert["created"]).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        lines = [alert["description"], "", f"Severity: {alert['severity']}", f"Detected: {when}"]
        if alert.get("device"):
            lines.append(f"Reported by: {alert['device']}")
        guide = advice(alert)
        if guide["technique"]:
            lines.append(f"ATT&CK: {guide['technique']['id']} {guide['technique']['name']} ({guide['stage']})")
        if guide["why"]:
            lines += ["", "Why it matters: " + guide["why"]]
        if guide["actions"]:
            lines += ["", "What to do:"] + [f"{i}. {step}" for i, step in enumerate(guide["actions"][:4], 1)]
        if self.public_url:
            link = alert.get("link") or (f"#/alerts?id={alert['id']}" if alert.get("id") else "#/alerts")
            lines += ["", f"{self.public_url}/{link}"]
        return subject, "\n".join(lines)

    def _allow(self, channel_id: int, now: float) -> bool:
        sent = self._sent.setdefault(channel_id, deque())
        while sent and sent[0] < now - 60:
            sent.popleft()
        if len(sent) >= RATE_LIMIT_PER_MINUTE:
            return False
        sent.append(now)
        return True

    def notify(self, alert: dict) -> None:
        """Queue an alert for every channel that wants it. Never blocks."""
        now = time.time()
        for ch in self.channels:
            if not ch["enabled"] or sev_rank(alert["severity"]) < sev_rank(ch["min_severity"]):
                continue
            if not self._allow(ch["id"], now):
                self._suppressed[ch["id"]] = self._suppressed.get(ch["id"], 0) + 1
                continue
            subject, body = self.format(alert)
            self._enqueue(ch, subject, body, payload_for(alert, subject, body, self.link(alert)))

    def link(self, alert: dict) -> str:
        if not self.public_url:
            return ""
        return f"{self.public_url}/" + (alert.get("link") or (f"#/alerts?id={alert['id']}" if alert.get("id") else "#/alerts"))

    def _enqueue(self, ch: dict, subject: str, body: str, payload: dict | None = None) -> None:
        if len(self.pending) >= PENDING_MAX:
            log.warning("too many notifications waiting to be stored; dropping one for %s", ch["name"])
            return
        self.pending.append((time.time(), ch["id"], subject, body,
                             json.dumps(payload, separators=(",", ":"), default=str) if payload else None))

    def drain(self) -> list[tuple]:
        """Notifications for the outbox, taken by the engine's write (Batch.notices)."""
        out, self.pending = self.pending, []
        return out

    def tick(self) -> None:
        """Send a summary for alerts that were held back by the rate limit."""
        now = time.time()
        for ch in self.channels:
            held = self._suppressed.get(ch["id"], 0)
            if held and self._allow(ch["id"], now):
                self._suppressed[ch["id"]] = 0
                body = (f"{held} more alert(s) were raised but not sent individually because this channel "
                        f"is limited to {RATE_LIMIT_PER_MINUTE} notifications per minute. "
                        "Open the dashboard to review them.")
                if self.public_url:
                    body += f"\n\n{self.public_url}/#/alerts"
                subject = f"[Cerberus] {held} more alerts"
                self._enqueue(ch, subject, body, {**payload_for(None, subject, body, event="summary"),
                                                  "count": held, "link": self.link({})})

    async def deliver(self, ch: dict, subject: str, body: str, retry: bool = True,
                      payload: dict | None = None) -> str | None:
        """Send (with retries unless told otherwise) and record the outcome.
        Returns an error string or None."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=20)
        error = None
        for attempt, delay in enumerate((0, 5, 20) if retry else (0,)):
            if delay:
                await asyncio.sleep(delay)
            try:
                await send(ch, subject, body, self._client, payload)
                error = None
                break
            except Exception as exc:  # delivery failures must never take the app down
                error = (str(exc) if isinstance(exc, RuntimeError) else f"{type(exc).__name__}: {exc}")[:300]
                # Bot tokens ride in the Telegram URL; keep them out of logs and the UI.
                for key in SECRET_KEYS:
                    secret = json.loads(ch["config"]).get(key) if isinstance(ch["config"], str) else None
                    if secret:
                        error = error.replace(secret, "***")
                log.warning("notify via %s failed (attempt %d): %s", ch["name"], attempt + 1, error)
        await asyncio.to_thread(self.db.channel_result, ch["id"], time.time(), not error, error)
        return error

    async def _send_from_outbox(self, row: dict) -> None:
        try:
            async with self._slots:
                ch = next((c for c in self.channels if c["id"] == row["channel_id"]), None)
                if ch is None or not ch["enabled"]:
                    error = "channel removed or disabled"
                    await asyncio.to_thread(self.db.outbox_done, row["id"], time.time(), error)
                    return
                payload = json.loads(row["payload"]) if row.get("payload") else None
                error = await self.deliver(ch, row["subject"], row["body"], payload=payload)
                await asyncio.to_thread(self.db.outbox_done, row["id"], time.time(), error)
                if error:
                    self.failed += 1
                else:
                    self.sent += 1
        except Exception:
            log.exception("sending a notification from the outbox failed")
        finally:
            self._inflight.discard(row["id"])

    async def send_due(self) -> int:
        """Start sending what is due in the outbox; returns how many were started."""
        rows = await asyncio.to_thread(self.db.outbox_due, time.time(), 50)
        started = 0
        for row in rows:
            if row["id"] in self._inflight:
                continue
            self._inflight.add(row["id"])
            task = asyncio.create_task(self._send_from_outbox(row))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            started += 1
        return started

    async def run(self) -> None:
        """Send from the outbox: notifications whose alerts are stored. Only the active
        processor runs this, so each is sent once (a crash between sending and recording
        it can send one again)."""
        await self.reload()
        while True:
            try:
                await self.send_due()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("reading the notification outbox failed: %s", exc)
            await asyncio.sleep(1)

    async def close(self) -> None:
        if self._client:
            await self.aclose_client()

    async def aclose_client(self) -> None:
        await self._client.aclose()
        self._client = None
