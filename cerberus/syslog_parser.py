"""Lenient syslog envelope parsing.

Network gear is loose with the RFCs, so this never rejects a message: it
recognises RFC 5424 and RFC 3164 headers when present and otherwise hands the
whole payload on as the message. Connectors do the vendor-specific work.
"""
from __future__ import annotations

import re

_PRI = re.compile(r"^<(\d{1,3})>")
_R5424 = re.compile(
    r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$", re.S
)
_R3164 = re.compile(
    r"^((?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)|(?:\d{4}-\d\d-\d\dT\S+)) (\S+) (.*)$", re.S
)
_TAG = re.compile(r"^([A-Za-z0-9_./()-]{1,48})(?:\[(\d+)\])?: ?(.*)$", re.S)
# Cisco IOS: "[seq: ][origin-id: ][*]Mon dd [yyyy ]hh:mm:ss[.mmm][ TZ]: %FAC-SEV-MNEMONIC: text"
_CISCO = re.compile(
    r"^(?:\d+: )?(?:([\w.\-]+): )?[*.]?[A-Z][a-z]{2} [ \d]\d (?:\d{4} )?\d\d:\d\d:\d\d(?:\.\d+)?(?: [A-Z]{2,5})?: (.*)$",
    re.S,
)

MAX_MESSAGE = 8192


def _dash(value: str) -> str:
    return "" if value == "-" else value


def parse_syslog(data: bytes | str) -> dict:
    """Return dict(facility, severity, hostname, app, message, raw).

    `raw` is everything after the <PRI>; `message` is the text after whatever
    header could be recognised.
    """
    if isinstance(data, bytes):
        text = data[:MAX_MESSAGE].decode("utf-8", errors="replace")
    else:
        text = data[:MAX_MESSAGE]
    text = text.strip("\r\n\x00 ")

    pri = 13  # user.notice, the RFC default when PRI is missing
    m = _PRI.match(text)
    if m:
        value = int(m.group(1))
        if value <= 191:
            pri = value
        text = text[m.end():]

    out = {
        "facility": pri >> 3,
        "severity": pri & 7,
        "hostname": "",
        "app": "",
        "message": text,
        "raw": text,
    }

    m = _R5424.match(text)
    if m:
        out["hostname"] = _dash(m.group(2))
        out["app"] = _dash(m.group(3))
        out["message"] = (m.group(7) or "").lstrip("\ufeff")
        return out

    m = _R3164.match(text)
    if m:
        out["hostname"] = m.group(2)
        rest = m.group(3)
        tag = _TAG.match(rest)
        if tag:
            out["app"] = tag.group(1)
            out["message"] = tag.group(3)
        else:
            out["message"] = rest
        return out

    m = _CISCO.match(text)
    if m:
        out["hostname"] = m.group(1) or ""
        out["message"] = m.group(2)
    return out
