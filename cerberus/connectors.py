"""Connector definitions: declarative YAML that turns a vendor's syslog text
into normalised Event fields.

A connector has a `match` (which messages it claims) and ordered `rules`.
Each rule uses one parser:

  regex  `pattern` with named groups; the rule applies when it matches.
  csv    positional `columns` / indexed `fields`, with nested `switch` layouts.
  kv     key=value pairs, with `rename` and `extract`.
  json   a JSON object, with `rename`.

See connectors_builtin/*.yaml for worked examples and README.md for the schema.
"""
from __future__ import annotations

import csv
import json
import logging
import re
from pathlib import Path

import yaml

from .models import SEVERITIES, Event, clean_ip

log = logging.getLogger("cerberus.connectors")

BUILTIN_DIR = Path(__file__).parent / "connectors_builtin"

_STR_FIELDS = ("event_type", "action", "proto", "user", "interface", "state", "level")
_INT_FIELDS = ("src_port", "dst_port", "bytes")
_IP_FIELDS = ("src_ip", "dst_ip")
_COND_FIELDS = ("app", "message", "hostname", "raw")
_KV = re.compile(r'([\w.\-]+)=("(?:[^"\\]|\\.)*"|\S*)')


class ConnectorError(ValueError):
    pass


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class _Cond:
    """Regex conditions on envelope fields."""

    def __init__(self, spec: dict | None, require_all: bool):
        self.require_all = require_all
        self.checks: list[tuple[str, list[re.Pattern]]] = []
        for key, patterns in (spec or {}).items():
            if key not in _COND_FIELDS:
                raise ConnectorError(f"unknown condition field '{key}' (use one of {_COND_FIELDS})")
            self.checks.append((key, [re.compile(str(p)) for p in _as_list(patterns)]))

    def test(self, parsed: dict) -> bool:
        if not self.checks:
            return self.require_all
        results = (any(p.search(parsed[key]) for p in pats) for key, pats in self.checks)
        return all(results) if self.require_all else any(results)


def _prep_layout(layout: dict) -> dict:
    """Validate a csv layout and normalise switch-case keys to lowercase strings."""
    if not isinstance(layout, dict):
        raise ConnectorError("csv layout must be a mapping")
    out = dict(layout)
    out["columns"] = _as_list(layout.get("columns"))
    out["fields"] = {str(k): int(v) for k, v in (layout.get("fields") or {}).items()}
    out["set"] = dict(layout.get("set") or {})
    out["extract"] = [
        (str(e["from"]), [re.compile(str(p)) for p in _as_list(e.get("patterns"))])
        for e in _as_list(layout.get("extract"))
    ]
    sw = layout.get("switch")
    if sw:
        out["switch"] = {
            "field": str(sw["field"]),
            "cases": {str(k).lower(): _prep_layout(v or {}) for k, v in (sw.get("cases") or {}).items()},
            "default": _prep_layout(sw["default"]) if sw.get("default") is not None else None,
        }
    return out


def _apply_layout(layout: dict, cols: list[str], pos: int, out: dict) -> None:
    for name in layout["columns"]:
        if name and pos < len(cols):
            out[name] = cols[pos]
        pos += 1
    for name, idx in layout["fields"].items():
        if idx < len(cols):
            out[name] = cols[idx]
    out.update(layout["set"])
    for source, patterns in layout["extract"]:
        text = str(out.get(source, ""))
        for pat in patterns:
            m = pat.search(text)
            if m:
                out.update({k: v for k, v in m.groupdict().items() if v is not None})
                break
    sw = layout.get("switch")
    if sw:
        case = sw["cases"].get(str(out.get(sw["field"], "")).lower(), sw["default"])
        if case:
            _apply_layout(case, cols, pos, out)


class Rule:
    def __init__(self, spec: dict, index: int):
        self.name = str(spec.get("name") or f"rule-{index + 1}")
        self.parser = spec.get("parser", "regex")
        self.when = _Cond(spec.get("when"), require_all=True)
        self.source = spec.get("source", "message")
        if self.source not in ("message", "raw"):
            raise ConnectorError(f"rule {self.name}: source must be 'message' or 'raw'")
        self.set = dict(spec.get("set") or {})
        self.rename = {str(k): str(v) for k, v in (spec.get("rename") or {}).items()}
        self.map = {
            field: {str(k).lower(): v for k, v in (table or {}).items()}
            for field, table in (spec.get("map") or {}).items()
        }
        self.extract = [
            (str(e["from"]), [re.compile(str(p)) for p in _as_list(e.get("patterns"))])
            for e in _as_list(spec.get("extract"))
        ]
        if self.parser == "regex":
            if "pattern" not in spec:
                raise ConnectorError(f"rule {self.name}: regex parser needs 'pattern'")
            self.pattern = re.compile(str(spec["pattern"]))
        elif self.parser == "csv":
            self.delimiter = str(spec.get("delimiter", ","))
            self.min_columns = int(spec.get("min_columns", 1))
            self.layout = _prep_layout(spec)
            self.set = {}  # applied by the layout, so nested cases can override it
            self.extract = []
        elif self.parser not in ("kv", "json"):
            raise ConnectorError(f"rule {self.name}: unknown parser '{self.parser}'")

    def apply(self, parsed: dict) -> dict | None:
        if not self.when.test(parsed):
            return None
        text = parsed[self.source]
        out: dict = {}
        if self.parser == "regex":
            m = self.pattern.search(text)
            if not m:
                return None
            out = {k: v for k, v in m.groupdict().items() if v is not None}
        elif self.parser == "csv":
            try:
                cols = next(csv.reader([text], delimiter=self.delimiter))
            except (csv.Error, StopIteration):
                return None
            if len(cols) < self.min_columns:
                return None
            _apply_layout(self.layout, cols, 0, out)
        elif self.parser == "kv":
            out = {k: v.strip('"') for k, v in _KV.findall(text)}
            if not out:
                return None
        elif self.parser == "json":
            start = text.find("{")
            try:
                data = json.loads(text[start:]) if start >= 0 else None
            except ValueError:
                return None
            if not isinstance(data, dict):
                return None
            out = {k: v for k, v in data.items() if isinstance(v, (str, int, float, bool))}
        for old, new in self.rename.items():
            if old in out:
                out[new] = out.pop(old)
        for source, patterns in self.extract:
            text = str(out.get(source, ""))
            for pat in patterns:
                m = pat.search(text)
                if m:
                    # Fill gaps only: a field the log states outright beats one fished out of free text.
                    for key, value in m.groupdict().items():
                        if value is not None and not out.get(key):
                            out[key] = value
                    break
        out.update(self.set)
        for field, table in self.map.items():
            if field in out:
                key = str(out[field]).lower()
                if key in table:
                    out[field] = table[key]
                elif "_default" in table:
                    out[field] = table["_default"]
        return out


class Connector:
    def __init__(self, spec: dict, origin: str):
        if not isinstance(spec, dict) or "id" not in spec:
            raise ConnectorError("connector needs an 'id'")
        self.id = str(spec["id"])
        self.name = str(spec.get("name", self.id))
        self.description = str(spec.get("description", "")).strip()
        self.priority = int(spec.get("priority", 100))
        self.origin = origin
        match = spec.get("match")
        self.match_always = match == "always"
        self.match = _Cond(None if self.match_always else match, require_all=False)
        self.rules = [Rule(r, i) for i, r in enumerate(_as_list(spec.get("rules")))]

    def claims(self, parsed: dict) -> bool:
        return self.match_always or self.match.test(parsed)

    def parse(self, parsed: dict) -> tuple[str, dict]:
        for rule in self.rules:
            fields = rule.apply(parsed)
            if fields is not None:
                return rule.name, fields
        return "", {}

    def info(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "origin": self.origin,
            "rules": [r.name for r in self.rules],
        }


class ConnectorRegistry:
    def __init__(self, user_dir: Path | None = None):
        self.user_dir = user_dir
        self.connectors: list[Connector] = []
        self.by_id: dict[str, Connector] = {}
        self.errors: list[str] = []
        self.reload()

    def reload(self) -> None:
        found: dict[str, Connector] = {}
        errors: list[str] = []
        for directory, origin in ((BUILTIN_DIR, "builtin"), (self.user_dir, "user")):
            if not directory or not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.y*ml")):
                try:
                    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
                    conn = Connector(spec, origin)
                    found[conn.id] = conn  # user files override builtins by id
                except (ConnectorError, yaml.YAMLError, re.error, KeyError, TypeError, ValueError) as exc:
                    errors.append(f"{path.name}: {exc}")
                    log.error("connector %s failed to load: %s", path, exc)
        self.connectors = sorted(found.values(), key=lambda c: (c.priority, c.id))
        self.by_id = found
        self.errors = errors
        log.info("loaded connectors: %s", ", ".join(c.id for c in self.connectors))

    def build_event(self, parsed: dict, ts: float, device: str, source_ip: str, pin: str = "",
                    hint: str = "") -> Event:
        """hint: the connector this device's last message matched. A device speaks one
        format, so it is tried first instead of testing every connector on every message."""
        ev = Event(
            ts=ts,
            device=device,
            source_ip=source_ip,
            hostname=parsed["hostname"],
            facility=parsed["facility"],
            severity=parsed["severity"],
            app=parsed["app"],
            message=parsed["message"],
        )
        conn = self.by_id.get(pin) if pin else None
        if conn is None and hint:
            last = self.by_id.get(hint)
            if last is not None and not last.match_always and last.claims(parsed):
                conn = last
        if conn is None:
            conn = next((c for c in self.connectors if c.claims(parsed)), None)
        if conn is None:
            return ev
        ev.connector = conn.id
        ev.rule, fields = conn.parse(parsed)
        _normalise(ev, fields)
        return ev


def _normalise(ev: Event, fields: dict) -> None:
    for name in _STR_FIELDS:
        value = fields.pop(name, None)
        if value is not None:
            setattr(ev, name, str(value).strip()[:128])
    for name in _INT_FIELDS:
        value = fields.pop(name, None)
        if value not in (None, ""):
            try:
                number = int(str(value))
            except ValueError:
                continue
            if number >= 0 and (name == "bytes" or number <= 65535):
                setattr(ev, name, number)
    for name in _IP_FIELDS:
        value = fields.pop(name, None)
        if value:
            setattr(ev, name, clean_ip(str(value)))
    hostname = fields.pop("hostname", None)
    if hostname:
        ev.hostname = str(hostname)[:128]
    ev.action = ev.action.lower()
    ev.proto = ev.proto.lower()
    ev.level = ev.level.lower()
    if ev.level and ev.level not in SEVERITIES:
        ev.level = ""
    if not ev.event_type:
        ev.event_type = "other"
    extra = {}
    for key, value in fields.items():
        if len(extra) >= 40:
            break
        if value in (None, ""):
            continue
        extra[str(key)[:48]] = str(value)[:256]
    ev.extra = extra
