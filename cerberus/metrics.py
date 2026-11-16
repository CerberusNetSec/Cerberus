"""Prometheus metrics: /metrics on every role, in the text exposition format.

Counters and gauges only, read from what each process already counts; no client
library. Open like /healthz, unless CERBERUS_METRICS_TOKEN is set, in which
case a scrape must send "Authorization: Bearer <token>".
"""
from __future__ import annotations

import hmac
import time

from fastapi import Request
from fastapi.responses import PlainTextResponse

from . import __version__

# (metric, type, help, key in a status dict)
COLLECTOR = [
    ("cerberus_collector_messages_received_total", "counter", "Syslog messages received", "received"),
    ("cerberus_collector_messages_dropped_total", "counter", "Messages dropped because the queue was full", "dropped"),
    ("cerberus_collector_parse_errors_total", "counter", "Messages that could not be parsed", "parse_errors"),
    ("cerberus_collector_queue_messages", "gauge", "Messages waiting to be parsed", "queue"),
    ("cerberus_collector_devices", "gauge", "Devices this collector has heard from", "devices"),
    ("cerberus_collector_tcp_refused_total", "counter", "TCP connections refused (limit or PROXY header)", "tcp_refused"),
]
WORKER = [
    ("cerberus_worker_events_received_total", "counter", "Events received from the family topic", "received"),
    ("cerberus_worker_candidates_total", "counter", "Alert candidates sent to the processor", "candidates"),
    ("cerberus_worker_duplicates_total", "counter", "Copies of events ignored", "duplicates"),
    ("cerberus_worker_errors_total", "counter", "Events that failed in detection", "errors"),
    ("cerberus_worker_rebuilds_total", "counter", "Times state was rebuilt from the bus after a partition change",
     "rebuilds"),
    ("cerberus_worker_replayed_total", "counter", "Records replayed to rebuild state", "replayed"),
]
PUBLISHER = [
    ("cerberus_bus_published_total", "counter", "Records sent to the message bus", "published"),
    ("cerberus_bus_spooled_total", "counter", "Records written to the spool while the bus was unreachable", "spooled"),
    ("cerberus_spool_bytes", "gauge", "Bytes waiting in the spool", "spool_bytes"),
    ("cerberus_spool_limit_bytes", "gauge", "Bytes the spool may hold before the oldest records are dropped",
     "spool_limit"),
    ("cerberus_spool_volume_bytes", "gauge", "Size of the volume the spool is on", "volume_bytes"),
    ("cerberus_spool_volume_free_bytes", "gauge", "Free space on the volume the spool is on", "volume_free"),
    ("cerberus_spool_dropped_total", "counter", "Records dropped because the spool was full", "spool_dropped"),
    ("cerberus_bus_down", "gauge", "1 while the message bus is unreachable", "bus_down"),
]


def from_status(status: dict, table: list) -> list[tuple]:
    return [(m, kind, text, float(status.get(key) or 0), {}) for m, kind, text, key in table if key in status]


def common(role: str, name: str, active: int = 1) -> list[tuple]:
    return [
        ("cerberus_info", "gauge", "Version and role of this process", 1, {"version": __version__, "role": role,
                                                                             "name": name}),
        ("cerberus_active", "gauge", "1 if this process is active, 0 if it is a standby", active, {}),
    ]


def processor_samples(engine, notifier, heartbeats=None, outbox_pending: int | None = None) -> list[tuple]:
    now = time.time()
    out = [
        ("cerberus_events_received_total", "counter", "Events received", engine.received, {}),
        ("cerberus_events_per_second", "gauge", "Events a second over the last minute", round(engine.rate(), 3), {}),
        ("cerberus_events_dropped_total", "counter", "Messages dropped because the queue was full", engine.dropped, {}),
        ("cerberus_parse_errors_total", "counter", "Messages or bus records that could not be processed",
         engine.parse_errors, {}),
        ("cerberus_events_unwritten_total", "counter", "Events analysed but not stored because storage fell behind",
         engine.unwritten, {}),
        ("cerberus_devices_refused_total", "counter", "Messages from sources beyond the device limit",
         engine.refused_devices, {}),
        ("cerberus_devices", "gauge", "Devices known", len(engine.devices), {}),
        ("cerberus_flush_seconds", "gauge", "How long the last write to storage took", round(engine.flush_seconds, 4), {}),
        ("cerberus_alerts_active", "gauge", "Alerts still collecting repeats (within the cooldown)",
         len(engine.alerts.active), {}),
        ("cerberus_notifications_sent_total", "counter", "Notifications delivered", notifier.sent, {}),
        ("cerberus_notifications_failed_total", "counter", "Notification attempts that failed", notifier.failed, {}),
    ]
    if outbox_pending is not None:
        out.append(("cerberus_outbox_pending", "gauge", "Notifications waiting to be sent", outbox_pending, {}))
    if engine.dedup is not None:
        out.append(("cerberus_bus_duplicates_total", "counter", "Copies of events ignored", engine.dedup.duplicates, {}))
    if engine.source is not None:
        out.append(("cerberus_bus_replayed_total", "counter", "Events replayed after a takeover",
                    engine.source.replayed, {}))
    if heartbeats is not None:
        for peer, status in heartbeats.latest.items():
            labels = {"name": peer, "role": status.get("role", "collector")}
            out.append(("cerberus_peer_heartbeat_age_seconds", "gauge",
                        "Seconds since a collector or detection worker last reported",
                        round(now - status.get("received_at", now), 1), labels))
    return out


def _label(value) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render(samples: list[tuple]) -> str:
    lines, described = [], set()
    for metric, kind, text, value, labels in samples:
        if metric not in described:
            described.add(metric)
            lines += [f"# HELP {metric} {text}", f"# TYPE {metric} {kind}"]
        tags = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
        number = int(value) if isinstance(value, bool) else value
        lines.append(f"{metric}{{{tags}}} {number}" if tags else f"{metric} {number}")
    return "\n".join(lines) + "\n"


def add_endpoint(app, token: str, collect) -> None:
    """GET /metrics on app. collect: async () -> samples."""
    @app.get("/metrics")
    async def metrics(request: Request):
        if token:
            given = request.headers.get("authorization", "")
            if not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
                return PlainTextResponse("unauthorised\n", status_code=401)
        return PlainTextResponse(render(await collect()), media_type="text/plain; version=0.0.4")
