"""The storage contract.

Everything Cerberus keeps goes through these operations, and nothing outside a
backend writes SQL. Today's backend is SQLite (cerberus/db.py); clustering
adds PostgreSQL for alerts, devices and settings and ClickHouse for events and
counters (docs/CLUSTERING.md), each implementing this same interface.

Methods are synchronous and may block; async callers run them in a worker
thread. Rows are plain dicts.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

TOTAL = "*"  # stats_minute row holding the sum over all devices, so charts read one row per minute


class QueryTimeout(Exception):
    """A read ran past its deadline and was cancelled."""


@dataclass
class Batch:
    """Everything the pipeline has to write, gathered over about a second."""

    # Stored events, oldest first, as tuples in db.EVENT_COLUMNS order.
    events: list[tuple] = field(default_factory=list)
    # (minute, device, events, blocked): added to what is already stored.
    stats: list[tuple] = field(default_factory=list)
    # (id, ip, hostname, connector_seen, first_seen, last_seen, events): inserted or updated.
    devices: list[tuple] = field(default_factory=list)
    # (minute, port, direction, allowed, blocked): added to what is already stored.
    ports: list[tuple] = field(default_factory=list)
    # New alerts: (id, created, last_seen, detector, severity, title, description, entity,
    # src_ip, device, count, status, details, updated).
    new_alerts: list[tuple] = field(default_factory=list)
    # Changed alerts: (last_seen, count, severity, description, details, updated, id).
    alert_updates: list[tuple] = field(default_factory=list)
    # Notifications to send, written with the alerts they are about: (created, channel_id,
    # subject, body[, payload JSON]). Sent from the outbox once stored.
    notices: list[tuple] = field(default_factory=list)
    # Findings held back by a false-positive suppression: (hits to add, last hit, suppression id).
    suppression_hits: list[tuple] = field(default_factory=list)

    def __bool__(self) -> bool:
        return any((self.events, self.stats, self.devices, self.ports, self.new_alerts, self.alert_updates,
                    self.notices, self.suppression_hits))


def _todo(*_args, **_kwargs):
    raise NotImplementedError


SUPPRESSION_COLUMNS = ("id", "created", "detector", "entity", "title", "alert_id", "justification", "analyst",
                       "source", "active", "removed", "removed_by", "removed_source", "removed_justification",
                       "hits", "last_hit")
AUDIT_COLUMNS = ("id", "ts", "action", "analyst", "source", "alert_id", "suppression_id", "detail")


class NotFound(Exception):
    """The alert or suppression asked for does not exist (or is no longer active)."""


OUTBOX_ATTEMPTS = 5
OUTBOX_KEEP_SECONDS = 7 * 86400


def outbox_retry_at(now: float, attempts: int) -> float:
    """When to try a failed notification again: 1, 2, 4, 8 minutes."""
    return now + 60 * 2 ** max(0, attempts - 1)


class Leadership:
    """A lock only one process holds at a time, for as long as it stays connected.
    Blocking calls: run them in a thread."""

    def try_acquire(self) -> bool:
        """Take the lock if nobody holds it; True if this process now holds it."""
        raise NotImplementedError

    def still_held(self) -> bool:
        """False once the lock may have passed to someone else (the connection is gone)."""
        raise NotImplementedError

    def release(self) -> None:
        raise NotImplementedError


class SingleProcess(Leadership):
    """Storage only one process uses (SQLite): that process always leads."""

    def try_acquire(self) -> bool:
        return True

    def still_held(self) -> bool:
        return True

    def release(self) -> None:
        pass


class Store:
    """The operations a storage backend provides. See cerberus/db.py for the SQLite one."""

    # Relational tables import_table() accepts, with their columns. Events and counters are
    # not here: they move with write_batch().
    IMPORTABLE = {
        "settings": ("key", "value"),
        "devices": ("id", "ip", "hostname", "name", "connector_pin", "connector_seen", "first_seen", "last_seen",
                    "events", "snmp_mode", "snmp_community", "snmp_host"),
        "alerts": ("id", "created", "last_seen", "detector", "severity", "title", "description", "entity", "src_ip",
                   "device", "count", "status", "details", "updated"),
        "channels": ("id", "type", "name", "enabled", "min_severity", "config", "last_ts", "last_ok", "last_error"),
        "snmp_data": ("device", "polled", "ok", "error", "last_ok", "data"),
        "sessions": ("token_hash", "expires"),
        "sites": ("id", "name", "token_hash", "managed", "created", "last_seen", "silent", "address", "version",
                  "reported_name", "instance", "summary"),
        "site_alerts": ("id", "site_id", "instance", "alert_id", "created", "last_seen", "received", "detector",
                        "severity", "title", "description", "entity", "src_ip", "device", "count", "details",
                        "status", "pending"),
        "suppressions": SUPPRESSION_COLUMNS,
        "audit_log": AUDIT_COLUMNS,
    }

    def import_table(self, table: str, rows: list[dict]) -> None:
        """Migration only: insert rows exactly as given, ids included, into an empty table."""
        raise NotImplementedError

    # --- settings: small JSON values by key ---------------------------------------------
    def get_setting(self, key: str, default=None):
        raise NotImplementedError

    def set_setting(self, key: str, value) -> None:
        raise NotImplementedError

    def settings_with_prefix(self, prefix: str) -> dict:
        """Every setting whose key starts with prefix: {key: value}."""
        raise NotImplementedError

    # --- notification outbox -------------------------------------------------------------
    def outbox_due(self, now: float, limit: int) -> list[dict]:
        """Notifications waiting to be sent whose time has come, oldest first:
        {id, created, channel_id, subject, body, attempts, payload}."""
        raise NotImplementedError

    def outbox_done(self, outbox_id: int, now: float, error: str | None) -> None:
        """Record a delivery attempt: sent if error is None; otherwise tried again later,
        and given up after OUTBOX_ATTEMPTS attempts."""
        raise NotImplementedError

    def outbox_pending(self) -> int:
        """Notifications not yet sent nor given up."""
        raise NotImplementedError

    # --- false positives: suppressions and their audit trail --------------------------------
    def false_positive(self, alert_id: int, when: float, justification: str, analyst: str, source: str) -> dict:
        """In one transaction: suppress the alert's detector and entity (or reuse the active
        suppression for them), mark the alert false_positive and append to the audit log.
        Returns the suppression row. Raises NotFound for an unknown alert."""
        raise NotImplementedError

    def suppression_remove(self, suppression_id: int, when: float, justification: str, analyst: str,
                           source: str) -> dict:
        """Deactivate a suppression and append to the audit log, in one transaction. Returns
        the suppression row. Raises NotFound if there is no such active suppression."""
        raise NotImplementedError

    def suppressions(self) -> list[dict]:
        """Every suppression, active and removed, newest first."""
        raise NotImplementedError

    def audit_log(self, limit: int, alert_id: int = 0) -> list[dict]:
        """The audit trail, newest first (detail is a JSON string). Never pruned or edited."""
        raise NotImplementedError

    def leadership(self, name: str) -> Leadership:
        """The lock that decides which of several processes named name is active."""
        raise NotImplementedError

    async def aget_setting(self, key: str, default=None):
        return await asyncio.to_thread(self.get_setting, key, default)

    async def aset_setting(self, key: str, value) -> None:
        await asyncio.to_thread(self.set_setting, key, value)

    def close(self) -> None:
        raise NotImplementedError

    # --- the pipeline's writes ----------------------------------------------------------
    def write_batch(self, batch: Batch) -> None:
        """Write one Batch atomically."""
        raise NotImplementedError

    def prune(self, now: float, retention_days: int, max_events: int, alert_days: int) -> int:
        """Remove what is past retention; returns the number of events removed."""
        raise NotImplementedError

    # --- events ---------------------------------------------------------------------------
    def search_events(self, since: float = 0, before: int = 0, limit: int = 200, timeout: float = 0, *,
                      device: str = "", event_type: str = "", action: str = "", ip: str = "",
                      port: int | None = None, text: str = "") -> list[dict]:
        """Newest-first events at or after `since`, with id below `before` if given. `ip`
        matches source or destination, `port` the destination port, `text` the message.
        Raises QueryTimeout past `timeout` seconds."""
        raise NotImplementedError

    events_stored = oldest_event_ts = _todo

    # --- per-minute counters ----------------------------------------------------------------
    def traffic_series(self, start: int, bucket: int) -> list[dict]:
        """All-device message and blocked counts per bucket: [{t, e, b}]."""
        raise NotImplementedError

    def traffic_totals(self, since: int) -> tuple[int, int]:
        """All-device (messages, blocked) since a minute."""
        raise NotImplementedError

    def ensure_stats_totals(self) -> None:
        """Fill in all-device counter rows for data from before they existed (once)."""
        raise NotImplementedError

    def port_series(self, start: int, bucket: int) -> list[dict]:
        """High-risk port counts per bucket: [{t, port, direction, a, b}]."""
        raise NotImplementedError

    def port_minutes_since(self, minute: int) -> list[dict]:
        """High-risk port counts per minute, oldest first: [{minute, port, direction, allowed, blocked}]."""
        raise NotImplementedError

    # --- alerts ---------------------------------------------------------------------------------
    alert_next_id = _todo

    def alerts_active_since(self, last_seen: float) -> list[dict]:
        """Unresolved alerts seen after a time: what the alert manager folds repeats into."""
        raise NotImplementedError

    def alerts_find(self, *, status: str = "", severity: str = "", text: str = "", limit: int = 200,
                    alert_id: int = 0) -> list[dict]:
        """Alerts newest first. status: open, ack, resolved, active (not resolved) or any;
        severity: a minimum."""
        raise NotImplementedError

    def alerts_recent(self, limit: int) -> list[dict]:
        raise NotImplementedError

    def alerts_unresolved_since(self, last_seen: float, limit: int) -> list[dict]:
        """{id, detector, severity, title, last_seen, src_ip, device, details}, newest first."""
        raise NotImplementedError

    def alert_counts_open(self) -> dict[str, int]:
        """Open alerts by severity."""
        raise NotImplementedError

    def alert_counts_open_by_device(self) -> dict[str, dict[str, int]]:
        raise NotImplementedError

    def alert_ids_open(self) -> list[int]:
        raise NotImplementedError

    def set_alert_status(self, ids: list[int], status: str, stamp: float) -> None:
        raise NotImplementedError

    def alert_changes_since(self, updated: float, alert_id: int, limit: int) -> list[dict]:
        """Alerts changed after (updated, id), in that order: what a site reports."""
        raise NotImplementedError

    # --- devices --------------------------------------------------------------------------------
    devices_all = _todo

    def update_device(self, device_id: str, name: str, connector_pin: str, snmp_mode: str,
                      snmp_community: str, snmp_host: str) -> None:
        raise NotImplementedError

    def forget_device(self, device_id: str) -> None:
        """Remove a device and its SNMP record; its events and alerts stay."""
        raise NotImplementedError

    # --- notification channels --------------------------------------------------------------------
    channels = channel = add_channel = update_channel = delete_channel = _todo

    def channel_result(self, channel_id: int, when: float, ok: bool, error: str | None) -> None:
        raise NotImplementedError

    # --- SNMP -------------------------------------------------------------------------------------
    snmp_records = _todo

    def save_snmp_record(self, device: str, polled: float, ok: bool, error: str, last_ok: float | None,
                         data: str | None) -> None:
        raise NotImplementedError

    # --- dashboard sessions ------------------------------------------------------------------
    def session_add(self, token_hash: str, expires: float) -> None:
        raise NotImplementedError

    def session_expires(self, token_hash: str) -> float | None:
        """When a session ends, or None if there is no such session."""
        raise NotImplementedError

    def session_delete(self, token_hash: str) -> None:
        raise NotImplementedError

    # --- central console: sites and their alerts -------------------------------------------------
    def sites_provision(self, entries: list[tuple[str, str]], now: float) -> None:
        """(name, token hash) pairs from configuration: created, or re-keyed if present."""
        raise NotImplementedError

    def site_create(self, name: str, token_hash: str, now: float) -> int:
        """Raises ValueError if the name is taken."""
        raise NotImplementedError

    def site_rotate(self, site_id: int, token_hash: str) -> bool:
        """False for an unknown site or one set in configuration."""
        raise NotImplementedError

    def site_delete(self, site_id: int) -> None:
        """Raises LookupError if unknown, ValueError if set in configuration."""
        raise NotImplementedError

    site = sites_all = site_alert_open_counts = _todo

    def site_report(self, token_hash: str, instance: str, meta: dict, alerts: list[dict],
                    now: float) -> tuple[int, str, list[dict], list[dict]] | None:
        """Store one site report atomically. Returns (site id, site name, alerts new here,
        statuses for the site to apply), or None for an unknown token."""
        raise NotImplementedError

    def site_alerts_find(self, *, site_id: int = 0, status: str = "", severity: str = "", text: str = "",
                         limit: int = 200, alert_id: int = 0) -> list[dict]:
        raise NotImplementedError

    def site_alerts_set_status(self, ids: list[int], status: str) -> int:
        raise NotImplementedError

    def sites_newly_silent(self, cutoff: float) -> list[dict]:
        """Sites last heard from before cutoff and not yet flagged; flags them."""
        raise NotImplementedError
