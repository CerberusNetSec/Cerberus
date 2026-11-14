# Architecture

Cerberus is one Python process with one asyncio event loop and one SQLite
file. This page says how a log line becomes an alert, where state lives, and
where to make common changes.

## The path of a message

```
device ──UDP/TCP 514──▶ receiver.py ──▶ queue ──▶ engine.py
                                                   │
                         syslog_parser.py  ◀───────┤ 1. split the syslog envelope
                         connectors.py     ◀───────┤ 2. vendor text → normalised Event
                         detectors.py, security.py,│ 3. every enabled detector sees the Event
                         riskports.py      ◀───────┤
                                                   ▼
                                    AlertManager (folds repeats into one alert)
                                       │                    │
                                 notifiers.py          db.py (once a second)
                              (SMTP, Telegram,       events, alerts, per-minute
                                 Pushbullet)          counters, device records
```

1. **Receive.** `receiver.py` listens on UDP and TCP (octet-counted and
   newline framing) and hands each message to `Engine.submit`, which puts it on
   a bounded queue. A full queue drops the message and counts it.
2. **Parse.** `syslog_parser.py` reads the RFC 3164 / RFC 5424 / Cisco
   envelope. `connectors.py` then picks a connector (a YAML file in
   `connectors_builtin/` or the data volume) and applies its first matching
   rule, producing an `Event` (`models.py`) with normalised fields such as
   `event_type`, `action`, `src_ip`, `dst_port`.
3. **Detect.** Each detector's `process(event, now, emit)` runs on every
   event; `tick(now, emit)` runs every ten seconds for time-based checks.
   Detectors keep bounded in-memory state and report by emitting a `Candidate`.
4. **Alert.** `AlertManager` turns a candidate into a new alert, or folds it
   into an open alert for the same `detector|entity` within the cooldown. The
   correlator (`security.Correlation`) sees every alert and raises its own when
   several point at one host.
5. **Notify.** `notifiers.py` formats the alert with its guidance from
   `playbooks.py` and delivers it to each channel at or above its severity,
   rate-limited per channel.
6. **Store.** Once a second the engine writes the buffered events, counters,
   device records and alert changes in one transaction.

## Modules

| File | Role |
|---|---|
| `__main__.py` | Starts everything in one event loop |
| `config.py` | Environment variables |
| `receiver.py` | Syslog listeners |
| `syslog_parser.py` | Syslog envelope |
| `connectors.py`, `connectors_builtin/*.yaml` | Vendor formats → `Event` |
| `models.py` | `Event`, `Candidate`, address helpers |
| `detectors.py` | Detector base class; scan, flood, brute force, link flap, rate baseline, silence, new device |
| `security.py` | Exposure, risky egress, lateral movement, beaconing, credential attacks, admin access, watchlist, correlation |
| `riskports.py` | High-risk port counters, surge alert, findings for the Risk ports page |
| `playbooks.py` | Per-alert explanation, ATT&CK technique and steps |
| `engine.py` | Pipeline, device registry, alert folding, flush and prune loops |
| `db.py` | SQLite access and event segments |
| `notifiers.py` | Channels and delivery |
| `snmp.py`, `snmp_poller.py`, `topology.py` | SNMP v2c client, polling, map building |
| `web.py`, `static/` | JSON API and the single-page UI (no build step) |

## Storage

All state is in `cerberus.db` in the data directory (WAL mode, one writer
connection, four readers).

| Table | Holds |
|---|---|
| `events_NNNNNN` | Events, in segments of up to 250,000 rows or one day. Only the newest is written to; expiry drops the oldest table. `event_segments` lists them. |
| `alerts` | One row per alert, updated as it recurs |
| `stats_minute` | Messages and blocked connections per device per minute, plus an all-devices row (`device = '*'`) for charts |
| `port_minute` | Allowed and blocked connections per high-risk port, direction and minute |
| `devices` | Log sources and their per-device settings (including SNMP community strings) |
| `snmp_data` | Last SNMP poll result per device, as JSON |
| `channels` | Notification channels (including their credentials) |
| `settings` | Detector settings, ignore lists, SNMP settings, password hash, learned admin sources |

Held in memory only, and rebuilt after a restart: detector sliding windows, the
per-device rate baselines (30 minutes to warm up), top blocked sources and
ports, and the Risk ports page's busiest sources and "new" markers.

## Extending

**A new log format** needs no code: write a connector YAML (schema in the
README) and use the Connectors page to test a sample line.

**A new detector:**

1. Subclass `Detector` (`detectors.py`): set `id`, `name`, `description` and
   `params` (each becomes an editable setting), and implement `process` and/or
   `tick`. Use `self._get` for per-key state and `self._may_emit` to throttle.
2. Add it to `build_detectors()` or `build_security_detectors()`.
3. Add an entry under its `id` in `playbooks.PLAYBOOKS` (stage, technique,
   why, actions). `tests/test_security.py` checks every alert kind has one.
4. If it is keyed on a source or destination address, add its `id` to
   `_SOURCE_KEYED` / `_DEST_KEYED` in `engine.py` so the ignore lists apply.
5. Add a scenario to `tools/simulate.py` and a test that feeds it through the
   real engine.

**A new notification channel:** add its fields to `CHANNEL_TYPES` and a sender
in `notifiers.py`; the UI form is generated from the field list.

## Limits by design

- One process: parsing and detection use one CPU core. See "Running at scale"
  in the README for measured rates.
- Syslog input is unauthenticated plain text; SNMP is v2c. Both belong on a
  management network.
- No clustering, replication or multi-user accounts.
