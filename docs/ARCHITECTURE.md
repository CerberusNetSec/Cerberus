# Architecture

Cerberus is one Python process with one asyncio event loop and one SQLite
file. This page says how a log line becomes an alert, where state lives, and
where to make common changes.

## The path of a message

```
device ──UDP/TCP 514──▶ receiver.py ──▶ queue ──▶ Engine
                                                    │
               parse   syslog_parser.py,  ◀─────────┤ bytes → Event
                       connectors.py                │
               record  device registry, counters,◀──┤ Event → storage buffer
                       storage buffer               │
               detect  detectors.py, security.py,◀──┤ Event → Candidates
                       riskports.py                 │
                                                    ▼
               alert   AlertManager + Correlation   (folds repeats into one alert)
                          │                    │
                    notifiers.py        Store (cerberus/storage.py), written once a second
                 (SMTP, Telegram,       as one Batch: events, alerts, counters, devices
                    Pushbullet)
```

1. **Receive.** `receiver.py` listens on UDP and TCP (octet-counted and
   newline framing) and hands each message to `Engine.submit`, which puts it on
   a bounded queue. A full queue drops the message and counts it.
2. **Parse.** `syslog_parser.py` reads the RFC 3164 / RFC 5424 / Cisco
   envelope. `connectors.py` then picks a connector (a YAML file in
   `connectors_builtin/` or the data volume) and applies its first matching
   rule, producing an `Event` (`models.py`) with normalised fields such as
   `event_type`, `action`, `src_ip`, `dst_port`.
3. **Record.** The engine updates the device registry and per-minute
   counters and buffers the event for storage.
4. **Detect.** Each detector declares the event types it reads
   (`Detector.event_types`); its `process(event, now, emit)` runs on those,
   and `tick(now, emit)` every ten seconds for time-based checks. Detectors
   keep bounded state and report by emitting a `Candidate`.
5. **Alert.** `AlertManager` turns a candidate into a new alert, or folds it
   into an open alert for the same `detector|entity` within the cooldown. The
   correlator (`security.Correlation`) sees every alert and raises its own when
   several point at one host.
6. **Notify.** `notifiers.py` formats the alert with its guidance from
   `playbooks.py` and delivers it to each channel at or above its severity,
   rate-limited per channel.
7. **Store.** Once a second the engine writes the buffered events, counters,
   device records and alert changes as one `Batch`.

`Engine.parse`, `record` and `detect` are separate methods and pass nothing
between them but the `Event`, and candidates go to the alert stage as data:
clustering can run the stages in different processes. A test runs the
reference traffic with every event and candidate passed through JSON between
stages and requires identical results.

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
| `storage.py` | The storage contract (`Store`, `Batch`): every operation a backend provides |
| `db.py` | The SQLite backend: connections, event segments, and the contract's SQL |
| `state.py` | JSON codec for detector state (no pickle) |
| `notifiers.py` | Channels and delivery |
| `snmp.py`, `snmp_poller.py`, `topology.py` | SNMP v2c client, polling, map building |
| `federation.py` | Site → central console reporting (`Forwarder`) and the console side (`Central`) |
| `web.py`, `static/` | JSON API and the single-page UI (no build step) |

## Storage

Everything is stored through the operations in `cerberus/storage.py`; no
other module contains SQL (a test enforces it), so another backend can replace
SQLite by implementing that contract. Today's backend keeps everything in
`cerberus.db` in the data directory (WAL mode, one writer connection, four
readers).

| Table | Holds |
|---|---|
| `events_NNNNNN` | Events, in segments of up to 250,000 rows or one day. Only the newest is written to; expiry drops the oldest table. `event_segments` lists them. |
| `alerts` | One row per alert, updated as it recurs |
| `stats_minute` | Messages and blocked connections per device per minute, plus an all-devices row (`device = '*'`) for charts |
| `port_minute` | Allowed and blocked connections per high-risk port, direction and minute |
| `devices` | Log sources and their per-device settings (including SNMP community strings) |
| `snmp_data` | Last SNMP poll result per device, as JSON |
| `channels` | Notification channels (including their credentials) |
| `settings` | Detector settings, ignore lists, SNMP settings, password hash, the detectors' saved working state (`engine_state`), the site's report cursor and instance id |
| `sessions` | Dashboard logins, as hashes of their tokens |
| `sites`, `site_alerts` | Central console only: registered sites (token hashes, last report, health summary) and the alerts they reported |

Detectors work in memory. Their working state (sliding windows, rate
baselines, learned admin sources, correlation, risk-port history, top blocked
sources) is encoded by `state.py` and saved every 5 minutes and at shutdown,
and loaded at start; after a real outage, device silence is measured from the
restart. A reference run stopped and restarted three times gives exactly the
same alerts as an uninterrupted one.

## Extending

**A new log format** needs no code: write a connector YAML (schema in the
README) and use the Connectors page to test a sample line.

**A new detector:**

1. Subclass `Detector` (`detectors.py`): set `id`, `name`, `description` and
   `params` (each becomes an editable setting), and implement `process` and/or
   `tick`. Use `self._get` for per-key state and `self._may_emit` to throttle.
   Declare `event_types` (what `process` reacts to) and `partition` (what its
   state is keyed by); list any extra state attributes in `_persist`, and mark
   helper classes kept in state with `@persistent`.
   `tests/test_partitioning.py` checks both declarations on real traffic.
2. Add it to `build_detectors()` or `build_security_detectors()`.
3. Add an entry under its `id` in `playbooks.PLAYBOOKS` (stage, technique,
   why, actions). `tests/test_security.py` checks every alert kind has one.
4. If it is keyed on a source or destination address, add its `id` to
   `_SOURCE_KEYED` / `_DEST_KEYED` in `engine.py` so the ignore lists apply.
5. Add a scenario to `tools/simulate.py` and a test that feeds it through the
   real engine. A new scenario changes the reference run: re-record
   `tests/golden/` (see below) and say so in the commit.

## Guard rails for refactoring

| Test | Holds the code to |
|---|---|
| `test_equivalence.py` | The same alerts, events, counters and devices as the 0.2.0 release, on two simulated hours of traffic (`tests/golden.py`); also restarted midway, and with every stage boundary passed through JSON |
| `test_api_contract.py` | The same answer from every HTTP endpoint, reads and writes, as recorded in `tests/golden/api.json` |
| `test_partitioning.py` | Each detector finding the same when its events are divided by its declared key, and when fed only its declared event types |
| `test_storage_contract.py` | No SQL outside the backend; every contract operation implemented |

A deliberate change in behaviour means re-recording a reference
(`python tests/golden.py --code <checkout> --out ...` from a release, or
`RECORD_API_CONTRACT=1`) and explaining why in the commit.

**A new notification channel:** add its fields to `CHANNEL_TYPES` and a sender
in `notifiers.py`; the UI form is generated from the field list.

## Federation

A site's `Forwarder` reads alerts whose `updated` time is past its cursor,
posts them with a health summary to the console, and advances the cursor only
when the console accepts the report, so delivery is at least once. The console
stores them under (site, the site database's random instance id, alert id), so
repeats are harmless and a site rebuilt from scratch cannot overwrite its old
alerts. A status set at the console is kept as `pending` and returned in each
reply until the site reports the alert back with that status. See
[deploy/README.md](../deploy/README.md) and [CLUSTERING.md](CLUSTERING.md).

## Limits by design

- One process: parsing and detection use one CPU core. See "Running at scale"
  in the README for measured rates.
- Syslog input is unauthenticated plain text; SNMP is v2c. Both belong on a
  management network.
- No clustering, replication or multi-user accounts; many sites are handled by
  federation, and clustering is planned in [CLUSTERING.md](CLUSTERING.md).
