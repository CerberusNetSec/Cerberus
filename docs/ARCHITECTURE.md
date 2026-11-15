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
   `playbooks.py` for each channel at or above its severity, rate-limited per
   channel, and holds it for the next write.
7. **Store.** Once a second the engine writes the buffered events, counters,
   device records, alert changes and notifications as one `Batch`; the
   notifier then sends from the outbox table what has been stored.

`Engine.parse`, `record` and `detect` are separate methods and pass nothing
between them but the `Event`, and candidates go to the alert stage as data:
clustering can run the stages in different processes. A test runs the
reference traffic with every event and candidate passed through JSON between
stages and requires identical results.

## Modules

| File | Role |
|---|---|
| `__main__.py` | Starts everything in one event loop, in the configured mode (`all`, `collector`, `processor`, `detector`) |
| `config.py` | Environment variables |
| `receiver.py` | Syslog listeners |
| `syslog_parser.py` | Syslog envelope |
| `connectors.py`, `connectors_builtin/*.yaml` | Vendor formats → `Event` |
| `models.py` | `Event`, `Candidate`, address helpers |
| `detectors.py` | Detector base class; scan, flood, brute force, link flap, rate baseline, silence, new device |
| `security.py` | Exposure, risky egress, lateral movement, beaconing, credential attacks, admin access, watchlist, correlation |
| `riskports.py` | High-risk port counters, surge alert, findings for the High Risk Ports page; the port/protocol list (`parse_entries`, `format_entries`) |
| `playbooks.py` | Per-alert explanation, ATT&CK technique and steps |
| `engine.py` | Pipeline, device registry, alert folding, flush and prune loops |
| `storage.py` | The storage contract (`Store`, `Batch`): every operation a backend provides |
| `db.py` | The SQLite backend: connections, event segments, and the contract's SQL |
| `pg.py`, `ch.py`, `backends.py` | The PostgreSQL + ClickHouse backend, and choosing a backend |
| `state.py` | JSON codec for detector state (no pickle) |
| `notifiers.py` | Channels and delivery |
| `snmp.py`, `snmp_poller.py`, `topology.py` | SNMP v2c client, polling, map building |
| `federation.py` | Site → central console reporting (`Forwarder`) and the console side (`Central`) |
| `bus.py`, `collector.py` | Scale-out: publishing to and consuming from the message bus, the collector's spool, copy detection, heartbeats; the collector process |
| `worker.py` | Detection worker: one family of detectors on its share of the events, alert candidates back over the bus |
| `leader.py` | Active/standby processors: the standby server, taking and keeping the leadership lock |
| `secrets_scan.py` | Plaintext secrets: found and redacted in the parse stage (`parse_message`), alerted on by `PlaintextSecret` |
| `attack.py` | The MITRE ATT&CK matrix: tactics, where each detector's technique sits, alert counts |
| `mcp.py` | The MCP server for agents (JSON-RPC over `POST /mcp`); its tools are defined in `web.py` |
| `listeners.py` | Syslog listener settings (Settings → Syslog): saved ports over the environment; `SyslogReceiver.reconfigure` applies them live |
| `metrics.py` | Prometheus metrics for every role |
| `web.py`, `static/` | JSON API and the single-page UI (no build step) |

## Storage

Everything is stored through the operations in `cerberus/storage.py`; no
other module contains SQL or calls a storage method outside that contract
(tests enforce both). `backends.open_store()` picks the backend:

- **SQLite** (`db.py`, the default): everything in `cerberus.db` in the data
  directory (WAL mode, one writer connection, four readers). The tables are
  below.
- **PostgreSQL + ClickHouse** (`pg.py`, `ch.py`), when `CERBERUS_POSTGRES_URL`
  and `CERBERUS_CLICKHOUSE_URL` are set: the same relational tables in
  PostgreSQL; events (one MergeTree table, partitioned by hour, ids assigned
  in arrival order) and the per-minute counters (SummingMergeTree) in
  ClickHouse. `tests/test_backends.py` runs the reference traffic, the API
  contract, the federation tests and a migration against both and requires
  identical results.

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
README) and use Settings → Connectors to test a sample line.

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

## Scale-out ingest

In `collector` mode a process runs only the receive and parse stages: each
parsed `Event` is published to the bus topic (`CERBERUS_KAFKA_TOPIC`), keyed by
device so each device's events stay in order, with a unique id (the collector's
run id and a sequence number). In `processor` mode the engine has no receiver;
`Engine._consume` reads batches from the bus and runs record, detect and alert
on each event, dropping any whose id it has already seen (`bus.Deduplicator`).
`_flush` takes the bus position before swapping its buffers and commits it
only after the batch is stored, so a crash re-reads at most about a second of
events.

A collector that cannot reach the bus appends to its spool
(`spool/<name>/*.jsonl`, locked while it runs) and sends the spool, oldest
first, once the bus answers; new events queue behind the spool so order holds.
A spool folder whose lock nobody holds belongs to a collector that has gone,
and a running collector adopts it.

`tests/test_bus.py` runs the reference traffic through a collector, a real
broker and the processor (also with the processor restarted midway, and with
a share of events sent twice) and requires exactly what the single process
stores.

## Detection workers

Every detector declares a partition (`Detector.partition`): what its state is
keyed by. The detectors keyed by `source`, `target`, `pair`, `port` and
`account` form families (`detectors.WORKER_FAMILIES`) that can run elsewhere;
`device` detectors and correlation (`alerts`) stay in the processor.
`CERBERUS_DETECTION_WORKERS` lists the families that workers run. A collector
then also publishes each event to `<topic>.<family>` for every listed family
whose detectors read that event type (`family_event_types`), keyed by
`family_key`, with the same unique id. A worker (`CERBERUS_MODE=detector`,
`worker.DetectionWorker`) consumes its family's topic in a consumer group
shared with the family's other workers, so one key always reaches one worker;
it runs an `Engine` limited to that family (`Engine.families`), ticks on the
wall clock, and publishes each `Candidate` with the time it was found and a
unique id to `<topic>.candidates`. The processor's engine skips the offloaded
families and reads the candidates topic into `raise_alert`, dropping copies
and committing the candidates' position only after the resulting alerts are
stored.

Two pieces of cross-detector state follow the families: `hostile_allowed`
reads the alerts of source detectors, so a source worker feeds it its own
candidates; and the High Risk Ports page reads the port detector's memory, so a
port worker writes the per-minute port counters and publishes a summary under
the setting `riskports_view:<worker>`, which the dashboard merges.

`tests/test_workers.py` runs the reference traffic through a processor and
two workers per family (routed by key, events and candidates as JSON) and
requires the same alerts and identical storage; `tests/test_bus.py` does the
same through a real broker.

## False positives

`Store.false_positive` marks an alert, creates (or reuses) the active
suppression for its `(detector, entity)` and appends to `audit_log`, in one
transaction; `suppression_remove` deactivates one, also audited. Nothing
updates or deletes audit rows. `Engine.suppressed` maps `(detector, entity)`
to the suppression; `raise_alert` checks it first, so a matching candidate
creates no alert, no notification and feeds neither correlation nor
hostile-address tracking, and is counted (`Batch.suppression_hits`). Detection
workers reload suppressions with their settings, so source workers stop
marking a suppressed finding's address as hostile.

## High availability

Processors take a session advisory lock through `Store.leadership()`
(`pg.py`; SQLite has one process, which always leads). Until it holds the
lock a processor serves only `leader.standby_app`; then it starts as usual,
and `keep_leadership` exits the process if the lock's connection fails.

`Engine.snapshot()` includes the bus position (`EventSource.positions()`)
that the state matches; the processor saves it every `CHECKPOINT_SECONDS`.
On start, `Engine.prepare_resume()` gives each source the saved positions;
when a partition is assigned, `EventSource.assigned` seeks back to it and
records the committed offset as `replay_until`. Records before it go through
`Engine.take` as a replay: `detect` runs with `_replaying` set, so
`raise_alert` feeds only the alert-stream detectors and the high-risk port
counters are not written again; `commit` never moves a partition back while
it replays. A detection worker does the same from a time
(`EventSource.rewind`) whenever its assignment changes, after resetting to
empty state.

Notifications: `Notifier.notify` formats and rate-limits, `_enqueue` holds the
message, `Engine._flush` writes it as `Batch.notices` with the alerts (one
transaction), and `Notifier.run` sends due outbox rows (`outbox_due`,
`outbox_done`).

## Limits by design

- Detection of one family runs in one process per key; alerting and the
  device detectors run in the one active processor.
- Syslog input is plain text unless syslog over TLS is used; SNMP is v2c. Both
  belong on a management network.
- No multi-user accounts. Many sites are handled by federation.
