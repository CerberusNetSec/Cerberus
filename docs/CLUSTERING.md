# Scaling Cerberus to thousands of log sources

Status: **stage 1 (federation) in 0.2.0; stage 2 phase 1 (seams) in 0.3.0, phase 2 (shared storage) in 0.4.0, phase 3 (scale-out ingest) in 0.5.0, phase 4 (sharded detection) in 0.6.0, phase 5 (availability) in 0.7.0.**

What to deploy today for an estate of this size, with measured sizes, is in
[REFERENCE-ARCHITECTURE.md](REFERENCE-ARCHITECTURE.md), and for 50,000,
100,000 and 500,000 devices in
[REFERENCE-ARCHITECTURE-50000.md](REFERENCE-ARCHITECTURE-50000.md) and the
two after it. In short: one cluster
handles about 10,000 messages a second, limited by its one active processor;
the 100,000 a second below is reached with several clusters under a console,
not with one.

## Goal

Serve enterprises with thousands of log sources:

- 5,000 log sources, 100,000 messages/s sustained, 300,000/s in bursts
- 30 days of searchable events
- no single point of failure; losing one node loses no alerts

A single Cerberus handles a few hundred devices: one process, one SQLite file,
with parsing and detection on one CPU core (see "Running at scale" in the
README).

## Decisions

| Question | Decision |
|---|---|
| Targets | As above |
| First step | Federation: one Cerberus per site, reporting alerts to a central console |
| Message bus (clustering) | Kafka-compatible (Apache Kafka or Redpanda): key-partitioned consumer groups are what sharded detection needs |
| Event store (clustering) | ClickHouse: columnar compression well below today's ~850 bytes per event, and these ingest rates |
| Reference deployments | Standalone, Docker Compose, Docker Swarm and Kubernetes (Kustomize layers), one image published to GHCR |
| Licence | Apache 2.0 |

## Stage 1: federation (released in 0.2.0)

Each site runs an unchanged Cerberus against its own devices. With
`CERBERUS_CENTRAL_URL` set, it reports new and changed alerts plus a health
summary to a console every 15 seconds; the console (`CERBERUS_CENTRAL=on`)
lists every site's alerts, notifies, hands acknowledgements back, and alerts
when a site goes silent. See [deploy/README.md](../deploy/README.md).

What it gives: thousands of devices in total, spread over sites of a few
hundred each; sites that keep working through WAN or console outages; one
place to triage.

What it does not give, and stage 2 does:

- **No correlation across sites.** A scan that touches five sites is five
  alerts, and "compromised host" correlation only sees one site's alerts.
- **One site is still one process.** A single location with more traffic than
  one core parses must be split into several sites by hand.
- **The console is a single instance** (one SQLite writer). It only stores
  alerts and summaries, so its load is small, but it has no failover.
- **Events stay at the sites.** There is no search across all sites' events.

## Stage 2: clustering

The same image, with `CERBERUS_MODE=all|collector|detector|alerter|web|poller`;
`all` stays today's single-node behaviour on SQLite.

| Tier | Role | Scales by |
|---|---|---|
| Load balancer | Spreads syslog across collectors, a device always to the same collector, source address preserved | — |
| Collectors | Receive, parse and normalise (about 60% of today's CPU time); stateless | Nodes |
| Kafka | Durable, partitioned stream of normalised events | Partitions |
| Detection workers | Each detector consumes a stream keyed by what it counts: source, destination, account or device | Partitions per stream |
| Alert service | Folds candidates into alerts, correlates, notifies | Active/standby |
| PostgreSQL | Alerts, devices, settings, secrets | Its own replication |
| ClickHouse | Events and per-minute counters | Its own clustering |
| Web/API | Stateless replicas behind an HTTP load balancer | Nodes |
| SNMP pollers | Devices assigned by lease; placeable per site | Nodes |

Federation stays useful on top: a clustered region can report to the same
console as small sites.

### Phases

Estimates assume one experienced engineer and are rough.

1. **Seams in the single node. Done.** No change in behaviour, proved by
   identical results to 0.2.0 on a reference run (`tests/test_equivalence.py`)
   and identical API answers (`tests/test_api_contract.py`).
   - Storage behind a contract (`cerberus/storage.py`); no SQL outside the
     SQLite backend.
   - The engine split into parse, record, detect and alert stages that share
     nothing but serialisable events and candidates.
   - Each detector declares the event types it reads and its partition key,
     checked by dividing the reference traffic four ways. Every event-driven
     detector divides correctly except `credential_attacks`, which keys on
     source and on account and must be split in two (phase 4).
   - Detector state snapshots and restores through a JSON codec, and survives
     restarts.
   - Dashboard sessions stored, not held in memory.
2. **Shared storage. Done.** PostgreSQL for alerts, devices, settings,
   channels, sessions and console sites; ClickHouse for events and counters
   (`pg.py`, `ch.py`), chosen by setting `CERBERUS_POSTGRES_URL` and
   `CERBERUS_CLICKHOUSE_URL`. `tools/migrate.py` moves a SQLite installation
   across. Proved by `tests/test_backends.py` against real servers in CI: the
   reference traffic stores exactly what SQLite stores (also across
   restarts), the API contract answers identically, federation works with
   console and sites on their own databases, and a migrated database reads
   back identically. Reference deployments: `compose/clustered-storage.yml`
   and the Kubernetes `components/clustered-storage`.
   - Moved to phase 4: top blocked sources, and the Risk ports page's busiest
     talkers and "new source" markers, are still counted in memory. They only
     need to become queries once detection runs on several workers, and
     phase 4 is where that happens.
   - Event ids are assigned by the one Cerberus process writing; several
     collectors writing at once (phase 3) need ids that cannot collide.
3. **Scale-out ingest. Done.** `CERBERUS_MODE=collector` and `processor`
   (`collector.py`, `bus.py`); a Kafka-compatible bus; collectors spool to
   their own locked folder on disk while the bus is unreachable, and adopt the
   spools of collectors that have gone; every event carries a unique id and
   the processor ignores copies; the processor commits its bus position only
   after storing; collector heartbeats and a "collector stopped reporting"
   alert; syslog over TLS (RFC 5425) with optional device certificates; PROXY
   protocol v1/v2 from trusted load balancers. Reference deployments:
   `compose/scale-out.yml` (with HAProxy) and the Kubernetes `collector` and
   `processor` layers. Proved by `tests/test_bus.py` against a real broker in
   CI (the reference traffic through collector, bus and processor stores
   exactly what one process stores, also with the processor restarted midway
   and with events sent twice), and by live runs on Compose (a bus outage:
   every event stored exactly once) and k3s.
   - Event ids are still assigned by the one process writing events (the
     processor), so several writers are not needed yet; they become necessary
     only if storage writing is divided in phase 4.
   - The processor's copy detection is in memory: a processor restart can
     store up to about a second of events twice (at least once).
4. **Sharded detection. Done.** Every detector keys on one thing:
   `credential_attacks` became `password_spray` (source) and
   `distributed_guessing` (account), and correlation gave `hostile_allowed`
   (source) a detector of its own. Detectors form families by key (source,
   target, pair, port, account; the device family and correlation stay with
   the processor). `CERBERUS_DETECTION_WORKERS` names the families that
   detection workers (`CERBERUS_MODE=detector`, `worker.py`) run: collectors
   publish each event to every family topic whose detectors read its type,
   keyed by the family's key; a family's workers share its topic as a
   consumer group; they send alert candidates, with the time found and a
   unique id, to a candidates topic that the processor folds into alerts
   (ignoring copies, committing only after storing). Source workers mark
   hostile addresses from their own alerts, as one process does. The port
   worker writes the high-risk port counters and publishes a summary of what
   it holds for the Risk ports page. Workers reload detector settings from
   storage every 30 seconds and send heartbeats. Reference deployments: the
   `detector-*` services in `compose/scale-out.yml` and the Kubernetes
   `detector` layer. Proved by `tests/test_workers.py` (the reference traffic
   through a processor and two workers per family, events and candidates as
   JSON: the same alerts, and identical storage) and `tests/test_bus.py`
   (the same through a real broker), and a live Compose run with a worker
   stopped midway (its keys moved to the other worker, and the processor
   raised "Detection worker stopped reporting").
   - Alerting stays in the one processor, so alert upserts and notifications
     need no coordination yet; idempotent upserts and a notification outbox
     move to phase 5 with active/standby alerting.
   - Worker state is in memory: a replaced worker's keys start their windows
     again (phase 5 rebuilds them by replaying the window from the bus).
   - Busiest talkers and "new source" markers come from the port workers'
     summaries rather than ClickHouse queries; top blocked sources are still
     counted by the processor, which sees every event.
   - Bus traffic is multiplied by the number of families reading an event
     (about four times for firewall traffic with every family offloaded).
5. **Availability and operations. Done.**
   - **Active/standby processors** (`leader.py`): a session advisory lock in
     PostgreSQL; standbys answer 503 at `/readyz` and take over when the lock
     is freed (at once if the leader exits or crashes, within about 25 seconds
     by TCP keepalive if its host vanishes). A leader that cannot confirm its
     lock exits without writing more. SNMP polling runs on the active
     processor only, so no separate poller leases were needed.
   - **Exact takeover:** the detector state, learned baselines included, is
     saved every minute with the bus position it matches; a new leader seeks
     back to it and replays up to the committed position through detection
     only (no storage, no alerts, no notifications; the correlator and
     hostile-address tracking still learn from replayed candidates). Alert
     writes stay with one writer, so no idempotent upserts were needed.
   - **Notification outbox:** notifications are written in the same
     transaction as their alerts and sent from the table, with retries.
   - **Detection workers rebuild their windows** by replaying the last
     `CERBERUS_WORKER_REPLAY_MINUTES` of their partitions whenever their
     assignment changes.
   - **Prometheus metrics** on every role.
   - Reference deployments: two processors behind HAProxy in
     `compose/scale-out.yml`, two replicas with readiness on `/readyz` in the
     Kubernetes `processor` layer.
   - Proved by `tests/test_bus.py` (a processor that dies after its
     checkpoint, having stored more since and holding more unstored, and a
     successor: exactly what one uninterrupted process stores; a worker
     replaced midway: together exactly the alerts one worker raises),
     `tests/test_leader.py`, `tests/test_outbox.py`, and live on Compose (the
     active processor killed twice: dashboard back in 8 seconds, replay of
     the events since the checkpoint, every event stored once).
   - Added in 0.12.0: a Helm chart (`deploy/helm/cerberus`, standalone or
     scaled out), operator-run Kafka (Strimzi), PostgreSQL (CloudNativePG)
     and ClickHouse (Altinity) in `deploy/kubernetes/operators`, and SASL
     authentication to the bus (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512). Tested
     together on k3s; the Kustomize layers remain for those who prefer them.
6. **Enterprise features.** Done in 0.12.0: local accounts and OpenID Connect
   single sign-on with groups mapped to viewer, analyst and admin roles; an
   audit log of every sign-in and change, with secrets masked. Not planned:
   tenancy (run one Cerberus per tenant, with a console if needed).

### How it will be proven

- **Equivalence:** the same simulated corpus through a single node and through
  a multi-shard cluster must produce the identical set of alerts. This gates
  phase 4.
- **Failure:** kill a collector, a detection worker and the alert leader mid
  run; no alert lost or duplicated.
- **Load:** `tools/loadtest.py` extended to drive the cluster at the target rates.

### Main risks

- **Cross-shard volume.** An event published to several keyed streams
  multiplies Kafka traffic; collectors must pre-filter by what each detector
  declares it needs.
- **UDP load balancing.** Devices cannot add a PROXY header, so the balancer
  has to keep source addresses (direct server return or equivalent). Docker
  Desktop already drops external UDP; TCP syslog is the safe default.
- **Branch drift.** Land phase 1 on `main` and merge each later phase behind
  the mode switch, rather than keeping a long-lived branch.
