# Scaling Cerberus to thousands of log sources

Status: **stage 1 (federation) released in 0.2.0; stage 2 phase 1 (seams) done.**

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
2. **Shared storage (3–4 weeks).** PostgreSQL and ClickHouse backends and a
   migration tool from SQLite. Top talkers and "new source" figures become
   queries rather than in-memory counters.
3. **Scale-out ingest (2–3 weeks).** Collector role, publishing to Kafka, TLS
   syslog, spooling to disk when Kafka is unreachable, load-balancer
   reference configurations.
4. **Sharded detection and alerting (4–6 weeks).** Keyed streams, the
   detection worker role, idempotent alert upserts, correlation on the alert
   stream, a notification outbox so each alert is sent exactly once.
5. **Availability and operations (3–4 weeks).** State rebuilt on failover by
   replaying a detector's window from Kafka, snapshots for learned baselines,
   leader election, poller leases, Prometheus metrics, and the reference
   deployments extended (Compose and Swarm with Kafka, PostgreSQL and
   ClickHouse; Kubernetes with operators for them, and a Helm chart).
6. **Enterprise features (open-ended).** Single sign-on, roles, audit log,
   optionally tenancy.

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
