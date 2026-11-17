# Reference architecture: 5,000 network devices

What it takes to run Cerberus for an estate of about 5,000 firewalls, switches
and access points. It is a design to start a pilot from, sized from
measurements of each component; it has **not** been run end to end at this
size ([what has and has not been tested](#what-has-and-has-not-been-tested)).

Larger estates, built from clusters like this one:
[50,000 devices](REFERENCE-ARCHITECTURE-50000.md) ·
[100,000 devices](REFERENCE-ARCHITECTURE-100000.md) ·
[500,000 devices](REFERENCE-ARCHITECTURE-500000.md).

- [The short version](#the-short-version)
- [First, your message rate](#first-your-message-rate)
- [What one core does](#what-one-core-does)
- [One cluster: up to 10,000 messages a second](#one-cluster-up-to-10000-messages-a-second)
- [More than that: several clusters and a console](#more-than-that-several-clusters-and-a-console)
- [Settings that must change](#settings-that-must-change)
- [On Kubernetes](#on-kubernetes)
- [Running it](#running-it)
- [What has and has not been tested](#what-has-and-has-not-been-tested)

## The short version

- **Message rate decides the design, not device count.** 5,000 devices can
  mean 1,500 messages a second or 50,000, depending on what the firewalls log.
- **One cluster handles about 10,000 messages a second**, because every event
  passes through one active processor. Collectors, detection workers and the
  bus scale out; the processor does not.
- **Up to that rate:** one scale-out cluster of about 4 collectors, 3 Kafka
  brokers, 6 detection workers, 2 processors (one standby), PostgreSQL and
  ClickHouse.
- **Beyond it:** divide the estate (by region or data centre) into several
  such clusters, each reporting to one central console.
- **Raise four settings** that default to single-site values: the limit on log
  sources, the event cap, the collectors' spool and the bus retention.

## First, your message rate

Switches and access points send a few messages a minute. Firewalls that log
every connection send almost everything else. For 4,500 switches and access
points and 500 firewalls:

| What the firewalls log | Per firewall | Total |
|---|---|---|
| Blocked traffic, threats and logins only | about 2/s | about 1,500/s |
| Every connection, branch-office firewalls | about 20/s | about 10,500/s |
| Every connection, busy data-centre firewalls | 100/s and up | 50,000/s and up |

These are illustrations. Measure yours: a firewall's log rate is its session
rate, which its own dashboard shows; or point a sample of devices at a
standalone Cerberus and read **Messages / second**. Note that detecting
exposed services, lateral movement, beaconing and large transfers needs the
logs of *allowed* connections.

## What one core does

Measured with `tools/loadtest.py`'s generator: 5,000 simulated devices, 95% of
messages from firewalls, on one core of a desktop PC (Python 3.12), with
PostgreSQL 16 and ClickHouse 24.8 on the same machine.

| Component | What it does per message | One core handles |
|---|---|---|
| Collector | Parses, and encodes for the event topic and 3.8 family topics on average | 6,900 messages/s |
| Processor | Reads from the bus, records, runs per-device detection, writes to ClickHouse and PostgreSQL (41% of its time) | 21,000 events/s |
| Detection worker, `source` family | Scans, sweeps, floods, brute force, beaconing and the rest | 33,000 events/s |
| Detection worker, `target`, `pair` or `port` family | | about 70,000 events/s each |
| ClickHouse | Stores an event | 97 bytes (simulated logs; real ones compress less) |
| Bus | Carries an event to 4.8 topics | about 4.6 KB before compression, 1.0 KB after the producers' LZ4 (simulated logs) |

The sizes below plan for **half** of these figures, which leaves room for
bursts, slower cores and a node being away. Run the same measurement on your
hardware before you buy any.

## One cluster: up to 10,000 messages a second

```
 5,000 devices
      │ syslog: UDP, TCP or TLS
      ▼
 load balancer (layer 4, keeps each device's source address)
      │
      ▼
 collectors ×4 ──────── spool on disk while the bus is unreachable
      │ events, and a copy per detector family
      ▼
 Kafka ×3 ──────────────► detection workers ×6 (source ×2, target, pair, port, account)
      │                              │ alert candidates
      ▼                              ▼
 processor (active) ◄────────────────┘        processor (standby)
      │  records events, per-device detection, alerts, notifications,
      │  SNMP polling, dashboard, API, MCP
      ├──► ClickHouse   events and per-minute counters
      └──► PostgreSQL ×3   alerts, devices, settings, accounts, audit log
```

| Component | Count | Each | Why that many |
|---|---|---|---|
| Load balancer | 1 (or a pair) | | Kubernetes `LoadBalancer` with `externalTrafficPolicy: Local` (UDP and TCP), or HAProxy with PROXY protocol (TCP and TLS). It must keep source addresses, or set `CERBERUS_DEVICE_IDENTITY=hostname` |
| Collectors | 4 | 1 CPU, 1 GiB, 30 GiB spool volume | 10,000/s at 3,400 per collector is 3; one more so losing one changes nothing |
| Kafka (or Redpanda) | 3 brokers | 4 CPU, 8 GiB, 500 GiB | Replication 3. About 46 MB/s before compression and 10 MB/s after LZ4 (4.7 times smaller on simulated logs; plan for 15 MB/s with real ones). With 6 hours kept, about 320 GB per copy |
| Detection workers | 6 | 1 CPU, 1 GiB | `source` ×2 (the busiest family, and so one can be replaced without a gap), `target`, `pair`, `port` and `account` ×1 |
| Processors | 2 | 2 CPU, 4 GiB | One active, one standby that takes over in seconds. A second active one is not possible |
| PostgreSQL | 3 instances | 2 CPU, 4 GiB, 20 GiB | Small: alerts, devices and settings. Replicated, with automatic failover |
| ClickHouse | 1 server | 8 CPU, 32 GiB, 1 to 4 TB | See below |

**ClickHouse and how much to keep.** 10,000 events a second is 864 million a
day: about 85 GB a day as measured, so plan for 130 GB with real logs.

| Keeping | 30 days needs about |
|---|---|
| Everything | 2.5 to 4 TB |
| One allowed connection in ten (`CERBERUS_TRAFFIC_SAMPLE=10`); blocked traffic, threats, logins and device events in full | 0.5 to 0.8 TB |

Sampling changes what the Events page can show, not what is detected: the
detectors see every message. Cerberus's ClickHouse tables are not replicated,
so this is one server: back it up (volume snapshots or `clickhouse-backup`),
and expect event search to be unavailable while it is down. Alerts, which are
in PostgreSQL, are not affected by its loss.

**SNMP topology.** The active processor polls every device. At the highest
setting of 64 devices at a time, a sweep of 5,000 takes a few minutes (it
depends on how fast your devices answer), so poll every 15 to 30 minutes
rather than the default 5 (Topology → SNMP polling). The processor must be
able to reach the devices' management addresses.

## More than that: several clusters and a console

The active processor is the limit: at 21,000 events a second measured, plan
for 10,000. A 5,000-device estate above that rate is divided, usually the way
the network already is: by region, data centre or business unit.

```
 region A: ≤10,000/s            region B: ≤10,000/s            small sites
 collectors → bus → workers     collectors → bus → workers     one standalone
 → processor → stores           → processor → stores           Cerberus each
           │                              │                         │
           └──────────────┬───────────────┴─────────────────────────┘
                          ▼
              central console (CERBERUS_CENTRAL=on)
              every alert in one list · notifications · health of every cluster
```

- Each cluster is the design above, sized for its own rate, with its own
  processor, databases and bus.
- Each reports to the console as a site (`CERBERUS_SITE_NAME`,
  `CERBERUS_CENTRAL_URL`, a token); see [deploy/README.md](../deploy/README.md).
  The console holds alerts only, so it is small: one instance.
- Detection is per cluster. An attacker seen in two regions raises an alert in
  each, side by side in the console, rather than one correlated alert. Divide
  along lines that traffic rarely crosses.
- Events are searched in the cluster that holds them.

At 50,000 messages a second that is five or six clusters. If that is more
than you want to run, the alternative is to send Cerberus less: keep
connection logging on the firewall rules that matter (internet edge, server
VLANs, management networks) and log only blocks on the rest.

Many clusters can share Kafka, PostgreSQL and ClickHouse servers, each with
its own topics and databases. How, and the sizes for 50,000, 100,000 and
500,000 devices, are in the
[50,000-device reference architecture](REFERENCE-ARCHITECTURE-50000.md).

## Settings that must change

| Setting | Default | For this design | Why |
|---|---|---|---|
| `CERBERUS_MAX_DEVICES` (processor) | `5000` | `7500` | Log sources tracked; beyond it new sources are ignored. Leave room for growth and for devices that log from several addresses |
| `CERBERUS_MAX_EVENTS` (processor) | `2000000` | `26000000000` for 30 days of everything at 10,000/s; `5000000000` with sampling | The cap on stored events, whatever the retention |
| `CERBERUS_RETENTION_DAYS` (processor) | `7` | `30` | |
| `CERBERUS_TRAFFIC_SAMPLE` (processor) | `1` | `10` unless you have the disk | See ClickHouse above |
| `CERBERUS_SPOOL_MB` (collectors) | `1024` | `24576`, on a 30 GiB volume | A collector at 2,500 messages/s spools about 14 MB a second while the bus is unreachable: the default lasts 75 seconds, this lasts 30 minutes. [Storage thresholds](../README.md#scale-out-ingest) warn at 70% and 90% |
| `CERBERUS_KAFKA_REPLICATION` | `1` | `3` | |
| `CERBERUS_KAFKA_PARTITIONS` | `12` | `12` | The most workers one family can have; raise it before the first start if you expect more |
| Bus retention (`log.retention.hours`) | broker's | `6` | Must exceed the workers' replay (`CERBERUS_WORKER_REPLAY_MINUTES`, 60) plus the longest processor outage to ride out. Days of retention at this volume costs terabytes |
| `CERBERUS_DETECTION_WORKERS` (everywhere) | | `all` | Without workers the processor runs every detector and handles far less |
| `CERBERUS_MAX_TCP_CLIENTS` (collectors) | `1000` | `2000` | Devices sending over TCP or TLS hold a connection each; 5,000 over 4 collectors is 1,250 |
| `net.core.rmem_max` (collector hosts) | | `8388608` or more | UDP syslog is lost silently when the kernel's buffer fills in a burst |
| SNMP interval and concurrency | 5 min, 16 | 15 to 30 min, 64 | See SNMP above |

Sign-in for a team this size: [single sign-on with roles](../README.md#users-roles-and-single-sign-on),
and the built-in admin switched off.

## On Kubernetes

The Helm chart and the operator manifests are the starting point
([deploy/README.md](../deploy/README.md#kubernetes-with-helm-and-operators)).
[`values-5000.yaml`](../deploy/helm/cerberus/values-5000.yaml) holds the
sizes above for one cluster:

```sh
kubectl apply -k deploy/kubernetes/operators     # after editing the sizes, below
helm install cerberus deploy/helm/cerberus -n cerberus \
  -f deploy/helm/cerberus/values-operators.yaml -f deploy/helm/cerberus/values-5000.yaml \
  --set auth.password='choose-one' --set publicUrl=https://cerberus.example.com
```

Edit the operator manifests before applying them; they ship sized for a small
installation:

- `kafka.yaml`: volumes of `500Gi`, `log.retention.hours: 6`, and 4 CPU and
  8 GiB per node.
- `clickhouse.yaml`: the data volume (1 to 4 TB) and 8 CPU and 32 GiB.
- Spread collectors, Kafka nodes and PostgreSQL instances over nodes and zones
  (pod anti-affinity), and give collectors a `PodDisruptionBudget`.

## Running it

Watch these; all are on `/metrics` of the role named, and most have an alert
of their own in the dashboard:

| Watch | Where | It means |
|---|---|---|
| Consumer lag of the processor's group on the event topic | Kafka | The processor is not keeping up: the cluster is at its limit |
| `cerberus_bus_down`, `cerberus_spool_bytes` | Collectors | The bus is unreachable and collectors are spooling |
| Collector storage alerts | Dashboard | A spool or its volume is filling |
| Dropped messages | Dashboard, collectors' `/status` | A collector's queue overflowed: add collectors |
| "Collector stopped reporting", "Detection worker stopped reporting" | Alerts | A node is down |
| `cerberus_active` | Processors | Exactly one should be 1 |
| Searchable history | Dashboard | How far back events really go, against what you planned |

Roll out in steps: one region or a few hundred devices first, compare the
measured rate and disk use with this document, then add the rest.

## What has and has not been tested

Tested:

- Each component's throughput, as in [What one core does](#what-one-core-does),
  with 5,000 simulated devices.
- That the scale-out pipeline finds exactly the alerts one process finds, and
  stores exactly the same, including across a processor takeover and a
  replaced worker (CI, against real PostgreSQL, ClickHouse and a
  Kafka-compatible broker).
- Collector spooling through a bus outage with no loss; processor failover in
  seconds; the Helm chart on operator-run Kafka, PostgreSQL and ClickHouse in
  k3s. All at small scale.
- Federation of sites to a console.

Not tested:

- A whole cluster at 10,000 messages a second for days. The limit is derived
  from the per-core measurements at half their value, not observed.
- Kafka sizing with real logs: compression was measured on simulated ones.
- ClickHouse holding terabytes of Cerberus events, and searches at that size.
- An SNMP sweep of 5,000 real devices.
- A scale-out cluster reporting to a console (supported by the same code
  path as a site, but only standalone sites have been run against one).

Treat the numbers as a first estimate, and the pilot as the test.
