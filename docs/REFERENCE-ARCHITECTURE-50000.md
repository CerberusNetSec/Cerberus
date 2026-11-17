# Reference architecture: 50,000 network devices

What it takes to run Cerberus for an estate of about 50,000 firewalls,
switches and access points. It builds on the
[5,000-device reference architecture](REFERENCE-ARCHITECTURE.md), which sizes
one scale-out cluster; read that first. This document adds what changes when
you need many such clusters: grouping them into regions that share Kafka,
PostgreSQL and ClickHouse, the central console, and running the whole fleet.

It is a design to start a pilot from. The parts have been measured, but
nothing has been run at this size
([what has and has not been tested](#what-has-and-has-not-been-tested)).

Larger estates: [100,000 devices](REFERENCE-ARCHITECTURE-100000.md) ·
[500,000 devices](REFERENCE-ARCHITECTURE-500000.md).

- [The short version](#the-short-version)
- [First, your message rate](#first-your-message-rate)
- [The building blocks](#the-building-blocks)
- [The design: 12 cells in 3 regions](#the-design-12-cells-in-3-regions)
- [Regions: shared Kafka, PostgreSQL and ClickHouse](#regions-shared-kafka-postgresql-and-clickhouse)
- [The console](#the-console)
- [Settings for each cell](#settings-for-each-cell)
- [Running the fleet](#running-the-fleet)
- [What has and has not been tested](#what-has-and-has-not-been-tested)

## The short version

- **Message rate decides the design, again.** 50,000 devices send from about
  15,000 messages a second, if firewalls log only blocks, threats and logins,
  to 500,000 and more if busy firewalls log every connection.
- **The unit of scale is the cell**: one scale-out cluster as in the
  5,000-device design, good for up to **10,000 messages a second and 20,000
  devices**. A cell does its own detection, has its own dashboard, and holds
  its own events.
- **Cells are grouped into regions** that share one Kafka cluster, one
  PostgreSQL cluster and a set of ClickHouse servers, each cell with its own
  topics and databases. That saves running a Kafka and a PostgreSQL per cell.
- **One central console** lists every cell's alerts, sends the notifications
  your security team needs, and alerts when a cell stops reporting.
- **For about 105,000 messages a second** (branch firewalls logging every
  connection): 12 cells in 3 regions, about **360 CPU cores and 1 TB of
  memory**, and 10 TB of event storage for 30 days with sampling (48 TB
  without).

## First, your message rate

Assume one device in ten is a firewall, as in the 5,000-device design:
5,000 firewalls and 45,000 switches and access points (about 5,000 messages a
second between them).

| What the firewalls log | Per firewall | Total | Cells |
|---|---|---|---|
| Blocked traffic, threats and logins only | about 2/s | about 15,000/s | 3 |
| Every connection, branch-office firewalls | about 20/s | about 105,000/s | 11, so 12 in 3 regions of 4 |
| Every connection, busy data-centre firewalls | 100/s and up | 500,000/s and up | 50 and up |

The number of cells is the larger of these two, rounded up:

- your message rate ÷ 10,000
- your device count ÷ 20,000

In the first row the device count decides: 15,000 messages a second fits in
two cells, but 50,000 devices need three. In the last row, before building 50
cells, reconsider what the firewalls log. Logging allowed connections at
internet edges, server networks and management networks, and only blocks
elsewhere, usually keeps most of the detection for a fraction of the volume.
[Measure your rate](REFERENCE-ARCHITECTURE.md#first-your-message-rate) before
you plan.

## The building blocks

| Block | What it is | Limit |
|---|---|---|
| **Cell** | One scale-out Cerberus cluster: collectors, detection workers, an active and a standby processor ([5,000-device design](REFERENCE-ARCHITECTURE.md#one-cluster-up-to-10000-messages-a-second)) | 10,000 messages a second (its one active processor), 20,000 devices |
| **Region** | The Kafka, PostgreSQL and ClickHouse that several cells share, usually in one data centre or cloud region, often one Kubernetes cluster | 4 to 8 cells: a size you are willing to lose together |
| **Console** | One Cerberus with `CERBERUS_CENTRAL=on`, to which every cell reports | Hundreds of cells (measured below) |

Why these limits:

- **10,000 messages a second per cell** is half the measured rate of one
  processor (21,000 events a second on one core). Collectors, workers and Kafka
  grow with a cell; the processor does not. See
  [What one core does](REFERENCE-ARCHITECTURE.md#what-one-core-does).
- **20,000 devices per cell** is as far as has been measured. Tracking more
  devices costs the processor little: with the same traffic from 20,000
  devices it handled 2% fewer messages a second than from 5,000. What grows is
  the SNMP sweep (below) and the size of the Devices and Topology pages.
- **Cells share nothing in detection.** A scan that touches two cells raises an
  alert in each, side by side in the console, not one correlated alert. Draw
  cell boundaries where traffic rarely crosses: a country, a campus, a group
  of branches, a data centre.

## The design: 12 cells in 3 regions

For 105,000 messages a second: about 4,200 devices and 9,000 messages a second
in each cell.

```
 region EU                       region Americas                 region APAC
 ┌─────────────────────────┐    ┌─────────────────────────┐    ┌─────────────────────────┐
 │ cell eu-1 … cell eu-4   │    │ cell am-1 … cell am-4   │    │ cell ap-1 … cell ap-4   │
 │  each: syslog address,  │    │                         │    │                         │
 │  collectors ×4,         │    │        the same         │    │        the same         │
 │  workers ×6,            │    │                         │    │                         │
 │  processors ×2,         │    │                         │    │                         │
 │  ClickHouse ×1          │    │                         │    │                         │
 │ ─────────────────────── │    │ ─────────────────────── │    │ ─────────────────────── │
 │ Kafka ×4: a topic set   │    │ Kafka ×4                │    │ Kafka ×4                │
 │   per cell              │    │                         │    │                         │
 │ PostgreSQL ×3: a        │    │ PostgreSQL ×3           │    │ PostgreSQL ×3           │
 │   database per cell     │    │                         │    │                         │
 └────────────┬────────────┘    └────────────┬────────────┘    └────────────┬────────────┘
              │ alerts and health, every 15 seconds, over HTTPS              │
              └──────────────────────────────┬────────────────────────────────┘
                                             ▼
                         central console (one instance, own PostgreSQL)
                         every alert in one list · notifications · SSO
```

| Component | Count | Each | Total |
|---|---|---|---|
| Collectors | 48 (4 per cell) | 1 CPU, 1 GiB, 30 GiB spool | 48 CPU, 48 GiB |
| Detection workers | 72 (6 per cell) | 1 CPU, 1 GiB | 72 CPU, 72 GiB |
| Processors | 24 (2 per cell, one active) | 2 CPU, 4 GiB | 48 CPU, 96 GiB |
| ClickHouse | 12 (1 per cell) | 8 CPU, 32 GiB, 0.8 to 4 TB | 96 CPU, 384 GiB |
| Kafka brokers | 12 (4 per region) | 4 CPU, 16 GiB, 1.5 TB | 48 CPU, 192 GiB |
| PostgreSQL | 9 (3 per region) | 4 CPU, 16 GiB, 200 GiB | 36 CPU, 144 GiB |
| Console | 1, and 3 small PostgreSQL | 2 CPU, 4 GiB; 2 CPU, 4 GiB, 20 GiB | 8 CPU, 16 GiB |
| **Total** | | | **about 356 CPU, 952 GiB** |

Storage, for 30 days:

| | With sampling (`CERBERUS_TRAFFIC_SAMPLE=10`) | Everything |
|---|---|---|
| ClickHouse, all cells | about 10 TB | about 48 TB |
| Kafka, all regions (6 hours, 3 copies) | 18 TB of volumes | 18 TB |
| Collector spools | 1.4 TB | 1.4 TB |

For the first row of the rate table (15,000 a second, three cells in one
region) the same arithmetic gives about 100 CPU and 260 GiB.

## Regions: shared Kafka, PostgreSQL and ClickHouse

A cell needs a Kafka topic set, a PostgreSQL database and a ClickHouse
database of its own, not servers of its own. Cells in a region share them:

| Shared service | How cells are kept apart | Size |
|---|---|---|
| Kafka (Strimzi, or any Kafka-compatible bus) | Each cell has its own topic prefix (`CERBERUS_KAFKA_TOPIC=eu-1.events` makes `eu-1.events`, `eu-1.source`, `eu-1.candidates` and the rest) and its own consumer groups (`CERBERUS_KAFKA_GROUP=eu-1`). With SASL, one user per cell, allowed only topics starting `eu-1.` and groups starting `eu-1` | One broker per cell, at least 3: 4 CPU, 16 GiB, 1.5 TB each |
| PostgreSQL (CloudNativePG) | One database per cell. The active-processor lock is per database | 3 instances, 4 CPU and 16 GiB each; 100 GiB plus 20 GiB per cell; `max_connections` of 80 per cell plus 50 |
| ClickHouse | One database per cell; each cell's database lives on one server | One server per cell (8 CPU, 32 GiB), or a larger server for two cells |

Every cell must have its **own consumer group**: cells sharing the default
group would join each other's rebalances, and only one of their processors
would be active.

Sizes come from the measurements:

- **Kafka.** One cell at 10,000 messages a second puts 46 MB/s on the bus
  before compression; the producers' LZ4 brings that to 10 MB/s (measured on
  simulated logs: 4.7 times smaller; plan for 15 MB/s with real ones). Six
  hours kept, three copies: about 1 TB of broker disk per cell.
- **PostgreSQL** holds alerts, devices, settings and accounts: tens of GiB per
  cell. Each Cerberus process keeps 6 connections, and a cell runs about 12
  processes.
- **ClickHouse**: 8 CPU and 32 GiB for a cell's 10,000 events a second, and the
  disk from the [5,000-device design](REFERENCE-ARCHITECTURE.md#one-cluster-up-to-10000-messages-a-second):
  about 130 GB a day when storing everything, a fifth of that with sampling.
  Cerberus's tables are not replicated: back the servers up, and a server's
  loss stops event search in its cells (detection and alerts carry on).

Create each cell's PostgreSQL database before installing it
(`CREATE DATABASE eu_1`, or a CloudNativePG `Database`). Cerberus creates its
ClickHouse database (given the grant to), its tables and its topics.

A region is also what fails together. Keep regions to a size you are
willing to lose at once, and put each on infrastructure of its own
(Kubernetes cluster, storage, network) so one region's trouble does not reach
another.

## The console

Every cell reports its new and changed alerts and a health summary to the
console every 15 seconds. Measured with a console on PostgreSQL 16 (on the
same desktop PC as the other measurements) taking reports from 500 simulated
cells:

| Reports | One thread | Four threads |
|---|---|---|
| Health only | 105 a second | 380 a second |
| With 5 alerts each | 59 a second (300 alerts) | 195 a second (980 alerts) |
| With 50 alerts each | 11 a second (580 alerts) | 38 a second (1,900 alerts) |

Twelve cells send under one report a second. With 2 million alerts stored,
the alert list opened in 7 ms, one cell's alerts in 66 ms, a text search in
89 ms and the Sites page in 230 ms. The console is not what limits this
design.

- **Where it runs.** A standalone Cerberus with `CERBERUS_CENTRAL=on`, on a
  PostgreSQL of its own (3 small instances) and a database on any ClickHouse
  server (it stores alerts, not events). It is one instance: if it stops,
  the cells keep detecting and notifying, and send what it missed when it is
  back. Kubernetes restarts it; back up its database.
- **Sites.** Each cell is a site at the console, with a token. Keep the tokens
  in a Secret (`federation.console.siteTokensSecret` in the Helm chart, a
  `site-name token` line per cell) so the list of cells is in version control
  rather than created by hand.
- **Notifications.** Every cell has its own notification channels, and so does
  the console. A workable split: each cell notifies the team responsible for
  its region; the console notifies the security operations team of high and
  critical alerts, and sends alerts to your SIEM or SOAR tool by webhook. The
  console names the cell in every notification.
- **Triage.** Analysts work from the console's alert list. Events are searched
  in the cell that holds them, on its own dashboard. Use the same single
  sign-on, with the same groups and roles, on the console and every cell.
- **Silence.** The console raises "Site stopped reporting" after 5 minutes
  without a report (`CERBERUS_SITE_SILENT_MINUTES`).

## Settings for each cell

Everything in the
[5,000-device settings](REFERENCE-ARCHITECTURE.md#settings-that-must-change)
applies to every cell. In addition:

| Setting | For each cell | Why |
|---|---|---|
| `CERBERUS_KAFKA_TOPIC` (Helm `kafka.topic`) | `<cell>.events`, e.g. `eu-1.events` | Its own topics on the shared bus |
| `CERBERUS_KAFKA_GROUP` (Helm `kafka.group`) | `<cell>`, e.g. `eu-1` | Its own consumer groups and its own active processor |
| `CERBERUS_POSTGRES_URL`, `CERBERUS_CLICKHOUSE_URL` | The cell's databases | |
| `CERBERUS_MAX_DEVICES` | The cell's devices and half again, at most 30,000 | |
| `CERBERUS_SITE_NAME` (Helm `federation.site.name`) | The cell's name | How the console shows it |
| `CERBERUS_CENTRAL_URL`, `CERBERUS_CENTRAL_TOKEN_FILE` (Helm `federation.site`) | The console, and the cell's token | Report to the console |
| `CERBERUS_MAX_TCP_CLIENTS` | Devices sending over TCP or TLS ÷ collectors, and a third again | One connection per device |

With the Helm chart, one release per cell, each with a short values file on
top of [`values-5000.yaml`](../deploy/helm/cerberus/values-5000.yaml):

```yaml
# cells/eu-1.yaml
kafka:
  bootstrap: kafka-eu-kafka-bootstrap.kafka.svc:9093
  topic: eu-1.events
  group: eu-1
  security: SASL_SSL
  caSecret: kafka-eu-cluster-ca-cert
  sasl: {username: eu-1, existingSecret: eu-1}  # Strimzi's KafkaUser Secret
storage:
  type: clustered
  existingSecret: eu-1-storage  # postgres-url and clickhouse-url of the cell's databases
federation:
  site:
    consoleUrl: https://cerberus-console.example.com
    name: eu-1
    existingSecret: eu-1-console-token  # a "token" key
publicUrl: https://eu-1.cerberus.example.com
config:
  CERBERUS_MAX_DEVICES: "7500"
```

```sh
helm install eu-1 deploy/helm/cerberus -n cerberus-eu-1 \
  -f deploy/helm/cerberus/values-5000.yaml -f cells/eu-1.yaml
```

The console is one more release, standalone with clustered storage:

```sh
helm install console deploy/helm/cerberus -n cerberus-console \
  --set storage.type=clustered --set storage.existingSecret=console-storage \
  --set federation.console.enabled=true --set federation.console.siteTokensSecret=console-sites \
  --set publicUrl=https://cerberus-console.example.com
```

## Running the fleet

- **Pointing devices at cells.** Each cell has its own syslog address (its
  load balancer). Assign devices to cells by site or region in whatever
  configures them at this size (FortiManager, Panorama, Cisco DNA Center or
  Catalyst Center, Ansible), and keep the assignment where everyone can see
  it. A device sending to the wrong cell is still detected, just in the wrong
  place.
- **SNMP.** Each cell's active processor polls its own devices. Restrict
  polling to the switches whose topology you want (Topology → SNMP polling →
  "Only poll devices in these networks"), poll every 30 to 60 minutes at a concurrency of 64, and expect a
  sweep of a cell's 4,000 devices to take a few minutes.
- **One release per cell, from version control.** Generate the cells' values
  files from one list (Argo CD's ApplicationSet or Flux do this), so a change
  of setting reaches every cell the same way.
- **Upgrades.** Upgrade one cell, watch it for a day, then the rest region by
  region.
- **Monitoring.** Scrape `/metrics` from every role in every cell (Prometheus
  per region, and a global view above it). The signals that matter are in
  [Running it](REFERENCE-ARCHITECTURE.md#running-it); add, per region, Kafka
  disk use and PostgreSQL connections, and at the console the Sites page.
- **Growth.** When a cell nears 10,000 messages a second or 20,000 devices,
  split it: start a new cell and move a group of devices to its syslog
  address. Alerts already raised stay in the old cell.

## What has and has not been tested

Measured for this document, in addition to
[the 5,000-device measurements](REFERENCE-ARCHITECTURE.md#what-has-and-has-not-been-tested):

- A processor with 20,000 devices: 2% fewer messages a second than with
  5,000, on the same traffic.
- Bus volume with every detection family on workers: 4.8 records and 4.6 KB
  per message before compression, 1.0 KB after LZ4.
- The console on PostgreSQL: reports a second from 500 simulated cells, and
  page times with 2 million alerts stored (above).
- The Helm chart's per-cell settings (`kafka.group`, `federation.site`,
  `federation.console`), rendered and linted.

Not tested:

- Anything at this size end to end: many cells, a region's shared Kafka,
  PostgreSQL and ClickHouse, a console with real cells reporting.
- Cells sharing a Kafka cluster with per-cell topics, groups and ACLs, and a
  PostgreSQL server with per-cell databases. Both are configuration of what
  exists, but neither has been run.
- More than 20,000 devices in one cell; an SNMP sweep of thousands of real
  devices; the Topology page with thousands of devices.
- Compression of real logs on the bus (the figure is from simulated ones).

Start with one region and a few cells, compare the measured rate, disk use and
consumer lag with this document, then add the rest.
