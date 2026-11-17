# Reference architecture: 100,000 network devices

What it takes to run Cerberus for an estate of about 100,000 firewalls,
switches and access points. It uses the building blocks of the
[50,000-device reference architecture](REFERENCE-ARCHITECTURE-50000.md)
(cells, regions that share Kafka, PostgreSQL and ClickHouse, and a central
console), and the cell itself is the cluster of the
[5,000-device design](REFERENCE-ARCHITECTURE.md). Read those first; this
document sizes the design for twice the estate and covers what changes at
this size.

It is a design to start a pilot from. The parts have been measured, but
nothing has been run at this size
([what has and has not been tested](#what-has-and-has-not-been-tested)).

- [The short version](#the-short-version)
- [First, your message rate](#first-your-message-rate)
- [The design: 24 cells in 4 regions](#the-design-24-cells-in-4-regions)
- [If firewalls log only blocks, threats and logins](#if-firewalls-log-only-blocks-threats-and-logins)
- [What changes at this size](#what-changes-at-this-size)
- [What has and has not been tested](#what-has-and-has-not-been-tested)

## The short version

- **Between 30,000 and 1,000,000 messages a second**, depending on what the
  firewalls log. The design follows from that number.
- **A cell** (one scale-out cluster) handles up to 10,000 messages a second
  and 20,000 devices; **a region** shares one Kafka, one PostgreSQL and a set of
  ClickHouse servers among 4 to 8 cells; **one console** sees every cell's
  alerts.
- **For about 210,000 messages a second** (branch firewalls logging every
  connection): 24 cells in 4 regions of 6, about **680 CPU cores and 1.8 TB of
  memory**, and 19 TB of event storage for 30 days with sampling (96 TB
  without).
- **If firewalls log only blocks, threats and logins** (about 30,000 a second),
  five cells in one region are enough: about 150 cores.
- **Most of the work at this size is running the fleet**: assigning devices to
  cells, one Helm release per cell from version control, upgrades and
  monitoring across about 350 pods.

## First, your message rate

One device in ten a firewall: 10,000 firewalls and 90,000 switches and access
points (about 10,000 messages a second between them).

| What the firewalls log | Per firewall | Total | Cells |
|---|---|---|---|
| Blocked traffic, threats and logins only | about 2/s | about 30,000/s | 5 (the device count decides) |
| Every connection, branch-office firewalls | about 20/s | about 210,000/s | 21, so 24 in 4 regions of 6 |
| Every connection, busy data-centre firewalls | 100/s and up | 1,000,000/s and up | 100 and up |

Cells: the larger of your message rate ÷ 10,000 and your device count ÷
20,000, rounded up. A million messages a second is a hundred cells; log
allowed connections where they matter (internet edges, server and management
networks) and only blocks elsewhere before going there.
[Measure your rate](REFERENCE-ARCHITECTURE.md#first-your-message-rate) first.

## The design: 24 cells in 4 regions

About 4,200 devices and 8,750 messages a second in each cell, with room in
every cell to grow by about a seventh.

```
 region 1            region 2            region 3            region 4
 cells 1-1 … 1-6     cells 2-1 … 2-6     cells 3-1 … 3-6     cells 4-1 … 4-6
 Kafka ×6            Kafka ×6            Kafka ×6            Kafka ×6
 PostgreSQL ×3       PostgreSQL ×3       PostgreSQL ×3       PostgreSQL ×3
 ClickHouse ×6       ClickHouse ×6       ClickHouse ×6       ClickHouse ×6
      │                   │                   │                   │
      └───────────────────┴─────────┬─────────┴───────────────────┘
                                    ▼  alerts and health every 15 s
                       central console (one instance, own PostgreSQL)
```

Each cell: collectors ×4, detection workers ×6, processors ×2 (one active),
its own syslog address, and a ClickHouse server, as in the
[5,000-device design](REFERENCE-ARCHITECTURE.md#one-cluster-up-to-10000-messages-a-second).

| Component | Count | Each | Total |
|---|---|---|---|
| Collectors | 96 (4 per cell) | 1 CPU, 1 GiB, 30 GiB spool | 96 CPU, 96 GiB |
| Detection workers | 144 (6 per cell) | 1 CPU, 1 GiB | 144 CPU, 144 GiB |
| Processors | 48 (2 per cell, one active) | 2 CPU, 4 GiB | 96 CPU, 192 GiB |
| ClickHouse | 24 (1 per cell) | 8 CPU, 32 GiB, 0.8 to 4 TB | 192 CPU, 768 GiB |
| Kafka brokers | 24 (6 per region) | 4 CPU, 16 GiB, 1.5 TB | 96 CPU, 384 GiB |
| PostgreSQL | 12 (3 per region) | 4 CPU, 16 GiB, 250 GiB; `max_connections` 550 | 48 CPU, 192 GiB |
| Console | 1, and 3 small PostgreSQL | 2 CPU, 4 GiB; 2 CPU, 4 GiB, 20 GiB | 8 CPU, 16 GiB |
| **Total** | | | **about 680 CPU, 1,790 GiB** |

Storage, for 30 days:

| | With sampling (`CERBERUS_TRAFFIC_SAMPLE=10`) | Everything |
|---|---|---|
| ClickHouse, all cells | about 19 TB | about 96 TB |
| Kafka, all regions (6 hours, 3 copies) | 36 TB of volumes | 36 TB |
| Collector spools | 2.9 TB | 2.9 TB |

How the regions share Kafka, PostgreSQL and ClickHouse, the console, and each
cell's settings and Helm values are in the 50,000-device document:
[regions](REFERENCE-ARCHITECTURE-50000.md#regions-shared-kafka-postgresql-and-clickhouse) ·
[console](REFERENCE-ARCHITECTURE-50000.md#the-console) ·
[settings for each cell](REFERENCE-ARCHITECTURE-50000.md#settings-for-each-cell).

## If firewalls log only blocks, threats and logins

About 30,000 messages a second. The device count decides: five cells of
20,000 devices and about 6,000 messages a second each, in one region.

| Component | Count | Each |
|---|---|---|
| Collectors | 20 (4 per cell) | 1 CPU, 1 GiB, 30 GiB spool |
| Detection workers | 30 (6 per cell) | 1 CPU, 1 GiB |
| Processors | 10 (2 per cell) | 2 CPU, 4 GiB |
| ClickHouse | 5 | 8 CPU, 32 GiB, 1.5 to 2.5 TB for 30 days (blocked traffic is never sampled) |
| Kafka brokers | 5 | 4 CPU, 16 GiB, 1.5 TB |
| PostgreSQL | 3 | 4 CPU, 16 GiB, 200 GiB |
| Console | 1, and 3 small PostgreSQL | as above |
| **Total** | | **about 150 CPU, 390 GiB** |

At 20,000 devices a cell, set `CERBERUS_MAX_DEVICES` to `30000` and, if
devices send over TCP or TLS, `CERBERUS_MAX_TCP_CLIENTS` to `7000` (20,000
connections over 4 collectors, and a third again). Lateral movement, beaconing,
large transfers and exposed services are not detected without logs of allowed
connections.

## What changes at this size

- **The console sees more than people can read.** 24 cells send under two
  reports a second; the console measured 105 a second on one thread, and its
  pages stayed fast with 2 million alerts stored
  ([the console](REFERENCE-ARCHITECTURE-50000.md#the-console)). The limit is
  the people. Tune detectors per cell before going live (Settings →
  Detection, and marking false positives), have the console notify only high and
  critical alerts, and send the rest to your SIEM or SOAR tool by webhook. The
  console holds alerts for 90 days (`CERBERUS_ALERT_RETENTION_DAYS`).
- **One console, not a hierarchy.** Cells report to one console; a console
  cannot pass its sites' alerts on to another console. Regional teams work on
  their cells' dashboards, the security operations team on the console.
- **Syslog over the WAN.** Cells usually sit in a few data centres, so most
  devices send across the WAN. At a few hundred bytes a message, a cell's
  traffic is tens of Mbit/s. Use TCP or TLS (RFC 5425) rather than UDP, which
  loses messages silently on a congested link, and have devices send to the
  cell in their own region.
- **Pointing 100,000 devices.** Assign devices to cells in the tools that
  configure them (FortiManager, Panorama, Catalyst Center, Ansible), from one
  table of site → cell, and check each cell's Devices page against it. Keep
  every cell under 20,000 devices and 10,000 messages a second; split a cell
  that grows past either.
- **The fleet.** 24 Helm releases, about 290 Cerberus pods plus 24 Kafka
  brokers, 12 PostgreSQL instances and 24 ClickHouse servers. Generate each
  cell's values from one list in version control (Argo CD ApplicationSet,
  Flux), roll upgrades out one cell, then one region, at a time, and alert on
  each cell's consumer lag, spool and "Detection worker stopped reporting"
  ([Running it](REFERENCE-ARCHITECTURE.md#running-it)).
- **Losing a region.** A region's Kafka or PostgreSQL going down stops
  detection in all its cells: collectors spool to disk (30 minutes at the
  sizes above) and nothing is lost if it returns in time. Six cells, a
  quarter of the estate, is the blast radius. Smaller regions mean more
  Kafka and PostgreSQL clusters to run; that is the trade.
- **SNMP topology.** Each cell polls its own devices, about 4,200 here; restrict
  polling to the switches whose topology you want and poll every 30 to 60
  minutes.

## What has and has not been tested

The measurements behind this design are those of the
[5,000-device](REFERENCE-ARCHITECTURE.md#what-has-and-has-not-been-tested) and
[50,000-device](REFERENCE-ARCHITECTURE-50000.md#what-has-and-has-not-been-tested)
documents: each component per core, a processor tracking 20,000 devices, bus
volume after compression, and a console taking reports from 500 simulated
cells.

Not tested: anything at this size end to end, shared regional Kafka and
PostgreSQL, a console with real cells reporting, more than 20,000 devices in a
cell, and an SNMP sweep or Topology page of thousands of real devices.

Start with one region, compare its measured rate, disk use and consumer lag
with this document, then add the others.
