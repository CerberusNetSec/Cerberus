# Reference architecture: 500,000 network devices

What it takes to run Cerberus for an estate of about 500,000 firewalls,
switches and access points: a retailer with tens of thousands of stores, a
national network, or a service provider's managed estate. It uses the
building blocks of the
[50,000-device reference architecture](REFERENCE-ARCHITECTURE-50000.md)
(cells, regions that share Kafka, PostgreSQL and ClickHouse, and a central
console); a cell is the cluster of the
[5,000-device design](REFERENCE-ARCHITECTURE.md). Read those first.

It is a design to start a pilot from. The parts have been measured, but
nothing has been run at this size, and at this size the pilot matters more
than at any other
([what has and has not been tested](#what-has-and-has-not-been-tested)).

- [The short version](#the-short-version)
- [First, your message rate](#first-your-message-rate)
- [Design A: blocks, threats and logins (25 cells)](#design-a-blocks-threats-and-logins-25-cells)
- [Design B: every connection at the branches (60 cells)](#design-b-every-connection-at-the-branches-60-cells)
- [What changes at this size](#what-changes-at-this-size)
- [Where the design runs out](#where-the-design-runs-out)
- [What has and has not been tested](#what-has-and-has-not-been-tested)

## The short version

- **An estate this size is mostly switches and access points.** Assume one
  device in twenty is a firewall: 25,000 firewalls and 475,000 switches and
  access points. The firewalls still decide the message rate.
- **Design A: firewalls log blocks, threats and logins.** About 100,000
  messages a second. The device count decides: **25 cells** of 20,000 devices
  in 5 regions, about **620 CPU cores and 1.5 TB of memory**, 25 to 40 TB of
  event storage for 30 days.
- **Design B: branch firewalls log every connection.** About 550,000 messages a
  second: **60 cells** in 10 regions, about **1,700 CPU cores and 4.4 TB of
  memory**, 48 TB of event storage with sampling (240 TB without).
- **Data-centre firewalls logging every connection** add 100 messages a second
  each and up, a cell per hundred of them. Log allowed connections where they
  matter (internet edges, server and management networks), not everywhere.
- **One console** takes reports from all cells; measured, it has room for more
  than ten times as many. People reading alerts, not machines, are the limit.
- Running this is a platform team's job: 5 to 10 regions, each with its own
  Kafka, PostgreSQL and Kubernetes, and 25 to 60 Cerberus releases kept alike
  from version control.

## First, your message rate

25,000 firewalls and 475,000 switches and access points (about 52,000 messages
a second between them):

| What the firewalls log | Per firewall | Total | Cells |
|---|---|---|---|
| Blocked traffic, threats and logins only | about 2/s | about 100,000/s | 25 (the device count decides) |
| Every connection, branch firewalls | about 20/s | about 550,000/s | 55, so 60 in 10 regions of 6 |
| Every connection, and busy data-centre firewalls | 100/s and up each | add a cell per 100 of them | |

Cells: the larger of your message rate ÷ 10,000 and your device count ÷
20,000, rounded up. If your share of firewalls is higher than one in twenty,
use the [100,000-device](REFERENCE-ARCHITECTURE-100000.md#first-your-message-rate)
table, times five.
[Measure your rate](REFERENCE-ARCHITECTURE.md#first-your-message-rate) on a
sample of sites before you plan: at this size, every 10,000 messages a second
you send is another cell.

## Design A: blocks, threats and logins (25 cells)

Each cell: 20,000 devices, about 4,000 messages a second. With so many devices
per cell, a cell has the usual collectors, workers and processors, and a
smaller ClickHouse.

```
 region 1 … region 5, each:
 ┌──────────────────────────────────────────────────────────────┐
 │ 5 cells, each: syslog address, collectors ×4, workers ×6,    │
 │                processors ×2, ClickHouse ×1                  │
 │ Kafka ×5 · PostgreSQL ×3                                     │
 └──────────────────────────────┬───────────────────────────────┘
                                ▼ alerts and health every 15 s
                  central console (one instance, own PostgreSQL)
```

| Component | Count | Each | Total |
|---|---|---|---|
| Collectors | 100 (4 per cell) | 1 CPU, 1 GiB, 30 GiB spool | 100 CPU, 100 GiB |
| Detection workers | 150 (6 per cell) | 1 CPU, 1 GiB | 150 CPU, 150 GiB |
| Processors | 50 (2 per cell, one active) | 2 CPU, 4 GiB | 100 CPU, 200 GiB |
| ClickHouse | 25 (1 per cell) | 4 CPU, 16 GiB, 1 to 1.6 TB | 100 CPU, 400 GiB |
| Kafka brokers | 25 (5 per region) | 4 CPU, 16 GiB, 1 TB | 100 CPU, 400 GiB |
| PostgreSQL | 15 (3 per region) | 4 CPU, 16 GiB, 200 GiB; `max_connections` 450 | 60 CPU, 240 GiB |
| Console | 1, and 3 small PostgreSQL | 2 CPU, 4 GiB; 2 CPU, 4 GiB, 20 GiB | 8 CPU, 16 GiB |
| **Total** | | | **about 620 CPU, 1,500 GiB** |

Event storage for 30 days: 25 to 40 TB. Blocked traffic, threats and logins
are always stored in full; sampling only thins allowed connections, of which
there are few here.

Settings that differ from the
[per-cell settings](REFERENCE-ARCHITECTURE-50000.md#settings-for-each-cell):
`CERBERUS_MAX_DEVICES=30000`, and for devices sending over TCP or TLS,
`CERBERUS_MAX_TCP_CLIENTS=7000` (20,000 connections over 4 collectors, and a
third again for a collector being away).

What design A does not detect: lateral movement, beaconing, large transfers
and exposed services all need logs of allowed connections. A middle way is
design A everywhere, plus design B's connection logging at internet edges and
data centres, sized by their message rate.

## Design B: every connection at the branches (60 cells)

Each cell: about 8,300 devices and 9,200 messages a second, as in the
[100,000-device design](REFERENCE-ARCHITECTURE-100000.md#the-design-24-cells-in-4-regions),
in 10 regions of 6 cells.

| Component | Count | Each | Total |
|---|---|---|---|
| Collectors | 240 (4 per cell) | 1 CPU, 1 GiB, 30 GiB spool | 240 CPU, 240 GiB |
| Detection workers | 360 (6 per cell) | 1 CPU, 1 GiB | 360 CPU, 360 GiB |
| Processors | 120 (2 per cell, one active) | 2 CPU, 4 GiB | 240 CPU, 480 GiB |
| ClickHouse | 60 (1 per cell) | 8 CPU, 32 GiB, 0.8 to 4 TB | 480 CPU, 1,920 GiB |
| Kafka brokers | 60 (6 per region) | 4 CPU, 16 GiB, 1.5 TB | 240 CPU, 960 GiB |
| PostgreSQL | 30 (3 per region) | 4 CPU, 16 GiB, 250 GiB; `max_connections` 550 | 120 CPU, 480 GiB |
| Console | 1, and 3 small PostgreSQL | as above | 8 CPU, 16 GiB |
| **Total** | | | **about 1,700 CPU, 4,450 GiB** |

Storage, for 30 days:

| | With sampling (`CERBERUS_TRAFFIC_SAMPLE=10`) | Everything |
|---|---|---|
| ClickHouse, all cells | about 48 TB | about 240 TB |
| Kafka, all regions (6 hours, 3 copies) | 90 TB of volumes | 90 TB |
| Collector spools | 7.2 TB | 7.2 TB |

`CERBERUS_MAX_DEVICES=12500` and, for TCP or TLS, `CERBERUS_MAX_TCP_CLIENTS=3000`.

## What changes at this size

- **Cells follow the network.** Draw cells along regions, store groups or
  customers, so that traffic between cells is rare: detection is per cell, and
  an attacker seen in two cells raises an alert in each, not one. For a
  service provider, a cell per customer, or per group of small customers,
  also keeps each customer's events apart.
- **Who sees what.** Everyone with access to the console sees every cell's
  alerts; roles are viewer, analyst and admin, not per region or per customer.
  Give regional teams or customers their cells' dashboards, and keep the
  console for the team that watches everything. A cell reports to one console,
  so a customer-facing console per group of cells is also possible.
- **The console.** 60 cells send four reports a second; the console measured
  105 a second on one thread, about 1,500 cells' worth, and stayed fast with
  2 million alerts stored ([the console](REFERENCE-ARCHITECTURE-50000.md#the-console)).
  It is one instance: if it stops, cells keep detecting and notifying, and
  catch it up when it returns. Notify from the console only what the central
  team acts on, and send the rest to your SIEM or SOAR tool by webhook.
- **Pointing half a million devices.** Devices are assigned to cells from one
  table (site → cell), applied by the tools that configure them, and checked
  against each cell's Devices page. A store that opens is added to a cell with
  room; a cell that reaches 20,000 devices or 10,000 messages a second is
  split.
- **Syslog over the WAN.** Devices at stores and branches send across the WAN
  to the cell for their region. Use TCP or TLS rather than UDP, and expect a
  cell's syslog to be tens of Mbit/s.
- **SNMP topology.** A cell of 20,000 devices cannot sweep them all every few
  minutes, and a map of 20,000 devices is not readable. Poll only the
  switches whose topology you care about (core, distribution, data centre),
  every hour.
- **The platform.** 5 to 10 regions, each a Kubernetes cluster with a Kafka, a
  PostgreSQL and its ClickHouse servers, run by a platform team. Generate every
  cell's Helm values from one list (Argo CD ApplicationSet, Flux), upgrade one
  cell, then one region, at a time, and aggregate metrics per region
  ([Running it](REFERENCE-ARCHITECTURE.md#running-it)). Watch each cell's
  consumer lag: it is the first sign a cell has outgrown itself.
- **Losing a region** stops detection for a fifth (design A) or a tenth (design B) of the estate
  while collectors spool (30 minutes at the sizes above). Regions are the
  unit to keep apart: their own clusters, storage and network paths.

## Where the design runs out

Two hard limits make this design as large as it is, and neither is a matter
of hardware:

- **One active processor per cell.** Per-device detection, alerting and
  storage writes run in one process, so a cell is planned at 10,000 messages
  a second however many machines it has. Dividing the processor's work by
  device would let one cell take several times that, and design B would need
  a fraction of the cells, regions and Kafka clusters.
- **No correlation between cells.** The console lists alerts; it does not
  combine them. An attacker working across many stores is many alerts.

Smaller gaps that matter at this size: the console has no standby, and
consoles cannot report to a console above them; console roles are not scoped
by region or customer; notification channels filter by severity, not by
cell.

None of these is planned yet; they are listed so the trade-offs are clear. If
you are planning an estate of this size, open an issue: which of them matters
most is worth knowing.

## What has and has not been tested

The measurements behind this design are those of the
[5,000-device](REFERENCE-ARCHITECTURE.md#what-has-and-has-not-been-tested) and
[50,000-device](REFERENCE-ARCHITECTURE-50000.md#what-has-and-has-not-been-tested)
documents: each component per core, a processor tracking 20,000 devices (2%
slower than 5,000), bus volume after compression, and a console taking reports
from 500 simulated cells.

Not tested: anything near this size end to end; shared regional Kafka and
PostgreSQL; a console with real cells reporting; a cell of 20,000 real
devices; collectors holding 7,000 TCP connections each; an SNMP sweep or
Topology page of thousands of real devices; real logs' compression on the
bus.

Pilot with one region of real devices, compare its rate, disk use and
consumer lag with this document, and only then commit to the rest.
