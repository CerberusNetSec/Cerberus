# Deploying Cerberus

Four reference deployments, all built from the same image
(`ghcr.io/wrcrooks/cerberus`):

| Deployment | Files | Use it for |
|---|---|---|
| **Standalone** | [`docker-compose.yml`](../docker-compose.yml) at the repo root | One network, one host. Start here |
| **Compose** | [`compose/`](compose/) | A central console and several sites, one Docker host each |
| **Swarm** | [`swarm/`](swarm/) | A console and its sites as one stack across Swarm nodes |
| **Kubernetes** | [`kubernetes/`](kubernetes/) | Standalone, site and console layers for clusters |

One instance handles a few hundred devices (see "Running at scale" in the main
README). Beyond that, run **one Cerberus per site** and connect the sites to a
**central console**:

```
  site "north"                 site "south"                 ...
  devices ─syslog─▶ Cerberus   devices ─syslog─▶ Cerberus
                       │ alerts + health           │
                       └──────────────┬────────────┘
                                      ▼
                         central console (CERBERUS_CENTRAL=on)
                         one alert list · notifications · site health
```

On a desktop PC one instance took 6,000 messages a second through the whole
application without loss, and about 10,000 a second in the in-process load
test. Split a larger location into several sites (by building, zone or
firewall cluster).

## The image

Version tags are published by CI for `linux/amd64` and `linux/arm64`:

```sh
docker pull ghcr.io/wrcrooks/cerberus:0.4.0
```

To build your own, `docker build -t registry.example.com/cerberus:0.4.0 .`,
push it, and set `CERBERUS_IMAGE` (Compose, Swarm) or the `images:` entry in
`kubernetes/base/kustomization.yaml`.

## How sites and the console work together

- **Up**, every 15 seconds: alerts that are new or changed since the last
  report (with their guidance details), and a health summary (message rate,
  device counts, open alerts, dropped messages, how far back events go).
  Events themselves stay at the site.
- **Down**, in the reply: alerts acknowledged or resolved at the console. The
  site applies them as if they were set in its own UI.
- If the console is unreachable the site keeps working, retries with back-off
  (up to every 5 minutes), and sends everything it missed when it reconnects.
  Delivery is at least once and the console stores alerts idempotently, so
  nothing is lost or doubled.
- The console raises a **"Site stopped reporting"** alert when a site has been
  silent for 5 minutes (`CERBERUS_SITE_SILENT_MINUTES`).
- Investigating an alert (its events, the device, the map) happens on that
  site's own dashboard.
- Configure notification channels on the console. A site with its own
  channels sends its alerts too, so they would arrive twice.

| Variable | Where | |
|---|---|---|
| `CERBERUS_CENTRAL=on` | console | Accept site reports and show the **Sites** page |
| `CERBERUS_SITE_TOKENS_FILE` | console | File of `site-name token` lines: the sites allowed to report. Sites can also be added in the UI, which shows a new token once |
| `CERBERUS_SITE_SILENT_MINUTES` | console | Minutes without a report before alerting (default 5) |
| `CERBERUS_SITE_NAME` | site | Name shown at the console (default: the container's hostname) |
| `CERBERUS_CENTRAL_URL` | site | The console's base URL |
| `CERBERUS_CENTRAL_TOKEN` or `_TOKEN_FILE` | site | This site's token |
| `CERBERUS_CENTRAL_CA` | site | CA bundle to trust for the console's certificate, when it is not publicly trusted |
| `CERBERUS_PASSWORD_FILE` | all | Read the dashboard password from a file (Docker and Kubernetes secrets) |

### Secrets

```sh
python deploy/make-secrets.py north south     # writes deploy/secrets/ (git-ignored)
```

This creates the console's password and `site_tokens.txt`, and for each site a
`<site>.token` and `<site>_password.txt`. Run it again with a new name to add a
site; existing tokens are kept. Give each site only its own two files.

Tokens are bearer credentials: anyone holding a site's token can post alerts
as that site. Keep the token files out of version control, send site reports
over HTTPS or an encrypted network, and rotate a token (Sites page → New
token, or a new `make-secrets.py` file and a restart) if one leaks.

## Standalone

```sh
cp .env.example .env          # optional: password, public URL, device identity
docker compose up -d --build
```

The main README covers this in full. The same instance can later become a
site by adding `CERBERUS_CENTRAL_URL` and a token; its data is kept. On
Kubernetes, use [`kubernetes/standalone`](kubernetes/standalone).

## Compose

**Try it on one machine** (console and two sites, plain HTTP):

```sh
python deploy/make-secrets.py north south
docker compose -f deploy/compose/demo.yml up -d --build
python tools/simulate.py --tcp --port 5141    # attacks at north
```

Open http://localhost:8090 (password in `deploy/secrets/central_password.txt`).
The sites' own dashboards are on 8091 and 8092. Remove it all with
`docker compose -f deploy/compose/demo.yml down -v`.

**Production.** On the console's host:

```sh
CENTRAL_DOMAIN=cerberus.example.com docker compose -f deploy/compose/central.yml up -d
```

Caddy terminates HTTPS and obtains a certificate automatically when
`CENTRAL_DOMAIN` resolves publicly to the host; for an internal name, see the
note in `compose/Caddyfile`. On each site's host, with that site's two secret
files in `deploy/secrets/`:

```sh
CERBERUS_SITE_NAME=north CERBERUS_CENTRAL_URL=https://cerberus.example.com \
  docker compose -f deploy/compose/site.yml up -d
```

Set `CERBERUS_IMAGE=ghcr.io/wrcrooks/cerberus:0.4.0` to use the published image
instead of building locally. Compose (without Swarm) bind-mounts secret files,
so they must be readable by the container's user (uid 10001); `make-secrets.py`
writes them mode 0644.

## Swarm

[`swarm/stack.yml`](swarm/stack.yml) deploys the console, an HTTPS proxy for
its dashboard, and two example sites as one stack:

- **Pinned instances.** Each Cerberus is one replica pinned by a node label,
  because its database is on that node's local volume. Updates stop the old
  task before starting the new one.
- **Encrypted reporting.** Sites report to the console over an encrypted
  overlay network (IPsec), so no certificates need handing out. Allow IP
  protocol 50 between nodes; encrypted overlays do not work on Windows nodes.
- **Real source addresses.** Site ports are published in `host` mode so
  devices keep their real source addresses; the routing mesh would replace
  them.
- **Certificates.** `Caddyfile` gets a public certificate. For a name that only
  resolves internally, deploy with `CADDYFILE=Caddyfile.internal`, which
  issues Caddy's own.

The header of the file lists the commands: label the nodes, create the secrets,
then

```sh
CENTRAL_DOMAIN=cerberus.example.com docker stack deploy -c deploy/swarm/stack.yml cerberus
```

Swarm suits sites that are all reachable from one manager. For sites run by
different teams or without a shared control plane, use the Compose files per
site instead.

## Clustered storage (any deployment)

Any of the deployments can keep its data in PostgreSQL and ClickHouse instead
of SQLite, by setting `CERBERUS_POSTGRES_URL` and `CERBERUS_CLICKHOUSE_URL`
(or their `_FILE` forms for secrets). See "Clustered storage" in the main
README for what changes.

- **Compose:** `compose/clustered-storage.yml` runs Cerberus with both
  databases on one host. Generate its secrets with
  `python deploy/make-secrets.py --storage`. For your own database servers,
  set the two URLs on any of the other Compose files instead.
- **Swarm:** add the two `_FILE` variables and secrets holding the URLs to a
  service in `swarm/stack.yml`; the service then needs no node label, since its
  data no longer lives on a node.
- **Kubernetes:** add `components: [../components/clustered-storage]` to a
  layer's kustomization and create a `cerberus-storage` secret with
  `postgres-url` and `clickhouse-url` keys (see the component's header). The
  volume claim is dropped.

Run PostgreSQL and ClickHouse with replication and backups as your platform
does (managed services, operators); the Compose file's single containers are
for trying it.

## Kubernetes

Kustomize, in layers over one [`base`](kubernetes/base):

| Layer | Namespace | What it adds |
|---|---|---|
| [`standalone`](kubernetes/standalone) | `cerberus` | Nothing: one instance on its own |
| [`site`](kubernetes/site) | `cerberus` | Site name, console URL, token |
| [`central`](kubernetes/central) | `cerberus-central` | Console mode, site tokens, an Ingress; no syslog service |

```sh
# standalone
kubectl create namespace cerberus
kubectl -n cerberus create secret generic cerberus --from-literal=password='choose-one'
kubectl apply -k deploy/kubernetes/standalone

# console
kubectl create namespace cerberus-central
kubectl -n cerberus-central create secret generic cerberus \
  --from-file=password=deploy/secrets/central_password.txt \
  --from-file=site-tokens=deploy/secrets/site_tokens.txt
kubectl apply -k deploy/kubernetes/central

# each site, in that site's cluster (or its own namespace)
kubectl create namespace cerberus
kubectl -n cerberus create secret generic cerberus \
  --from-file=password=deploy/secrets/north_password.txt \
  --from-file=central-token=deploy/secrets/north.token
kubectl apply -k deploy/kubernetes/site
```

Edit the `kustomization.yaml` files first: the console's host name (also in
`central/ingress.yaml`), and the site's name and console URL. A site in the
same cluster as the console can use
`http://cerberus.cerberus-central.svc:8080` instead of the public URL.

- **One replica, `Recreate` strategy.** Each instance is a single SQLite
  writer on a `ReadWriteOnce` volume. Use block or local storage, not NFS.
- **Syslog Service.** `type: LoadBalancer` with `externalTrafficPolicy: Local`
  keeps devices' source addresses. Restrict `loadBalancerSourceRanges` to your
  management networks. If your load balancer still rewrites addresses, set
  `CERBERUS_DEVICE_IDENTITY=hostname`.
- **Ingress.** The console's Ingress allows request bodies up to 8 MB, which a
  site catching up after an outage needs.
- **Hardening.** Non-root (uid 10001), read-only root filesystem, no
  capabilities, no service-account token.

## What has been tested

| Deployment | How |
|---|---|
| Standalone | Root `docker-compose.yml` on Docker Desktop with the 0.2.0 image: alerts raised, console endpoints absent, federation off |
| Compose | `compose/demo.yml` on Docker Desktop: both sites reported; an acknowledgement at the console reached the site; a site caught up fully after the console was stopped and restarted |
| Swarm | `swarm/stack.yml` on a three-node swarm (Docker-in-Docker): services placed by label, both sites reported over the overlay, traffic between nodes confirmed ESP-encrypted, console reached through Caddy's HTTPS, site saw devices' real source addresses |
| Kubernetes | `standalone`, `site` and `central` on k3s 1.31: all rolled out as non-root with read-only filesystems; the site reported to the console; syslog through the LoadBalancer kept the sender's real address |

| Clustered storage | `compose/clustered-storage.yml` on Docker Desktop with PostgreSQL 16 and ClickHouse 24.8: every attack scenario over TCP, alerts, event search and risk ports through the API, then a restart with the session and detector state intact. The Kubernetes component is checked by rendering only |

Not yet tested: Swarm across real hosts on separate networks, Kubernetes on a
managed cloud load balancer, the console's Ingress with an ingress
controller (k3s ran without one), and the clustered-storage component on a
running cluster. CI checks on every push that all four
deployments' files are valid.
