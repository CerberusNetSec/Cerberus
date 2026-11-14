# Deploying Cerberus across many sites

Large networks run **one Cerberus per site** and connect them to a **central
console**. Each site collects and analyses its own devices' syslog, keeps its
own events, devices and topology, and works on its own if the console is
unreachable. The console shows every site's alerts in one list, sends the
notifications, and tells you when a site goes quiet.

```
  site "north"                 site "south"                 ...
  devices ─syslog─▶ Cerberus   devices ─syslog─▶ Cerberus
                       │ HTTPS: alerts + health    │
                       └──────────────┬────────────┘
                                      ▼
                         central console (Cerberus, CERBERUS_CENTRAL=on)
                         one alert list · notifications · site health
```

Sizing a site is covered in the main README under "Running at scale": one
site handles a few hundred devices; on a desktop PC it took 6,000 messages a
second through the whole application without loss, and about 10,000 a second
in the in-process load test. Split a larger location into several sites (by
building, zone or firewall cluster).

## What travels between a site and the console

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

Investigating an alert (its events, the device, the map) happens on that
site's own dashboard.

## Settings

| Variable | Where | |
|---|---|---|
| `CERBERUS_CENTRAL=on` | console | Accept site reports and show the **Sites** page |
| `CERBERUS_SITE_TOKENS_FILE` | console | File of `site-name token` lines: the sites allowed to report. Sites can also be added in the UI, which shows a new token once |
| `CERBERUS_SITE_SILENT_MINUTES` | console | Minutes without a report before alerting (default 5) |
| `CERBERUS_SITE_NAME` | site | Name shown at the console (default: the container's hostname) |
| `CERBERUS_CENTRAL_URL` | site | The console's base URL, e.g. `https://cerberus.example.com` |
| `CERBERUS_CENTRAL_TOKEN` or `_TOKEN_FILE` | site | This site's token |
| `CERBERUS_CENTRAL_CA` | site | CA bundle to trust for the console's certificate, when it is not publicly trusted |
| `CERBERUS_PASSWORD_FILE` | both | Read the dashboard password from a file (Docker and Kubernetes secrets) |

Notifications: configure channels on the console. If a site also has
channels, its alerts are sent twice (once by the site, once by the console).

## Secrets

```sh
python deploy/make-secrets.py north south     # writes deploy/secrets/ (git-ignored)
```

This creates the console's password and `site_tokens.txt`, and for each site a
`<site>.token` and `<site>_password.txt`. Run it again with a new name to add a
site; existing tokens are kept. Give each site only its own two files.

Tokens are bearer credentials: anyone holding a site's token can post alerts
as that site. Serve the console over HTTPS, keep the token files out of
version control, and rotate a token (Sites page → New token, or a new
`make-secrets.py` file and restart) if one leaks.

## The image

All three deployments use the same image. Build it and push it somewhere every
host or cluster can pull from:

```sh
docker build -t registry.example.com/cerberus:0.2.0 .
docker push registry.example.com/cerberus:0.2.0
```

## Docker Compose

Files in [`compose/`](compose/).

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

Set `CERBERUS_IMAGE` to use a pushed image instead of building locally.
Compose (without Swarm) bind-mounts secret files, so they must be readable by
the container's user (uid 10001); `make-secrets.py` writes them mode 0644.

## Docker Swarm

[`swarm/stack.yml`](swarm/stack.yml) deploys the console, its HTTPS proxy and
two example sites as one stack. Each Cerberus is one replica pinned by a node
label, because its database is on that node's local volume; updates stop the
old task before starting the new one. Site ports are published in `host` mode
so devices keep their real source addresses (the routing mesh would replace
them). The header of the file lists the commands: label the nodes, create the
secrets, then

```sh
CERBERUS_IMAGE=registry.example.com/cerberus:0.2.0 CENTRAL_DOMAIN=cerberus.example.com \
  docker stack deploy -c deploy/swarm/stack.yml cerberus
```

Swarm suits sites that are all reachable from one manager. For sites run by
different teams or without a shared control plane, use the Compose files per
site instead.

## Kubernetes

Kustomize bases in [`kubernetes/central`](kubernetes/central) and
[`kubernetes/site`](kubernetes/site).

```sh
# console
kubectl create namespace cerberus
kubectl -n cerberus create secret generic cerberus-central \
  --from-file=password=deploy/secrets/central_password.txt \
  --from-file=site-tokens=deploy/secrets/site_tokens.txt
kubectl apply -k deploy/kubernetes/central

# each site, in that site's cluster (or its own namespace)
kubectl -n cerberus create secret generic cerberus-site \
  --from-file=password=deploy/secrets/north_password.txt \
  --from-file=central-token=deploy/secrets/north.token
kubectl apply -k deploy/kubernetes/site
```

Before applying, edit the `kustomization.yaml` files: the image, the console's
host name (also in `central/ingress.yaml`), and the site's name and console
URL. Notes:

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

## What is verified

- The federation protocol has end-to-end tests (`tests/test_federation.py`):
  reporting, catch-up in batches, idempotency, status hand-back, token
  rotation, rebuilt sites, configured sites, silence alerts, console outages.
- `compose/demo.yml` was run on Docker Desktop: both sites reported, an
  acknowledgement at the console reached the site, and a site caught up fully
  after the console was stopped and restarted, all with read-only containers.
- The Swarm stack and the Kubernetes bases are validated by rendering
  (`docker stack config`, `kubectl kustomize`) but have not been deployed to a
  real Swarm or cluster yet.
