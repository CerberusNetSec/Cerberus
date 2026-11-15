# Contributing

## Set up

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt pytest      # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest
```

Python 3.12. Run it locally without Docker:

```sh
CERBERUS_PASSWORD=dev .venv/bin/python -m cerberus     # syslog on 5514, UI on http://localhost:8080
python tools/simulate.py --port 5514                   # sample attacks and ordinary traffic
```

### Clustered-storage tests

`tests/test_backends.py` runs against real PostgreSQL and ClickHouse when two
URLs are set, and is skipped otherwise:

```sh
docker run -d --name cerberus-dev-pg -p 127.0.0.1:15432:5432 -e POSTGRES_USER=cerberus \
  -e POSTGRES_PASSWORD=devtest -e POSTGRES_DB=cerberus postgres:16-alpine
docker run -d --name cerberus-dev-ch -p 127.0.0.1:18123:8123 -e CLICKHOUSE_USER=cerberus \
  -e CLICKHOUSE_PASSWORD=devtest -e CLICKHOUSE_DB=cerberus --ulimit nofile=262144:262144 \
  clickhouse/clickhouse-server:24.8
CERBERUS_TEST_POSTGRES_URL=postgresql://cerberus:devtest@127.0.0.1:15432/cerberus \
CERBERUS_TEST_CLICKHOUSE_URL=http://cerberus:devtest@127.0.0.1:18123/cerberus \
  .venv/bin/python -m pytest tests/test_backends.py
```

Each test creates and drops its own databases. CI runs them with service
containers.

`tests/test_bus.py` needs a Kafka-compatible broker:

```sh
docker run -d --name cerberus-dev-kafka -p 127.0.0.1:19092:19092 redpandadata/redpanda:v24.2.7 \
  redpanda start --mode dev-container --smp 1 --memory 512M \
  --kafka-addr external://0.0.0.0:19092 --advertise-kafka-addr external://127.0.0.1:19092
CERBERUS_TEST_KAFKA_BOOTSTRAP=127.0.0.1:19092 .venv/bin/python -m pytest tests/test_bus.py
```

## Tools

| Command | What it does |
|---|---|
| `python tools/simulate.py [scenario ...]` | Sends fake syslog over UDP. `--list` shows the scenarios |
| `python tools/snmp_sim.py [--rogue] [--sites N]` | Fake SNMP agents for the topology feature |
| `python tools/loadtest.py [--devices N --messages N]` | In-process throughput, storage and query timings (`--postgres` and `--clickhouse` measure clustered storage on empty databases) |
| `python tools/migrate.py --from cerberus.db --postgres ... --clickhouse ...` | Move a SQLite installation to clustered storage |
| `python deploy/make-secrets.py <site> ...` and `docker compose -f deploy/compose/demo.yml up -d --build` | A central console and two sites on one machine |

CI (`.github/workflows/ci.yml`) runs the tests and validates all four
deployments on every push and pull request, builds the image for amd64 and
arm64, and publishes it to `ghcr.io/cerberusnetsec/cerberus` when a `v*` tag is
pushed. A change to a deployment should keep `docker compose config`,
`docker stack config` and `kubectl kustomize` passing for it.

## Expectations for a change

- **Tests go through the real engine.** Feed log lines in (see the `Harness`
  in `tests/test_security.py`) and assert on the alerts that come out, rather
  than testing a detector's internals.
- **A new alert kind needs a playbook entry** in `cerberus/playbooks.py`: why
  it matters and what a network team should do. Write it for the person who
  gets the notification at 3 a.m.
- **A new or changed connector needs a real sample line** in a test. If you
  only have the vendor's documentation to go on, say so in the connector's
  description.
- **State must be bounded.** Anything keyed on an address from a log line can
  be forged in bulk; cap it (`MAX_TRACKED`, `_get`).
- **No new runtime dependencies** without a good reason, and no front-end build
  step: `static/` is plain HTML, CSS and JavaScript.
- **No real data.** Use the documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) and invented hostnames in samples. Never
  commit device logs, `.env` or the `data/` directory.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit and
[docs/API.md](docs/API.md) for the HTTP API.
