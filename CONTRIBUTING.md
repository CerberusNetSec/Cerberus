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

## Tools

| Command | What it does |
|---|---|
| `python tools/simulate.py [scenario ...]` | Sends fake syslog over UDP. `--list` shows the scenarios |
| `python tools/snmp_sim.py [--rogue] [--sites N]` | Fake SNMP agents for the topology feature |
| `python tools/loadtest.py [--devices N --messages N]` | In-process throughput, storage and query timings |
| `python deploy/make-secrets.py <site> ...` and `docker compose -f deploy/compose/demo.yml up -d --build` | A central console and two sites on one machine |

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
