# HTTP API

The dashboard is a client of this JSON API, served on the web port (8080 by
default). It is stable enough to script against but is not versioned.

## Authentication

`POST /api/login` with `{"password": "..."}` sets a session cookie
(`cerberus_session`, 7 days, HttpOnly, SameSite=Strict). Every other `/api/`
path returns `401` without it. Repeated failures from one address are
throttled (`429`). With `CERBERUS_AUTH=off` no login is needed.

```sh
curl -c jar -H 'Content-Type: application/json' -d '{"password":"change-me"}' http://host:8080/api/login
curl -b jar 'http://host:8080/api/alerts?status=open&severity=high'
```

Errors are `{"detail": "message"}` with a 4xx/5xx status. Secrets (channel
credentials, SNMP community strings) are never returned: they read back as
`********`, and sending that value back leaves the stored one unchanged.

## Endpoints

| Method and path | Purpose |
|---|---|
| `GET /healthz` | Liveness check, no login needed |
| `GET /api/me` | `{signed_in, auth, version}` |
| `POST /api/login`, `POST /api/logout` | Session |
| `GET /api/summary?range=1h\|6h\|24h\|7d` | Dashboard: message-rate series, open alerts by severity, hosts by risk, alerts by attack stage, top blocked sources and ports, collector health |
| `GET /api/alerts?status=&severity=&q=&limit=&id=` | Alerts, newest first. `status`: `open`, `ack`, `resolved`, `active` (not resolved) or empty for all. `severity` is a minimum. Each alert carries `details` and `advice` (stage, ATT&CK technique, why, actions) |
| `POST /api/alerts/status` | `{"ids": [1,2], "status": "ack"}` or `{"all_open": true, "status": "ack"}` |
| `POST /api/ignore` | `{"ip": "10.0.0.5", "kind": "source"\|"destination"}` adds to an ignore list |
| `GET /api/events?hours=&device=&type=&action=&ip=&port=&q=&before=&limit=` | Events, newest first. `ip` matches source or destination, `port` is the destination port, `q` is text in the message, `before` is an event id for paging. A search running over 10 seconds returns `504` |
| `GET /api/riskports?range=` | High-risk ports: per port, totals by direction (`[allowed, blocked]`), series, findings, open alert count; plus summary figures and ports with no traffic |
| `GET /api/riskports/port?port=3389` | Busiest sources and destinations per direction, and open alerts naming the port |
| `GET /api/devices` | Log sources with SNMP polling status |
| `PUT /api/devices` | `{"id", "name", "connector_pin", "snmp_mode": "default"\|"custom"\|"off", "snmp_community", "snmp_host"}` |
| `POST /api/devices/forget` | `{"id"}` removes a device record (its events and alerts stay) |
| `GET /api/topology` | Nodes and links for the map, SNMP settings and polling progress |
| `GET /api/topology/device?id=` | One device's system details, interfaces and neighbours |
| `PUT /api/snmp` | `{"enabled", "community", "interval", "concurrency", "networks": [...]}` |
| `POST /api/snmp/poll` | Poll now. `{"id": "..."}` for one device; with more than 20 devices it returns immediately with `{"background": true}` |
| `GET /api/connectors` | Loaded connectors and load errors |
| `POST /api/connectors/reload` | Re-read connector files |
| `POST /api/connectors/test` | `{"raw": "<134>...", "connector": ""}` returns the parsed event |
| `GET /api/detectors` | Each detector's settings schema and values, plus general settings |
| `PUT /api/detectors` | `{"detectors": {"port_scan": {"enabled": true, "ports": 25}}, "general": {"cooldown_minutes": 30, "ignore_sources": [], "ignore_destinations": []}}` |
| `GET /api/channels` | Notification channels and the field list for each type |
| `POST /api/channels`, `PUT /api/channels/{id}`, `DELETE /api/channels/{id}` | Manage channels |
| `POST /api/channels/{id}/test` | Send a test notification; `502` with the provider's error on failure |

### Central console only

These exist when the instance runs with `CERBERUS_CENTRAL=on`.

| Method and path | Purpose |
|---|---|
| `POST /api/federation/report` | A site's report. Authenticated by `Authorization: Bearer <site token>`, not a session. Body: `{site, instance, version, sent, summary, alerts: [...]}` (at most 8 MB); reply: `{ok, site, status: [{id, status}], interval}` where `status` lists alerts acknowledged or resolved at the console that the site should apply |
| `GET /api/sites` | Sites with state (`waiting`, `reporting`, `silent`), last report, health summary and open alerts by severity |
| `POST /api/sites` | `{"name": "north"}` registers a site and returns its token, once |
| `POST /api/sites/{id}/token` | Issue a new token; the old one stops working |
| `DELETE /api/sites/{id}` | Remove a site and the alerts it reported (sites from `CERBERUS_SITE_TOKENS_FILE` cannot be removed here) |
| `GET /api/site-alerts?site=&status=&severity=&q=&limit=&id=` | Alerts from all sites, newest first, with `site` and `advice` |
| `POST /api/site-alerts/status` | `{"ids": [...], "status": "ack"}`; each site applies it with its next report |

Timestamps are Unix seconds. Severities are `info`, `low`, `medium`, `high`,
`critical`.
