# HTTP API

The dashboard is a client of this JSON API, served on the web port (8080 by
default). It is stable enough to script against but is not versioned.

## Authentication

`POST /api/login` with `{"username": "...", "password": "..."}` sets a session
cookie (`cerberus_session`, 7 days, HttpOnly, SameSite=Strict); leave out the
username (or send `""`) to sign in as the built-in admin with the shared
password. Single sign-on starts at `GET /api/auth/oidc/login` in a browser.
Every other `/api/` path returns `401` without a session. Repeated failures
from one address are throttled (`429`). With `CERBERUS_AUTH=off` no login is
needed.

**Roles.** A session acts with its account's role. **Viewers** may make `GET`
requests, except to the admin-only `/api/tokens`, `/api/users`, `/api/channels`
and `/api/auth/settings`, and `/api/audit` (analysts and admins). **Analysts**
may also `POST /api/alerts/status`, `/api/alerts/false-positive`,
`/api/suppressions/remove`, `/api/ignore` and (on a console)
`/api/site-alerts/status`. **Admins** may do everything. Anything else answers
`403`. Everyone with a local account may `POST /api/me/password`.

```sh
curl -c jar -H 'Content-Type: application/json' -d '{"password":"change-me"}' http://host:8080/api/login
curl -b jar 'http://host:8080/api/alerts?status=open&severity=high'
```

**API tokens** (Settings → API & agents) are for agents and scripts: send
`Authorization: Bearer cerb_...`. A **read** token acts as a viewer and a
**write** token as an analyst (its changes are recorded in the audit log
against the token); neither can reach the admin-only paths.
Anything else answers `403`; a missing, wrong or revoked token `401`
(revocation takes effect within 30 seconds).

## MCP server

`POST /mcp` is a Model Context Protocol server (streamable HTTP, JSON
responses; protocol versions 2025-06-18, 2025-03-26 and 2024-11-05), with the
same bearer token. `GET /mcp` answers `405`: there is no server-sent stream.
Requests from a browser on another site (an `Origin` header that is not this
host) are refused. Tools: `get_status`, `list_alerts`, `get_alert`,
`search_events`, `list_devices`, `get_attack_matrix`, `get_high_risk_ports`,
and, with a write token, `set_alert_status` and `mark_false_positive`.

## Webhook payload

Webhook channels POST this; custom API calls send it when their body template
is empty, and `{{payload}}` inserts it:

```json
{"event": "alert", "source": "cerberus", "version": "1.2.0", "id": 42,
 "title": "Port scan from 192.168.1.77", "description": "...", "severity": "high",
 "detector": "port_scan", "device": "OPNsense.lan", "src_ip": "192.168.1.77",
 "created": "2026-11-15T10:00:00+00:00", "created_epoch": 1794708000.0, "details": {"target": "192.168.10.5"},
 "stage": "Discovery", "technique": "T1046 Network Service Discovery", "actions": ["..."],
 "link": "https://cerberus.example/#/alerts?id=42", "subject": "[Cerberus HIGH] Port scan from 192.168.1.77",
 "text": "the e-mail style message"}
```

`event` is `alert`, `summary` (alerts held back by a channel's rate limit,
with `count`) or `test`. With a signing secret: `X-Cerberus-Timestamp: <unix
time>` and `X-Cerberus-Signature: sha256=<hex HMAC-SHA256(secret, timestamp +
"." + body)>`; also `X-Cerberus-Event` and a unique `X-Cerberus-Delivery`.

Errors are `{"detail": "message"}` with a 4xx/5xx status. Secrets (channel
credentials, SNMP community strings) are never returned: they read back as
`********`, and sending that value back leaves the stored one unchanged.

## Endpoints

| Method and path | Purpose |
|---|---|
| `GET /healthz` | Liveness check, no login needed |
| `GET /readyz` | Ready for traffic (`503` on a standby processor), no login needed |
| `GET /metrics` | Prometheus metrics; no login, or `Authorization: Bearer` with `CERBERUS_METRICS_TOKEN` |
| `GET /api/me` | `{signed_in, auth, version, user: {username, name, role, kind, local, source}, sso: {enabled, label}, builtin_admin, central, site}`, without login |
| `POST /api/login`, `POST /api/logout` | Session: `{"username", "password"}`; the answer has the signed-in `user` |
| `POST /api/me/password` | `{"current", "new"}`: change your own password (local accounts; 12 characters or more) |
| `GET /api/auth/oidc/login`, `GET /api/auth/oidc/callback` | Single sign-on (browser redirects); a failure returns to `/?sso_error=<why>` |
| `GET /api/users` | Admin: accounts (`id, username, display_name, email, role, source` (`local` or `sso`), `disabled, created, last_login`), the roles, `builtin_admin`, and single sign-on settings (no secret) |
| `POST /api/users` | Admin: `{"username", "display_name", "email", "role": "viewer"\|"analyst"\|"admin", "password"}`; `409` if the name is taken |
| `PUT /api/users/{id}` | Admin: any of `display_name`, `role` (not for single sign-on users), `disabled`, `password` (local users). A change of role, a new password or disabling signs the user out. `409` if it would leave no admin; you cannot demote or disable yourself |
| `DELETE /api/users/{id}` | Admin: delete an account; not your own, nor the last admin |
| `PUT /api/auth/builtin` | Admin: `{"allowed": false}` switches the shared-password admin off; `409` unless another admin account (or a single sign-on admin group) exists |
| `GET /api/collector-storage` | Storage thresholds for collectors and detection workers: `settings` (`enabled`, `warn` and `critical` in percent, `volume`: also watch the volume the spool is on), `defaults`, whether this is a processor (`available`), and each process's `spool_bytes`, `spool_limit`, `spool_percent`, `volume_bytes`, `volume_free`, `volume_percent`, `storage_percent` (the fuller of the two), `storage_what`, `storage_level` (empty, `warning` or `critical`) and `state` |
| `PUT /api/collector-storage` | Admin: `{"settings": {"enabled": true, "warn": 70, "critical": 90, "volume": true}}`, any of them; `400` unless 1 ≤ warn < critical ≤ 100 |
| `GET /api/display`, `PUT /api/display` | Display settings: `{"display": {"attack_hide_uncovered": true}}` hides ATT&CK tactics without a Cerberus detector |
| `GET /api/summary?range=1h\|6h\|24h\|7d` | Dashboard: message-rate series, open alerts by severity, hosts by risk, alerts by attack stage, top blocked sources and ports, collector health |
| `GET /api/alerts?status=&severity=&q=&limit=&id=&detector=` | Alerts, newest first. `status`: `open`, `ack`, `resolved`, `false_positive`, `active` (open or acknowledged) or empty for all. `severity` is a minimum. Each alert carries `details` and `advice` (stage, ATT&CK technique, why, actions); a false positive also carries `false_positive` (who, when, why, findings held back since) |
| `POST /api/alerts/status` | `{"ids": [1,2], "status": "ack"}` or `{"all_open": true, "status": "ack"}` |
| `GET /api/attack?range=24h\|7d\|30d\|90d\|all&status=real\|active\|all` | The MITRE ATT&CK matrix: per tactic, each technique Cerberus detects with its alert count, occurrences, severities, last seen and detectors; plus alerts outside ATT&CK, and `hide_uncovered` (the display setting). `status=real` leaves out false positives |
| `GET /api/tokens`, `POST /api/tokens`, `POST /api/tokens/{id}/revoke` | API tokens (dashboard session only): `{"name", "scope": "read"\|"write"}`; the token is in the creation answer, once |
| `GET /api/alerts/counts` | Open alerts by severity and in total, for the navigation badge: `{"open": {"high": 2}, "total": 2}` |
| `POST /api/alerts/false-positive` | `{"id": 7, "analyst": "name", "justification": "at least 10 characters"}`: marks the alert a false positive and suppresses its detector and entity; audited. `400` without a name or justification, `404` for an unknown alert |
| `GET /api/suppressions` | Every suppression, active and removed, with `hits` and `last_hit` |
| `POST /api/suppressions/remove` | `{"id": 3, "analyst": "name", "justification": "..."}`: alerts resume; audited. `404` if not active |
| `GET /api/audit?limit=&alert_id=&before=` | Analysts and admins: the audit log, newest first, `before` an entry id for paging. `action` is `login`, `login_failed`, `login_refused`, `logout`, `password_changed`, `false_positive`, `false_positive_again`, `suppression_removed`, an MCP tool's name, or the request (`PUT /api/detectors`) for any other change; `analyst` is who, `source` the address, then `alert_id`, `suppression_id` and `detail` (the request with secrets masked, or the justification) |
| `POST /api/ignore` | `{"ip": "10.0.0.5", "kind": "source"\|"destination"}` adds to an ignore list |
| `GET /api/events?hours=&device=&type=&action=&ip=&port=&q=&before=&limit=` | Events, newest first. `ip` matches source or destination, `port` is the destination port, `q` is text in the message, `before` is an event id for paging. A search running over 10 seconds returns `504` |
| `GET /api/riskports?range=` | High Risk Ports: per port, its `name`, `protocols` (`any`, `tcp`, `udp` or `tcp/udp`), totals by direction (`[allowed, blocked]`), series, findings, open alert count; plus summary figures and ports with no traffic |
| `GET /api/riskports/port?port=3389` | Busiest sources and destinations per direction, and open alerts naming the port |
| `GET /api/devices` | Log sources with SNMP polling status |
| `PUT /api/devices` | `{"id", "name", "connector_pin", "snmp_mode": "default"\|"custom"\|"off", "snmp_community", "snmp_host"}` |
| `POST /api/devices/forget` | `{"id"}` removes a device record (its events and alerts stay) |
| `GET /api/topology` | Nodes and links for the map, SNMP settings and polling progress |
| `GET /api/topology/device?id=` | One device's system details, interfaces and neighbours |
| `PUT /api/snmp` | `{"enabled", "community", "interval", "concurrency", "networks": [...]}` |
| `POST /api/snmp/poll` | Poll now. `{"id": "..."}` for one device; with more than 20 devices it returns immediately with `{"background": true}` |
| `GET /api/connectors` | Loaded connectors and load errors |
| `GET /api/listeners` | Syslog listeners: per `udp`/`tcp`/`tls`, `enabled`, `port`, whether it is `listening` and any `error`; whether this process receives syslog (`available`), runs in a container, and has a TLS certificate |
| `PUT /api/listeners` | `{"listeners": {"tcp": {"enabled": true, "port": 1514}}}`: applied at once and saved; a listener that cannot change reports its `error` and keeps running as it was. `409` on a processor (collectors receive syslog) |
| `POST /api/connectors/reload` | Re-read connector files |
| `POST /api/connectors/test` | `{"raw": "<134>...", "connector": ""}` returns the parsed event |
| `GET /api/detectors` | Each detector's settings schema and values, plus general settings. The High Risk Ports list (`risk_ports` → `ports`) has type `ports`, with `entries` (`[{port, proto, name}]`), `default_entries` and the built-in `catalog`; it is saved as a string, `PORT[/tcp\|/udp][=name]` separated by commas |
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
