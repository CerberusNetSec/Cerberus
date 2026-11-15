# Security

## Reporting a vulnerability

Please report security problems privately through GitHub: on this repository
open **Security → Report a vulnerability**. Do not open a public issue for
something exploitable. Include the version (`/api/me`), how to reproduce it,
and what an attacker gains.

This is a small project maintained in spare time; there is no guaranteed
response time and no bounty.

## What to know before deploying

- **Plain syslog is unauthenticated and unencrypted.** Anyone who can reach the
  syslog port can inject log lines, and so create alerts or new "devices".
  Expose it only to your management network, or use syslog over TLS
  (`CERBERUS_SYSLOG_TLS_PORT`), with `CERBERUS_SYSLOG_TLS_CLIENT_CA` to accept
  only devices holding a certificate your CA issued.
- **PROXY protocol** headers are trusted only from the addresses in
  `CERBERUS_PROXY_PROTOCOL_FROM`; list only your load balancers, or any sender
  could claim any device address.
- **The message bus (scale-out)** carries every parsed event. Use
  `CERBERUS_KAFKA_SECURITY=SASL_SSL` (TLS and a SCRAM password), give Cerberus's
  Kafka user access to its own topics and groups only, and restrict who can
  reach the bus.
- **The dashboard is plain HTTP.** Put it behind a TLS reverse proxy if it is
  reachable from anywhere you do not fully trust; single sign-on needs HTTPS.
- **Accounts and roles.** The shared dashboard password signs in as the
  built-in admin. Give people their own accounts (or single sign-on) with the
  least role they need, then switch the built-in admin off under Settings →
  Users, so every change in the audit log has a person's name on it. Local
  passwords are stored as scrypt hashes; changing a user's role or password,
  or disabling them, ends their sessions.
- **Single sign-on** trusts your identity provider's groups for roles,
  refreshed at each sign-in. Map only groups you control, and leave
  `CERBERUS_OIDC_DEFAULT_ROLE` empty unless everyone your provider will sign in
  should see your network's alerts.
- **The audit log** records sign-ins and every change, with passwords, tokens
  and community strings masked. It is kept in Cerberus's own database, so an
  admin with access to that database could alter it; forward it elsewhere
  (`GET /api/audit`) if you need it tamper-evident.
- **Secrets are stored unencrypted** in the database (the SQLite file in the
  data volume, or PostgreSQL): SMTP passwords, Telegram and Pushbullet tokens,
  webhook signing secrets, and SNMP community strings.
  The API never returns them, but anyone who can read the database can.
  Protect it and its backups.
- **SNMP is v2c.** The community string crosses the network in clear text. Use
  a read-only community that is not reused elsewhere. Cerberus only polls
  addresses inside the allowed networks unless an address was entered by hand,
  because a syslog source address can be forged.
- **Alerts contain addresses, usernames and rule names** from your network, and
  notifications send them to third-party services (your mail server, Telegram,
  Pushbullet). Choose channels accordingly.
- **API tokens are bearer credentials** too. Give agents and scripts read-only
  tokens unless they must triage; no token can change settings, channels or
  tokens. Cerberus stores only a hash, records what write tokens do in the
  audit log, and a token can be revoked at once under Settings → API & agents.
- **Agents read attacker-writable text.** Alert and event text comes from
  device logs, which anyone who can reach a device can write to. The MCP
  server tells agents to treat it as data; do not give an agent tools elsewhere
  that it could be talked into using.
- **Plaintext secrets found in logs are redacted** before events are stored
  (on by default). Turning redaction off keeps them in storage.
- **Site tokens are bearer credentials.** Anyone holding one can post alerts as
  that site to the central console. Serve the console over HTTPS only, keep
  token files out of version control, and rotate a token that may have leaked.
  The console stores only a hash of each token.
- The container runs as an unprivileged user, with a read-only root filesystem,
  and needs no capabilities.

## Never commit

`.env`, the `data/` directory (the database holds the secrets above), packet
captures, or real device logs. Sample logs in tests and tools use documentation
address ranges and invented hostnames; keep it that way.
