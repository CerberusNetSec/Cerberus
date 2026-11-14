# Security

## Reporting a vulnerability

Please report security problems privately through GitHub: on this repository
open **Security → Report a vulnerability**. Do not open a public issue for
something exploitable. Include the version (`/api/me`), how to reproduce it,
and what an attacker gains.

This is a small project maintained in spare time; there is no guaranteed
response time and no bounty.

## What to know before deploying

- **Syslog is unauthenticated and unencrypted.** Anyone who can reach the
  syslog port can inject log lines, and so create alerts or new "devices".
  Expose it only to your management network. There is no TLS listener.
- **The dashboard is plain HTTP.** Put it behind a TLS reverse proxy if it is
  reachable from anywhere you do not fully trust. It has one shared password
  and no user accounts.
- **Secrets are stored unencrypted** in the SQLite file in the data volume:
  SMTP passwords, Telegram and Pushbullet tokens, and SNMP community strings.
  The API never returns them, but anyone who can read the volume can. Protect
  the volume and its backups.
- **SNMP is v2c.** The community string crosses the network in clear text. Use
  a read-only community that is not reused elsewhere. Cerberus only polls
  addresses inside the allowed networks unless an address was entered by hand,
  because a syslog source address can be forged.
- **Alerts contain addresses, usernames and rule names** from your network, and
  notifications send them to third-party services (your mail server, Telegram,
  Pushbullet). Choose channels accordingly.
- The container runs as an unprivileged user and needs no capabilities.

## Never commit

`.env`, the `data/` directory (the database holds the secrets above), packet
captures, or real device logs. Sample logs in tests and tools use documentation
address ranges and invented hostnames; keep it that way.
