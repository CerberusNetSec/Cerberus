<p align="center"><img src="docs/logo.svg" width="128" height="128" alt="Cerberus logo: three hound heads on a shield"></p>

# Cerberus

[![CI](https://github.com/CerberusNetSec/Cerberus/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CerberusNetSec/Cerberus/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/CerberusNetSec/Cerberus?sort=semver)](https://github.com/CerberusNetSec/Cerberus/releases/latest)
[![Licence: Apache 2.0](https://img.shields.io/github/license/CerberusNetSec/Cerberus)](LICENSE)
[![Container image](https://img.shields.io/badge/image-ghcr.io%2Fcerberusnetsec%2Fcerberus-2496ED?logo=docker&logoColor=white)](https://github.com/CerberusNetSec/Cerberus/pkgs/container/cerberus)
[![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](Dockerfile)
[![Last commit](https://img.shields.io/github/last-commit/CerberusNetSec/Cerberus)](https://github.com/CerberusNetSec/Cerberus/commits/main)
[![Stars](https://img.shields.io/github/stars/CerberusNetSec/Cerberus?style=flat)](https://github.com/CerberusNetSec/Cerberus/stargazers)
[![Open issues](https://img.shields.io/github/issues/CerberusNetSec/Cerberus)](https://github.com/CerberusNetSec/Cerberus/issues)

![Connectors: 15](https://img.shields.io/badge/connectors-15-6f42c1)
![Detectors: 24](https://img.shields.io/badge/detectors-24-d73a49)
![Tests: 332](https://img.shields.io/badge/tests-332-2ea44f)
![Deployments: standalone, Compose, Swarm, Kubernetes, Helm](https://img.shields.io/badge/deploy-standalone%20%7C%20Compose%20%7C%20Swarm%20%7C%20Kubernetes%20%7C%20Helm-0366d6)

Cerberus is open-source, self-hosted network threat detection from the logs
your firewalls and switches already produce. It receives their syslog,
detects attacks and behaviour that is out of the ordinary (port scans, brute
force, lateral movement, beaconing, exposed services and more), maps them to
MITRE ATT&CK, shows them on a web dashboard with what to do about each, and
tells you by email, Telegram, Pushbullet, webhooks or any HTTP API. No agents
on your devices: OPNsense, Palo Alto, FortiGate, Cisco, Meraki, Juniper,
SonicWall, Sophos, Ubiquiti, Aruba and others send it the syslog they already can. It can also poll those devices over SNMP and draw
the network topology they describe. It runs as a single instance for a few
hundred devices, and scales out to collectors, detection workers and
clustered storage for [thousands](docs/REFERENCE-ARCHITECTURE.md), with reference
architectures up to [500,000 devices](docs/REFERENCE-ARCHITECTURE-500000.md).

**[Try the live demo](https://cerberusnetsec.github.io/Cerberus/demo/)**: the real
dashboard on simulated data, read-only. · [Website](https://cerberusnetsec.github.io/Cerberus/)

More documentation: [architecture](docs/ARCHITECTURE.md) ·
[HTTP API](docs/API.md) · [deployments](deploy/README.md) ·
reference architectures for [5,000](docs/REFERENCE-ARCHITECTURE.md),
[50,000](docs/REFERENCE-ARCHITECTURE-50000.md), [100,000](docs/REFERENCE-ARCHITECTURE-100000.md)
and [500,000 devices](docs/REFERENCE-ARCHITECTURE-500000.md) ·
[scaling plan](docs/CLUSTERING.md) · [security](SECURITY.md) ·
[contributing](CONTRIBUTING.md)

## Contents

- [Screenshots](#screenshots)
- [Quick start](#quick-start) · [Set up with an AI assistant](#set-up-with-an-ai-assistant) ·
  [Telling devices apart](#telling-devices-apart)
- [Pointing devices at it](#pointing-devices-at-it)
- [What it detects](#what-it-detects)
  - [Security detections](#security-detections) · [MITRE ATT&CK](#mitre-attck) · [High Risk Ports](#high-risk-ports) ·
    [Anomaly and health detections](#anomaly-and-health-detections) · [False positives](#false-positives)
- [Topology (SNMP)](#topology-snmp)
- [Clustered storage](#clustered-storage)
- [Scale-out ingest](#scale-out-ingest)
  - [Detection workers](#detection-workers) · [High availability](#high-availability) · [Metrics](#metrics) ·
    [Kafka authentication](#kafka-authentication)
- [Kubernetes: Helm and operators](#kubernetes-helm-and-operators)
- [Many sites](#many-sites) · [Running at scale](#running-at-scale) · Reference architectures:
  [5,000](docs/REFERENCE-ARCHITECTURE.md) · [50,000](docs/REFERENCE-ARCHITECTURE-50000.md) ·
  [100,000](docs/REFERENCE-ARCHITECTURE-100000.md) · [500,000 devices](docs/REFERENCE-ARCHITECTURE-500000.md)
- [Users, roles and single sign-on](#users-roles-and-single-sign-on) · [Audit log](#audit-log)
- [Notifications](#notifications) · [Agents and the API](#agents-and-the-api) · [Connectors](#connectors)
- [Configuration](#configuration) · [Security notes](#security-notes)
- [Questions](#questions) · [Development](#development) · [Licence](#licence)

## Screenshots

Taken from a demo instance fed by `tools/simulate.py` and `tools/snmp_sim.py`;
every address and hostname in them is simulated.

| | |
|---|---|
| [![Dashboard](docs/screenshots/dashboard.png)](docs/screenshots/dashboard.png) **Dashboard**: message rate, hosts ranked by risk, alerts by attack stage | [![Alert guidance](docs/screenshots/alert-guidance.png)](docs/screenshots/alert-guidance.png) **Alert**: why it matters and what to do |
| [![High Risk Ports](docs/screenshots/risk-ports.png)](docs/screenshots/risk-ports.png) **High Risk Ports**: traffic and findings on RDP, SMB, Telnet, FTP, HTTP and others | [![Topology](docs/screenshots/topology.png)](docs/screenshots/topology.png) **Topology**: the map built from SNMP, with alert counts per device |
| [![Alerts](docs/screenshots/alerts.png)](docs/screenshots/alerts.png) **Alerts** | [![Events](docs/screenshots/events.png)](docs/screenshots/events.png) **Events** |
| [![MITRE ATT&CK](docs/screenshots/attack.png)](docs/screenshots/attack.png) **ATT&CK**: alerts laid out in the MITRE ATT&CK matrix | [![Sites](docs/screenshots/sites.png)](docs/screenshots/sites.png) **Sites** (central console): every site's health and alerts in one place |
| [![Devices](docs/screenshots/devices.png)](docs/screenshots/devices.png) **Devices** | [![Detection](docs/screenshots/detection.png)](docs/screenshots/detection.png) **Detection settings** |
| [![Users](docs/screenshots/users.png)](docs/screenshots/users.png) **Users**: accounts, roles, single sign-on | [![Audit log](docs/screenshots/audit-log.png)](docs/screenshots/audit-log.png) **Audit log**: every sign-in and change, by whom |

## Quick start

This is the standalone deployment: one instance on one Docker host. For Docker
Swarm, Kubernetes, or several sites reporting to a central console, see
[deploy/README.md](deploy/README.md).

You need [Docker](https://docs.docker.com/get-docker/) (with the Compose
plugin) and git.

```sh
git clone https://github.com/CerberusNetSec/Cerberus.git
cd Cerberus

# optional: choose the dashboard password and the URL used in notification links
cp .env.example .env        # then edit it

docker compose up -d --build
```

- Dashboard: `http://<host>:8080`
- Syslog: UDP and TCP port `514` on the host
- If you did not set `CERBERUS_PASSWORD`, one is generated and printed once in
  `docker logs cerberus`.
- On Docker Desktop (Windows or macOS), send syslog over TCP and set
  `CERBERUS_DEVICE_IDENTITY=hostname` in `.env`
  ([why](#telling-devices-apart)).

Then point your devices at the host (below) and add a channel under
**Settings → Notifications**. To see it working before you touch a real device:

```sh
python tools/simulate.py            # port scan, brute force, exposed RDP, lateral movement, C2, ...
python tools/simulate.py --list
```

### Set up with an AI assistant

Paste this into Claude, ChatGPT, Grok or another assistant. It asks about your
setup one question at a time, gives you the exact commands for your system,
and helps with anything that goes wrong. In an agent that can run commands
(such as Claude Code), it can do the steps for you, asking first.

<!-- setup-prompt:start -->
```text
Help me install and set up Cerberus (https://github.com/CerberusNetSec/Cerberus), an open-source, self-hosted tool that detects threats from firewall and switch syslog. Act as my setup guide.

How to work with me:
- Ask me one question at a time and wait for my answer. Start by asking what I will run it on (a Linux server, Windows or macOS with Docker Desktop, or Kubernetes) and whether Docker is installed.
- Give me exact commands to copy and paste for my operating system, one step at a time, and ask me to paste back the output before moving on. If you can run commands yourself, tell me what each one does and ask before running it.
- If something fails, ask for the exact error and fix that before continuing. Never guess about my network: ask.
- If you can browse the web, read the README at the URL above and prefer it over your memory. Otherwise use the facts below.

Facts about Cerberus:
- Install: `git clone https://github.com/CerberusNetSec/Cerberus.git`, `cd Cerberus`, optionally `cp .env.example .env` and edit it, then `docker compose up -d --build`. It needs Docker with the Compose plugin and git.
- Dashboard: http://<host>:8080. The password is CERBERUS_PASSWORD in .env; if that is not set, one is generated and printed once in `docker logs cerberus`.
- Syslog is received on UDP and TCP port 514 on the host. If 514 or 8080 is taken, change the left-hand side of the port mappings in docker-compose.yml.
- On Docker Desktop (Windows or macOS): devices must send syslog over TCP, because UDP from other machines often never arrives; and set CERBERUS_DEVICE_IDENTITY=hostname in .env, because Docker Desktop hides each device's address. The host firewall must allow inbound TCP 514.
- On Linux, UDP works. For busy networks run `sysctl -w net.core.rmem_max=8388608`.
- To see alerts before touching a real device: `python tools/simulate.py` (add `--tcp` on Docker Desktop). It needs Python 3 and sends simulated attacks to port 514 on this machine.
- Devices with built-in support: OPNsense, Palo Alto, Fortinet FortiGate, Cisco IOS/IOS-XE, Cisco ASA/Firepower, Cisco Meraki, Juniper, SonicWall, Sophos Firewall, Ubiquiti, Aruba, Dell, Brocade/Ruckus, and Suricata sensors (EVE JSON). Anything else that sends standard syslog also works. The README section "Pointing devices at it" has the steps for each vendor; firewalls only log the rules that have logging switched on.
- Working means: the dashboard's "Messages / second" is above zero and the Devices page lists my devices.
- Notifications (email, Telegram, Pushbullet, webhook, custom API call) are added in the dashboard under Settings > Notifications, each with a "Send test" button.
- Keep it safe: only my management network should reach port 514; put the dashboard behind HTTPS if it is reachable from anywhere I do not trust; under Settings > Users, create named accounts and switch off the shared admin password.
- One instance suits a few hundred devices. If I have more, or want Kubernetes, point me to deploy/README.md and docs/REFERENCE-ARCHITECTURE.md in the repository before installing anything.

Ask me these as they become relevant, not all at once:
1. What will it run on, and is Docker installed?
2. Roughly how many devices, and which vendors and models?
3. Do I want to choose the dashboard password, or use a generated one?
4. For each device: can I reach its admin interface now, so we can point its syslog at Cerberus?
5. How do I want to be notified?
6. Do I want the network topology map (needs a read-only SNMP community on my devices)?

When we are done, summarise what was set up, where the dashboard is, and what I should do next.
```
<!-- setup-prompt:end -->

### Telling devices apart

Devices are identified by the source IP of their syslog packets. Docker's bridge
network preserves that on Linux. **Docker Desktop (Windows/macOS) and rootless
Docker rewrite it**, so every device appears as one address. Either run on a
Linux host with `network_mode: host`, or set `CERBERUS_DEVICE_IDENTITY=hostname`
to identify devices by the hostname in the syslog header. See the comments in
`docker-compose.yml`.

## Pointing devices at it

Cerberus listens for syslog on UDP and TCP 5514 inside the container (published
as 514). Switch the UDP, TCP and TLS listeners on or off and change their ports
under **Settings → Syslog**; changes take effect at once, and the page shows
whether each one is listening. In Docker, change the published port mapping to
match.

**On Docker Desktop for Windows, use TCP.** UDP syslog from other machines may
never reach the container even with the port published and Windows Firewall
open (seen with OPNsense: nothing arrived over UDP, TCP worked at once). If the
dashboard's "Messages / second" stays at zero, switch the device's syslog
transport to TCP on port 514 before looking anywhere else. On a Linux host UDP
works as normal.

| Device | Where | Notes |
|---|---|---|
| **OPNsense** | System → Settings → Logging → Remote: add a destination, transport UDP(4) or TCP(4), port 514 | Leave applications empty to send everything, or pick at least *filter (filterlog)*, *audit*, *suricata*, *sshd*. Firewall rules only appear if the rule has **Log** ticked. |
| **Palo Alto (PA-440)** | Device → Server Profiles → Syslog: add the server, UDP/514, format BSD. Attach it through a Log Forwarding profile on your security rules (traffic, threat) and under Device → Log Settings (system, config). | Uses the default log format. Custom log formats need an adjusted copy of the connector. |
| **Fortinet FortiGate** | `config log syslogd setting` → `set status enable`, `set server <ip>`, `set format default` | Default key=value format only (not CSV or CEF). Traffic appears for policies with logging enabled. |
| **Cisco IOS / IOS-XE** | `logging host <ip>` and `logging trap informational` | Recommended: `service timestamps log datetime msec`, `logging origin-id hostname`, `login on-failure log`, `login on-success log`. |
| **RTL-Playground** | Enable syslog and set the server IP in the switch's CLI/config | Sends UDP only. Set a hostname on the switch so its lines carry it. |
| **Cisco ASA / Firepower** | ASA: `logging enable`, `logging host <if> <ip>` (or `<ip> tcp/514`), `logging trap informational`, `logging timestamp`, `logging device-id hostname`. FTD: Platform Settings → Syslog in FMC, and *Send Syslog* in the access policy's logging. | Level 6 (informational) is needed for connections built. **Over TCP, an ASA stops passing new connections if it cannot reach the syslog server** unless you also set `logging permit-hostdown`. |
| **Juniper SRX / Junos** | `set system syslog host <ip> any info`; for traffic, `set security log mode event` and `then log session-init session-close` on the policies | The default (brief) message format. EX switches send logins, commits and link state with the same `syslog host` line. |
| **Ubiquiti UniFi / EdgeOS** | UniFi: Settings → Control Plane → Integrations (or System → Remote Logging on older versions), syslog server and port. EdgeOS: `set system syslog host <ip> facility all level info` | Firewall rules only appear when the rule's logging is on; Threat Management alerts are included. |
| **Aruba** | AOS-CX: `logging <ip> severity info`. AOS-S/ProCurve: `logging <ip>` and `logging severity info`. Mobility controller: `logging <ip>` with `logging level informational user` and `security` | Controller user authentication covers Wi-Fi and 802.1X logins, so password spraying against users is seen too. |
| **Dell / Brocade** | OS10: `logging server <ip>`. OS9 and N-series: `logging <ip>`. Brocade/Ruckus ICX: `logging host <ip>`. Fabric OS: `syslogadmin --set -ip <ip>` | N-series and other FASTPATH switches (UniFi gen 1, EdgeSwitch) send `%% Link Up/Down`, which is recognised too. |
| **Cisco Meraki** | Network-wide → General → Reporting → Syslog servers: add the server (UDP/514) and its roles (*Appliance event log*, *Flows*, *Security events*, *IDS alerts*, *URLs*, *Switch event log*, *Wireless event log*) | Meraki sends UDP only, so on Docker Desktop relay it through a Linux host. Firewall rules appear only with their syslog box ticked. Admin logins and configuration changes are in the dashboard's change log, not syslog. |
| **SonicWall** | Device → Log → Syslog: add the server, *Syslog Format* Default (not CEF), and turn on the categories to send under Log → Settings | Keep *Connection Closed* logging on: it carries the byte counts. IPS, anti-spyware and gateway anti-virus alerts, and admin and user logins, are recognised. |
| **Sophos Firewall** | System services → Log settings: add a syslog server, then tick the categories (Firewall, IPS, Anti-Virus, ATP, Events: Admin, Authentication, System) | Both the older (19.0) and newer log formats. Firewall rules appear only when *Log firewall traffic* is on in the rule. |
| **Suricata** (EVE JSON) | In `suricata.yaml`, an `eve-log` output with `filetype: syslog` (and `identity: suricata`), or forward `eve.json` with rsyslog or another shipper | Alerts, flows (with bytes each way) and protocol records. A sensor on a span port gives traffic and threat detection without firewall logging. On OPNsense, its fast.log alerts work too. |
| Anything else | Send RFC 3164 or RFC 5424 syslog | The generic connector understands OpenSSH/PAM logins, netfilter logs and common link up/down wording. Write a connector for the rest. |

## What it detects

Every threshold is editable under **Settings → Detection**, and each detector can be
switched off. The **Alerts** page refreshes itself (every 10 seconds by default;
choose 30 s, 1 or 5 minutes, or off), highlights alerts that arrived since you
opened it, and the open-alert count next to **Alerts** stays current on every page.

### Security detections

These look for specific attacker activity. Each alert opens with why it
matters, the MITRE ATT&CK technique, and numbered steps for a firewall or
network team; where the firewall logged it, the alert names the rule and zones
that allowed the traffic. Notifications carry the same guidance and link
straight to the alert.

| Detector | Fires when | Default |
|---|---|---|
| Sensitive service reachable from the internet | the firewall allows an internet address to an internal host on SSH, RDP, SMB, a database port, etc. (follows destination NAT) | 16 ports |
| Risky outbound connection | an internal host is allowed out on SMB, RDP, Telnet, IRC, Tor, SOCKS or common malware ports | 14 ports |
| Lateral movement | one internal host makes un-blocked administration connections to many internal hosts | 8 hosts / 10 min |
| Beaconing | an internal host contacts one internet address at near-constant intervals | 12 in a row, ≤10% variation |
| Password spraying / distributed guessing | one source tries many usernames, or one account is attacked from many sources | 6 users / 5 sources in 10 min |
| Unexpected administrative access | a device login from the internet, or from an address that has never managed that device; optionally activity outside working hours | learns for 24 h |
| Surge on a high-risk port | an hour's traffic on a watched port (RDP, SMB, Telnet, FTP, HTTP, databases, ...) is several times what that port normally carries, per direction, allowed and blocked judged separately | 4x and 100 connections, after 6 h of history |
| Watchlist match | traffic to or from addresses you list (incident IOCs, a feed you paste in) | empty |
| Threat not blocked | an IDS/threat signature fired but the device only alerted | on |
| Correlation: likely compromised host | one internal host shows three different kinds of attack behaviour in 24 h | 3 kinds |
| Correlation: hostile address allowed in | an internet address that was scanning or guessing passwords is later allowed through to an internal host | 24 h |
| Plaintext passwords and secrets | a password, API key, token or private key appears in clear in a log: credentials in URLs (`user:password@`, `?password=`), HTTP Basic and bearer headers quoted by an IDS or proxy, AWS, GitHub, Slack, Google and Stripe keys | on; secrets removed from stored events |

**Plaintext secrets** are looked for as each message is parsed, before it is
stored. What is found is replaced in the stored event by `[REDACTED kind
fingerprint]`, so Cerberus does not keep other people's passwords; the alert
shows the kind, where it was seen, a preview that never reveals it (`AKIA…
(20 characters)`) and a fingerprint, so the same secret seen again folds into
one alert. The fingerprint is keyed per installation and cannot be turned back
into a password. Values a device has already masked (`****`, `<hidden>`) are
left alone. Switch it off, or keep the alerts but stop the redaction, under
**Settings → Detection → Plaintext passwords and secrets**.

### MITRE ATT&CK

The **ATT&CK** page lays the alerts out in the MITRE ATT&CK Enterprise matrix:
the 14 tactics as columns, and each technique Cerberus detects as a cell shaded
by how many alerts it had (darker is more; the count is on every cell), over
24 hours to all time, with or without false positives. A cell links to its
alerts. Tactics Cerberus cannot see from network logs (Execution, Collection
and others) say so, and alerts with no ATT&CK technique (a correlated
compromise, network health) are counted separately. A technique that ATT&CK
lists under several tactics is shown once, under the one that fits the
detector, so nothing is counted twice. To show only the tactics Cerberus has
detectors for, tick **Settings → General → Hide tactic columns Cerberus has no
detector for**.

### High Risk Ports

The **High Risk Ports** page is a standing view of the services attackers go for
first: remote access (RDP, SSH, Telnet, VNC, WinRM), file sharing (SMB,
NetBIOS, NFS, FTP, TFTP), clear-text protocols (HTTP, POP3, IMAP, LDAP) and
databases. For each port it shows allowed connections from the internet, to
the internet and inside the network, blocked connections, a trend line, and
any open alerts that name the port. Ports with a finding are listed first:

| Finding | Meaning |
|---|---|
| Open to the internet | the firewall allowed internet addresses in on this port (web ports are marked lower: expected for a public web server) |
| Surge | traffic in one direction is well above this port's own history |
| Allowed out to the internet | SMB, RDP, Telnet, FTP and the like leaving the network (web and SSH are not flagged) |
| New sources | internal hosts that started using the port in the last 24 hours |
| Clear-text protocol in use | FTP, Telnet, POP3, IMAP or LDAP was allowed somewhere |

Click a port for why it is on the list, a chart, the busiest sources and
destinations in each direction, and links to the matching events and alerts.
Alerts that involve a port link back here.

The list is yours to change: **Edit the list of ports and protocols** on the
page (or **Settings → Detection → High-risk port activity**) has one row per port and
protocol. **Any** counts every protocol on that port; **TCP** or **UDP**
counts only that one, plus traffic whose protocol the device did not log, so
nothing slips through unlabelled. Give a port your own service name (an
in-house admin portal on 8443/tcp, say), remove ports you do not care about,
or restore the built-in list. A port narrowed to one protocol is shown as
`161/udp` on the page and in its alerts. Lists saved by earlier versions (port
numbers only) keep working and mean any protocol. Blocked probes from the internet on these ports are constant
background noise and are counted but not treated as a finding unless they
surge.

It only knows what firewalls log: a rule without logging, and traffic that
never crosses a firewall, do not appear.

The dashboard ranks **hosts needing attention** by a risk score (severity of
each unresolved alert, weighted up when a host shows several kinds of
behaviour) and breaks alerts down by attack stage.

Expect to tune these in the first week. Add scanners, management and backup
servers to **ignored sources**; add servers that are public on purpose, and
internet services you have confirmed are legitimate, to **ignored
destinations**. An alert's detail has a one-click "stop alerting on this
source". Beaconing in particular also matches monitoring agents and update
checkers until their destinations are ignored.

What these cannot see: anything the firewall does not log (rules without
logging, traffic inside one VLAN that never crosses a firewall), the contents
of encrypted traffic, and DNS queries unless the firewall logs them as traffic
or threats. There is no geolocation or built-in threat feed; the watchlist is
whatever you paste into it.

### Anomaly and health detections

| Detector | Fires when | Default |
|---|---|---|
| Port scan | one source hits many ports on one destination | 25 ports / 60 s |
| Host sweep | one source tries one port on many hosts (blocked attempts) | 20 hosts / 60 s |
| Blocked-traffic flood | one source has a large number of connections blocked | 300 / 60 s |
| Login brute force | repeated failed logins from one source; **critical** if a success follows | 5 / 5 min |
| IDS / threat log | the device itself reports a threat (PAN-OS threat log, Suricata) | vendor severity ≥ low |
| Notable device events | port-security / DHCP-ARP inspection violations, loops, spanning-tree guards, MAC flaps, restarts, config changes, critical-level syslog | on |
| Link flapping | an interface changes state repeatedly | 6 / 5 min |
| Large outbound transfer | an internal host sends a lot to the internet (needs byte counts, e.g. PAN-OS) | 2 GB / 10 min |
| Traffic rate anomaly | a device logs far above its learned per-minute baseline, overall or blocked | 4σ, ≥3× baseline, after 30 min |
| Device went silent | a normally chatty device stops sending. Five or more within 10 minutes become one "several devices went silent together" alert | 15 min |
| New log source | an address that never sent logs before starts. More than ten within 10 minutes become one alert | quiet for the first 30 min after install |
| Topology change | a device gains or loses an LLDP/CDP neighbour between SNMP polls (needs SNMP polling) | on |

Scans, sweeps and floods from an internal address are rated higher than the
same thing from the internet, where it is background noise. Repeats of one
problem fold into a single alert with a count (30 minutes by default), and you
are notified once per alert, again only if it escalates.

**Ignored sources** (Settings → Detection → General) exempts addresses such as a
vulnerability scanner from the source-based detectors.

What the detectors have learned (rate baselines, sliding windows, admin
sources, correlation, risk-port history) is saved every 5 minutes and at
shutdown, so a restart does not start them from scratch. A new installation
needs about 30 minutes of traffic before the rate and silence detectors judge
anything.

### False positives

When an alert is expected behaviour (a vulnerability scanner, a backup job, a
monitoring system), open it on the **Alerts** page and choose **Mark as false
positive**. You give your name and a justification (at least 10 characters).

- **The same finding never alerts again:** the same detector on the same
  entity (the address, address pair or account in the alert) raises no alert
  and sends no notification, and no longer counts towards correlated
  "likely compromised host" alerts. Other detectors still alert on it, and the
  same detector still alerts on anything else.
- **Nothing is silently hidden:** the **False positives** page lists every
  suppression with how many findings it has held back and when it last did,
  and a suppression can be removed (again with a name and a justification).
- **Audited:** each marking and removal is recorded with the time, the name
  given, the address it came from and the justification, in an audit log that
  cannot be edited or deleted. There are no individual accounts yet, so the
  name is what the analyst types.

To silence everything from an address instead, use **Stop alerting on ... as
a source** (Settings → Detection → General).

## Topology (SNMP)

Switch it on under **Topology → SNMP polling** and enter a read-only community
string. Every device that sends logs is then polled (every 5 minutes by
default) for its identity, interfaces and LLDP/CDP neighbours, and the map is
drawn from the result:

- Solid nodes are log sources. Dashed nodes are devices that only a neighbour
  has reported - something on your network that is not sending logs here.
- A coloured ring and a count mark devices with open alerts. Click a device for
  its system details, links, and per-interface speed and traffic rate.
- Drag devices to arrange the map; positions are remembered in your browser.
- Alerts link to their device on the map.
- On a large network the map opens zoomed out to show everything. Use **+ / −
  / Fit**, Ctrl + scroll, or drag the background; type in **Find a device** and
  press Enter to jump to one.
- Phones, access points and anything else that only one switch reports and that
  sends no logs are folded away once there are more than 40 of them. Tick
  **Show endpoints** to draw them.

On each device: enable SNMP v2c with that community, allow queries from the
Cerberus host (UDP 161 outbound from the container, which Docker's default
networking permits), and enable LLDP (or CDP on Cisco). A device that does not
speak SNMP still appears if a neighbour that does can see it.

Per device, on the **Devices** page, you can use a different community, turn
polling off, or give a different address to poll (`ip` or `ip:port`) for when
the management address is not the one its syslog comes from.

Limits to know about:

- **SNMP v2c only** - no SNMPv3, and IPv4 targets only. v2c sends the community
  string unencrypted.
- Because a syslog source address can be forged, Cerberus only polls addresses
  inside the allowed networks (private ranges by default) unless you typed the
  address in yourself. Use a read-only community that is not reused elsewhere.
- Links come from LLDP and CDP, so only devices that run one of them are
  placed. Endpoints (PCs, printers) are not mapped: that needs the switches'
  MAC tables, which are not read yet.
- A neighbour has to be missing from two polls in a row before it is reported
  as gone, so "lost" alerts lag by one poll interval.
- Sixteen devices are polled at a time (adjustable). A device that keeps failing
  is retried less and less often, down to once an hour, so devices that will
  never answer do not slow the rest; the Devices page shows when the next try is.

To try it without hardware: `python tools/snmp_sim.py` starts fake agents for
the devices that `tools/simulate.py` logs as (run Cerberus with
`CERBERUS_DEVICE_IDENTITY=hostname`), then set each device's SNMP address to
the one it prints. `--rogue` adds an unexpected switch to trigger the alert.
`--sites 30` serves a 302-device campus instead.

## Clustered storage

By default everything is kept in one SQLite file. For more history, faster
searches, or databases your team already runs and backs up, Cerberus can use
**PostgreSQL** (alerts, devices, settings, channels, sessions, console sites)
and **ClickHouse** (events and per-minute counters) instead:

```sh
CERBERUS_POSTGRES_URL=postgresql://cerberus:PASSWORD@db-host:5432/cerberus
CERBERUS_CLICKHOUSE_URL=http://cerberus:PASSWORD@ch-host:8123/cerberus
```

Both must be set; the tables are created on first start. Behaviour is
identical: the same reference traffic produces exactly the same alerts,
stored events and API answers on either backend (tested in CI against real
servers). On the load test ClickHouse stored an event in about 100 bytes
against SQLite's 830 and searched message text over all stored events in
50 ms; real logs compress less than simulated ones.

- **Try it:** `python deploy/make-secrets.py --storage` then
  `docker compose -f deploy/compose/clustered-storage.yml up -d --build`
  runs Cerberus with both databases on one host.
- **Kubernetes:** add the `components/clustered-storage` component to any
  layer; see [deploy/README.md](deploy/README.md).
- **Moving an installation across:** stop Cerberus, then
  `python tools/migrate.py --from data/cerberus.db --postgres ... --clickhouse ...`
  (also in the image). Everything moves, the detectors' learned state
  included; the SQLite file is only read.

Expiry with ClickHouse drops whole hours of events, so the total can exceed
`CERBERUS_MAX_EVENTS` by up to an hour's worth. A batch is written to
ClickHouse and then PostgreSQL as two writes, not one transaction.

## Scale-out ingest

One process parses about 15,000 messages a second, and parsing is most of the
work. For more, run several **collectors** (`CERBERUS_MODE=collector`) that
receive and parse syslog and publish the events to a Kafka-compatible bus, and
one **processor** (`CERBERUS_MODE=processor`) that records, detects, alerts
and serves the dashboard. Clustered storage is required.

- **Collectors are stateless and interchangeable.** Put them behind a load
  balancer: Kubernetes keeps device addresses with
  `externalTrafficPolicy: Local` (TCP and UDP); HAProxy passes them over TCP
  with PROXY protocol, which collectors accept only from the addresses in
  `CERBERUS_PROXY_PROTOCOL_FROM`.
- **Nothing is lost if the bus goes down.** A collector spools events to its
  own folder on disk and sends them, in order, when the bus is back; the
  folder of a collector that is replaced is picked up by another. Every event
  carries a unique id, and the processor ignores copies, so events sent twice
  around an outage are stored once.
- **The processor commits its place on the bus only after storing.** If it
  crashes, it re-reads at most the last second or so of events (at least
  once).
- **Health:** collectors send a heartbeat every 15 seconds; the processor's
  dashboard shows them and raises "Collector stopped reporting" when one goes
  quiet. Each collector's own counters are at `:8080/status`.
- **Storage thresholds:** every collector and detection worker reports how
  full its spool is (against `CERBERUS_SPOOL_MB`) and how full the volume under
  it is. Past the warning threshold (70% by default) the processor raises a
  medium alert, past the critical one (90%) a high alert, each with what to
  do; set them under **Settings → General → Collector storage**, which also
  lists every process's storage. A spool fills while the bus is unreachable,
  when no heartbeat gets through, so the collector also warns in its own log,
  and its first heartbeat afterwards carries the peak: you are told a spool
  reached 93% even if it has emptied again. A bus that stops answering counts
  as down after 20 seconds.
- **Syslog over TLS** (RFC 5425) is available in every mode
  (`CERBERUS_SYSLOG_TLS_PORT`, usually 6514), optionally requiring device
  certificates.

### Detection workers

When one processor cannot keep up with detection, run **detection workers**
(`CERBERUS_MODE=detector`). Detectors fall into families by what they count:

| Family | Keyed by | Detectors |
|---|---|---|
| `source` | source address | port scans, host sweeps, floods, brute force, password spraying, threats, large transfers, risky egress, lateral movement, beaconing, hostile addresses allowed in |
| `target` | target host | services exposed to the internet |
| `pair` | address pair | watchlist |
| `port` | port | high-risk ports (and the High Risk Ports page) |
| `account` | account | one account guessed from many addresses |

Set `CERBERUS_DETECTION_WORKERS=all` (or some of the families) on the
collectors, the processor and the workers, and run workers with
`CERBERUS_DETECTION_FAMILY` set to their family; run as many of each as you
need. Collectors send each family the events it reads, divided by its key, so
everything about one source address (say) reaches the same worker. Workers send
what they find back over the bus; the processor keeps per-device detection
(rate baselines, silent and new devices, link flaps, notable events, admin
access), correlation, alerts and notifications. Workers read detector settings
from storage every 30 seconds, so dashboard changes reach them.

- **Bus traffic grows:** an event goes to the event topic and to each family
  that reads it - with every family offloaded, firewall traffic is sent about
  four times.
- **Workers rebuild their state from the bus.** When a worker starts, or the
  bus moves partitions between workers, it replays the last
  `CERBERUS_WORKER_REPLAY_MINUTES` (default 60) of its partitions, detecting
  without raising anything, so a replaced worker neither misses nor repeats
  alerts. Each worker sends a heartbeat; the processor raises "Detection
  worker stopped reporting" when one goes quiet.
- The same alerts are found as by one process: `tests/test_workers.py` and
  `tests/test_bus.py` run the reference traffic through workers and compare.

### High availability

Run two processors (or more): one is active, the others wait as standbys
(leadership is a lock in PostgreSQL). A standby is alive (`/healthz`) but not
ready (`/readyz` answers 503), so a load balancer or Kubernetes Service sends
the dashboard only to the active one. When the active processor stops or
crashes, a standby takes over within seconds:

- **Exactly where the old one left off.** The processor saves its detector
  state every minute together with the bus position it matches. The new
  leader goes back to that position and replays up to what was stored,
  through detection only, so windows and baselines are rebuilt and nothing is
  stored or raised twice.
- **Notifications go through an outbox:** they are stored with their alert
  and sent afterwards, retried at 1, 2, 4 and 8 minutes if a channel fails.
  A takeover neither loses one nor sends one twice (except in the moment
  between sending and recording it).
- **A leader that loses PostgreSQL stops at once**, so two processors never
  write together; its restart brings it back as a standby.

Checked by `tests/test_bus.py` (a processor that dies after its checkpoint
and a successor that takes over: exactly what one uninterrupted process
stores) and live on Compose (the active processor killed: the dashboard back
in 8 seconds, every event stored once).

### Metrics

Every role serves Prometheus metrics at `:8080/metrics`: events, errors,
write times, alerts, notifications and the outbox on the processor; messages,
spool and bus state on collectors (`cerberus_spool_bytes`,
`cerberus_spool_limit_bytes`, `cerberus_spool_volume_bytes` and
`cerberus_spool_volume_free_bytes`, for alerting on storage from Prometheus
too); events, candidates and rebuilds on workers; `cerberus_active` is 1 on
the active processor and 0 on a standby.
Set `CERBERUS_METRICS_TOKEN` to require `Authorization: Bearer <token>`.

Reference deployments: `deploy/compose/scale-out.yml` (HAProxy, collectors,
Redpanda, detection workers, two processors, both databases), the Helm chart
(below) and the Kubernetes `collector`, `detector` and `processor` layers; see
[deploy/README.md](deploy/README.md) and [docs/CLUSTERING.md](docs/CLUSTERING.md).

### Kafka authentication

Collectors, processors and workers can sign in to the bus with a username and
password (SASL), with or without TLS:

```sh
CERBERUS_KAFKA_SECURITY=SASL_SSL            # or SASL_PLAINTEXT on a trusted network
CERBERUS_KAFKA_SASL_MECHANISM=SCRAM-SHA-512 # or SCRAM-SHA-256, PLAIN
CERBERUS_KAFKA_USERNAME=cerberus
CERBERUS_KAFKA_PASSWORD_FILE=/run/secrets/kafka_password
CERBERUS_KAFKA_CA=/run/secrets/kafka-ca.crt # SASL_SSL with a private CA
```

`PLAIN` sends the password as it is, so use it only with `SASL_SSL`. Cerberus
needs to read and write its topics (`cerberus.events` and the topics that start
with it) and to use the consumer groups that start with `cerberus`; it creates
the topics itself when allowed to, and otherwise expects them to exist. CI runs
against a Redpanda that requires SCRAM-SHA-512.

## Kubernetes: Helm and operators

The Helm chart in [`deploy/helm/cerberus`](deploy/helm/cerberus) installs
Cerberus either **standalone** (one pod with a volume, SQLite) or **scaled
out** (collectors behind a `LoadBalancer` that keeps device addresses, a
processor with a standby, and a detection-worker Deployment per family):

```sh
helm install cerberus deploy/helm/cerberus -n cerberus --create-namespace \
  --set auth.password='choose-one' --set publicUrl=https://cerberus.example.com
```

The scaled-out form needs Kafka, PostgreSQL and ClickHouse.
[`deploy/kubernetes/operators`](deploy/kubernetes/operators) runs them with
their operators:

| Store | Operator | What you get |
|---|---|---|
| Kafka | [Strimzi](https://strimzi.io) 1.x | 3 KRaft nodes, a TLS listener with SCRAM-SHA-512, a `KafkaUser` limited to Cerberus's topics and groups |
| PostgreSQL | [CloudNativePG](https://cloudnative-pg.io) | 3 instances with streaming replication and automatic failover |
| ClickHouse | [Altinity operator](https://github.com/Altinity/clickhouse-operator) | one server (Cerberus's tables are not replicated; back it up) |

```sh
kubectl apply -k deploy/kubernetes/operators        # after installing the operators
helm install cerberus deploy/helm/cerberus -n cerberus -f deploy/helm/cerberus/values-operators.yaml \
  --set auth.password='choose-one' --set publicUrl=https://cerberus.example.com
```

`values-operators.yaml` takes the database URLs and the Kafka password from
the Secrets the operators write, so the only credential made by hand is
ClickHouse's. Step by step, with the operator installs, in
[deploy/README.md](deploy/README.md#kubernetes-with-helm-and-operators).
Tested end to end in k3s: syslog in, an alert out, data in both stores.

## Many sites

For more devices than one instance handles, run one Cerberus per site and
connect them to a central console (`CERBERUS_CENTRAL=on`). Each site keeps
collecting and analysing on its own; the console shows every site's alerts,
sends the notifications, hands acknowledgements back to the sites, and alerts
when a site stops reporting. The reference deployments (standalone,
Compose, Swarm, Kubernetes and Helm) and the settings are in
[deploy/README.md](deploy/README.md). A published image is at
`ghcr.io/cerberusnetsec/cerberus`.
For one large estate, [docs/REFERENCE-ARCHITECTURE.md](docs/REFERENCE-ARCHITECTURE.md)
sizes a scale-out cluster (and several under one console) for 5,000 devices.
Beyond that, clusters are grouped into regions that share Kafka, PostgreSQL
and ClickHouse, under one console: reference architectures for
[50,000](docs/REFERENCE-ARCHITECTURE-50000.md),
[100,000](docs/REFERENCE-ARCHITECTURE-100000.md) and
[500,000 devices](docs/REFERENCE-ARCHITECTURE-500000.md).

## Running at scale

A standalone Cerberus is one process and one SQLite file. That is enough for
a few hundred devices; these are the things that decide whether it is enough
for yours. Past that, see [Scale-out ingest](#scale-out-ingest) and the
[reference architecture for 5,000 devices](docs/REFERENCE-ARCHITECTURE.md).

**Message rate, not device count, is the limit.** Parsing and detection run on
one CPU core. On the development machine (a desktop PC) that core handled about
15,000 messages a second, and a test of the whole application with 302
simulated devices sending 6,000 a second over UDP lost none. Switches send a
few messages a minute; firewalls logging every connection send the rest.
`python tools/loadtest.py` measures your own hardware. The dashboard's
**Dropped messages** tile says when the queue overflowed, the disk is slow or a
limit was hit.

**Decide what to keep.** Every message is analysed, but storing every allowed
connection is what fills the disk: an event takes about 850 bytes.

| Average rate | Events per day | Disk per day, storing everything |
|---|---|---|
| 100/s | 8.6 million | about 7 GB |
| 1,000/s | 86 million | about 73 GB |
| 5,000/s | 432 million | about 370 GB |

The default cap of 2,000,000 events is about 1.7 GB, and at 1,000 messages a
second that is 33 minutes of history. The dashboard's **Searchable history** tile
shows how far back your events actually go. To make it longer:

- Raise `CERBERUS_MAX_EVENTS` to what your disk allows. Events are stored in
  segments of up to 250,000, and only the newest is written to, so writing does
  not get slower as more is kept (in the load test it took the same time per
  batch with 1.25 million events stored as with none). Old segments are dropped
  whole, so the total can run up to two segments over the cap.
- Set `CERBERUS_TRAFFIC_SAMPLE=20` to store one allowed connection in twenty, or
  `0` to store none. Blocked traffic, threats, logins and device events are
  always stored, and the detectors still see every message, so alerts are
  unaffected - but the Events page then shows only a sample of ordinary traffic.
- Turn off logging of allowed traffic on firewall rules where you do not need
  it. Note that exposure, lateral-movement, beaconing and data-transfer
  detection all depend on allowed-traffic logs.

Alerts are small and kept for 90 days regardless.

**Searches stay fast when they name something.** A device, an address or a port
is found through an index whatever the table size. Free-text search has to read
every event in the chosen time range, so keep the range short; a search still
running after 10 seconds is stopped rather than left to slow everyone else down.

**Network settings.**

- UDP syslog is lost silently if the kernel's receive buffer fills during a
  burst. Cerberus asks for 4 MB; Linux grants at most `net.core.rmem_max`, so on
  the Docker host run `sysctl -w net.core.rmem_max=8388608` (and persist it).
- Run on Linux with `network_mode: host` or the default bridge so each device
  keeps its own source address (see [Telling devices apart](#telling-devices-apart)).
- Devices that send syslog over TCP hold a connection open each:
  `CERBERUS_MAX_TCP_CLIENTS` (default 1,000).

**What grows with the estate, and how it is kept in check.**

- One device or site going down, or a rollout of new devices, raises one alert
  that counts the devices rather than one alert each.
- The Devices page filters by status, connector and text, and sorts by longest
  quiet; SNMP polling runs sixteen devices at a time and backs off from ones
  that do not answer.
- Up to 5,000 log sources are tracked (`CERBERUS_MAX_DEVICES`). Beyond that new
  sources are ignored (and the dashboard says so), which also bounds what
  forged source addresses can do.

**When one instance is not enough.** For sustained rates beyond what one core
parses, or for high availability, run the [scale-out](#scale-out-ingest)
form: several collectors, detection workers, an active and a standby
processor, PostgreSQL and ClickHouse. If you need months of every flow
searchable, put a log platform (a SIEM or a syslog pipeline with its own
storage) in front and send Cerberus the firewall and switch logs you want
analysed.

## Notifications

Add channels under **Settings → Notifications**; each has a minimum severity and a **Send test** button.

- **Email (SMTP)**: server, port, STARTTLS/SSL/none, optional login, any number of recipients.
- **Telegram**: create a bot with @BotFather, send it a message, and use the bot token plus your chat ID (several IDs may be comma-separated; group IDs work too).
- **Pushbullet**: an access token from your account settings; optionally an email or channel tag to target.
- **Webhook**: POSTs each alert as JSON to a URL (the payload is in [docs/API.md](docs/API.md#webhook-payload)).
  With a signing secret, `X-Cerberus-Signature: sha256=<HMAC-SHA256 of timestamp + "." + body>` and
  `X-Cerberus-Timestamp` let the receiver check it came from Cerberus and is recent. Extra headers are allowed.
- **Custom API call**: any method, URL, headers and body, for ticketing systems, chat tools or SOAR platforms.
  Placeholders such as `{{title}}`, `{{severity}}`, `{{src_ip}}`, `{{link}}` and `{{payload}}` (the whole alert)
  fill in the alert; they are escaped for where they are (JSON-escaped in a JSON body, URL-encoded in the URL),
  and a JSON body is checked when you save. For example, a Slack-style incoming webhook:
  `{"text": "{{subject}}: {{description}} {{link}}"}`.

A channel sends at most 10 notifications a minute; anything beyond that arrives
as one "N more alerts" summary. Notifications are stored with their alert and
sent from there about a second later; one that fails is tried again at 1, 2, 4
and 8 minutes. Credentials are stored in the database (SQLite in
the data volume, or PostgreSQL) and are never returned by the API.

## Agents and the API

AI agents can monitor Cerberus through its built-in **MCP server**, and scripts
through its **HTTP API**. Create a token under **Settings → API & agents**:

- **Read only** (recommended): everything the dashboard shows.
- **Read and triage**: also acknowledge, resolve and mark false positives,
  recorded in the audit log against the token.
- No token can change settings, notification channels or tokens: those need the
  dashboard. Tokens are shown once, stored as a hash, and can be revoked.

The page shows the setup for the token it just made. For Claude Code:

```sh
claude mcp add --transport http cerberus https://cerberus.example:8080/mcp \
  --header "Authorization: Bearer cerb_..."
```

Any MCP client that speaks streamable HTTP works the same way (URL
`/mcp`, the token as a bearer header). The tools: `get_status`, `list_alerts`,
`get_alert` (with why it matters, what to do, and the ATT&CK technique),
`search_events`, `list_devices`, `get_attack_matrix`, `get_high_risk_ports`,
and with a triage token `set_alert_status` and `mark_false_positive`. The
server tells agents that alert and event text comes from network devices, which
attackers can write to, and must be treated as data, not instructions.

For scripts, the same token works on the HTTP API ([docs/API.md](docs/API.md)):
`curl -H "Authorization: Bearer cerb_..." https://cerberus.example:8080/api/alerts?status=open`.

## Users, roles and single sign-on

Out of the box there is one shared dashboard password, which signs in as the
**built-in admin**. To know who did what, give people their own accounts under
**Settings → Users**, or let them sign in through your identity provider. Each
account has a role:

| Role | Can |
|---|---|
| **Viewer** | see everything: dashboards, alerts, events, devices, topology |
| **Analyst** | also acknowledge and resolve alerts and mark false positives |
| **Admin** | also change settings, notification channels, users and API tokens |

Local accounts have their own password (12 characters or more, stored as a
scrypt hash), which they can change from the menu under their name. Once you
have an admin account of your own, switch the built-in admin off on the same
page. Cerberus will not let you lock everyone out: the last working admin
cannot be removed, and the built-in admin stays on while single sign-on has no
admin group.

**Single sign-on** works with any OpenID Connect provider: Okta, Microsoft
Entra ID, Google, Keycloak, Authentik and others. Register Cerberus as a web
application with the redirect URL `https://<your Cerberus>/api/auth/oidc/callback`,
then set:

```sh
CERBERUS_PUBLIC_URL=https://cerberus.example.com
CERBERUS_OIDC_ISSUER=https://login.example.com/realms/corp
CERBERUS_OIDC_CLIENT_ID=cerberus
CERBERUS_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_secret
CERBERUS_OIDC_ADMIN_GROUPS=netsec-admins
CERBERUS_OIDC_ANALYST_GROUPS=netsec,soc
CERBERUS_OIDC_VIEWER_GROUPS=noc
```

The login page then shows **Sign in with single sign-on**. Roles come from the
groups in the ID token (`CERBERUS_OIDC_ROLE_CLAIM`, default `groups`; the
userinfo endpoint is asked when the token has none) and are refreshed at every
sign-in, so taking someone out of a group takes effect the next time they sign
in. Someone in none of the groups is refused, unless you set
`CERBERUS_OIDC_DEFAULT_ROLE`. The provider must use HTTPS; Cerberus uses the
authorization code flow with PKCE and checks the token's issuer, audience,
expiry and nonce.

Signed-in names are recorded on everything people do: an alert's
acknowledgement, a false positive's justification, the audit log. API tokens
act as viewers (read-only tokens) or analysts (triage tokens).

## Audit log

**Settings → Audit log** (analysts and admins) lists every sign-in, failed
sign-in and change: who, from which address, when, and what, with the request's
details. Passwords, tokens, community strings and other secrets are masked
before they are stored. Entries cannot be edited or deleted through Cerberus.
The same entries are at `GET /api/audit`.

## Connectors

A connector is a YAML file that turns one vendor's log text into normalised
fields. Built-ins are in `cerberus/connectors_builtin/`. Put your own in the
`connectors/` folder of the data volume (a file with the same `id` replaces a
built-in), then press **Reload definitions** under Settings → Connectors. That page
also has a box to paste a raw log line and see exactly how it parses.

```yaml
id: my_switch
name: My switch
priority: 50              # lower is tried first; generic is 1000
match:                    # claim a message if ANY of these regexes matches
  app: ['^myswitchd$']    # fields: app, hostname, message, raw (everything after <PRI>)
  message: ['^PORT-']
rules:                    # first rule that applies wins
  - name: link
    pattern: 'PORT-(?P<interface>\d+) link (?P<state>up|down)'   # parser: regex (default)
    set: {event_type: link_state}

  - name: firewall
    when: {app: '^fw$'}   # optional precondition; ALL listed fields must match
    parser: csv
    columns: [action, proto, src_ip, src_port, dst_ip, dst_port]   # null skips a column
    set: {event_type: traffic}
    map: {action: {permit: allow, _default: block}}                # translate values
```

Parsers: `regex` (named groups), `csv` (`columns` in order and/or `fields:
{name: index}`, plus nested `switch: {field: <name>, cases: {...}, default:
{...}}` layouts and `extract` to regex a column), `kv` (`key=value` pairs, values
bare or in double or single quotes, with `rename`), `json` (with `rename`;
nested objects become dotted names such as `alert.severity`). Renames apply in
the order written. Any rule can add `extract: [{from: <field>,
patterns: [...]}]` to pull named groups out of a field it already parsed, as
the Fortinet connector does to get the client address out of `ui="ssh(10.0.0.5)"`;
`from: message` reads the message itself when no parsed field has that name,
which is how the Meraki connector reads the device name in front of its
key=value pairs. Extracted values fill gaps and never replace a parsed field. `source: raw` runs a rule against the text
before the header was stripped.

Fields the detectors use:

| Field | Values |
|---|---|
| `event_type` | `traffic`, `threat`, `auth_failure`, `auth_success`, `link_state`, `config_change`, `security_violation`, `stp_guard`, `loop_detected`, `mac_flap`, `stp_change`, `system_restart`, `system`, or anything else (stored, not analysed) |
| `action` | `allow` or `block` |
| `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `bytes` | traffic details |
| `user`, `interface`, `state`, `hostname` | context |
| `level` | vendor importance: `info`, `low`, `medium`, `high`, `critical` |

Any other captured name is kept with the event and shown in the UI.

If a device's logs are attributed to the wrong connector, pin one on the
**Devices** page.

## Configuration

| Variable | Default | |
|---|---|---|
| `CERBERUS_PASSWORD` | generated | Dashboard password (the [built-in admin](#users-roles-and-single-sign-on)) |
| `CERBERUS_AUTH` | `on` | `off` disables the login (only behind your own authenticating proxy) |
| `CERBERUS_PUBLIC_URL` | | Base URL for links in notifications |
| `CERBERUS_DEVICE_IDENTITY` | `ip` | `ip` or `hostname` |
| `CERBERUS_RETENTION_DAYS` | `7` | How long events are kept |
| `CERBERUS_MAX_EVENTS` | `2000000` | Hard cap on stored events (see [Running at scale](#running-at-scale)) |
| `CERBERUS_TRAFFIC_SAMPLE` | `1` | Store one in N *allowed* traffic events; `0` stores none. Detection still sees all of them |
| `CERBERUS_MAX_TCP_CLIENTS` | `1000` | Syslog-over-TCP connections accepted at once |
| `CERBERUS_MAX_DEVICES` | `5000` | Log sources tracked; messages from further ones are ignored |
| `CERBERUS_ALERT_RETENTION_DAYS` | `90` | |
| `CERBERUS_SYSLOG_UDP_PORT` / `_TCP_PORT` | `5514` | Inside the container; `0` disables. Once listeners are saved under Settings → Syslog, those win |
| `CERBERUS_WEB_PORT` | `8080` | |
| `CERBERUS_DATA_DIR` | `/data` | SQLite database and user connectors |
| `CERBERUS_PASSWORD_FILE` | | Read the password from a file instead (Docker and Kubernetes secrets) |
| `CERBERUS_CENTRAL_URL`, `CERBERUS_CENTRAL_TOKEN[_FILE]`, `CERBERUS_SITE_NAME`, `CERBERUS_CENTRAL_CA` | | Report to a central console (see [deploy/README.md](deploy/README.md)) |
| `CERBERUS_CENTRAL`, `CERBERUS_SITE_TOKENS_FILE`, `CERBERUS_SITE_SILENT_MINUTES` | `off`, , `5` | Act as the central console |
| `CERBERUS_POSTGRES_URL`, `CERBERUS_CLICKHOUSE_URL` (or `_FILE`) | | Store data in PostgreSQL and ClickHouse instead of SQLite; set both (see [Clustered storage](#clustered-storage)) |
| `CERBERUS_MODE` | `all` | `collector`, `processor` or `detector` for [scale-out ingest](#scale-out-ingest) |
| `CERBERUS_DETECTION_WORKERS`, `CERBERUS_DETECTION_FAMILY` | | Families run by [detection workers](#detection-workers) (`all`, or a comma-separated list), the same everywhere; and a worker's own family |
| `CERBERUS_WORKER_REPLAY_MINUTES` | `60` | How far back a detection worker replays the bus to rebuild its windows |
| `CERBERUS_METRICS_TOKEN` (or `_FILE`) | | Require this bearer token for [`/metrics`](#metrics) |
| `CERBERUS_KAFKA_BOOTSTRAP`, `_TOPIC`, `_GROUP`, `_PARTITIONS`, `_REPLICATION`, `_SECURITY`, `_CA` | | The message bus between collectors and the processor; `_SECURITY` is `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT` or `SASL_SSL` |
| `CERBERUS_KAFKA_SASL_MECHANISM`, `_USERNAME`, `_PASSWORD` (or `_FILE`) | `SCRAM-SHA-512` | [Kafka authentication](#kafka-authentication) |
| `CERBERUS_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET` (or `_FILE`), `_REDIRECT_URL`, `_SCOPES`, `_LABEL` | | [Single sign-on](#users-roles-and-single-sign-on); the redirect URL defaults to `CERBERUS_PUBLIC_URL` + `/api/auth/oidc/callback`, the scopes to `openid email profile groups` |
| `CERBERUS_OIDC_ROLE_CLAIM`, `_ADMIN_GROUPS`, `_ANALYST_GROUPS`, `_VIEWER_GROUPS`, `_DEFAULT_ROLE` | `groups` | Which groups get which role (comma-separated), and the role for people in none of them (default: refused) |
| `CERBERUS_COLLECTOR_NAME`, `CERBERUS_SPOOL_MB`, `CERBERUS_COLLECTOR_SILENT_SECONDS` | hostname, `1024`, `90` | Collector identity, spool size while the bus is unreachable, and when the processor calls a collector silent |
| `CERBERUS_SYSLOG_TLS_PORT`, `_TLS_CERT`, `_TLS_KEY`, `_TLS_CLIENT_CA` | `0` | Syslog over TLS (RFC 5425), optionally requiring device certificates |
| `CERBERUS_PROXY_PROTOCOL_FROM` | | Load balancer addresses whose TCP connections start with a PROXY protocol header carrying the device's address |

## Security notes

- Plain syslog is unauthenticated and unencrypted. Keep port 514 reachable only
  from your management network; anyone who can reach it can inject log lines
  (and so alerts). Syslog over TLS (`CERBERUS_SYSLOG_TLS_PORT`) encrypts it, and
  with `CERBERUS_SYSLOG_TLS_CLIENT_CA` only devices with a certificate are heard.
- The dashboard speaks plain HTTP. Put it behind a TLS reverse proxy if it is
  reachable from anywhere you do not trust (single sign-on requires it).
- Give people their own accounts or single sign-on, with the least role they
  need, and switch the built-in admin off; every change is then in the
  [audit log](#audit-log) under a person's name.
- The container runs as an unprivileged user.

## Questions

**What is Cerberus?**
Cerberus is a free, open-source, self-hosted tool that detects attacks and unusual behaviour from the syslog that firewalls and switches already send. It raises alerts mapped to MITRE ATT&CK, each with why it matters and what to do, and shows them on a web dashboard. It can notify you by email, Telegram, Pushbullet, webhooks or any HTTP API.

**Is Cerberus a SIEM?**
No. A SIEM collects and keeps logs from everything: servers, endpoints, cloud services. Cerberus does one part of that job: it analyses network device logs and tells a network security team what needs attention. It keeps events for days rather than years, and it can run beside a SIEM, sending its alerts there by webhook or API.

**Which firewalls and switches does Cerberus support?**
Built-in connectors cover OPNsense, Palo Alto Networks, Fortinet FortiGate, Cisco IOS and IOS-XE, Cisco ASA and Firepower, Cisco Meraki (MX, MS, MR), Juniper SRX and Junos, SonicWall, Sophos Firewall, Ubiquiti UniFi and EdgeOS, Aruba, Dell, Brocade and Ruckus ICX, RTL-Playground switches, and Suricata sensors (EVE JSON). Any other device that sends RFC 3164 or RFC 5424 syslog works through the generic connector, and you can add a vendor with a short YAML file.

**Do I need to install agents on my devices?**
No. Devices send syslog to Cerberus, which every firewall and managed switch can do from its own settings. Optionally Cerberus polls them over read-only SNMP to draw the network topology.

**What attacks does Cerberus detect?**
Port scans and host sweeps, connection floods, brute-force logins and password spraying, a login that succeeds after many failures, lateral movement between internal hosts, beaconing to a command-and-control server, large data transfers, sensitive services reachable from the internet, risky outbound connections such as Tor or IRC, administrator logins from new places or at odd hours, vendor threat alerts, and passwords or keys sent in clear text. It also watches network health: devices that go quiet, link flapping, spanning-tree trouble and unusual log volume.

**How do I install Cerberus?**
With Docker: git clone https://github.com/CerberusNetSec/Cerberus.git, cd Cerberus, then docker compose up -d --build. The dashboard is on port 8080 and syslog is received on port 514. There is also a Helm chart for Kubernetes. The README has a prompt you can paste into Claude, ChatGPT or Grok to be walked through the setup.

**Does Cerberus run on Windows or macOS?**
Yes, with Docker Desktop. Two things differ from Linux: have your devices send syslog over TCP rather than UDP, and set CERBERUS_DEVICE_IDENTITY=hostname, because Docker Desktop hides each device's address. For production, a Linux host is the better choice.

**How many devices can Cerberus handle?**
One instance handles a few hundred devices; the limit is message rate rather than device count. Scaled out with collectors, detection workers, Kafka, PostgreSQL and ClickHouse, one cluster is planned for about 10,000 messages a second, and several clusters can report to one console. Reference architectures in the repository size this for 5,000, 50,000, 100,000 and 500,000 devices; past one cluster, clusters are grouped into regions that share Kafka, PostgreSQL and ClickHouse.

**Is Cerberus free?**
Yes. It is open source under the Apache License 2.0, with no paid edition. It runs on your own hardware and has no telemetry: it contacts only the notification services you set up.

**Can AI agents work with Cerberus?**
Yes. Cerberus has a built-in Model Context Protocol (MCP) server, so Claude and other agents can list alerts, read the guidance, search events and, with a triage token, acknowledge alerts or mark false positives. Tokens are scoped, and everything an agent changes is in the audit log.

## Development

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest   # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest
CERBERUS_PASSWORD=dev .venv/bin/python -m cerberus       # syslog on 5514, UI on 8080
python tools/simulate.py --port 5514
python tools/loadtest.py                                  # throughput and query times for 300 devices
```

Layout: `receiver.py` (UDP/TCP listeners) → `syslog_parser.py` (envelope) →
`connectors.py` (YAML definitions) → `detectors.py` + `security.py` → `engine.py` (pipeline,
alert folding, batching to SQLite) → `notifiers.py` and `web.py` + `static/`.
Alongside: `snmp.py` (a small v2c client) → `snmp_poller.py` → `topology.py`.
The wording of every alert's guidance lives in `playbooks.py`; `riskports.py` is the high-risk port
tracker and its list of services.

## Licence

Apache License 2.0: see [LICENSE](LICENSE). You may use, modify and
redistribute Cerberus, including commercially and inside your organisation,
without charge. Keep the licence and the [NOTICE](NOTICE) file with copies you
distribute, and mark files you change. The licence includes a patent grant and
comes with no warranty.
