"""What each alert means and what to do about it.

Kept apart from the detectors so the wording can be reviewed and edited in
one place. advice() is applied when an alert is read or sent, so changes here
also apply to alerts already stored.

Technique IDs refer to MITRE ATT&CK (Enterprise).
"""
from __future__ import annotations

from .models import is_internal

# Kill-chain order, used to sort the dashboard's "attack stage" breakdown.
STAGES = ["Reconnaissance", "Initial Access", "Credential Access", "Discovery", "Lateral Movement",
          "Command and Control", "Exfiltration", "Impact", "Defense Evasion", "Compromise", "Network health"]

_ISOLATE = "Isolate {src} from the network (quarantine VLAN, or shut its switch port) until it has been examined."
_EVENTS = "Review every event for {src} on the Events page to see what else it has been doing."
_BLOCK_EXT = "Block {src} at the perimeter. If it keeps returning from nearby addresses, block the range or its ASN."

# detector id -> stage, technique, why, and actions. "internal"/"external" pick
# actions by where the alert's source address is; "actions" applies to both.
PLAYBOOKS: dict[str, dict] = {
    "port_scan": {
        "stage": "Discovery", "technique": ("T1046", "Network Service Discovery"),
        "why": "Scanning is how an attacker finds what to attack next. From inside your network it usually means a "
               "compromised or misused machine; from the internet it is constant background noise.",
        "internal": [
            "Identify {src} and its owner. If it is not an authorised scanner, treat it as compromised.",
            _ISOLATE, _EVENTS,
            "If it is an authorised scanner, add it to the ignored sources under Settings → Detection.",
        ],
        "external": [
            "No action is needed for a single scan that was blocked.",
            "Check which of the scanned ports your firewall actually allows from the internet, and close any that "
            "are not meant to be public.",
            _BLOCK_EXT,
        ],
    },
    "host_sweep": {
        "stage": "Discovery", "technique": ("T1018", "Remote System Discovery"),
        "why": "Trying one port across many hosts is how worms and intruders look for machines to spread to.",
        "internal": [
            "Identify {src}; a sweep of SMB, RDP or SSH from a workstation is a strong sign of malware.",
            _ISOLATE,
            "Check whether any swept host accepted the connection: search Events for {src} with action Allowed.",
        ],
        "external": [
            "Confirm the swept port is closed from the internet on every address you own.", _BLOCK_EXT,
        ],
    },
    "deny_flood": {
        "stage": "Impact", "technique": ("T1498", "Network Denial of Service"),
        "why": "A large volume of blocked traffic from one source is either an attack on availability, a "
               "misconfigured device retrying forever, or malware probing for a way out.",
        "internal": [
            "Look at what {src} is being blocked from reaching: a misconfigured application and malware look "
            "different in the destination ports.",
            "If the destinations are random or on unusual ports, isolate {src} and scan it.",
            "If it is a broken application, fix it or add a specific rule so the noise stops hiding real events.",
        ],
        "external": [
            "Check the firewall's CPU and session table; if they are under pressure, rate-limit or drop {src} "
            "upstream (DoS protection profile, or ask your ISP).", _BLOCK_EXT,
        ],
    },
    "brute_force": {
        "stage": "Credential Access", "technique": ("T1110", "Brute Force"),
        "why": "Repeated login failures from one source mean someone is guessing passwords.",
        "internal": [
            "Find out what {src} is: a person mistyping, a script with a stale password, or an attacker.",
            "If it is not explained, isolate {src} and check the targeted accounts for a successful login.",
            "Restrict management access on the device to a dedicated management network.",
        ],
        "external": [
            "Management logins should not be reachable from the internet: remove that exposure, or restrict it "
            "to known addresses or a VPN.",
            _BLOCK_EXT,
            "Make sure the targeted accounts have strong passwords and MFA, and that lockout is enabled.",
        ],
    },
    "brute_force_success": {
        "stage": "Credential Access", "technique": ("T1110", "Brute Force"),
        "why": "A login that succeeds straight after many failures usually means the password was guessed. "
               "Treat the account and the device as compromised until shown otherwise.",
        "actions": [
            "Confirm with the account owner whether this was them. If not, or if unsure, continue.",
            "Disable or reset the account now and end its active sessions on the device.",
            "Review what the account did after logging in: configuration changes, new users, new rules.",
            "Compare the device's running configuration with your last known-good backup.",
            "Block or isolate {src}.",
        ],
    },
    "password_spray": {
        "stage": "Credential Access", "technique": ("T1110.003", "Password Spraying"),
        "why": "Trying a few passwords against many usernames avoids per-account lockouts. It means the attacker "
               "has, or is guessing, a list of your accounts.",
        "internal": [
            _ISOLATE, "Check each targeted account for a successful login from {src} afterwards.",
            "Reset any account that could have had a weak or default password.",
        ],
        "external": [
            _BLOCK_EXT,
            "Take the login service off the internet or put it behind a VPN with MFA.",
            "Check the targeted accounts for successful logins from any new address.",
        ],
    },
    "distributed_brute_force": {
        "stage": "Credential Access", "technique": ("T1110", "Brute Force"),
        "why": "One account attacked from many addresses at once is a coordinated attempt that per-source "
               "blocking and lockout counters do not stop.",
        "actions": [
            "Enforce MFA on this account, or rename or disable it if it is a default name such as admin.",
            "Restrict where the login service can be reached from, rather than blocking sources one by one.",
            "Check for a successful login to this account during the attack.",
        ],
    },
    "admin_from_internet": {
        "stage": "Initial Access", "technique": ("T1133", "External Remote Services"),
        "why": "Someone administered a firewall or switch from the internet. Even if it was a colleague, an "
               "exposed management interface is one of the most common ways network devices are taken over.",
        "actions": [
            "Confirm with the account owner that this login was theirs.",
            "If it was not, reset the account, end its sessions, and audit the configuration for changes.",
            "Remove management access from the internet-facing interface; require a VPN.",
            "Check the device's firmware against the vendor's security advisories.",
        ],
    },
    "admin_new_source": {
        "stage": "Lateral Movement", "technique": ("T1078", "Valid Accounts"),
        "why": "A device was administered from an address that has never managed it before. That is how a stolen "
               "credential looks when it is used from an attacker's foothold.",
        "actions": [
            "Confirm with the account owner that they logged in from {src}.",
            "If it is a new but legitimate admin workstation, no action is needed: it is now remembered.",
            "If unexplained, reset the account, review what was changed on the device, and investigate {src}.",
        ],
    },
    "admin_after_hours": {
        "stage": "Defense Evasion", "technique": ("T1078", "Valid Accounts"),
        "why": "Administrative activity outside working hours is worth a second look: intruders prefer to work "
               "when nobody is watching.",
        "actions": [
            "Confirm with the account owner that this was planned work.",
            "If it was not, review the change and compare the configuration with your last backup.",
        ],
    },
    "exposed_service": {
        "stage": "Initial Access", "technique": ("T1133", "External Remote Services"),
        "why": "A remote-access, file-sharing or database service is being reached from the internet. These "
               "are attacked continuously, and one weak password or missing patch is enough.",
        "actions": [
            "Decide whether this service is meant to be public. In most networks it is not.",
            "If not: tighten or remove the firewall rule that allows it (named in the details below), or "
            "restrict the rule's source to the addresses that need it.",
            "If remote access is needed, move it behind a VPN instead of a port forward.",
            "Check the target host's logs for successful logins from the listed addresses.",
            "If it is intentionally public, add the server to ignored destinations, or remove the port from "
            "this detector.",
        ],
    },
    "hostile_allowed": {
        "stage": "Initial Access", "technique": ("T1190", "Exploit Public-Facing Application"),
        "why": "An address that was just scanning or attacking you has now been let through the firewall. "
               "Reconnaissance followed by an accepted connection is what a successful intrusion looks like.",
        "actions": [
            "Block {src} at the perimeter now.",
            "Examine the target host for signs of compromise, starting with its logs at the time of this alert.",
            "Review the rule that allowed the connection and restrict its source or remove it.",
            _EVENTS,
        ],
    },
    "threat": {
        "stage": "Initial Access", "technique": ("T1190", "Exploit Public-Facing Application"),
        "why": "The firewall's own threat engine matched this traffic against a known attack or malware signature.",
        "blocked": [
            "The device blocked it, so no immediate action is required.",
            "If the source is internal, investigate that host: it attempted the attack.",
            "If the target is one of your servers, confirm it is patched against this specific threat.",
        ],
        "not_blocked": [
            "This was detected but NOT blocked. Assume the attack reached its target.",
            "Examine the target host for compromise and patch it against this threat.",
            "Change the security profile so this signature (or its severity level) is blocked, not just alerted.",
            "If the source is internal, isolate it.",
        ],
    },
    "risky_egress": {
        "stage": "Command and Control", "technique": ("T1571", "Non-Standard Port"),
        "why": "This kind of outbound traffic has little legitimate use from a managed network. Outbound SMB "
               "leaks credentials; IRC, Tor, SOCKS and port 4444 are staples of malware and of people "
               "bypassing policy.",
        "actions": [
            "Identify {src} and what on it made the connection.",
            "Block this port outbound for everyone who does not need it. A default-deny egress policy with "
            "explicit allows prevents this whole class of problem.",
            "If the software is not known and approved, isolate {src} and scan it.",
        ],
    },
    "risk_ports": {
        "stage": "Discovery", "technique": ("T1046", "Network Service Discovery"),
        "why": "A sudden rise in traffic on a port attackers favour means something changed: a scanning wave, a "
               "worm spreading, a new exposure, or a misconfigured system. Allowed traffic matters most; a rise "
               "in blocked traffic shows the firewall doing its job, but also that someone is trying.",
        "actions": [
            "Open the High Risk Ports page and expand this port to see who the traffic is from and to.",
            "If the connections are allowed from the internet, find the firewall rule that permits them and "
            "restrict it to the sources that need it.",
            "If one internal host accounts for most of it, identify the host; many destinations on SMB, RDP or "
            "Telnet from one machine is how worms spread, so isolate it if it is not an administrator's.",
            "If it is expected (a migration, a new backup job), acknowledge the alert; the baseline adjusts within a day.",
        ],
    },
    "beaconing": {
        "stage": "Command and Control", "technique": ("T1071", "Application Layer Protocol"),
        "why": "Malware calls home on a timer. Connections to one internet address at near-identical intervals "
               "are the trace that leaves. Monitoring agents and update checkers produce it too, so this needs "
               "a look rather than an automatic response.",
        "actions": [
            "Look up the destination address and port: who owns it, and is it something you use?",
            "Find out which process on {src} is making the connection.",
            "If it is known software, add the destination to the ignore list under Settings → Detection.",
            "If it is not explained, block the destination and isolate {src} for examination.",
        ],
    },
    "lateral_movement": {
        "stage": "Lateral Movement", "technique": ("T1021", "Remote Services"),
        "why": "A single machine opening administration connections to many others is how an intruder, or "
               "ransomware, spreads through a network once inside.",
        "actions": [
            "Identify {src}. Management servers, backup servers and jump hosts do this legitimately: add those "
            "to the ignored sources.",
            "If it is a workstation or an unexpected server, isolate it immediately.",
            "Check the hosts it reached for new logins, services or scheduled tasks.",
            "Segment the network so workstations cannot reach each other on these ports at all.",
        ],
    },
    "large_transfer": {
        "stage": "Exfiltration", "technique": ("T1048", "Exfiltration Over Alternative Protocol"),
        "why": "An unusually large upload to the internet can be data being stolen. It can also be a backup or "
               "a video call, so confirm before acting.",
        "actions": [
            "Identify the destination (shown in the details) and whether it is a service you use.",
            "Ask the owner of {src} what was being uploaded.",
            "If unexplained, block the destination, preserve the firewall logs, and treat it as a possible "
            "data breach under your incident process.",
        ],
    },
    "watchlist": {
        "stage": "Command and Control", "technique": ("T1071", "Application Layer Protocol"),
        "why": "This address is on the watchlist you maintain.",
        "actions": [
            "If the connection was allowed, treat the internal host involved as compromised until examined.",
            "Add an explicit block rule for the watchlisted address if one is not already in place.",
            _EVENTS,
        ],
    },
    "compromise_suspected": {
        "stage": "Compromise", "technique": None,
        "why": "Several independent detections point at the same internal host. Any one could be a false alarm; "
               "together they describe an attack in progress.",
        "actions": [
            "Isolate {src} now: quarantine VLAN, or shut its switch port.",
            "Preserve evidence before rebuilding: memory and disk image if you can, and export its events from here.",
            "Reset the credentials of every account that has been used on {src}.",
            "Check the hosts it talked to (Events page, filtered by {src}) for the same behaviour.",
            "Rebuild the machine rather than cleaning it.",
        ],
    },
    "topology_change": {
        "stage": "Initial Access", "technique": ("T1200", "Hardware Additions"),
        "why": "A device appeared on, or vanished from, a switch port. An unexpected switch, access point or "
               "small computer plugged into the network bypasses your perimeter entirely.",
        "actions": [
            "Check whether the change was planned (new equipment, a move, maintenance).",
            "If not, find the port physically, or shut it on the switch until someone can look.",
            "Enable port security or 802.1X on access ports so unknown devices cannot join.",
        ],
    },
    "notable": {
        "stage": "Network health", "technique": None,
        "why": "The device itself reported something that needs attention.",
        "actions": [
            "Read the device's message in the details below.",
            "Port-security, DHCP-snooping or ARP-inspection violations mean a device on that port sent traffic "
            "it should not: find out what is plugged in. Spoofed ARP or DHCP is how traffic gets intercepted.",
            "For an unexpected configuration change, confirm who made it and compare with your last backup.",
            "For loops and spanning-tree guard trips, check the cabling on the named port before re-enabling it.",
        ],
    },
    "link_flap": {
        "stage": "Network health", "technique": None,
        "why": "A port that keeps going up and down causes outages and spanning-tree churn.",
        "actions": ["Replace the cable or optic on this port.", "Check the device at the other end for power or "
                    "driver problems.", "If it cannot be fixed now, shut the port to stop the churn."],
    },
    "rate_anomaly": {
        "stage": "Network health", "technique": None,
        "why": "A sudden jump in log volume or blocked traffic means something changed: an attack, a "
               "misconfiguration, or a failing device.",
        "actions": ["Open the Events page for this device and look at what the extra messages are.",
                    "Check Top blocked sources on the dashboard for a single address behind the spike."],
    },
    "plaintext_secret": {
        "stage": "Credential Access", "technique": ("T1552", "Unsecured Credentials"),
        "why": "A password or key that crosses the network in clear, or sits in a log, can be read by anyone with "
               "access to that traffic or those logs, and used later without any further attack.",
        "actions": [
            "Treat the credential as exposed: rotate the password, key or token now, before anything else.",
            "Find what sent it ({src} or the device that logged it) and change it to use an encrypted connection, "
            "and to keep credentials out of URLs and query strings.",
            "Check who else stores these logs (log servers, proxies, SIEM) and remove the secret there too.",
            "If it is an API key, review its provider's audit log for use you do not recognise.",
        ],
    },
    "device_silent": {
        "stage": "Defense Evasion", "technique": ("T1562", "Impair Defenses"),
        "why": "A device that stops logging is either down or has had its logging turned off. Attackers disable "
               "logging to hide what they do next, so do not assume it is only an outage.",
        "actions": [
            "Check whether the device is up and passing traffic.",
            "If it is up, check its syslog configuration and who changed it.",
            "Check the network path between the device and Cerberus (UDP/TCP 514).",
        ],
    },
    "collector_silent": {
        "stage": "Network health", "technique": None,
        "why": "A collector receives syslog and passes it on for analysis. While one is down, logs sent to it "
               "are lost or delayed, unless the load balancer in front moves its devices to another collector.",
        "actions": [
            "Check the collector's container or pod and its log; restart it if it has stopped.",
            "Check that the load balancer's health check has taken it out of rotation.",
            "If it is running but not reporting, check it can reach the message bus: its /status page shows "
            "spooled events and the last bus error.",
        ],
    },
    "site_silent": {
        "stage": "Network health", "technique": None,
        "why": "While a site is not reporting, nothing it detects reaches this console. The site may be down, cut "
               "off from the console, or have had its Cerberus stopped.",
        "actions": [
            "Check that the site's Cerberus container is running (`docker ps`, or its pod) and look at its log.",
            "From the site, check it can reach this console's address over HTTPS; a changed firewall rule or "
            "certificate is the usual cause.",
            "If the site was rebuilt, check it still has its token (CERBERUS_CENTRAL_TOKEN).",
            "Alerts raised at the site meanwhile are kept there and arrive here once it reconnects.",
        ],
    },
    "new_device": {
        "stage": "Network health", "technique": None,
        "why": "Something started sending logs here for the first time.",
        "actions": ["If you just configured it, no action is needed.",
                    "If you did not, find out what it is: unsolicited syslog can be used to inject false events."],
    },
}

_FALLBACK = {"stage": "Network health", "technique": None, "why": "", "actions": []}


def detector_stage(detector: str) -> str:
    return PLAYBOOKS.get(detector, _FALLBACK)["stage"]


def advice(alert: dict) -> dict:
    """Guidance for one alert row (needs detector, src_ip and, for threats, details)."""
    book = PLAYBOOKS.get(alert.get("detector", ""), _FALLBACK)
    src = alert.get("src_ip") or ""
    if "actions" in book:
        actions = book["actions"]
    elif "blocked" in book:
        details = alert.get("details") or {}
        actions = book["blocked"] if details.get("blocked", True) else book["not_blocked"]
    else:
        actions = book["internal"] if src and is_internal(src) else book["external"]
    name = src or "the source"
    technique = book["technique"]
    return {
        "stage": book["stage"],
        "technique": {"id": technique[0], "name": technique[1],
                      "url": "https://attack.mitre.org/techniques/" + technique[0].replace(".", "/") + "/"}
        if technique else None,
        "why": book["why"],
        "actions": [a.replace("{src}", name) for a in actions],
    }
