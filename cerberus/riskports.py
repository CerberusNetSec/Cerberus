"""High-risk ports: one place to see what is happening on the services attackers
go for first (remote access, file sharing, clear-text protocols, databases).

RiskPorts is a detector like the others - it watches every event and raises an
alert when traffic on one of these ports jumps well above its own history -
but it also keeps the counts the "Risk ports" page is drawn from: per port and
direction, allowed and blocked, minute by minute, with the busiest sources and
destinations.
"""
from __future__ import annotations

from collections import Counter, deque

from .detectors import Detector
from .models import Candidate, is_internal

# port -> (service, why it is here). Shown on the page next to the numbers.
CATALOG: dict[int, tuple[str, str]] = {
    20: ("FTP data", "Clear-text file transfer: passwords and files cross the network unencrypted."),
    21: ("FTP", "Clear-text file transfer: passwords and files cross the network unencrypted."),
    22: ("SSH", "Remote shell. Constantly brute-forced when reachable from the internet."),
    23: ("Telnet", "Clear-text remote shell. Still the main way IoT botnets spread."),
    25: ("SMTP", "Mail relay. From a workstation it usually means spam-sending malware."),
    69: ("TFTP", "File transfer with no authentication at all."),
    80: ("HTTP", "Unencrypted web traffic: content and credentials are readable in transit."),
    110: ("POP3", "Clear-text mail retrieval."),
    135: ("MS RPC", "Windows remote procedure calls; a route for remote code execution and lateral movement."),
    137: ("NetBIOS", "Legacy Windows naming and file sharing; leaks names and credentials."),
    138: ("NetBIOS", "Legacy Windows naming and file sharing; leaks names and credentials."),
    139: ("NetBIOS", "Legacy Windows naming and file sharing; leaks names and credentials."),
    143: ("IMAP", "Clear-text mail access."),
    161: ("SNMP", "Device management, often with default community strings."),
    389: ("LDAP", "Directory access without encryption; credentials can be read in transit."),
    445: ("SMB", "Windows file sharing: how ransomware and worms spread, and it leaks credentials when allowed out."),
    512: ("rexec", "Legacy remote execution with clear-text or no authentication."),
    513: ("rlogin", "Legacy remote login with clear-text or no authentication."),
    1433: ("MS SQL", "Database. Should never be reachable from the internet."),
    1521: ("Oracle DB", "Database. Should never be reachable from the internet."),
    2049: ("NFS", "File sharing with weak, host-based authentication."),
    3306: ("MySQL", "Database. Should never be reachable from the internet."),
    3389: ("RDP", "Windows remote desktop: the most common way in for ransomware operators."),
    5432: ("PostgreSQL", "Database. Should never be reachable from the internet."),
    5900: ("VNC", "Remote desktop, often with weak or no password."),
    5985: ("WinRM", "Windows remote management; used for lateral movement."),
    5986: ("WinRM", "Windows remote management; used for lateral movement."),
    6379: ("Redis", "In-memory database, usually with no authentication."),
    8080: ("HTTP (alt)", "Unencrypted web traffic, and a common port for admin panels and proxies."),
    9200: ("Elasticsearch", "Search database, frequently left open with no authentication."),
    27017: ("MongoDB", "Database, frequently left open with no authentication."),
}
CLEARTEXT = {20, 21, 23, 69, 80, 110, 143, 389, 512, 513, 8080}  # protocols with an encrypted replacement
WEB = {80, 8080}  # in use everywhere; only inbound exposure and spikes are worth flagging
DIRECTIONS = ("inbound", "outbound", "internal")
DIRECTION_TEXT = {"inbound": "from the internet", "outbound": "to the internet", "internal": "inside the network"}
TOP_KEYS = 3000  # distinct addresses remembered per port, direction and hour
FIRST_SEEN_MAX = 100_000


def direction(src_ip: str, dst_ip: str | None, nat_dst: str = "") -> str:
    if not is_internal(src_ip):
        return "inbound"
    if dst_ip and not is_internal(dst_ip) and not (nat_dst and is_internal(nat_dst)):
        return "outbound"
    return "internal"


def parse_ports(text: str) -> list[int]:
    out = []
    for part in str(text).replace(";", ",").replace("\n", ",").replace(" ", ",").split(","):
        if part.isdigit() and 0 < int(part) < 65536 and int(part) not in out:
            out.append(int(part))
    return out


class RiskPorts(Detector):
    id = "risk_ports"
    name = "High-risk port activity"
    description = ("Tracks traffic on ports that attackers target first, for the Risk ports page, and alerts when "
                   "traffic on one of them rises far above what that port normally carries.")
    params = [
        ("ports", ",".join(str(p) for p in CATALOG), "High-risk ports (comma separated)"),
        ("spike_ratio", 4.0, "Alert when an hour's traffic is this many times the usual"),
        ("spike_min", 100, "... and at least this many connections in the hour"),
        ("history_hours", 6, "Hours of history needed before judging a spike"),
    ]
    multiline = ("ports",)
    # _unsaved is not state: it is written to port_minute at every flush.
    _persist = (*Detector._persist, "minute", "current", "recent", "hours", "talkers", "first_seen", "since")

    def __init__(self):
        super().__init__()
        self.ports = set(parse_ports(self.cfg["ports"]))
        self.minute = 0
        self.current: dict[tuple, list[int]] = {}  # (port, direction) -> [allowed, blocked] in this minute
        self.recent: deque = deque(maxlen=60)  # (minute, {key: [allowed, blocked]}) for closed minutes
        self.hours: dict[int, dict[tuple, list[int]]] = {}  # hour -> key -> [allowed, blocked]
        self.talkers: dict[int, dict[tuple, tuple[Counter, Counter]]] = {}  # hour -> key -> (sources, destinations)
        self.first_seen: dict[tuple, float] = {}  # (port, direction, internal source) -> when first seen allowed
        self.since = 0.0  # start of the history we hold
        self._unsaved: dict[tuple, list[int]] = {}  # (minute, port, direction) -> [allowed, blocked]

    def configure(self, settings: dict) -> None:
        super().configure(settings)
        self.ports = set(parse_ports(self.cfg["ports"]))

    # --- counting -------------------------------------------------------------
    def process(self, ev, now, emit):
        port = ev.dst_port
        if port not in self.ports or ev.event_type != "traffic" or not ev.src_ip or ev.action not in ("allow", "block"):
            return
        self._roll(now)
        way = direction(ev.src_ip, ev.dst_ip, ev.extra.get("nat_dst_ip", ""))
        key = (port, way)
        slot = 0 if ev.action == "allow" else 1
        self.current.setdefault(key, [0, 0])[slot] += 1
        self._unsaved.setdefault((self.minute * 60, port, way), [0, 0])[slot] += 1
        hour = int(now // 3600)
        sources, destinations = self.talkers.setdefault(hour, {}).setdefault(key, (Counter(), Counter()))
        # Key by address and outcome, so the page can say who got through and who was stopped.
        for table, address in ((sources, ev.src_ip), (destinations, ev.dst_ip)):
            if address and ((address, slot) in table or len(table) < TOP_KEYS):
                table[(address, slot)] += 1
        if slot == 0 and way != "inbound":
            seen = (port, way, ev.src_ip)
            if seen not in self.first_seen and len(self.first_seen) < FIRST_SEEN_MAX:
                self.first_seen[seen] = now

    def _roll(self, now: float) -> None:
        minute = int(now // 60)
        if minute == self.minute:
            return
        if self.minute and self.current:
            self.recent.append((self.minute, self.current))
            bucket = self.hours.setdefault(self.minute // 60, {})
            for key, counts in self.current.items():
                total = bucket.setdefault(key, [0, 0])
                total[0] += counts[0]
                total[1] += counts[1]
        if not self.since:
            self.since = now
        self.current = {}
        self.minute = minute

    # --- persistence ----------------------------------------------------------
    def drain(self) -> list[tuple]:
        """Rows for port_minute since the last call."""
        rows = [(minute, port, way, v[0], v[1]) for (minute, port, way), v in self._unsaved.items()]
        self._unsaved = {}
        return rows

    def restore_rows(self, rows: list[dict], now: float) -> None:
        """Rebuild the hourly history from stored port_minute rows after a restart."""
        for row in rows:
            key = (row["port"], row["direction"])
            minute = row["minute"] // 60
            total = self.hours.setdefault(minute // 60, {}).setdefault(key, [0, 0])
            total[0] += row["allowed"]
            total[1] += row["blocked"]
            if now - row["minute"] < 3600:
                if not self.recent or self.recent[-1][0] != minute:
                    self.recent.append((minute, {}))
                self.recent[-1][1][key] = [row["allowed"], row["blocked"]]
            self.since = min(self.since or row["minute"], row["minute"])

    # --- judging --------------------------------------------------------------
    def last_hour(self, now: float) -> dict[tuple, list[int]]:
        cutoff = int(now // 60) - 60
        out: dict[tuple, list[int]] = {}
        for minute, counts in [*self.recent, (self.minute, self.current)]:
            if minute > cutoff:
                for key, v in counts.items():
                    total = out.setdefault(key, [0, 0])
                    total[0] += v[0]
                    total[1] += v[1]
        return out

    def usual(self, key: tuple, now: float) -> tuple[list[float], float]:
        """([allowed, blocked] per hour over the previous day, hours of history behind it).
        The last two clock hours are left out so a spike is not compared with itself."""
        this_hour = int(now // 3600)
        span = min(24.0, (now - self.since) / 3600 - 1) if self.since else 0.0
        if span <= 0:
            return [0.0, 0.0], 0.0
        total = [0, 0]
        for hour in range(this_hour - 25, this_hour - 1):
            counts = self.hours.get(hour, {}).get(key)
            if counts:
                total[0] += counts[0]
                total[1] += counts[1]
        return [total[0] / span, total[1] / span], span

    def spikes(self, now: float) -> list[dict]:
        """Port/direction/outcome combinations running well above their own history."""
        out = []
        cfg = self.cfg
        for key, counts in self.last_hour(now).items():
            usual, span = self.usual(key, now)
            if span < cfg["history_hours"]:
                continue
            for slot, outcome in ((0, "allowed"), (1, "blocked")):
                # A floor of 5 an hour: going from nothing to a handful is not a spike.
                if counts[slot] >= cfg["spike_min"] and counts[slot] >= cfg["spike_ratio"] * max(usual[slot], 5.0):
                    out.append({"port": key[0], "direction": key[1], "outcome": outcome,
                                "count": counts[slot], "usual": round(usual[slot], 1)})
        return out

    def tick(self, now, emit):
        self._roll(now)
        for hour in [h for h in self.hours if h < now // 3600 - 30]:
            del self.hours[hour]
        for hour in [h for h in self.talkers if h < now // 3600 - 25]:
            del self.talkers[hour]
        if len(self.first_seen) >= FIRST_SEEN_MAX // 2:
            for key in [k for k, t in self.first_seen.items() if now - t > 7 * 86400]:
                del self.first_seen[key]
        for s in self.spikes(now):
            port, way = s["port"], s["direction"]
            if not self._may_emit((port, way, s["outcome"]), now):
                continue
            label = f"{service_name(port)} ({port})"
            allowed = s["outcome"] == "allowed"
            sources = self.top(port, way, now, 1)["sources"]
            lead = sources[0]["ip"] if sources else None
            emit(Candidate(
                self.id, f"{port}|{way}|{s['outcome']}",
                ("high" if way == "inbound" else "medium") if allowed else "low",
                f"Surge in {s['outcome']} {label} traffic {DIRECTION_TEXT[way]}",
                f"{s['count']:,} {s['outcome']} {label} connections {DIRECTION_TEXT[way]} in the last hour; "
                f"this port normally carries about {s['usual']:,.0f} an hour."
                + (f" The busiest source is {lead}." if lead else ""),
                lead, "", {"port": port, "direction": way, "outcome": s["outcome"],
                           "last_hour": s["count"], "usual_per_hour": s["usual"]},
            ))

    # --- read side ------------------------------------------------------------
    def top(self, port: int, way: str, now: float, limit: int = 6, hours: int = 24) -> dict:
        """Busiest sources and destinations for one port and direction."""
        sources: Counter = Counter()
        destinations: Counter = Counter()
        for hour, table in self.talkers.items():
            if hour >= now // 3600 - hours and (port, way) in table:
                sources.update(table[(port, way)][0])
                destinations.update(table[(port, way)][1])

        def rank(counter: Counter, new_for: str = "") -> list[dict]:
            merged: dict[str, list[int]] = {}
            for (address, slot), n in counter.items():
                merged.setdefault(address, [0, 0])[slot] += n
            rows = sorted(merged.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))[:limit]
            out = []
            for address, (allowed, blocked) in rows:
                first = self.first_seen.get((port, new_for, address)) if new_for else None
                out.append({"ip": address, "allowed": allowed, "blocked": blocked, "internal": is_internal(address),
                            # "New" only means something once there is history to be new against.
                            "new": bool(first and now - first < 86400 and first - self.since > 6 * 3600)})
            return out
        return {"sources": rank(sources, way if way != "inbound" else ""), "destinations": rank(destinations)}


def service_name(port: int) -> str:
    return CATALOG.get(port, (f"port {port}", ""))[0]


def flags(port: int, totals: dict[str, list[int]], spikes: list[dict], new_sources: int) -> list[dict]:
    """Why a port needs a look, worst first. totals: direction -> [allowed, blocked] over the range shown."""
    out = []
    name = service_name(port)
    if totals["inbound"][0]:
        out.append({"kind": "exposed", "severity": "medium" if port in WEB else "high",
                    "label": "Open to the internet",
                    "text": f"{totals['inbound'][0]:,} connections from the internet to {name} were allowed."
                            + (" Expected for a public web server; make sure it is only that server." if port in WEB
                               else " Unless this is a deliberately published service, close it or put it behind a VPN.")})
    for s in spikes:
        if s["port"] == port:
            out.append({"kind": "spike", "severity": "medium" if s["outcome"] == "allowed" else "low",
                        "label": f"Surge {DIRECTION_TEXT[s['direction']]}",
                        "text": f"{s['count']:,} {s['outcome']} connections {DIRECTION_TEXT[s['direction']]} in the last "
                                f"hour against a usual {s['usual']:,.0f}."})
    if totals["outbound"][0] and port not in WEB and port != 22:
        out.append({"kind": "egress", "severity": "medium", "label": "Allowed out to the internet",
                    "text": f"{totals['outbound'][0]:,} {name} connections to internet addresses were allowed. "
                            "Few networks need this; block it outbound except for named hosts."})
    if new_sources:
        out.append({"kind": "new", "severity": "medium", "label": f"{new_sources} new source{'s' if new_sources > 1 else ''}",
                    "text": f"{new_sources} internal host{'s' if new_sources > 1 else ''} started using {name} "
                            "in the last 24 hours. Check that each has a reason to."})
    clear = totals["outbound"][0] + totals["internal"][0]
    if port in CLEARTEXT and port not in WEB and clear:
        out.append({"kind": "cleartext", "severity": "low", "label": "Clear-text protocol in use",
                    "text": f"{name} sends everything, passwords included, unencrypted. "
                            f"{clear:,} connections were allowed; move those systems to the encrypted equivalent."})
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda f: order[f["severity"]])
