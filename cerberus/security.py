"""Security-focused detectors: the things a network security team acts on.

Where detectors.py looks for volume and behaviour anomalies, these look for
specific attacker activity visible in firewall and device logs - exposure,
command-and-control, lateral movement, credential attacks, unexpected admin
access - and a correlator joins separate alerts into "this host is in trouble".
"""
from __future__ import annotations

import ipaddress
import statistics
import time
from collections import deque

from .detectors import Detector, SlidingSet, _clip, _origin
from .models import Candidate, Event, is_internal
from .state import persistent

SERVICES = {
    22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 161: "SNMP", 445: "SMB", 1080: "SOCKS proxy",
    1433: "MSSQL", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit default port",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 6667: "IRC", 6697: "IRC",
    9001: "Tor", 9030: "Tor", 9050: "Tor", 9150: "Tor", 9200: "Elasticsearch", 27017: "MongoDB",
}
# Outbound ports with little legitimate use from a managed network.
_C2_PORTS = {1080, 4444, 6667, 6697, 9001, 9030, 9050, 9150}
_CONTEXT = ("policy", "policyname", "policyid", "pf_label", "acl", "application", "service",
            "src_zone", "dst_zone", "out_interface", "nat_dst_ip")


def service(port: int | None, proto: str = "") -> str:
    name = SERVICES.get(port or -1)
    label = f"{proto or 'port'}/{port}"
    return f"{name} ({label})" if name else label


def context(ev: Event) -> dict:
    """The firewall's own description of the flow: which rule, zones, application.
    This is what tells the reader where to make a change."""
    out = {k: ev.extra[k] for k in _CONTEXT if ev.extra.get(k)}
    if ev.interface:
        out["interface"] = ev.interface
    out["reported_by"] = ev.hostname or ev.device
    return out


def rule_name(ev: Event) -> str:
    extra = ev.extra
    return extra.get("policy") or extra.get("policyname") or extra.get("acl") or (
        f"policy {extra['policyid']}" if extra.get("policyid") else "")


def _parse_ports(text: str) -> set[int]:
    ports = set()
    for part in str(text).replace(";", ",").replace(" ", ",").split(","):
        if part.isdigit() and 0 < int(part) < 65536:
            ports.add(int(part))
    return ports


def _inside(ev: Event) -> str | None:
    """The internal address an inbound flow ends at, allowing for destination NAT
    (PAN-OS and FortiOS log the public address as the destination)."""
    if ev.dst_ip and is_internal(ev.dst_ip):
        return ev.dst_ip
    nat = ev.extra.get("nat_dst_ip", "")
    return nat if nat and is_internal(nat) else None


class _PortDetector(Detector):
    """Shared handling for detectors configured with a port list."""

    ttl = 3900.0

    def __init__(self):
        super().__init__()
        self.ports = _parse_ports(self.cfg["ports"])

    def configure(self, settings: dict) -> None:
        super().configure(settings)
        self.ports = _parse_ports(self.cfg["ports"])

    def tick(self, now, emit):
        self._prune(now, self.ttl)


class ExposedService(_PortDetector):
    id = "exposed_service"
    name = "Sensitive service reachable from the internet"
    description = ("The firewall allowed an internet address to connect to an internal host on a remote-access, "
                   "file-sharing or database port. If a port here is exposed on purpose, remove it from the list "
                   "or add the server under ignored destinations.")
    params = [
        ("ports", "22,23,135,139,445,1433,2375,3306,3389,5432,5900,5985,5986,6379,9200,27017", "Sensitive ports"),
    ]

    def process(self, ev, now, emit):
        if (ev.event_type != "traffic" or ev.action != "allow" or ev.dst_port not in self.ports
                or not ev.src_ip or is_internal(ev.src_ip)):
            return
        target = _inside(ev)
        if not target:
            return
        key = (target, ev.dst_port)
        sources = self._get(key, SlidingSet, now)
        if sources is None:
            return
        count = sources.add(ev.src_ip, now, 3600)
        if not self._may_emit(key, now):
            return
        rule = rule_name(ev)
        emit(Candidate(
            self.id, f"{target}:{ev.dst_port}", "high",
            f"{service(ev.dst_port, ev.proto)} on {target} reached from the internet",
            f"{ev.hostname or ev.device} allowed {ev.src_ip} to connect to {target} on {service(ev.dst_port, ev.proto)}"
            + (f" under rule '{_clip(rule, 60)}'" if rule else "")
            + f". {count} internet address{'es' if count != 1 else ''} did so in the last hour.",
            ev.src_ip, ev.device,
            {"target": target, "port": ev.dst_port, "sources_last_hour": count,
             "sample_sources": list(sources.items)[-10:], **context(ev)},
        ))


class RiskyEgress(_PortDetector):
    id = "risky_egress"
    name = "Risky outbound connection"
    description = ("An internal host was allowed out to the internet on a port with little legitimate use: SMB, "
                   "RDP or Telnet outbound, IRC, Tor, SOCKS or common malware ports.")
    params = [
        ("ports", "23,135,139,445,1080,3389,4444,5900,6667,6697,9001,9030,9050,9150", "Ports to flag outbound"),
    ]

    def process(self, ev, now, emit):
        if (ev.event_type != "traffic" or ev.action != "allow" or ev.dst_port not in self.ports
                or not ev.src_ip or not ev.dst_ip or not is_internal(ev.src_ip) or is_internal(ev.dst_ip)):
            return
        key = (ev.src_ip, ev.dst_port)
        dests = self._get(key, SlidingSet, now)
        if dests is None:
            return
        count = dests.add(ev.dst_ip, now, 3600)
        if not self._may_emit(key, now):
            return
        rule = rule_name(ev)
        emit(Candidate(
            self.id, f"{ev.src_ip}:{ev.dst_port}", "high" if ev.dst_port in _C2_PORTS else "medium",
            f"{ev.src_ip} connected out on {service(ev.dst_port, ev.proto)}",
            f"Internal host {ev.src_ip} was allowed to reach {ev.dst_ip} on {service(ev.dst_port, ev.proto)}"
            + (f" under rule '{_clip(rule, 60)}'" if rule else "")
            + f" ({count} destination{'s' if count != 1 else ''} in the last hour).",
            ev.src_ip, ev.device,
            {"port": ev.dst_port, "destinations_last_hour": count,
             "sample_destinations": list(dests.items)[-10:], **context(ev)},
        ))


class LateralMovement(_PortDetector):
    id = "lateral_movement"
    name = "Lateral movement"
    description = ("One internal host opening remote-administration or file-sharing connections to many other "
                   "internal hosts. Add legitimate management servers and scanners to the ignored sources.")
    params = [
        ("ports", "22,23,135,445,3389,5985,5986", "Administration ports"),
        ("hosts", 8, "Distinct internal destinations"),
        ("window", 600, "Within (seconds)"),
    ]

    def process(self, ev, now, emit):
        if (ev.event_type != "traffic" or ev.action == "block" or ev.dst_port not in self.ports
                or not ev.src_ip or not ev.dst_ip or not is_internal(ev.src_ip) or not is_internal(ev.dst_ip)):
            return
        key = (ev.src_ip, ev.dst_port)
        dests = self._get(key, SlidingSet, now)
        if dests is None:
            return
        count = dests.add(ev.dst_ip, now, self.cfg["window"])
        if count >= self.cfg["hosts"] and self._may_emit(key, now):
            emit(Candidate(
                self.id, f"{ev.src_ip}:{ev.dst_port}", "high",
                f"{ev.src_ip} reached {count} internal hosts on {service(ev.dst_port, ev.proto)}",
                f"Internal host {ev.src_ip} connected to {count} different internal hosts on "
                f"{service(ev.dst_port, ev.proto)} within {self.cfg['window'] // 60} minutes, and the connections "
                "were not blocked.",
                ev.src_ip, ev.device,
                {"port": ev.dst_port, "distinct_hosts": count, "sample_hosts": list(dests.items)[-12:], **context(ev)},
            ))

    def tick(self, now, emit):
        self._prune(now, self.cfg["window"] + 60)


@persistent
class _Beat:
    __slots__ = ("last", "gaps")

    def __init__(self, size: int):
        self.last = 0.0
        self.gaps: deque = deque(maxlen=size)


class Beaconing(Detector):
    id = "beaconing"
    name = "Beaconing (possible command-and-control)"
    description = ("An internal host contacting the same internet address at very regular intervals, the way "
                   "malware checks in with its controller. Monitoring agents and some cloud software do this "
                   "too: add those destinations to the ignore list as you confirm them.")
    params = [
        ("connections", 12, "Consecutive regular connections"),
        ("jitter", 0.1, "Maximum variation in the interval (0.1 = 10%)"),
        ("min_interval", 20, "Shortest interval considered (seconds)"),
        ("max_interval", 3600, "Longest interval considered (seconds)"),
        ("skip_ports", "53,123", "Ports to leave out (DNS, NTP)"),
    ]

    def __init__(self):
        super().__init__()
        self.skip = _parse_ports(self.cfg["skip_ports"])

    def configure(self, settings: dict) -> None:
        super().configure(settings)
        self.skip = _parse_ports(self.cfg["skip_ports"])

    def process(self, ev, now, emit):
        if (ev.event_type != "traffic" or ev.action != "allow" or ev.dst_port is None or ev.dst_port in self.skip
                or not ev.src_ip or not ev.dst_ip or not is_internal(ev.src_ip) or is_internal(ev.dst_ip)):
            return
        cfg = self.cfg
        need = max(4, cfg["connections"] - 1)
        key = (ev.src_ip, ev.dst_ip, ev.dst_port)
        beat = self._get(key, lambda: _Beat(need), now)
        if beat is None:
            return
        gap = now - beat.last
        if beat.last and gap < 5:
            return  # several sessions of one check-in
        if beat.last:
            beat.gaps.append(gap)
        beat.last = now
        if len(beat.gaps) < need:
            return
        mean = statistics.fmean(beat.gaps)
        if not cfg["min_interval"] <= mean <= cfg["max_interval"]:
            return
        spread = statistics.pstdev(beat.gaps) / mean
        if spread <= cfg["jitter"] and self._may_emit(key, now):
            emit(Candidate(
                self.id, f"{ev.src_ip}>{ev.dst_ip}:{ev.dst_port}", "medium",
                f"{ev.src_ip} is beaconing to {ev.dst_ip}:{ev.dst_port}",
                f"Internal host {ev.src_ip} has contacted {ev.dst_ip} on {service(ev.dst_port, ev.proto)} every "
                f"{mean:.0f} seconds, {len(beat.gaps) + 1} times in a row, varying by only {spread * 100:.0f}%.",
                ev.src_ip, ev.device,
                {"destination": ev.dst_ip, "port": ev.dst_port, "interval_seconds": round(mean),
                 "variation_percent": round(spread * 100, 1), **context(ev)},
            ))

    def tick(self, now, emit):
        self._prune(now, self.cfg["max_interval"] * 2 + 60)


class CredentialAttacks(Detector):
    id = "credential_attacks"
    name = "Password spraying and distributed guessing"
    description = ("One source trying many different usernames (spraying), or one account being attacked from "
                   "many sources at once - patterns that slip under a simple failed-login count.")
    params = [
        ("users", 6, "Spraying: distinct usernames from one source"),
        ("sources", 5, "Distributed: distinct sources against one account"),
        ("window", 600, "Within (seconds)"),
    ]

    def process(self, ev, now, emit):
        if ev.event_type != "auth_failure" or not ev.user:
            return
        user = ev.user[:64]
        host = ev.hostname or ev.device
        if ev.src_ip:
            key = ("spray", ev.src_ip, ev.device)
            users = self._get(key, SlidingSet, now)
            if users is not None:
                count = users.add(user, now, self.cfg["window"])
                if count >= self.cfg["users"] and self._may_emit(key, now):
                    emit(Candidate(
                        "password_spray", f"{ev.src_ip}@{ev.device}",
                        "high" if is_internal(ev.src_ip) else "medium",
                        f"Password spraying from {ev.src_ip} against {_clip(host, 40)}",
                        f"{_origin(ev.src_ip).capitalize()} {ev.src_ip} failed to log in to {host} as {count} "
                        f"different users within {self.cfg['window'] // 60} minutes: "
                        f"{_clip(', '.join(users.items), 140)}.",
                        ev.src_ip, ev.device, {"usernames": list(users.items)[-20:]},
                    ))
            key = ("dist", ev.device, user)
            sources = self._get(key, SlidingSet, now)
            if sources is not None:
                count = sources.add(ev.src_ip, now, self.cfg["window"])
                if count >= self.cfg["sources"] and self._may_emit(key, now):
                    emit(Candidate(
                        "distributed_brute_force", f"{user}@{ev.device}", "medium",
                        f"Account '{_clip(user, 30)}' on {_clip(host, 40)} attacked from {count} sources",
                        f"Logins to {host} as '{_clip(user, 40)}' failed from {count} different addresses within "
                        f"{self.cfg['window'] // 60} minutes. Per-source lockouts will not stop this.",
                        None, ev.device, {"user": user, "sources": list(sources.items)[-20:]},
                    ))


class AdminAccess(Detector):
    id = "admin_access"
    name = "Unexpected administrative access"
    description = ("A successful login to a firewall or switch from the internet, or from an address that has "
                   "never managed that device before. Optionally also flags logins and configuration changes "
                   "outside working hours.")
    params = [
        ("learning_hours", 24, "Learn each device's usual admin sources for (hours)"),
        ("quiet_start", 0, "Out-of-hours starts at (hour 0-23; same as end = off)"),
        ("quiet_end", 0, "Out-of-hours ends at (hour 0-23)"),
    ]

    _persist = (*Detector._persist, "known", "first")

    def __init__(self):
        super().__init__()
        self.known: dict[str, dict[str, float]] = {}  # device -> {source ip: first seen}
        self.first: dict[str, float] = {}  # device -> first login ever observed

    def restore_legacy(self, state: dict) -> None:
        """What 0.2.0 and earlier saved, under the 'admin_sources' setting."""
        self.known = {str(k): dict(v) for k, v in (state.get("known") or {}).items()}
        self.first = {str(k): float(v) for k, v in (state.get("first") or {}).items()}

    def _quiet(self, now: float) -> bool:
        start, end = self.cfg["quiet_start"] % 24, self.cfg["quiet_end"] % 24
        if start == end:
            return False
        hour = time.localtime(now).tm_hour
        return start <= hour < end if start < end else hour >= start or hour < end

    def process(self, ev, now, emit):
        if ev.event_type not in ("auth_success", "config_change"):
            return
        host = ev.hostname or ev.device
        who = _clip(ev.user, 40) or "unknown user"
        if self._quiet(now) and self._may_emit(("quiet", ev.device, ev.event_type, ev.user), now):
            what = "Configuration change" if ev.event_type == "config_change" else "Admin login"
            emit(Candidate(
                "admin_after_hours", f"{ev.device}|{ev.event_type}|{ev.user}", "medium",
                f"{what} on {_clip(host, 40)} outside working hours",
                f"{what} on {host} by {who}" + (f" from {ev.src_ip}" if ev.src_ip else "")
                + f" at {time.strftime('%H:%M', time.localtime(now))}, outside the hours you set as normal.",
                ev.src_ip, ev.device, {"user": ev.user},
            ))
        if ev.event_type != "auth_success" or not ev.src_ip:
            return
        if not is_internal(ev.src_ip):
            if self._may_emit(("ext", ev.device, ev.src_ip), now):
                emit(Candidate(
                    "admin_from_internet", f"{ev.src_ip}@{ev.device}", "high",
                    f"Admin login to {_clip(host, 40)} from the internet ({ev.src_ip})",
                    f"{who} logged in to {host} from the internet address {ev.src_ip}. Management access "
                    "should not be reachable from outside.",
                    ev.src_ip, ev.device, {"user": ev.user},
                ))
            return
        first = self.first.setdefault(ev.device, now)
        seen = self.known.setdefault(ev.device, {})
        if ev.src_ip in seen:
            return
        if len(seen) < 500:
            seen[ev.src_ip] = now
        if now - first >= self.cfg["learning_hours"] * 3600:
            emit(Candidate(
                "admin_new_source", f"{ev.src_ip}@{ev.device}", "medium",
                f"First admin login to {_clip(host, 40)} from {ev.src_ip}",
                f"{who} logged in to {host} from {ev.src_ip}, an address that has not managed this device "
                f"before ({len(seen) - 1} known admin source{'s' if len(seen) != 2 else ''}).",
                ev.src_ip, ev.device, {"user": ev.user, "known_sources": list(seen)[:20]},
            ))


class Watchlist(Detector):
    id = "watchlist"
    name = "Watchlist match"
    description = ("Traffic to or from addresses you list here: known-bad IPs from an incident or a threat feed, "
                   "sanctioned ranges, or anything else that should never appear. One IP or CIDR per line.")
    params = [
        ("entries", "", "Watched IPs and CIDR ranges"),
    ]
    multiline = ("entries",)

    def __init__(self):
        super().__init__()
        self.nets: list = []
        self.cache: dict[str, bool] = {}

    def configure(self, settings: dict) -> None:
        super().configure(settings)
        nets, kept = [], []
        for item in str(self.cfg["entries"]).replace(",", "\n").split():
            try:
                nets.append(ipaddress.ip_network(item, strict=False))
                kept.append(item)
            except ValueError:
                continue
        self.cfg["entries"] = "\n".join(kept)
        self.nets, self.cache = nets, {}

    def _listed(self, ip: str | None) -> bool:
        if not ip:
            return False
        hit = self.cache.get(ip)
        if hit is None:
            try:
                addr = ipaddress.ip_address(ip)
                hit = any(addr.version == n.version and addr in n for n in self.nets)
            except ValueError:
                hit = False
            if len(self.cache) > 100_000:
                self.cache.clear()
            self.cache[ip] = hit
        return hit

    def process(self, ev, now, emit):
        if not self.nets or ev.event_type != "traffic":
            return
        if self._listed(ev.src_ip):
            listed, peer, direction = ev.src_ip, ev.dst_ip, "from"
        elif self._listed(ev.dst_ip):
            listed, peer, direction = ev.dst_ip, ev.src_ip, "to"
        else:
            return
        allowed = ev.action == "allow"
        key = (listed, peer, allowed)
        if not self._may_emit(key, now):
            return
        # The alert is "about" the internal host only when it reached out, or was reached:
        # a blocked inbound attempt says nothing against its target.
        suspect = peer if peer and is_internal(peer) and (allowed or direction == "to") else listed
        emit(Candidate(
            self.id, f"{listed}|{peer}|{'allow' if allowed else 'block'}", "high" if allowed else "low",
            f"{'Allowed' if allowed else 'Blocked'} traffic {direction} watchlisted {listed}",
            f"{ev.hostname or ev.device} {'allowed' if allowed else 'blocked'} a connection {direction} watchlisted "
            f"address {listed} ({peer or '?'} {'→' if direction == 'to' else '←'} {listed}"
            + (f", {service(ev.dst_port, ev.proto)}" if ev.dst_port is not None else "") + ").",
            suspect, ev.device,
            {"watchlisted": listed, "peer": peer, "allowed": allowed, **context(ev)},
        ))


# Alerts that say something hostile about their source address.
_INDICATORS = {
    "port_scan": "port scanning", "host_sweep": "host sweeping", "deny_flood": "a flood of blocked traffic",
    "brute_force": "login brute forcing", "brute_force_success": "a login after repeated failures",
    "password_spray": "password spraying", "threat": "an IDS/threat detection", "risky_egress": "risky outbound traffic",
    "lateral_movement": "lateral movement", "beaconing": "beaconing", "large_transfer": "a large outbound transfer",
    "watchlist": "watchlisted traffic", "admin_new_source": "a first-time admin login",
}
_HOSTILE = ("port_scan", "host_sweep", "deny_flood", "brute_force", "password_spray", "threat")
# Detectors that see the same behaviour from different angles count once towards
# "several kinds of attack behaviour": the same failed logins trip both brute force
# and spraying, and a sweep and a port scan are both scanning.
_SAME_KIND = {"port_scan": "network scanning", "host_sweep": "network scanning",
              "brute_force": "password guessing", "password_spray": "password guessing",
              "brute_force_success": "password guessing"}


class Correlation(Detector):
    id = "correlation"
    name = "Correlation"
    description = ("Joins separate alerts: an internal host showing several different kinds of attack behaviour "
                   "is raised as a likely compromise, and an internet address that was scanning or guessing "
                   "passwords is flagged if the firewall later lets it in.")
    params = [
        ("indicators", 3, "Different kinds of attack behaviour on one host to call it compromised"),
        ("window_hours", 24, "Look back (hours)"),
    ]

    _persist = (*Detector._persist, "hosts", "hostile")

    def __init__(self):
        super().__init__()
        self.hosts: dict[str, dict[str, float]] = {}  # internal ip -> {kind of behaviour: last seen}
        self.hostile: dict[str, tuple[float, str]] = {}  # external ip -> (when, why)

    def on_alert(self, c: Candidate, now: float, emit) -> None:
        """Called for every alert any detector raises."""
        if not c.src_ip or c.detector not in _INDICATORS:
            return
        window = self.cfg["window_hours"] * 3600
        if not is_internal(c.src_ip):
            if c.detector in _HOSTILE and (c.src_ip in self.hostile or len(self.hostile) < 20_000):
                self.hostile[c.src_ip] = (now, _INDICATORS[c.detector])
            return
        seen = self.hosts.get(c.src_ip)
        if seen is None:
            if len(self.hosts) >= 20_000:
                return
            seen = self.hosts[c.src_ip] = {}
        seen[_SAME_KIND.get(c.detector, _INDICATORS[c.detector])] = now
        for name in [d for d, t in seen.items() if now - t > window]:
            del seen[name]
        if len(seen) >= self.cfg["indicators"] and self._may_emit(("host", c.src_ip), now):
            what = list(seen)
            emit(Candidate(
                "compromise_suspected", c.src_ip, "critical",
                f"Likely compromised host: {c.src_ip}",
                f"Internal host {c.src_ip} has shown {len(seen)} different kinds of attack behaviour in the last "
                f"{self.cfg['window_hours']} hours: {', '.join(what)}.",
                c.src_ip, c.device, {"indicators": what},
            ))

    def process(self, ev, now, emit):
        if not self.hostile or ev.event_type != "traffic" or ev.action != "allow" or not ev.src_ip:
            return
        entry = self.hostile.get(ev.src_ip)
        if not entry or now - entry[0] > self.cfg["window_hours"] * 3600:
            return
        target = _inside(ev)
        if not target or not self._may_emit(("hostile", ev.src_ip, target), now):
            return
        rule = rule_name(ev)
        emit(Candidate(
            "hostile_allowed", f"{ev.src_ip}>{target}", "high",
            f"Hostile address {ev.src_ip} was allowed in to {target}",
            f"{ev.src_ip} was seen {entry[1]} {max(1, int((now - entry[0]) // 60))} minutes ago, and "
            f"{ev.hostname or ev.device} has now allowed it to connect to {target}"
            + (f" on {service(ev.dst_port, ev.proto)}" if ev.dst_port is not None else "")
            + (f" under rule '{_clip(rule, 60)}'" if rule else "") + ".",
            ev.src_ip, ev.device,
            {"target": target, "port": ev.dst_port, "earlier_activity": entry[1], **context(ev)},
        ))

    def tick(self, now, emit):
        window = self.cfg["window_hours"] * 3600
        for ip in [ip for ip, (t, _) in self.hostile.items() if now - t > window]:
            del self.hostile[ip]
        for ip in [ip for ip, seen in self.hosts.items() if all(now - t > window for t in seen.values())]:
            del self.hosts[ip]
        self._prune(now, 600)


def build_security_detectors() -> list[Detector]:
    from .riskports import RiskPorts  # imported here: riskports.py builds on detectors.py too

    return [ExposedService(), RiskyEgress(), LateralMovement(), Beaconing(), CredentialAttacks(),
            AdminAccess(), Watchlist(), RiskPorts(), Correlation()]
