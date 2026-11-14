"""Shared data types."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache

SEVERITIES = ["info", "low", "medium", "high", "critical"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def sev_rank(sev: str) -> int:
    return _RANK.get(sev, 0)


def _octets(value: str) -> tuple[int, int] | None:
    """First two octets of a canonical dotted IPv4 address, else None. This is the
    hot path: nearly every address in a firewall log is one of these, and
    ipaddress costs ten times as much."""
    parts = value.split(".")
    if len(parts) != 4:
        return None
    for p in parts:
        if not (p.isascii() and p.isdigit()) or len(p) > 3 or (p[0] == "0" and len(p) > 1) or int(p) > 255:
            return None
    return int(parts[0]), int(parts[1])


@lru_cache(maxsize=262144)
def clean_ip(value: str) -> str | None:
    """Return a canonical IP string, or None if the value is not an address."""
    value = value.strip().strip("[]")
    if _octets(value):
        return value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128",
)]


@lru_cache(maxsize=262144)
def is_internal(ip: str) -> bool:
    """True for RFC1918 / CGNAT / ULA / link-local / loopback addresses."""
    v4 = _octets(ip)
    if v4:
        a, b = v4
        return (a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
                or (a == 100 and 64 <= b <= 127) or (a == 169 and b == 254))
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Not ipaddress.is_private: that also covers documentation and benchmark
    # ranges, which are not "inside your network".
    return any(addr.version == net.version and addr in net for net in _INTERNAL)


@dataclass(slots=True)
class Event:
    """One syslog message after a connector has normalised it."""

    ts: float
    device: str  # device identity (source IP, or hostname if so configured)
    source_ip: str
    hostname: str = ""
    facility: int = 1
    severity: int = 5  # syslog severity, 0 (emergency) .. 7 (debug)
    app: str = ""
    message: str = ""
    connector: str = ""
    rule: str = ""
    event_type: str = "other"
    action: str = ""  # "allow" | "block" | ""
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: str = ""
    bytes: int | None = None
    user: str = ""
    interface: str = ""
    state: str = ""
    level: str = ""  # vendor-assigned importance, one of SEVERITIES
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {name: getattr(self, name) for name in self.__slots__}


@dataclass(slots=True)
class Candidate:
    """An alert a detector wants raised. `entity` identifies what it is about,
    so repeats of the same thing fold into one alert."""

    detector: str
    entity: str
    severity: str
    title: str
    description: str
    src_ip: str | None = None
    device: str = ""
    details: dict = field(default_factory=dict)
