"""Syslog listener settings: which of UDP, TCP and TLS are on, and on which port.

The environment (CERBERUS_SYSLOG_UDP_PORT, _TCP_PORT, _TLS_PORT) gives the
starting point. Once listeners are saved under Settings → Syslog, the saved
choice wins and is applied at every start. Changing a listener takes effect
immediately (see SyslogReceiver.reconfigure).

Only the process that receives syslog uses this: a single Cerberus. Collectors
in a scale-out deployment keep their environment, so all of them listen on the
same ports behind the load balancer.
"""
from __future__ import annotations

KINDS = ("udp", "tcp", "tls")
SETTING = "listeners"


def from_config(cfg) -> dict:
    """The listeners the environment asks for, in the saved-setting shape."""
    out = {}
    for kind, port, default in (("udp", cfg.syslog_udp_port, 5514), ("tcp", cfg.syslog_tcp_port, 5514),
                                ("tls", cfg.syslog_tls_port, 6514)):
        out[kind] = {"enabled": bool(port), "port": port or default}
    return out


def clean(given, current: dict) -> dict:
    """Validate a listeners setting; raises ValueError with a message for the user."""
    if not isinstance(given, dict):
        raise ValueError("invalid listener settings")
    out = {}
    for kind in KINDS:
        entry = given.get(kind, current[kind])
        if not isinstance(entry, dict):
            raise ValueError(f"invalid {kind.upper()} settings")
        try:
            port = int(entry.get("port", current[kind]["port"]))
        except (TypeError, ValueError):
            raise ValueError(f"the {kind.upper()} port must be a number")
        if not 1 <= port <= 65535:
            raise ValueError(f"the {kind.upper()} port must be between 1 and 65535")
        out[kind] = {"enabled": bool(entry.get("enabled", current[kind]["enabled"])), "port": port}
    if out["tcp"]["enabled"] and out["tls"]["enabled"] and out["tcp"]["port"] == out["tls"]["port"]:
        raise ValueError("TCP and TLS cannot share a port")
    return out


def ports(setting: dict) -> dict[str, int]:
    """{kind: port, 0 when off}."""
    return {kind: (setting[kind]["port"] if setting[kind]["enabled"] else 0) for kind in KINDS}


def apply_saved(cfg, saved) -> None:
    """Start with the saved listeners, if any (TLS only when a certificate is configured)."""
    if not isinstance(saved, dict):
        return
    try:
        setting = clean(saved, from_config(cfg))
    except ValueError:
        return
    wanted = ports(setting)
    cfg.syslog_udp_port, cfg.syslog_tcp_port = wanted["udp"], wanted["tcp"]
    cfg.syslog_tls_port = wanted["tls"] if cfg.syslog_tls_cert and cfg.syslog_tls_key else 0
