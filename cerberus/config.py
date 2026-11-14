"""Runtime configuration, read once from environment variables."""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _secret(name: str, default: str = "") -> str:
    """NAME, or the contents of the file named by NAME_FILE (Docker and Kubernetes secrets)."""
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(name, default)


def _site_tokens() -> list[tuple[str, str]]:
    """Sites declared for a central console: lines of "name token" in CERBERUS_SITE_TOKENS_FILE."""
    path = os.environ.get("CERBERUS_SITE_TOKENS_FILE")
    entries: list[tuple[str, str]] = []
    if not path:
        return entries
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2 or len(parts[1]) < 24:
                raise ValueError(f"{path} line {number}: expected 'site-name token' with a token of 24+ characters")
            entries.append((parts[0], parts[1]))
    return entries


@dataclass
class Config:
    data_dir: Path
    bind: str
    syslog_udp_port: int
    syslog_tcp_port: int
    web_port: int
    retention_days: int
    max_events: int
    alert_retention_days: int
    traffic_sample: int  # store one in N allowed-traffic events (1 = all, 0 = none)
    max_tcp_clients: int
    device_identity: str  # "ip" or "hostname"
    password: str
    auth_enabled: bool
    public_url: str
    # Federation
    site_name: str = ""
    central_url: str = ""  # set on a site to report to a central console
    central_token: str = ""
    central_ca: str = ""  # CA bundle to trust for the console's certificate
    central: bool = False  # act as the central console
    site_tokens: tuple = ()
    site_silent_minutes: int = 5

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get
        identity = env("CERBERUS_DEVICE_IDENTITY", "ip").lower()
        return cls(
            data_dir=Path(env("CERBERUS_DATA_DIR", "./data")),
            bind=env("CERBERUS_BIND", "0.0.0.0"),
            syslog_udp_port=_int("CERBERUS_SYSLOG_UDP_PORT", 5514),
            syslog_tcp_port=_int("CERBERUS_SYSLOG_TCP_PORT", 5514),
            web_port=_int("CERBERUS_WEB_PORT", 8080),
            retention_days=_int("CERBERUS_RETENTION_DAYS", 7),
            max_events=_int("CERBERUS_MAX_EVENTS", 2_000_000),
            alert_retention_days=_int("CERBERUS_ALERT_RETENTION_DAYS", 90),
            traffic_sample=max(0, _int("CERBERUS_TRAFFIC_SAMPLE", 1)),
            max_tcp_clients=max(1, _int("CERBERUS_MAX_TCP_CLIENTS", 1000)),
            device_identity=identity if identity in ("ip", "hostname") else "ip",
            password=_secret("CERBERUS_PASSWORD"),
            auth_enabled=env("CERBERUS_AUTH", "on").lower() not in ("off", "0", "false", "no"),
            public_url=env("CERBERUS_PUBLIC_URL", "").rstrip("/"),
            site_name=env("CERBERUS_SITE_NAME", "") or socket.gethostname(),
            central_url=env("CERBERUS_CENTRAL_URL", "").rstrip("/"),
            central_token=_secret("CERBERUS_CENTRAL_TOKEN"),
            central_ca=env("CERBERUS_CENTRAL_CA", ""),
            central=env("CERBERUS_CENTRAL", "off").lower() in ("on", "1", "true", "yes"),
            site_tokens=tuple(_site_tokens()),
            site_silent_minutes=_int("CERBERUS_SITE_SILENT_MINUTES", 5),
        )
