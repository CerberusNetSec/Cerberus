"""Runtime configuration, read once from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


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
            password=env("CERBERUS_PASSWORD", ""),
            auth_enabled=env("CERBERUS_AUTH", "on").lower() not in ("off", "0", "false", "no"),
            public_url=env("CERBERUS_PUBLIC_URL", "").rstrip("/"),
        )
