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


KAFKA_SECURITY = ("PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL")
SASL_MECHANISMS = ("PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512")


def _kafka_security(text: str) -> str:
    value = (text or "PLAINTEXT").strip().upper()
    if value not in KAFKA_SECURITY:
        raise ValueError(f"CERBERUS_KAFKA_SECURITY must be one of {', '.join(KAFKA_SECURITY)}")
    return value


FAMILIES = ("source", "target", "pair", "port", "account")


def _families(text: str) -> tuple:
    """CERBERUS_DETECTION_WORKERS: "all", or some of the worker families, comma-separated."""
    text = text.strip().lower()
    if not text:
        return ()
    if text == "all":
        return FAMILIES
    wanted = tuple(dict.fromkeys(f.strip() for f in text.replace(" ", ",").split(",") if f.strip()))
    unknown = [f for f in wanted if f not in FAMILIES]
    if unknown:
        raise ValueError(f"CERBERUS_DETECTION_WORKERS: unknown famil{'ies' if len(unknown) > 1 else 'y'} "
                         f"{', '.join(unknown)} (choose from {', '.join(FAMILIES)}, or all)")
    return wanted


def _networks(text: str) -> list[str]:
    """Comma- or space-separated IPs/CIDRs; anything else is a configuration error."""
    import ipaddress
    out = []
    for item in text.replace(",", " ").split():
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            raise ValueError(f"not an IP address or network: {item!r}") from None
    return out


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
    # Clustered storage: both set, or neither (SQLite in data_dir).
    postgres_url: str = ""
    clickhouse_url: str = ""
    # Scale-out: "all" (one process does everything), "collector" or "processor".
    mode: str = "all"
    kafka_bootstrap: str = ""
    kafka_topic: str = "cerberus.events"
    kafka_group: str = "cerberus-processor"
    kafka_partitions: int = 12
    kafka_replication: int = 1
    kafka_security: str = "PLAINTEXT"  # SSL, SASL_PLAINTEXT or SASL_SSL
    kafka_ca: str = ""
    kafka_sasl_mechanism: str = "SCRAM-SHA-512"  # PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512
    kafka_username: str = ""
    kafka_password: str = ""
    collector_name: str = ""
    spool_mb: int = 1024
    collector_silent_seconds: int = 90
    # Detection families run by detection workers rather than the processor (scale-out).
    detection_workers: tuple = ()
    detection_family: str = ""  # in CERBERUS_MODE=detector: which family this worker runs
    worker_replay_minutes: int = 60  # how far back a worker rebuilds its windows from the bus
    metrics_token: str = ""  # if set, /metrics requires "Authorization: Bearer <token>"
    # Single sign-on (OpenID Connect); see accounts.py
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_label: str = ""
    oidc_role_claim: str = "groups"
    oidc_admin_groups: str = ""
    oidc_analyst_groups: str = ""
    oidc_viewer_groups: str = ""
    oidc_default_role: str = ""
    # Ingest options for any mode that receives syslog.
    syslog_tls_port: int = 0
    syslog_tls_cert: str = ""
    syslog_tls_key: str = ""
    syslog_tls_client_ca: str = ""
    proxy_protocol_from: tuple = ()

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
            postgres_url=_secret("CERBERUS_POSTGRES_URL"),
            clickhouse_url=_secret("CERBERUS_CLICKHOUSE_URL"),
            mode=env("CERBERUS_MODE", "all").lower() if env("CERBERUS_MODE", "all").lower() in ("all", "collector", "processor", "detector") else "all",
            kafka_bootstrap=env("CERBERUS_KAFKA_BOOTSTRAP", ""),
            kafka_topic=env("CERBERUS_KAFKA_TOPIC", "cerberus.events"),
            kafka_group=env("CERBERUS_KAFKA_GROUP", "cerberus-processor"),
            kafka_partitions=max(1, _int("CERBERUS_KAFKA_PARTITIONS", 12)),
            kafka_replication=max(1, _int("CERBERUS_KAFKA_REPLICATION", 1)),
            kafka_security=_kafka_security(env("CERBERUS_KAFKA_SECURITY", "")),
            kafka_ca=env("CERBERUS_KAFKA_CA", ""),
            kafka_sasl_mechanism=env("CERBERUS_KAFKA_SASL_MECHANISM", "SCRAM-SHA-512").strip().upper(),
            kafka_username=env("CERBERUS_KAFKA_USERNAME", ""),
            kafka_password=_secret("CERBERUS_KAFKA_PASSWORD"),
            collector_name=env("CERBERUS_COLLECTOR_NAME", "") or socket.gethostname(),
            spool_mb=max(10, _int("CERBERUS_SPOOL_MB", 1024)),
            collector_silent_seconds=max(30, _int("CERBERUS_COLLECTOR_SILENT_SECONDS", 90)),
            detection_workers=_families(env("CERBERUS_DETECTION_WORKERS", "")),
            detection_family=env("CERBERUS_DETECTION_FAMILY", "").strip().lower(),
            worker_replay_minutes=max(0, _int("CERBERUS_WORKER_REPLAY_MINUTES", 60)),
            metrics_token=_secret("CERBERUS_METRICS_TOKEN"),
            oidc_issuer=env("CERBERUS_OIDC_ISSUER", "").strip(),
            oidc_client_id=env("CERBERUS_OIDC_CLIENT_ID", "").strip(),
            oidc_client_secret=_secret("CERBERUS_OIDC_CLIENT_SECRET"),
            oidc_redirect_url=env("CERBERUS_OIDC_REDIRECT_URL", "").strip(),
            oidc_scopes=env("CERBERUS_OIDC_SCOPES", "openid email profile groups").strip(),
            oidc_label=env("CERBERUS_OIDC_LABEL", "").strip(),
            oidc_role_claim=env("CERBERUS_OIDC_ROLE_CLAIM", "groups").strip(),
            oidc_admin_groups=env("CERBERUS_OIDC_ADMIN_GROUPS", ""),
            oidc_analyst_groups=env("CERBERUS_OIDC_ANALYST_GROUPS", ""),
            oidc_viewer_groups=env("CERBERUS_OIDC_VIEWER_GROUPS", ""),
            oidc_default_role=env("CERBERUS_OIDC_DEFAULT_ROLE", "").strip().lower(),
            syslog_tls_port=_int("CERBERUS_SYSLOG_TLS_PORT", 0),
            syslog_tls_cert=env("CERBERUS_SYSLOG_TLS_CERT", ""),
            syslog_tls_key=env("CERBERUS_SYSLOG_TLS_KEY", ""),
            syslog_tls_client_ca=env("CERBERUS_SYSLOG_TLS_CLIENT_CA", ""),
            proxy_protocol_from=tuple(_networks(env("CERBERUS_PROXY_PROTOCOL_FROM", ""))),
        )
