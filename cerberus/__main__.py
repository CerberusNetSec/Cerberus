"""Entry point: python -m cerberus"""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from . import __version__
from .config import Config
from .connectors import ConnectorRegistry
from .backends import open_store
from .engine import Engine
from .federation import Central, Forwarder
from .notifiers import Notifier
from .receiver import SyslogReceiver, tls_context
from .snmp_poller import SnmpPoller
from .web import create_app

log = logging.getLogger("cerberus")


def make_receiver(cfg: Config, submit) -> SyslogReceiver:
    tls = None
    if cfg.syslog_tls_port:
        if not (cfg.syslog_tls_cert and cfg.syslog_tls_key):
            raise SystemExit("CERBERUS_SYSLOG_TLS_PORT needs CERBERUS_SYSLOG_TLS_CERT and CERBERUS_SYSLOG_TLS_KEY.")
        tls = tls_context(cfg.syslog_tls_cert, cfg.syslog_tls_key, cfg.syslog_tls_client_ca)
    return SyslogReceiver(submit, cfg.bind, cfg.syslog_udp_port, cfg.syslog_tcp_port, cfg.max_tcp_clients,
                          cfg.syslog_tls_port, tls, cfg.proxy_protocol_from)


async def run_collector(cfg: Config) -> None:
    from .bus import Publisher, ensure_topics
    from .collector import Collector, status_app

    store = open_store(cfg) if cfg.postgres_url else None  # for device pins, when shared storage is in use
    try:
        await ensure_topics(cfg)
    except Exception as exc:
        log.warning("message bus not reachable at start (%s); events will be spooled", exc)
    collector = Collector(cfg, ConnectorRegistry(cfg.data_dir / "connectors"),
                          Publisher(cfg, cfg.data_dir / "spool"), store)
    receiver = make_receiver(cfg, collector.submit)
    collector.receiver = receiver
    await collector.start()
    await receiver.start()
    server = uvicorn.Server(uvicorn.Config(status_app(collector), host=cfg.bind, port=cfg.web_port,
                                           log_level="warning", access_log=False))
    log.info("Cerberus %s collector %s; status on http://%s:%d/status", __version__, collector.name, cfg.bind,
             cfg.web_port)
    try:
        await server.serve()
    finally:
        await receiver.stop()
        await collector.stop()
        if store:
            store.close()
        log.info("stopped")


async def run_worker(cfg: Config) -> None:
    from .bus import Publisher, ensure_topics
    from .detectors import WORKER_FAMILIES
    from .worker import DetectionWorker

    if cfg.detection_family not in WORKER_FAMILIES:
        raise SystemExit(f"CERBERUS_DETECTION_FAMILY must be one of {', '.join(WORKER_FAMILIES)}.")
    if cfg.detection_family not in cfg.detection_workers:
        raise SystemExit("CERBERUS_DETECTION_WORKERS must include this worker's family, as on the collectors "
                         "and the processor.")
    if not cfg.postgres_url:
        raise SystemExit("A detection worker needs clustered storage (CERBERUS_POSTGRES_URL and CERBERUS_CLICKHOUSE_URL).")
    store = open_store(cfg)
    await ensure_topics(cfg)
    engine = Engine(cfg, store, ConnectorRegistry(cfg.data_dir / "connectors"), Notifier(store))
    engine.families = {cfg.detection_family}
    worker = DetectionWorker(cfg, store, engine, Publisher(cfg, cfg.data_dir / "spool", name=f"worker-{cfg.detection_family}"))
    await worker.start()

    from fastapi import FastAPI
    app = FastAPI(title="Cerberus detection worker", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    @app.get("/status")
    async def status():
        return worker.status()

    server = uvicorn.Server(uvicorn.Config(app, host=cfg.bind, port=cfg.web_port, log_level="warning", access_log=False))
    log.info("Cerberus %s detection worker %s; status on http://%s:%d/status", __version__, worker.name, cfg.bind,
             cfg.web_port)
    try:
        await server.serve()
    finally:
        await worker.stop()
        store.close()
        log.info("stopped")


async def amain() -> None:
    cfg = Config.from_env()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    user_connectors = cfg.data_dir / "connectors"
    user_connectors.mkdir(exist_ok=True)
    if cfg.mode != "all" and not cfg.kafka_bootstrap:
        raise SystemExit(f"CERBERUS_MODE={cfg.mode} needs CERBERUS_KAFKA_BOOTSTRAP.")
    if cfg.mode == "collector":
        await run_collector(cfg)
        return
    if cfg.mode == "detector":
        await run_worker(cfg)
        return

    db = open_store(cfg)
    notifier = Notifier(db, cfg.public_url)
    engine = Engine(cfg, db, ConnectorRegistry(user_connectors), notifier)
    heartbeats = None
    receiver = None
    if cfg.mode == "processor":
        from .bus import Deduplicator, EventSource, Heartbeats, ensure_topics
        await ensure_topics(cfg)
        engine.source = EventSource(cfg)
        engine.dedup = Deduplicator()
        if cfg.detection_workers:
            from .bus import candidates_topic
            from .detectors import WORKER_FAMILIES
            engine.families = {"device", "alerts", *(f for f in WORKER_FAMILIES if f not in cfg.detection_workers)}
            engine.candidates = EventSource(cfg, topic=candidates_topic(cfg), group=f"{cfg.kafka_group}-alerts")
            await engine.candidates.start()
            engine.candidate_dedup = Deduplicator()
            log.info("detection workers run: %s", ", ".join(cfg.detection_workers))
        await engine.source.start()
        heartbeats = Heartbeats(cfg)
        log.info("processor: consuming %s from %s", cfg.kafka_topic, cfg.kafka_bootstrap)
    else:
        receiver = make_receiver(cfg, engine.submit)

    poller = SnmpPoller(engine, db)

    await engine.start()
    notify_task = asyncio.create_task(notifier.run())
    snmp_task = asyncio.create_task(poller.run())
    if receiver:
        await receiver.start()

    engine.receiver = receiver
    tasks = []
    if heartbeats:
        tasks.append(asyncio.create_task(heartbeats.watch()))
        tasks.append(asyncio.create_task(watch_collectors(cfg, engine, heartbeats)))
    forwarder = central = None
    if cfg.central_url:
        if len(cfg.central_token) < 24:
            raise SystemExit("CERBERUS_CENTRAL_URL is set but CERBERUS_CENTRAL_TOKEN is missing or too short.")
        forwarder = Forwarder(cfg, db, engine)
        tasks.append(asyncio.create_task(forwarder.run()))
    if cfg.central:
        central = Central(cfg, db, engine)
        await asyncio.to_thread(central.provision, list(cfg.site_tokens))
        tasks.append(asyncio.create_task(central.run()))
        log.info("acting as central console")
    app = create_app(cfg, db, engine, notifier, poller, forwarder, central, heartbeats)
    server = uvicorn.Server(uvicorn.Config(
        app, host=cfg.bind, port=cfg.web_port, log_level="warning", access_log=False))
    log.info("Cerberus %s - dashboard on http://%s:%d", __version__, cfg.bind, cfg.web_port)
    try:
        await server.serve()  # returns on SIGINT / SIGTERM
    finally:
        if receiver:
            await receiver.stop()
        for task in tasks:
            task.cancel()
        if forwarder:
            await forwarder.close()
        snmp_task.cancel()
        poller.client.close()
        await engine.stop()
        if engine.source:
            await engine.source.stop()
        if engine.candidates:
            await engine.candidates.stop()
        notify_task.cancel()
        await notifier.close()
        db.close()
        log.info("stopped")


async def watch_collectors(cfg: Config, engine, heartbeats) -> None:
    """Processor: alert when a collector that was reporting goes quiet."""
    import time

    from .models import Candidate
    silent: set[str] = set()
    while True:
        await asyncio.sleep(15)
        now = time.time()
        for name, status in list(heartbeats.latest.items()):
            quiet = now - status.get("received_at", now)
            if quiet <= cfg.collector_silent_seconds:
                silent.discard(name)
            elif name not in silent:
                silent.add(name)
                engine.raise_alert(Candidate(
                    "collector_silent", f"collector|{name}", "high", f"Collector stopped reporting: {name}",
                    f"Collector {name} has not sent a heartbeat for {int(quiet)} seconds. Devices sending to it are "
                    "not being analysed unless the load balancer has moved them to another collector.",
                    None, "", {"collector": name, "silent_seconds": int(quiet)}), now)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # its INFO lines include bot-token URLs
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
