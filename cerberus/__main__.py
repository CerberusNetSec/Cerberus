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
from .receiver import SyslogReceiver
from .snmp_poller import SnmpPoller
from .web import create_app

log = logging.getLogger("cerberus")


async def amain() -> None:
    cfg = Config.from_env()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    user_connectors = cfg.data_dir / "connectors"
    user_connectors.mkdir(exist_ok=True)

    db = open_store(cfg)
    notifier = Notifier(db, cfg.public_url)
    engine = Engine(cfg, db, ConnectorRegistry(user_connectors), notifier)
    receiver = SyslogReceiver(engine.submit, cfg.bind, cfg.syslog_udp_port, cfg.syslog_tcp_port,
                              cfg.max_tcp_clients)

    poller = SnmpPoller(engine, db)

    await engine.start()
    notify_task = asyncio.create_task(notifier.run())
    snmp_task = asyncio.create_task(poller.run())
    await receiver.start()

    engine.receiver = receiver
    tasks = []
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
    app = create_app(cfg, db, engine, notifier, poller, forwarder, central)
    server = uvicorn.Server(uvicorn.Config(
        app, host=cfg.bind, port=cfg.web_port, log_level="warning", access_log=False))
    log.info("Cerberus %s - dashboard on http://%s:%d", __version__, cfg.bind, cfg.web_port)
    try:
        await server.serve()  # returns on SIGINT / SIGTERM
    finally:
        await receiver.stop()
        for task in tasks:
            task.cancel()
        if forwarder:
            await forwarder.close()
        snmp_task.cancel()
        poller.client.close()
        await engine.stop()
        notify_task.cancel()
        await notifier.close()
        db.close()
        log.info("stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # its INFO lines include bot-token URLs
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
