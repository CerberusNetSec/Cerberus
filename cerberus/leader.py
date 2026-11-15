"""Active/standby: several processors, one active.

Every processor starts as a standby. It serves /healthz (alive) but answers
/readyz and everything else with 503, so a load balancer or Kubernetes Service
sends dashboard traffic only to the active one, and it tries every few seconds
to take the leadership lock in PostgreSQL. The one that holds the lock starts
the full processor: consuming the bus, detection, alerting, notifications,
SNMP polling and the dashboard.

The active processor checks its lock every few seconds. If the lock's
connection is gone, another processor may already be active, so it stops at
once, without writing anything more, and its restart policy brings it back as
a standby. Writes that were in flight are repeated by the new leader from the
last committed bus position (at least once, as after any crash).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time

log = logging.getLogger("cerberus.leader")

TRY_SECONDS = 3.0
CHECK_SECONDS = 3.0
CHECK_TIMEOUT = 10.0
LOST_EXIT_CODE = 75  # EX_TEMPFAIL: restart me


def standby_app(name: str, state: dict, metrics_token: str = ""):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    from .metrics import add_endpoint, common

    app = FastAPI(title="Cerberus (standby)", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "role": "standby", "name": name, "since": state["since"]}

    async def samples():
        return common("processor", name, active=0)
    add_endpoint(app, metrics_token, samples)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def standby(path: str):
        return JSONResponse({"error": "standby: another Cerberus processor is active", "role": "standby"},
                            status_code=503, headers={"Retry-After": "5"})

    return app


async def _call(fn, timeout: float = CHECK_TIMEOUT):
    return await asyncio.wait_for(asyncio.to_thread(fn), timeout)


async def wait_for_leadership(lock, serve=None, name: str = "", metrics_token: str = "") -> bool:
    """Wait until this process holds the lock: True. serve(app) -> (server, task) runs a
    standby server meanwhile; if that server stops (the process is told to shut down)
    before the lock is taken, returns False."""
    state = {"since": time.time()}
    server = task = None
    if serve is not None:
        server, task = serve(standby_app(name, state, metrics_token))
    logged = False
    try:
        while True:
            if task is not None and task.done():
                return False
            try:
                if await _call(lock.try_acquire):
                    log.info("this processor is now active")
                    return True
                if not logged:
                    log.info("standby: another processor is active; taking over when it stops")
                    logged = True
            except Exception as exc:
                log.warning("cannot reach PostgreSQL for the leadership lock: %s", exc)
                await asyncio.to_thread(lock.release)
            await asyncio.sleep(TRY_SECONDS)
    finally:
        if server is not None:
            server.should_exit = True
            await task


async def keep_leadership(lock, on_lost=None) -> None:
    """Run while active: when the lock may have been lost, stop the process at once."""
    while True:
        await asyncio.sleep(CHECK_SECONDS)
        try:
            held = await _call(lock.still_held)
        except Exception:
            held = False
        if not held:
            log.critical("lost the leadership lock (PostgreSQL unreachable); stopping so another processor "
                         "can take over")
            if on_lost is not None:
                on_lost()
                return
            os._exit(LOST_EXIT_CODE)  # no flush, no further writes: the new leader may be running
