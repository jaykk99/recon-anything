"""Standalone queue worker entrypoint (Railway: `python -m app.worker_main`).

Connects to the same Postgres DATABASE_URL as the UI. Claims queued
plugin jobs, runs them, writes results back. Safe to run N copies at
once: claims use SELECT ... FOR UPDATE SKIP LOCKED, run finalization
uses an atomic status flip.

Railway start command (service root = backend/):
    python -m app.worker_main

Required env: DATABASE_URL (Neon Postgres), RECON_ACCESS_CODE not needed
(the worker never serves HTTP).
"""
from __future__ import annotations

import asyncio
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("recon-worker")


def main() -> None:
    from .models import check_db, init_db
    from .runner import queue_worker_loop, reset_stale_queue_jobs

    check_db()
    init_db()
    n = reset_stale_queue_jobs()
    log.info("worker boot: requeued %d stale jobs", n)
    asyncio.run(queue_worker_loop())


if __name__ == "__main__":
    main()
