"""Standalone queue worker entrypoint (`python -m app.worker_main`).

Connects to the same Postgres DATABASE_URL as the UI. Claims queued
plugin jobs, runs them, writes results back. Safe to run N copies at
once: claims use SELECT ... FOR UPDATE SKIP LOCKED, run finalization
uses an atomic status flip.

Hosting (2026-10-20 split, Jay's order): the worker runs as its OWN
Render free web service (recon-anything-worker) so scan load can never
slow or wedge the UI/API service Jay uses. Render free web services
must bind an HTTP port, so this process also serves a trivial health
endpoint on $PORT (default 10000). A self-keepalive ping every 5 min
(RECON_KEEPALIVE_S, to its own RECON_WORKER_URL / RENDER_EXTERNAL_URL)
stops the free instance from spinning down, and the API also pings the
worker URL whenever a new run is created (RECON_WORKER_URL).

Start command (service root = backend/):
    python -m app.worker_main
Docker command override on Render:
    python -m app.worker_main

Required env: DATABASE_URL (Neon Postgres). RECON_ACCESS_CODE is not
needed by the worker itself (the health endpoint is unauthenticated
and reveals nothing).
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("recon-worker")


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server API)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep health pings out of the logs
        pass


def _serve_health() -> None:
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), _HealthHandler)
    log.info("health endpoint listening on :%d", port)
    server.serve_forever()


def _self_url() -> str:
    """Public URL this worker can hit to keep itself warm.

    Prefers RECON_WORKER_URL (the same value the API uses to wake the
    worker), falls back to RENDER_EXTERNAL_URL (injected automatically
    into every Render web service). Empty string = no URL known, so
    keepalive is skipped (e.g. in-process or local dev)."""
    return (os.environ.get("RECON_WORKER_URL")
            or os.environ.get("RENDER_EXTERNAL_URL")
            or "").rstrip("/")


def _keepalive_loop() -> None:
    """Ping our own public URL on an interval so Render's free tier does
    not spin the worker down for lack of inbound traffic.

    The queue loop only talks to Postgres, which Render does not count
    as inbound HTTP, so without this the instance sleeps after ~15 min
    idle and the next scan stalls at "plugins starting..." until a cold
    start finishes. Interval defaults to 300s (safely under the ~15 min
    window, with margin for cold-start jitter); set RECON_KEEPALIVE_S=0
    to disable. Fire-and-forget: every error is swallowed."""
    import urllib.request

    try:
        interval = int(os.environ.get("RECON_KEEPALIVE_S", "300"))
    except ValueError:
        interval = 300
    url = _self_url()
    if interval <= 0 or not url:
        log.info("keepalive disabled (interval=%ss, url=%r)", interval, url)
        return
    log.info("keepalive pinging %s every %ss", url, interval)
    while True:
        time.sleep(interval)
        try:
            req = urllib.request.Request(url + "/", method="GET")
            urllib.request.urlopen(req, timeout=10).close()
        except Exception as e:  # noqa: BLE001 - keepalive must never crash
            log.debug("keepalive ping failed: %s", e)


def main() -> None:
    from .models import check_db, init_db
    from .runner import queue_worker_loop, reset_stale_queue_jobs

    threading.Thread(target=_serve_health, daemon=True).start()
    threading.Thread(target=_keepalive_loop, daemon=True).start()
    check_db()
    init_db()
    n = reset_stale_queue_jobs()
    log.info("worker boot: requeued %d stale jobs", n)
    asyncio.run(queue_worker_loop())


if __name__ == "__main__":
    main()
