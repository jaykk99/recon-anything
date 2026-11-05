"""Keep both Render free services awake (Jay's 2026-10-29 order: "stop
it sleeping, set a ping, stop it losing connection when it runs").

Render's free tier spins a web service down after ~15 min with no
inbound HTTP. Before this module only the worker pinged itself; the
UI/API service never did, so it fell asleep mid-scan (an open SSE
stream does not count as new traffic) and the live feed dropped.

Now each service pings itself AND its peer:
  - API    -> self (/api/health)  + worker (RECON_WORKER_URL)
  - worker -> self (/)            + API    (RECON_API_PUBLIC_URL)
If one side does go to sleep anyway (deploy, crash, Render restart),
the other wakes it within one interval. A GitHub Actions cron
(.github/workflows/keepalive.yml) is the outside backstop for when both
are down at once.

Interval: RECON_KEEPALIVE_S (default 240s = 4 min, well under the
~15 min window even if one or two pings are lost). 0 disables.
Fire-and-forget: every error is swallowed, the loop can never crash
the process.
"""
from __future__ import annotations

import logging
import os
import random
import threading
import time
import urllib.request
from typing import Iterable, List

log = logging.getLogger("recon.keepalive")

DEFAULT_INTERVAL_S = 240
_started = False
_lock = threading.Lock()


def _interval() -> int:
    try:
        return int(os.environ.get("RECON_KEEPALIVE_S", str(DEFAULT_INTERVAL_S)))
    except ValueError:
        return DEFAULT_INTERVAL_S


def _clean(urls: Iterable[str]) -> List[str]:
    out: List[str] = []
    for u in urls:
        u = (u or "").strip()
        if u and u not in out:
            out.append(u)
    return out


def ping(url: str, timeout: float = 15) -> bool:
    """One GET. True on any HTTP response < 500 (a sleeping Render
    instance answers slowly but still counts as woken)."""
    try:
        req = urllib.request.Request(
            url, method="GET", headers={"User-Agent": "recon-keepalive/1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def _loop(urls: List[str], interval: int) -> None:
    fails = {u: 0 for u in urls}
    # Small startup delay so we don't ping before our own server binds.
    time.sleep(30)
    while True:
        for u in urls:
            ok = ping(u)
            if ok:
                if fails[u] >= 3:
                    log.info("keepalive: %s reachable again", u)
                fails[u] = 0
            else:
                fails[u] += 1
                if fails[u] == 3 or fails[u] % 15 == 0:
                    log.warning("keepalive: %s failed %d pings in a row",
                                u, fails[u])
        # Jitter so the two services don't ping in lockstep.
        time.sleep(interval + random.uniform(-15, 15))


def start(urls: Iterable[str]) -> None:
    """Start the background ping thread once per process."""
    global _started
    interval = _interval()
    targets = _clean(urls)
    with _lock:
        if _started:
            return
        if interval <= 0 or not targets:
            log.info("keepalive disabled (interval=%ss, urls=%r)",
                     interval, targets)
            return
        _started = True
    log.info("keepalive pinging %s every ~%ss", targets, interval)
    threading.Thread(target=_loop, args=(targets, interval),
                     daemon=True, name="keepalive").start()


def _base(env_name: str) -> str:
    return os.environ.get(env_name, "").strip().rstrip("/")


def api_targets() -> List[str]:
    """URLs the UI/API service keeps warm: itself + the worker."""
    self_url = _base("RECON_SELF_URL") or _base("RENDER_EXTERNAL_URL")
    worker = _base("RECON_WORKER_URL")
    return _clean([self_url and self_url + "/api/health",
                   worker and worker + "/"])


def worker_targets() -> List[str]:
    """URLs the worker keeps warm: itself + the UI/API service."""
    self_url = _base("RECON_WORKER_URL") or _base("RENDER_EXTERNAL_URL")
    api = _base("RECON_API_PUBLIC_URL")
    return _clean([self_url and self_url + "/",
                   api and api + "/api/health"])
