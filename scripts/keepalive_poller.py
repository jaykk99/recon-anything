#!/usr/bin/env python3
"""Always-on external keep-alive poller for ReconAnything.

Why this exists
---------------
ReconAnything's two Render free-tier services already ping themselves and
each other (backend/app/keepalive.py), and a GitHub Actions cron is a
backstop. But a free Render web service that has ALREADY gone to sleep has
its process suspended, so it cannot ping itself awake -- and when the API
and the worker both sleep at once (overnight, no traffic), the only thing
that can wake them is a request from OUTSIDE. GitHub's scheduled crons are
best-effort (often 5-15 min late) and GitHub auto-pauses them after 60 days
with no commits, so they are not dependable on their own.

This is the same pattern that keeps Forge 3D awake: an always-on worker
running on Colab/Kaggle (or any machine that stays up) that hits the
service on a short interval. Run this anywhere that stays on and both
services stay warm.

Usage
-----
    python keepalive_poller.py                      # default URLs below
    python keepalive_poller.py URL1 URL2 ...        # explicit URLs
    RECON_KEEPALIVE_URLS="https://a,https://b" python keepalive_poller.py

Env (all optional):
    RECON_KEEPALIVE_URLS       comma-separated URLs (overrides defaults)
    RECON_KEEPALIVE_S          seconds between rounds (default 240 = 4 min)
    RECON_KEEPALIVE_MAX_HOURS  stop after N hours (default 0 = run forever).
                               Set this on Colab/Kaggle (e.g. 8) so the loop
                               exits cleanly before the host kills the
                               session, ready for a fresh re-run.

No third-party dependencies (stdlib only), so it runs on a bare Colab /
Kaggle cell, a VPS, a Raspberry Pi, anything.
"""
from __future__ import annotations

import os
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ReconAnything's public Render URLs. Override via argv or
# RECON_KEEPALIVE_URLS if your service names differ.
DEFAULT_URLS = [
    "https://recon-anything.onrender.com/api/health",
    "https://recon-anything-worker.onrender.com/",
]

DEFAULT_INTERVAL_S = 240
COLD_START_TIMEOUT = 90  # a sleeping free instance can take ~60s to wake


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _urls() -> list[str]:
    if len(sys.argv) > 1:
        raw = sys.argv[1:]
    else:
        env = os.environ.get("RECON_KEEPALIVE_URLS", "")
        raw = env.split(",") if env else DEFAULT_URLS
    out: list[str] = []
    for u in raw:
        u = (u or "").strip()
        if u and u not in out:
            out.append(u)
    return out


def _interval() -> int:
    try:
        return max(30, int(os.environ.get("RECON_KEEPALIVE_S", DEFAULT_INTERVAL_S)))
    except ValueError:
        return DEFAULT_INTERVAL_S


def _max_seconds() -> float:
    try:
        return float(os.environ.get("RECON_KEEPALIVE_MAX_HOURS", "0")) * 3600.0
    except ValueError:
        return 0.0


def ping(url: str) -> tuple[bool, int, float]:
    """One GET. Returns (ok, status, elapsed_s). ok = any response < 500
    (a cold instance answers slowly with 200 once awake)."""
    t0 = time.time()
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "recon-keepalive-poller/1"})
    try:
        with urllib.request.urlopen(req, timeout=COLD_START_TIMEOUT) as r:
            return (r.status < 500, r.status, time.time() - t0)
    except urllib.error.HTTPError as e:
        return (e.code < 500, e.code, time.time() - t0)
    except Exception:
        return (False, 0, time.time() - t0)


def main() -> int:
    urls = _urls()
    interval = _interval()
    max_s = _max_seconds()
    if not urls:
        print("no URLs to ping; set RECON_KEEPALIVE_URLS or pass them as args")
        return 1
    print(f"[{_now()}] keepalive poller started: {len(urls)} url(s), "
          f"every ~{interval}s"
          + (f", stopping after {max_s/3600:.1f}h" if max_s else ", forever"))
    for u in urls:
        print(f"    - {u}")
    started = time.time()
    fails = {u: 0 for u in urls}
    while True:
        for u in urls:
            ok, status, dt = ping(u)
            if ok:
                fails[u] = 0
            else:
                fails[u] += 1
            flag = "ok " if ok else "FAIL"
            warn = f"  (x{fails[u]} in a row)" if fails[u] else ""
            print(f"[{_now()}] {flag} {status:>3} {dt:5.1f}s  {u}{warn}", flush=True)
        if max_s and (time.time() - started) >= max_s:
            print(f"[{_now()}] reached max hours, exiting cleanly")
            return 0
        time.sleep(interval + random.uniform(-15, 15))


if __name__ == "__main__":
    raise SystemExit(main())
