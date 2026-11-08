#!/usr/bin/env python3
"""Timing battery for GET /api/search (Jay's bar: 100 of anything in
1 second).

Runs a representative query battery against any base URL (local
service or the live Render URL), N reps each, and reports per-query
status, result count, p50 / p95 / max milliseconds, plus the worst
p95 across successful queries. Read-only GETs only.

  python3 scripts/search_bench.py --base-url http://127.0.0.1:8100
  python3 scripts/search_bench.py --base-url https://recon-anything.onrender.com

Note: /api/search sits behind the app sign-in gate. Unauthenticated
runs measure the gate path (401) — reported as such, never dressed up
as query timings. In fallback mode (no OAuth configured) pass the
access code with --code.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BATTERY = [
    ("kw common (withdraw)", {"q": "withdraw"}),
    ("kw rare (emergencyWithdraw)", {"q": "emergencyWithdraw"}),
    ("kw code term (delegatecall)", {"q": "delegatecall"}),
    ("multi-kw AND", {"q": "delegatecall sweep"}),
    ("kw + chain", {"q": "withdraw", "chain": "bsc"}),
    ("kw + verdict", {"q": "withdraw", "verdict": "FALSE_POSITIVE"}),
    ("filter verdict only", {"verdict": "TRIGGER_ONLY"}),
    ("filter chain solana", {"chain": "solana"}),
    ("filter plugin", {"plugin": "contract_logic"}),
    ("filter recipient", {"recipient": "CALLER-SUPPLIED"}),
    ("filter min value 100k", {"min_value_usd": "100000"}),
    ("filter has_source + kw", {"q": "mint", "has_source": "true"}),
    ("address lookup",
     {"q": "0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5"}),
    ("combined everything",
     {"q": "withdraw", "chain": "ethereum", "verdict": "UNVERIFIED",
      "min_value_usd": "1000", "limit": "100"}),
    ("limit 100 heavy (the)", {"q": "function", "limit": "100"}),
]


def pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round(p / 100 * (len(s) - 1)))))
    return s[k]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://127.0.0.1:8100")
    ap.add_argument("--code", default=None,
                    help="access code (fallback-mode services only)")
    ap.add_argument("--reps", type=int, default=5)
    args = ap.parse_args()

    print(f"base: {args.base_url}  reps: {args.reps}")
    worst_p95 = 0.0
    statuses = set()
    for name, params in BATTERY:
        p = dict(params)
        if args.code:
            p["code"] = args.code
        url = args.base_url.rstrip("/") + "/api/search?" + \
            urllib.parse.urlencode(p)
        times, status, count = [], None, None
        for _ in range(args.reps):
            t0 = time.time()
            try:
                with urllib.request.urlopen(url, timeout=90) as resp:
                    body = resp.read()
                    status = resp.status
            except urllib.error.HTTPError as e:
                body = e.read()
                status = e.code
            except Exception as e:  # connection error etc.
                status = f"ERR {type(e).__name__}"
                body = b""
            times.append((time.time() - t0) * 1000)
            if status == 200:
                try:
                    count = json.loads(body).get("count")
                except ValueError:
                    count = None
        statuses.add(status)
        p50 = pct(times, 50)
        p95 = pct(times, 95)
        if status == 200 and p95:
            worst_p95 = max(worst_p95, p95)
        print(f"{name:32s} status={status} count={count} "
              f"p50={p50:.0f}ms p95={p95:.0f}ms max={max(times):.0f}ms")
    print(f"\nworst p95 across 200s: {worst_p95:.0f} ms "
          f"(bar: 1000 ms)  statuses seen: {sorted(map(str, statuses))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
