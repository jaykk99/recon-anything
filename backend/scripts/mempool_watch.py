#!/usr/bin/env python3
"""Mempool fresh-deploy interceptor - CLI.

READ-ONLY: polls pending blocks through the keyless public RPC
pools, screens contract creations through the Tier-1 pass and the
inline gates, and queues UNVERIFIED fresh-deploy candidates for
the deep lane. Nothing is broadcast, ever.

Usage:
  python scripts/mempool_watch.py --duration 300
  python scripts/mempool_watch.py --chains ethereum,base --duration 240
  python scripts/mempool_watch.py --confirm-only

Output dir default: ~/workspace/recon-mempool-2026-11-09
(queue.jsonl + state.json checkpoints land there).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.mempool_watch import CHAINS, MempoolWatcher  # noqa: E402

DEFAULT_OUT = os.path.expanduser(
    "~/workspace/recon-mempool-2026-11-09")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--chains", default=",".join(CHAINS),
                    help="comma-separated subset of: " + ",".join(CHAINS))
    ap.add_argument("--duration", type=float, default=300.0,
                    help="seconds to watch (default 300)")
    ap.add_argument("--interval", type=float, default=12.0,
                    help="poll interval seconds (default 12, polite)")
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--engine", default="python",
                    choices=("python", "rust"),
                    help="tier1 engine; rust falls back to python "
                         "until the engine switch lands")
    ap.add_argument("--confirm-every", type=int, default=5,
                    help="run a mined-confirmation pass every N cycles")
    ap.add_argument("--confirm-only", action="store_true",
                    help="only stamp queued rows that have mined")
    args = ap.parse_args()

    chains = [c.strip() for c in args.chains.split(",") if c.strip()]
    from app.mempool_watch import Tier1Screener
    watcher = MempoolWatcher(
        args.out_dir, chains=chains,
        screener=Tier1Screener(engine=args.engine))
    if args.confirm_only:
        print(json.dumps({"confirm": watcher.confirm_mined()}))
        watcher.store.checkpoint()
        return 0
    totals = asyncio.run(watcher.run(
        args.duration, interval_s=args.interval,
        confirm_every=args.confirm_every))
    print(json.dumps({"totals": totals,
                      "queue_rows": len(watcher.store.rows),
                      "rpc_stats": watcher.rpc.stats}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
