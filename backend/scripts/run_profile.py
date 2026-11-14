#!/usr/bin/env python3
"""Where did a real run's time go?

Reads a finished run's plugin_jobs from the configured database
(DATABASE_URL, same as the app) and prints wall time, total plugin time,
the effective concurrency, the timeout count with the time they burned,
and the slowest plugins. Complements scripts/speed_bench.py (synthetic
fixture scenarios) for runs you actually did.

    cd backend
    python3 scripts/run_profile.py <run_id> [--top 20] [--json]

Timeouts clustered at one start time usually mean a shared dependency
stalled (DNS, a dead upstream, the target itself), not N slow plugins:
time those plugins standalone before optimizing any of them.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _reason(result: Any) -> str:
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            return ""
    return str((result or {}).get("reason") or "") if isinstance(result, dict) else ""


def profile(run_id: str, top: int = 20) -> Optional[Dict[str, Any]]:
    from app.models import PluginJob, get_session
    s = get_session()
    try:
        jobs = (s.query(PluginJob)
                .filter(PluginJob.run_id == run_id,
                        PluginJob.started_at.isnot(None),
                        PluginJob.finished_at.isnot(None)).all())
    finally:
        s.close()
    if not jobs:
        return None
    t0 = min(j.started_at for j in jobs)
    t1 = max(j.finished_at for j in jobs)
    wall = max((t1 - t0).total_seconds(), 1e-9)
    per: Dict[str, Dict[str, float]] = defaultdict(
        lambda: {"seconds": 0.0, "jobs": 0, "timeouts": 0})
    busy = timeout_s = 0.0
    timeouts = 0
    starts = defaultdict(int)
    for j in jobs:
        sec = (j.finished_at - j.started_at).total_seconds()
        busy += sec
        p = per[j.plugin_id]
        p["seconds"] += sec
        p["jobs"] += 1
        if "timeout after" in _reason(j.result):
            timeouts += 1
            timeout_s += sec
            p["timeouts"] += 1
            starts[int((j.started_at - t0).total_seconds() // 10) * 10] += 1
    slow = sorted(per.items(), key=lambda kv: -kv[1]["seconds"])[:top]
    return {
        "run_id": run_id, "jobs": len(jobs), "wall_s": round(wall, 1),
        "plugin_time_s": round(busy, 1),
        "effective_concurrency": round(busy / wall, 1),
        "timeouts": timeouts, "timeout_time_s": round(timeout_s, 1),
        "timeout_share": round(timeout_s / busy, 3) if busy else 0.0,
        "timeout_start_buckets_s": dict(sorted(starts.items())),
        "slowest": [{"plugin": k, **{kk: round(vv, 1) if kk == "seconds" else int(vv)
                                     for kk, vv in v.items()}}
                    for k, v in slow],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("run_id")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = profile(a.run_id, a.top)
    if r is None:
        print(f"no finished jobs for run {a.run_id} (check DATABASE_URL)",
              file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(r, indent=2))
        return 0
    print(f"run {r['run_id']}: {r['jobs']} jobs, wall {r['wall_s']}s, "
          f"plugin time {r['plugin_time_s']}s "
          f"(x{r['effective_concurrency']} concurrency)")
    print(f"timeouts: {r['timeouts']} jobs, {r['timeout_time_s']}s "
          f"({r['timeout_share']:.0%} of plugin time)")
    if r["timeout_start_buckets_s"]:
        print("timeout starts by 10s bucket:", r["timeout_start_buckets_s"])
    print("\nslowest plugins:")
    for p in r["slowest"]:
        print(f"  {p['seconds']:8.1f}s  {p['jobs']:>3} jobs  "
              f"{p['timeouts']:>3} timeouts  {p['plugin']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
