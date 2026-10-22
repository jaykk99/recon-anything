#!/usr/bin/env python3
"""Full plugin audit: every plugin vs the deterministic fixture site.

Unlike scripts/plugin_health.py (live target, results vary with the
network), this runs every plugin against tests/plugin_fixtures.py - a
rich fake site served over httpx MockTransport through the REAL Ctx -
so results are reproducible and a plugin that produces nothing (or
raises) against a fixture designed to trigger it stands out.

Catalog per plugin: works (findings > 0) / empty (ok, 0 findings) /
error (status error) / raised (exception escaped run()) / timeout /
skipped-key / n-a (target type not accepted).

Usage (from backend/):
    python3 scripts/plugin_audit.py                 # url + domain targets
    python3 scripts/plugin_audit.py --json-out /tmp/audit.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tests"))

from plugin_fixtures import domain_target, run_plugin_fixture, url_target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402


async def amain(args):
    classes = discover()
    modes = ["passive", "active"] if args.mode == "both" else [args.mode]
    rows = []
    for pid in sorted(classes):
        cls = classes[pid]
        # Mirror the production runner: per-plugin timeout is
        # min(plugin.timeout_s, MAX_PLUGIN_TIMEOUT_S=120).
        timeout = min(float(getattr(cls, "timeout_s", 60) or 60),
                      args.timeout_cap)
        row = {"id": pid, "module": cls.__module__.rsplit(".", 1)[-1],
               "phase": getattr(cls, "phase", 1)}
        for mode in modes:
            for label, target in (("url", url_target()),
                                  ("domain", domain_target())):
                print(f"  .. {pid} [{mode}/{label}]", flush=True)
                status, findings, err = await run_plugin_fixture(
                    cls, target, mode=mode, timeout=timeout)
                row[f"{mode}_{label}"] = {
                    "status": status, "findings": len(findings),
                    "keys": sorted({f.key for f in findings}),
                    "error": err[:500]}
        rows.append(row)
        r = row[f"{modes[0]}_url"]
        print(f"{pid:28} url:{r['status']:12} f={r['findings']:<3} "
              f"domain:{row[modes[0] + '_domain']['status']:12} "
              f"f={row[modes[0] + '_domain']['findings']}")
    counts = Counter(r[f"{modes[0]}_url"]["status"] for r in rows)
    works = sum(1 for r in rows if any(
        r[k]["findings"] for k in r if isinstance(r[k], dict)))
    print(f"\nplugins: {len(rows)}  with findings on fixture: {works}")
    print("url-target statuses:", dict(counts))
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(rows, f, indent=2)
        print("wrote", args.json_out)
    return 0


def main():
    ap = argparse.ArgumentParser(description="ReconAnything plugin audit")
    ap.add_argument("--mode", choices=["passive", "active", "both"],
                    default="both")
    ap.add_argument("--timeout-cap", type=float, default=125.0)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
