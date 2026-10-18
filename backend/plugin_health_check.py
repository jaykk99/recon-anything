"""Strict plugin health check: zero errors is the bar.

Runs every registered plugin against example.com (domain + url targets
where accepted) in active mode, through the runner's real _run_plugin
wrapper (per-plugin timeout + exception guard included).

PASS: status ok / skipped / rate_limited (degraded gracefully).
FAIL: status error (uncaught exception escaped the plugin).

External APIs down, DNS failures, timeouts, malformed responses, empty
results: all must degrade to ok-with-note or skipped, never error.

Usage: python3 plugin_health_check.py [--concurrency 12] [--only cards,webtech]
Exit code 0 = all pass, 1 = at least one plugin errored.
"""
import argparse
import asyncio
import os
import sys
import time

os.environ.setdefault("DATABASE_URL", "sqlite:///./health-check.db")
# isolate from any dev database
_db = os.environ["DATABASE_URL"]
if "health-check" not in _db:
    raise SystemExit("refusing to run against a non-scratch DB")

from app import config  # noqa: E402
from app import net as netmod  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.models import init_db  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import all_plugins, discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402
from app.runner import _run_plugin  # noqa: E402  (real wrapper, timeouts included)


async def check_one(plugin, target, ctx):
    t0 = time.monotonic()
    try:
        result = await _run_plugin(plugin, target, ctx)
        ms = int((time.monotonic() - t0) * 1000)
        return (plugin.id, target.type, result.status.value,
                (result.reason or "")[:160], len(result.findings), ms)
    except BaseException as e:  # noqa: BLE001 - the guard itself must never throw
        ms = int((time.monotonic() - t0) * 1000)
        return (plugin.id, target.type, "GUARD-ESCAPE",
                f"{type(e).__name__}: {str(e)[:140]}", 0, ms)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--concurrency", type=int, default=12)
    ap.add_argument("--only", default="",
                    help="comma-separated plugin ids to check")
    args = ap.parse_args()

    try:
        os.remove("./health-check.db")
    except OSError:
        pass
    init_db()
    discover()
    plugins = all_plugins()
    if args.only:
        want = set(args.only.split(","))
        plugins = [p for p in plugins if p.id in want]
    print(f"checking {len(plugins)} plugins", flush=True)

    targets = {
        "domain": Target(raw="example.com", type="domain",
                         normalized="example.com"),
        "url": Target(raw="https://example.com", type="url",
                      normalized="https://example.com"),
    }

    async with netmod.async_client(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.DEFAULT_TIMEOUT,
            follow_redirects=True) as http:
        ctx = Ctx(run_id="healthcheck", mode="active", http=http,
                  cache=Cache(), keys={}, limiter=RateLimiter(default_rps=25),
                  module_overrides={}, evidence_dir="./evidence",
                  source_type="website")
        sem = asyncio.Semaphore(args.concurrency)

        async def guarded(plugin, target):
            async with sem:
                return await check_one(plugin, target, ctx)

        jobs = []
        for p in plugins:
            for ttype, t in targets.items():
                if not p.accepts or ttype in p.accepts:
                    jobs.append(guarded(p, t))
        results = await asyncio.gather(*jobs)

    fails = [r for r in results if r[2] in ("error", "GUARD-ESCAPE")]
    skips = [r for r in results if r[2] == "skipped"]
    oks = [r for r in results if r[2] == "ok"]
    rl = [r for r in results if r[2] == "rate_limited"]

    print(f"\n{'plugin':22} {'target':8} {'status':12} {'ms':>8}  reason")
    print("-" * 100)
    for pid, ttype, status, reason, nfind, ms in sorted(results):
        mark = "FAIL" if status in ("error", "GUARD-ESCAPE") else "pass"
        print(f"{mark:4} {pid:22} {ttype:8} {status:12} {ms:8}  {reason[:70]}")
    print("-" * 100)
    print(f"total={len(results)} ok={len(oks)} skipped={len(skips)} "
          f"rate_limited={len(rl)} ERRORS={len(fails)}")
    if fails:
        print("\nFAILING PLUGINS (must be fixed):")
        for pid, ttype, status, reason, nfind, ms in fails:
            print(f"  - {pid} [{ttype}]: {status}: {reason}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    asyncio.run(main())
