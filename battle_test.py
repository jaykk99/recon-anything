"""Battle-test harness for the 17 crawler/extraction plugins.

Runs each plugin's run() directly with a real Ctx (real httpx client,
real RateLimiter, memory cache) against allowed targets only:
- example.com  (safe, tiny)
- httpbin.org  (rich test content)
- scanme.nmap.org (explicitly provisioned for scanning; used only for
  the aggressive enumeration plugins)

Usage: python battle_test.py [--plugins katana,gau] [--target example.com]
                             [--mode active|passive] [--timeout 60]
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import sys
import time
import traceback

import httpx

sys.path.insert(0, ".")

from backend.app.plugins.base import Ctx, Target
from backend.app.ratelimit import RateLimiter
from backend.app.cache import Cache

PLUGINS = [
    "katana", "gau", "waybackurls", "hakrawler", "wget", "httrack",
    "gobuster", "feroxbuster", "urlscan", "firecrawl", "photon", "devtools",
    "allsources", "filehunter", "jsdeep", "assetmap", "appintel",
]

# aggressive plugins only run against targets explicitly provisioned for
# scanning/testing (scanme.nmap.org, httpbin.org)
AGGRESSIVE = {"gobuster", "feroxbuster", "filehunter"}
AGGRESSIVE_TARGETS = {"scanme.nmap.org", "https://httpbin.org"}


def make_ctx(mode: str) -> Ctx:
    from backend.app.net import async_client
    client = async_client(
        timeout=httpx.Timeout(20.0, connect=10.0),
        follow_redirects=False,
        headers={"User-Agent": "ReconAnything/battle-test (authorized scan)"},
    )
    return Ctx(
        run_id="battle-test",
        mode=mode,
        http=client,
        cache=Cache(),
        keys={},
        # match production: backend/app/config.py DEFAULT_RPS=50
        limiter=RateLimiter(default_rps=50.0),
        shared={},
    )


async def run_one(plugin_id: str, target: Target, mode: str, timeout: float):
    mod = importlib.import_module(f"backend.app.plugins.{plugin_id}")
    cls = None
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and getattr(obj, "id", None) == plugin_id:
            cls = obj
            break
    if cls is None:
        return {"error": "no plugin class found"}
    plugin = cls()
    ctx = make_ctx(mode)
    t0 = time.monotonic()
    try:
        result = await asyncio.wait_for(plugin.run(target, ctx), timeout=timeout)
        dur = time.monotonic() - t0
        return {
            "status": str(result.status),
            "reason": result.reason[:300],
            "findings": len(result.findings),
            "duration_s": round(dur, 2),
            "dur_ms_reported": result.duration_ms,
            "keys": sorted({f.key for f in result.findings})[:20],
        }
    except asyncio.TimeoutError:
        dur = time.monotonic() - t0
        return {"error": f"TIMEOUT after {dur:.1f}s (plugin hung)"}
    except Exception as e:
        dur = time.monotonic() - t0
        return {
            "error": f"{type(e).__name__}: {e}",
            "duration_s": round(dur, 2),
            "traceback": traceback.format_exc()[-2000:],
        }
    finally:
        try:
            await ctx.http.aclose()
        except Exception:
            pass


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugins", default=",".join(PLUGINS))
    ap.add_argument("--target", default="example.com")
    ap.add_argument("--mode", default="passive", choices=["passive", "active"])
    ap.add_argument("--timeout", type=float, default=45.0)
    args = ap.parse_args()

    target_raw = args.target
    ttype = "url" if target_raw.startswith("http") else "domain"
    target = Target(raw=target_raw, type=ttype, normalized=target_raw)

    report = {"target": target_raw, "mode": args.mode, "results": {}}
    for pid in args.plugins.split(","):
        pid = pid.strip()
        if not pid:
            continue
        if pid in AGGRESSIVE and target_raw not in AGGRESSIVE_TARGETS:
            report["results"][pid] = {"skipped": "aggressive plugin: only tested on scan targets"}
            continue
        if args.mode == "passive" and pid in AGGRESSIVE:
            report["results"][pid] = {"skipped": "aggressive plugin needs active mode"}
            continue
        print(f"--- {pid} on {target_raw} ({args.mode}) ...", flush=True)
        res = await run_one(pid, target, args.mode, args.timeout)
        report["results"][pid] = res
        if "error" in res:
            print(f"    FAIL: {res['error']}")
        else:
            print(f"    {res['status']}: {res['findings']} findings, {res['duration_s']}s -- {res['reason'][:120]}")

    with open("/tmp/battle_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: (v.get("error") or f"{v.get('status')}:{v.get('findings')}f:{v.get('duration_s')}s")
                      for k, v in report["results"].items()}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
