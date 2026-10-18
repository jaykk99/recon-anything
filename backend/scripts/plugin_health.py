#!/usr/bin/env python3
"""Plugin health check for ReconAnything.

Imports every plugin module, instantiates each plugin, and runs it against
a target, recording: import failures, instantiation failures, crashes,
timeouts, skips (missing API key / not applicable to target type), and
finding counts.

A plugin must never crash the run: exceptions are caught and logged per
plugin, mirroring backend/app/runner.py's _run_plugin guarantees.

Usage (from backend/):
    python3 scripts/plugin_health.py
    python3 scripts/plugin_health.py --target https://example.com --mode passive
    python3 scripts/plugin_health.py --target 1.1.1.1 --concurrency 8 --json-out /tmp/health.json
    python3 scripts/plugin_health.py --import-only        # fast: no network
    python3 scripts/plugin_health.py --offline            # fail-fast network: resilience check

Exit code: 0 always (this is a report, not a gate). Use --fail-on-error
to exit non-zero when any plugin crashes or fails to import, for CI.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import importlib
import inspect
import json
import logging
import os
import pkgutil
import sys
import time
import traceback

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import cache as cache_mod            # noqa: E402
from app import config as config_mod           # noqa: E402
from app import net as net_mod                 # noqa: E402
from app import ratelimit as ratelimit_mod     # noqa: E402
from app.classifier import classify            # noqa: E402
from app.plugins import base as base_mod       # noqa: E402

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("plugin_health")

SKIP_MODULES = {"base", "registry", "__init__"}
VALID_GROUPS = set(base_mod.PLUGIN_GROUPS)


def discover_modules():
    """Import every plugin module; return (classes_by_id, import_failures, dup_ids)."""
    package = "app.plugins"
    pkg = importlib.import_module(package)
    classes = {}
    failures = {}
    dup_ids = []
    for mod in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda m: m.name):
        name = mod.name
        if name in SKIP_MODULES:
            continue
        try:
            module = importlib.import_module(f"{package}.{name}")
        except Exception as e:  # noqa: BLE001 - one broken module must not stop the audit
            failures[name] = f"{type(e).__name__}: {e}"
            log.warning("plugin module %s failed to import: %s", name, e)
            continue
        for attr in dir(module):
            obj = getattr(module, attr)
            if (isinstance(obj, type) and issubclass(obj, base_mod.Plugin)
                    and obj is not base_mod.Plugin and getattr(obj, "id", None)):
                pid = obj.id
                if pid in classes:
                    dup_ids.append(pid)
                    log.warning("duplicate plugin id %s in module %s", pid, name)
                else:
                    classes[pid] = (name, obj)
    return classes, failures, dup_ids


def check_metadata(pid, cls):
    """Return a list of metadata warnings for one plugin class."""
    warns = []
    if not getattr(cls, "label", ""):
        warns.append("missing label")
    if not getattr(cls, "description", ""):
        warns.append("missing description")
    if getattr(cls, "group", "") not in VALID_GROUPS:
        warns.append(f"unknown group {getattr(cls, 'group', '')!r}")
    if not inspect.iscoroutinefunction(getattr(cls, "run", None)):
        warns.append("run() is not a coroutine function")
    try:
        cost = cls.cost.value
    except Exception:  # noqa: BLE001
        warns.append(f"invalid cost {getattr(cls, 'cost', '')!r}")
    else:
        if cost not in ("free", "freemium", "paid"):
            warns.append(f"unknown cost {cost!r}")
    if not isinstance(getattr(cls, "phase", 1), int) or cls.phase not in (1, 2):
        warns.append(f"invalid phase {getattr(cls, 'phase', '')!r}")
    if not (getattr(cls, "timeout_s", 0) or 0) > 0:
        warns.append(f"invalid timeout_s {getattr(cls, 'timeout_s', '')!r}")
    return warns


async def run_one(plugin, target, ctx, timeout_s, sem):
    """Run one plugin; never raise. Returns a result dict."""
    rec = {"id": plugin.id, "module": getattr(plugin, "_health_module", "?"),
           "label": plugin.label, "status": None, "reason": "",
           "findings": 0, "keys": [], "duration_ms": 0}
    if plugin.missing_keys(ctx):
        rec["status"] = "skipped-key"
        rec["reason"] = "needs API key: " + ", ".join(plugin.missing_keys(ctx))
        return rec
    if plugin.accepts and target.type not in plugin.accepts:
        rec["status"] = "n/a"
        rec["reason"] = f"does not accept target type {target.type}"
        return rec
    async with sem:
        t0 = time.monotonic()
        try:
            result = await asyncio.wait_for(plugin.run(target, ctx), timeout=timeout_s)
        except asyncio.TimeoutError:
            rec["status"] = "timeout"
            rec["reason"] = f"timed out after {timeout_s}s"
        except Exception as e:  # noqa: BLE001 - health check must never die
            rec["status"] = "error"
            rec["reason"] = f"{type(e).__name__}: {str(e)[:300]}"
            rec["traceback"] = traceback.format_exc(limit=8)
        else:
            rec["status"] = result.status.value
            rec["reason"] = result.reason
            rec["findings"] = len(result.findings)
            rec["keys"] = sorted({f.key for f in result.findings})
        rec["duration_ms"] = int((time.monotonic() - t0) * 1000)
    return rec


class _FailFastTransport(httpx.AsyncBaseTransport):
    """httpx transport that fails every request instantly.

    Used by --offline: proves a plugin degrades gracefully (ok + reason)
    instead of crashing (error) or hanging (timeout) when the network
    is gone.
    """
    async def handle_async_request(self, request):
        raise httpx.ConnectError("offline mode: network disabled")


async def amain(args):
    classes, import_failures, dup_ids = discover_modules()

    rows = []
    for name, err in sorted(import_failures.items()):
        rows.append({"id": f"<module:{name}>", "module": name, "label": "",
                     "status": "import-failed", "reason": err, "findings": 0,
                     "keys": [], "duration_ms": 0})

    plugins = []
    only = {x.strip() for x in (args.only or "").split(",") if x.strip()}
    for pid in sorted(classes):
        if only and pid not in only:
            continue
        name, cls = classes[pid]
        meta_warns = check_metadata(pid, cls)
        try:
            inst = cls()
        except Exception as e:  # noqa: BLE001
            rows.append({"id": pid, "module": name, "label": "",
                         "status": "instantiate-failed",
                         "reason": f"{type(e).__name__}: {e}",
                         "findings": 0, "keys": [], "duration_ms": 0,
                         "meta_warnings": meta_warns})
            continue
        inst._health_module = name
        plugins.append((inst, meta_warns))

    if not args.import_only:
        c = classify(args.target)
        target = base_mod.Target(raw=args.target, type=c["type"],
                                 normalized=c.get("normalized") or args.target)
        if args.offline:
            import httpx as _httpx

            def _offline_client():
                return _httpx.AsyncClient(
                    transport=_FailFastTransport(),
                    headers={"User-Agent": config_mod.USER_AGENT},
                    timeout=config_mod.DEFAULT_TIMEOUT,
                    follow_redirects=True,
                    trust_env=False)

            http_ctx = _offline_client()
        else:
            http_ctx = net_mod.async_client(
                headers={"User-Agent": config_mod.USER_AGENT},
                timeout=config_mod.DEFAULT_TIMEOUT,
                follow_redirects=True)
        async with http_ctx as http:
            ctx = base_mod.Ctx(run_id="health-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S"),
                               mode=args.mode, http=http,
                               cache=cache_mod.Cache(), keys={},
                               limiter=ratelimit_mod.RateLimiter(),
                               source_type="website")
            sem = asyncio.Semaphore(args.concurrency)
            timeout_s = args.timeout
            results = await asyncio.gather(*[
                run_one(p, target, ctx, min(timeout_s, p.timeout_s or timeout_s), sem)
                for p, _warns in plugins
            ])
        for (p, warns), rec in zip(plugins, results):
            rec["meta_warnings"] = warns
            rows.append(rec)
    else:
        for p, warns in plugins:
            rows.append({"id": p.id, "module": p._health_module, "label": p.label,
                         "status": "not-run", "reason": "import-only mode",
                         "findings": 0, "keys": [], "duration_ms": 0,
                         "meta_warnings": warns})

    rows.sort(key=lambda r: (r["status"] != "ok", r["id"]))
    report = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": args.target if not args.import_only else None,
        "mode": args.mode,
        "plugin_count": len(classes),
        "import_failures": import_failures,
        "duplicate_ids": dup_ids,
        "rows": rows,
    }
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"wrote {args.json_out}")

    # Table
    print(f"\n{'PLUGIN':28} {'MODULE':18} {'STATUS':18} {'FIND':>4} {'MS':>7}  REASON")
    print("-" * 120)
    for r in rows:
        reason = (r["reason"] or "")[:55]
        mw = " [meta: " + "; ".join(r.get("meta_warnings") or []) + "]" if r.get("meta_warnings") else ""
        print(f"{r['id'][:27]:28} {r['module'][:17]:18} {r['status']:18} "
              f"{r['findings']:>4} {r['duration_ms']:>7}  {reason}{mw}")

    from collections import Counter
    counts = Counter(r["status"] for r in rows)
    print("\nsummary:", dict(counts))

    if args.fail_on_error and (import_failures or any(
            r["status"] in ("error", "import-failed", "instantiate-failed") for r in rows)):
        return 2
    return 0


def main():
    ap = argparse.ArgumentParser(description="ReconAnything plugin health check")
    ap.add_argument("--target", default="example.com",
                    help="target to run plugins against (default: example.com)")
    ap.add_argument("--mode", default="passive", choices=["passive", "active"])
    ap.add_argument("--timeout", type=int, default=60,
                    help="per-plugin timeout ceiling in seconds (default: 60)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--import-only", action="store_true",
                    help="only import plugins and check metadata, no network")
    ap.add_argument("--offline", action="store_true",
                    help="fail every network call instantly: tests that plugins "
                         "degrade gracefully instead of crashing or hanging")
    ap.add_argument("--json-out", default=None, help="write JSON report to file")
    ap.add_argument("--fail-on-error", action="store_true",
                    help="exit 2 if any plugin crashes or fails to import")
    ap.add_argument("--only", default=None,
                    help="comma-separated plugin ids to run (default: all)")
    args = ap.parse_args()
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
