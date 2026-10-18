"""Run engine.

Creates a run, classifies targets, executes matching plugins concurrently
(asyncio, semaphore-capped), streams SSE progress events, persists
findings, then builds the correlation graph. Plugins are pure async
functions over the shared registry, so a dedicated worker (ARQ/Celery)
can import the same registry later without changes.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import time
from typing import AsyncIterator, Dict, List, Optional

import httpx

from . import config
from .cache import Cache
from .classifier import classify_batch
from .models import Finding as FindingRow, Run, Target as TargetRow, get_session, init_db
from .plugins.base import Ctx, PluginResult, Target
from .plugins.registry import all_plugins, discover
from .ratelimit import RateLimiter

_cache = Cache()
_limiter = RateLimiter()

# In-memory event bus: run_id -> buffered SSE strings + live subscriber queues.
# Lets GET /api/runs/{id}/stream replay history then follow live events.
RUN_EVENT_BUFFER: Dict[str, List[str]] = {}
RUN_SUBSCRIBERS: Dict[str, List[asyncio.Queue]] = {}
RUN_DONE = "run_done"


def _sse(event: str, data: Dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


async def _emit(run_id: str, event: str, data: Dict):
    msg = _sse(event, data)
    RUN_EVENT_BUFFER.setdefault(run_id, []).append(msg)
    for q in list(RUN_SUBSCRIBERS.get(run_id, [])):
        await q.put(msg)


async def subscribe(run_id: str) -> AsyncIterator[str]:
    """Replay buffered events, then yield live ones until run_done."""
    queue: asyncio.Queue = asyncio.Queue()
    RUN_SUBSCRIBERS.setdefault(run_id, []).append(queue)
    try:
        for msg in RUN_EVENT_BUFFER.get(run_id, []):
            yield msg
            if msg.startswith(f"event: {RUN_DONE}"):
                return
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30)
                yield msg
                if msg.startswith(f"event: {RUN_DONE}"):
                    return
            except asyncio.TimeoutError:
                yield ": ping\n\n"
    finally:
        try:
            RUN_SUBSCRIBERS.get(run_id, []).remove(queue)
        except ValueError:
            pass


def _row_to_finding(f, run_id: str, target_id: str) -> FindingRow:
    return FindingRow(
        run_id=run_id, target_id=target_id, plugin_id=f.plugin_id, category=f.category,
        key=f.key, value=f.value, source=f.source, source_url=f.source_url,
        confidence=f.confidence, evidence=f.evidence, passive=f.passive,
        first_seen=dt.datetime.now(dt.timezone.utc), raw=f.raw,
    )


async def _run_plugin(plugin, target: Target, ctx: Ctx) -> PluginResult:
    if plugin.missing_keys(ctx):
        return plugin._skipped(
            "missing API keys: " + ", ".join(plugin.missing_keys(ctx)))
    await _emit(ctx.run_id, "plugin_start",
                {"plugin": plugin.id, "label": plugin.label, "target": target.normalized})
    t0 = time.monotonic()
    try:
        result = await asyncio.wait_for(plugin.run(target, ctx), timeout=180)
    except asyncio.TimeoutError:
        result = plugin._error("timeout after 180s")
    except Exception as e:  # never let one plugin kill the run
        result = plugin._error(f"unhandled: {str(e)[:200]}")
    result.duration_ms = int((time.monotonic() - t0) * 1000)
    await _emit(ctx.run_id, "plugin_done",
                {"plugin": plugin.id, "status": result.status.value,
                 "reason": result.reason, "findings": len(result.findings),
                 "ms": result.duration_ms})
    return result


# Estimated seconds per plugin per target (based on observed runs).
# Used to show Jay a time estimate before/during scans.
PLUGIN_TIME_ESTIMATES = {
    "subdomains": 25, "dns": 8, "tls": 10, "webtech": 12, "artifacts": 30,
    "jsminer": 20, "wayback": 15, "leaks": 10, "rdap": 8, "apidiscover": 15,
    "pivots": 5, "headers": 8, "mobile": 5, "bounty": 25, "emails": 15,
    "dorks": 2, "usernames": 20, "opendir": 20, "ports": 15, "robots": 10,
    "waf": 12, "takeover": 15, "banners": 10, "github": 10, "cves": 12,
    "clickjack": 8, "cors": 12, "pastes": 10, "phones": 2, "social": 12,
    "secrets": 25, "wallets": 20, "creds": 20, "sqli": 30, "xss": 30,
    "ssrf": 15, "idor": 10, "auth": 12, "db": 20, "backup": 60, "git": 15,
    "hashid": 8, "exif": 15, "crypto": 12,
}
DEFAULT_PLUGIN_ESTIMATE_S = 12
RUN_TIMEOUT_S = 1800  # 30 min hard cap, never leave a run stuck


async def execute_run(run_id: str, targets_raw: str, mode: str,
                      plugin_ids: Optional[List[str]] = None,
                      module_overrides: Optional[Dict[str, str]] = None,
                      keys: Optional[Dict[str, str]] = None):
    """Execute a full recon run, fanning SSE events to the run's bus."""
    init_db()
    RUN_EVENT_BUFFER[run_id] = []
    session = get_session()
    try:
        await _execute_run_inner(run_id, targets_raw, mode, plugin_ids,
                                 module_overrides, keys, session)
    except Exception as e:
        # Never leave a run stuck in "running". Mark it failed.
        try:
            run = session.query(Run).filter_by(id=run_id).first()
            if run and run.status == "running":
                run.status = "failed"
                run.finished_at = dt.datetime.now(dt.timezone.utc)
                run.summary = {"error": str(e)[:300], "findings": 0}
                session.commit()
        except Exception:
            pass
        try:
            await _emit(run_id, "run_done",
                        {"run_id": run_id, "findings": 0, "error": str(e)[:300]})
        except Exception:
            pass
    finally:
        try:
            session.close()
        except Exception:
            pass


async def _execute_run_inner(run_id: str, targets_raw: str, mode: str,
                             plugin_ids: Optional[List[str]],
                             module_overrides: Optional[Dict[str, str]],
                             keys: Optional[Dict[str, str]],
                             session):
    run = session.query(Run).filter_by(id=run_id).first()
    if not run:
        session.close()
        return
    discover()
    classified = classify_batch(targets_raw)
    plugins = all_plugins()
    if plugin_ids:
        plugins = [p for p in plugins if p.id in plugin_ids]

    # persist targets
    trobj: List[Target] = []
    for c in classified:
        t = Target(raw=c.get("raw", ""), type=c["type"], normalized=c["normalized"])
        trobj.append(t)
        session.add(TargetRow(id=t.id, run_id=run_id, raw=t.raw,
                              type=t.type, normalized=t.normalized))
    session.commit()

    # Time estimate: sum of per-plugin estimates x targets, capped by concurrency.
    n_targets = max(len(trobj), 1)
    total_plugin_s = sum(PLUGIN_TIME_ESTIMATES.get(p.id, DEFAULT_PLUGIN_ESTIMATE_S)
                         for p in plugins) * n_targets
    concurrency = max(getattr(config, "MAX_CONCURRENCY", 5), 1)
    estimated_s = max(int(total_plugin_s / concurrency), 10)

    await _emit(run_id, "run_start",
                {"run_id": run_id, "targets": [c["normalized"] for c in classified],
                 "mode": mode, "plugins": [p.id for p in plugins],
                 "estimated_s": estimated_s,
                 "plugin_count": len(plugins), "target_count": n_targets})

    async with httpx.AsyncClient(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.DEFAULT_TIMEOUT, follow_redirects=True,
            trust_env=False) as http:
        ctx = Ctx(run_id=run_id, mode=mode, http=http, cache=_cache,
                  keys=keys or {}, limiter=_limiter,
                  module_overrides=module_overrides or {},
                  evidence_dir=config.EVIDENCE_DIR)
        sem = asyncio.Semaphore(config.MAX_CONCURRENCY)

        total_jobs = 0
        for t in trobj:
            for p in plugins:
                if not p.accepts or t.type in p.accepts:
                    total_jobs += 1
                else:
                    await _emit(run_id, "plugin_skip",
                                {"plugin": p.id, "target": t.normalized,
                                 "reason": f"does not accept {t.type}"})
        completed_jobs = 0

        # Simpler: wrap each job with progress counting
        async def wrap(plugin, target):
            nonlocal completed_jobs
            async with sem:
                result = await _run_plugin(plugin, target, ctx)
            completed_jobs += 1
            await _emit(run_id, "progress",
                        {"done": completed_jobs, "total": total_jobs,
                         "plugin": plugin.id, "target": target.normalized})
            return plugin, target, result

        wrapped = []
        for t in trobj:
            for p in plugins:
                if not p.accepts or t.type in p.accepts:
                    wrapped.append(wrap(p, t))
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*wrapped), timeout=RUN_TIMEOUT_S)
        except asyncio.TimeoutError:
            await _emit(run_id, "progress",
                        {"done": completed_jobs, "total": total_jobs,
                         "note": "run timed out"})
            results = []

    # persist findings
    total = 0
    plugin_rows = {}
    for plugin, target, result in results:
        plugin_rows[plugin.id] = result
        for f in result.findings:
            session.add(_row_to_finding(f, run_id, target.id))
            total += 1
            await _emit(run_id, "finding",
                        {"plugin": f.plugin_id, "category": f.category,
                         "key": f.key, "value": f.value,
                         "source": f.source, "source_url": f.source_url,
                         "evidence": f.evidence,
                         "confidence": f.confidence,
                         "passive": f.passive, "target": target.normalized})
    session.commit()

    # correlation graph
    from .graph import build_graph
    n_nodes, n_edges = build_graph(session, run_id)
    session.commit()

    run.status = "done"
    run.finished_at = dt.datetime.now(dt.timezone.utc)
    run.summary = {"findings": total, "nodes": n_nodes, "edges": n_edges,
                   "targets": len(trobj),
                   "plugins": {pid: r.status.value for pid, r in plugin_rows.items()}}
    session.commit()
    session.close()
    await _emit(run_id, "run_done",
                {"run_id": run_id, "findings": total,
                 "nodes": n_nodes, "edges": n_edges})


async def launch_run(run_id: str, targets_raw: str, mode: str,
                   plugin_ids: Optional[List[str]] = None,
                   module_overrides: Optional[Dict[str, str]] = None,
                   keys: Optional[Dict[str, str]] = None) -> asyncio.Task:
    """Fire-and-forget: start execute_run as a background task."""
    return asyncio.create_task(
        execute_run(run_id, targets_raw, mode, plugin_ids, module_overrides, keys))
