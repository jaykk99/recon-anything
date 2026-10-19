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
import ssl
import time
import uuid
from typing import AsyncIterator, Dict, List, Optional

import httpx

from . import config
from . import net
from .cache import Cache
from .classifier import classify_batch
from .models import Finding as FindingRow, Run, RunEvent, Target as TargetRow, PluginJob, get_session, init_db, IS_SQLITE
from .plugins.base import Ctx, PluginResult, Target
from .plugins.registry import all_plugins, discover
from .plugins.priority import priority_for, HIGH as HIGH_TIER
from .ratelimit import RateLimiter

_cache = Cache()
_limiter = RateLimiter(default_rps=config.DEFAULT_RPS)

# In-memory event bus: run_id -> buffered SSE strings + live subscriber queues.
# Lets GET /api/runs/{id}/stream replay history then follow live events.
# NOTE: this is per-process. The durable copy lives in the run_events table
# (see _emit); subscribe() replays from the DB so live updates survive
# multi-worker deploys and restarts.
RUN_EVENT_BUFFER: Dict[str, List[str]] = {}
RUN_SUBSCRIBERS: Dict[str, List[asyncio.Queue]] = {}
RUN_DONE = "run_done"
RUN_SEQ: Dict[str, int] = {}  # per-run event sequence numbers


def _sse(event: str, data: Dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


async def _emit(run_id: str, event: str, data: Dict):
    msg = _sse(event, data)
    RUN_EVENT_BUFFER.setdefault(run_id, []).append(msg)
    for q in list(RUN_SUBSCRIBERS.get(run_id, [])):
        try:
            q.put_nowait(msg)
        except Exception:
            pass
    # Durable copy in run_events: the in-memory bus is invisible to other
    # worker processes and vanishes on restart, which is what silently
    # broke live UI updates. A DB failure must never break a scan.
    # Self-healing: if the table is missing (wiped DB), recreate and retry.
    try:
        _persist_event(run_id, event, data)
    except Exception:
        try:
            init_db()
            _persist_event(run_id, event, data)
        except Exception:
            pass


def _persist_event(run_id: str, event: str, data: Dict):
    RUN_SEQ[run_id] = RUN_SEQ.get(run_id, 0) + 1
    safe_data = json.loads(json.dumps(data, default=str))
    session = get_session()
    try:
        session.add(RunEvent(run_id=run_id, seq=RUN_SEQ[run_id],
                             event=event, data=safe_data))
        session.commit()
    finally:
        session.close()


async def subscribe(run_id: str) -> AsyncIterator[str]:
    """Replay persisted events, then follow live ones until run_done.

    Reads from the run_events table (not the in-memory bus) so the stream
    works across worker processes, restarts, and reconnects.
    Self-healing: recreates the table if a wiped DB left it missing,
    and falls back to the in-memory buffer if the DB is unusable.
    """
    try:
        async for msg in _subscribe_db(run_id):
            yield msg
        return
    except Exception:
        pass
    try:
        init_db()
        async for msg in _subscribe_db(run_id):
            yield msg
        return
    except Exception:
        pass
    # Last resort: in-memory buffer (same-process only).
    for msg in RUN_EVENT_BUFFER.get(run_id, []):
        yield msg


async def _subscribe_db(run_id: str) -> AsyncIterator[str]:
    last_seq = 0
    session = get_session()
    try:
        rows = (session.query(RunEvent).filter_by(run_id=run_id)
                .order_by(RunEvent.seq).all())
        for r in rows:
            last_seq = r.seq
            yield _sse(r.event, r.data or {})
            if r.event == RUN_DONE:
                return
    finally:
        session.close()
    # Follow live: poll for new rows. 1s granularity is plenty "live"
    # for the UI and is correct across processes.
    idle = 0
    while True:
        await asyncio.sleep(1)
        session = get_session()
        try:
            rows = (session.query(RunEvent)
                    .filter(RunEvent.run_id == run_id,
                            RunEvent.seq > last_seq)
                    .order_by(RunEvent.seq).all())
        finally:
            session.close()
        if rows:
            idle = 0
            for r in rows:
                last_seq = r.seq
                yield _sse(r.event, r.data or {})
                if r.event == RUN_DONE:
                    return
        else:
            idle += 1
            if idle >= 15:
                idle = 0
                yield ": ping\n\n"


def _row_to_finding(f, run_id: str, target_id: str) -> FindingRow:
    return FindingRow(
        run_id=run_id, target_id=target_id, plugin_id=f.plugin_id, category=f.category,
        key=f.key, value=f.value, source=f.source, source_url=f.source_url,
        confidence=f.confidence, evidence=f.evidence, passive=f.passive,
        first_seen=dt.datetime.now(dt.timezone.utc), raw=f.raw,
        bounty_value=getattr(f, "bounty_value", "low"),
    )


# Default per-plugin timeout ceiling (seconds). Individual plugins override
# via their timeout_s class attribute. 30s is the hard per-plugin cap
# (Jay's order 2026-10-18 - speed is top priority): if a plugin hasn't
# produced anything in 30s it is killed gracefully with a "skipped:
# timeout" note. Enforced in _run_plugin via MAX_PLUGIN_TIMEOUT_S.
DEFAULT_PLUGIN_TIMEOUT_S = 30
MAX_PLUGIN_TIMEOUT_S = 30

# Global scan time budget (seconds). A full scan has a HARD 80s ceiling
# (Jay's order 2026-10-18 - speed is top priority). The dispatcher:
#  - runs plugins in priority order (high-signal first, so the first
#    critical finding lands in <15s),
#  - after SCAN_SOFT_STOP_S only HIGH-priority plugins start (the rest are
#    recorded as ok(0) "skipped: time budget", never an error),
#  - after SCAN_HARD_STOP_S no new plugin starts,
#  - caps every in-flight plugin's timeout at the remaining budget, so the
#    last job always finishes by the deadline.
# All are env-overridable for tuning.
SCAN_BUDGET_S = float(__import__("os").environ.get("RECON_SCAN_BUDGET_S", "80"))
SCAN_SOFT_STOP_S = float(__import__("os").environ.get("RECON_SCAN_SOFT_STOP_S", "65"))
SCAN_HARD_STOP_S = float(__import__("os").environ.get("RECON_SCAN_HARD_STOP_S", "72"))
# Seconds reserved at the end of the budget for the correlation graph,
# summary persistence, and run_done emission. In-flight plugins are killed
# by (budget - SCAN_TAIL_RESERVE_S) so run_done always lands < 80s.
SCAN_TAIL_RESERVE_S = float(__import__("os").environ.get("RECON_SCAN_TAIL_RESERVE_S", "14"))


async def _run_plugin(plugin, target: Target, ctx: Ctx,
                    deadline: Optional[float] = None) -> PluginResult:
    """Run one plugin with hang protection + scan-budget awareness.

    deadline: monotonic timestamp of the scan's hard budget end. The
    plugin's effective timeout is the smallest of (a) its own timeout_s,
    (b) the 60s per-plugin cap, and (c) the time left in the scan budget.
    A plugin that cannot finish in the remaining window is killed
    gracefully: ok(0) with a "skipped: timeout" note - never an error,
    never a hang. Findings always win over speed, but a timeout with a
    clear note beats a stalled scan.
    """
    if plugin.missing_keys(ctx):
        return plugin._skipped(
            "needs API key: " + ", ".join(plugin.missing_keys(ctx)) +
            " (add it in the Keys tab to enable)")
    await _emit(ctx.run_id, "plugin_start",
                {"plugin": plugin.id, "label": plugin.label, "target": target.normalized})
    t0 = time.monotonic()
    # Per-plugin timeout ceiling from the plugin itself (default 60s),
    # clamped to the 60s hard cap no matter what a plugin asks for.
    timeout = min(getattr(plugin, "timeout_s", DEFAULT_PLUGIN_TIMEOUT_S)
                  or DEFAULT_PLUGIN_TIMEOUT_S, MAX_PLUGIN_TIMEOUT_S)
    if deadline is not None:
        # Never let an in-flight plugin push the scan past its budget.
        timeout = min(timeout, max(deadline - time.monotonic(), 2))
    try:
        result = await asyncio.wait_for(plugin.run(target, ctx),
                                        timeout=timeout)
    except asyncio.TimeoutError:
        # Jay's rule: no errors ever. A timeout degrades to ok(0) with a
        # note. Partial work is lost, but the scan keeps moving.
        result = plugin._degraded(
            f"skipped: timeout after {timeout:.0f}s - findings may be incomplete")
        await _emit(ctx.run_id, "plugin_timeout",
                    {"plugin": plugin.id, "timeout_s": round(timeout, 1),
                     "target": target.normalized})
    except Exception as e:  # never let one plugin kill the run
        # Environmental network failures degrade gracefully (ok with a note);
        # genuine code bugs still surface as errors so they can be fixed.
        if isinstance(e, (httpx.HTTPError, ssl.SSLError)):
            result = plugin._degraded(f"network blocked/unreachable: {str(e)[:150]}")
        else:
            result = plugin._error(f"unhandled: {str(e)[:200]}")
    result.duration_ms = int((time.monotonic() - t0) * 1000)
    await _emit(ctx.run_id, "plugin_done",
                {"plugin": plugin.id, "status": result.status.value,
                 "reason": result.reason, "findings": len(result.findings),
                 "ms": result.duration_ms})
    # WAF visibility (Task 4): if the target host has served 3+ protection
    # pages, tell Jay once per run instead of silently burning requests on
    # challenge pages. Does not change plugin behavior - findings still win.
    try:
        from urllib.parse import urlparse as _urlparse
        _host = _urlparse(target.normalized).netloc or target.normalized
        _lim = getattr(ctx, "limiter", None)
        if _lim and _lim.protection_hits(_host) >= 3 \
                and not ctx.shared.get("_waf_announced"):
            ctx.shared["_waf_announced"] = True
            await _emit(ctx.run_id, "waf_detected",
                        {"host": _host, "hits": _lim.protection_hits(_host),
                         "note": "target is behind WAF/challenge protection - "
                                 "active probes may return challenge pages; "
                                 "passive findings are unaffected"})
    except Exception:
        pass
    return result


# Estimated seconds per plugin per target (realistic, observed values).
# Used to show Jay a time estimate and to prioritize fast plugins first
# (quick wins land early; slow enumerators run without blocking results).
PLUGIN_TIME_ESTIMATES = {
    "subdomains": 25, "dns": 8, "tls": 10, "webtech": 12, "artifacts": 30,
    "jsminer": 20, "wayback": 15, "leaks": 10, "rdap": 8, "apidiscover": 15,
    "pivots": 5, "headers": 8, "mobile": 5, "bounty": 25, "emails": 15,
    "dorks": 5, "usernames": 20, "opendir": 20, "ports": 15, "robots": 10,
    "waf": 12, "takeover": 15, "banners": 10, "github": 10, "cves": 12,
    "clickjack": 8, "cors": 12, "pastes": 10, "phones": 5, "social": 12,
    "secrets": 25, "wallets": 20, "creds": 20, "sqli": 30, "xss": 30,
    "ssrf": 15, "idor": 10, "auth": 12, "db": 20, "backup": 60, "git": 15,
    "hashid": 8, "exif": 15, "crypto": 12, "keyleak": 15,
    "xxe": 20, "ssti": 30, "lfi": 30, "rce": 40, "redirect": 15,
    "hostheader": 10, "cache": 20, "asn": 10, "cert": 8, "http2": 8,
    "cookies": 8, "forms": 10, "breach": 15, "favicon": 8,
    "adminfinder": 20, "authbypass": 25, "acl": 15, "jwt": 12,
    "session": 15, "crawler": 45, "paramdiscover": 30, "apifuzz": 25,
    "s3": 20, "smartcontract": 15, "cryptoconfig": 25, "walletcheck": 20,
    "deepcrawl": 60, "defi": 15, "tokenapproval": 12, "rugpull": 12,
    "bridge": 12, "nft": 12, "financial": 15, "connections": 10,
    "supplychain": 20, "enterprise": 15, "iot": 15, "k8s": 12,
    "docker": 12, "hypervisor": 12, "cloud": 15, "fingerprint": 15,
    "hiddenpaths": 25, "bola": 15, "blogic": 15,
}
DEFAULT_PLUGIN_ESTIMATE_S = 12
RUN_TIMEOUT_S = 600  # 10 min hard cap (was 30 min)


# ---------------------------------------------------------------------------
# DB-backed plugin job queue
#
# Every (plugin x target) pair of a scan is a PluginJob row in Postgres.
# A background worker claims queued rows, runs them, and writes results
# back. If the server restarts mid-scan (deploy/crash on Render/Railway
# free tiers), jobs left queued/running are picked back up on boot - the
# scan RESUMES instead of dying with "server restarted during scan".
#
# The frontend polls run state from these rows (via run_progress) and
# findings from the findings table, never from in-memory state, so the UI
# works whether the worker runs in-process, on Railway, or on N machines.
#
# Coordination is pure Postgres: claims use SELECT ... FOR UPDATE SKIP
# LOCKED, run finalization uses an atomic status flip. No in-memory locks,
# no cross-process signaling. Multiple workers are safe.
# ---------------------------------------------------------------------------
import os as _os
import socket as _socket

WORKER_ID = f"{_socket.gethostname()}-{_os.getpid()}"
# RECON_WORKER_ENABLED=0 -> this process serves the UI/API only (Render).
# The standalone worker (python -m app.worker_main) runs the queue
# (Railway). Default 1 keeps single-deploy setups working out of the box.
WORKER_ENABLED = _os.environ.get("RECON_WORKER_ENABLED", "1") == "1"
# A "running" job whose worker never comes back within this long is
# presumed dead (deploy/crash) and requeued. Real jobs are capped by
# MAX_PLUGIN_TIMEOUT_S, so this only fires on actual worker death.
STALE_CLAIM_S = int(_os.environ.get("RECON_STALE_CLAIM_S", "600"))
# A job abandoned this many times is marked failed (poison-pill guard).
MAX_JOB_ATTEMPTS = 3

_queue_worker_task = None
_worker_http = None
_worker_limiter = None
_run_ctxs: Dict[str, Ctx] = {}    # run_id -> Ctx (per worker process)
_run_clocks: Dict[str, float] = {}  # run_id -> monotonic budget start
_last_sweep = 0.0


def start_queue_worker() -> None:
    """Start the in-process queue worker (idempotent). No-op when disabled."""
    global _queue_worker_task
    if not WORKER_ENABLED:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _queue_worker_task is None or _queue_worker_task.done():
        _queue_worker_task = loop.create_task(queue_worker_loop())


def reset_stale_queue_jobs() -> int:
    """Requeue jobs orphaned by dead workers. Safe to call on every boot
    and safe with multiple live workers: only jobs whose claim is older
    than STALE_CLAIM_S are touched."""
    session = get_session()
    n = 0
    try:
        cutoff = (dt.datetime.now(dt.timezone.utc)
                  - dt.timedelta(seconds=STALE_CLAIM_S))
        stale = (session.query(PluginJob)
                 .filter(PluginJob.status == "running",
                         PluginJob.started_at < cutoff).all())
        for j in stale:
            j.attempts = (j.attempts or 0) + 1
            if j.attempts >= MAX_JOB_ATTEMPTS:
                j.status = "failed"
                j.finished_at = dt.datetime.now(dt.timezone.utc)
                j.result = {"status": "failed",
                            "reason": ("abandoned by dead worker "
                                       f"{j.worker or '?'} "
                                       f"({j.attempts} attempts)"),
                            "findings": 0, "ms": 0}
            else:
                j.status = "queued"
                j.worker = None
                j.started_at = None
                j.result = None
            n += 1
        if n:
            session.commit()
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
    finally:
        try:
            session.close()
        except Exception:
            pass
    return n


def _pending_count(session, run_id: str) -> int:
    return (session.query(PluginJob)
            .filter(PluginJob.run_id == run_id,
                    PluginJob.status.in_(("queued", "running"))).count())


def _phase1_pending(session, run_id: str) -> bool:
    return (session.query(PluginJob)
            .filter(PluginJob.run_id == run_id, PluginJob.phase == 1,
                    PluginJob.status.in_(("queued", "running")))
            .count() > 0)


def _job_counts(session, run_id: str) -> Dict:
    total = session.query(PluginJob).filter_by(run_id=run_id).count()
    done = (session.query(PluginJob)
            .filter(PluginJob.run_id == run_id,
                    PluginJob.status.in_(("done", "skipped", "failed")))
            .count())
    running = [r.plugin_id for r in
               session.query(PluginJob).filter_by(run_id=run_id,
                                                  status="running").all()]
    return {"total": total, "done": done, "running": running}


def _budget_skip_reason() -> str:
    return (f"skipped: time budget - cut to hold the "
            f"{int(SCAN_BUDGET_S)}s scan ceiling")


def _claim_jobs(session, limit: int):
    """Claim up to `limit` queued jobs for this worker.

    Ordering: priority tier first, then phase, then id. Phase-2 jobs wait
    until no phase-1 jobs remain pending for their run (preserves the
    discovery-bus producer -> consumer ordering). Budget gates from the
    scan clock apply: past the hard stop jobs are recorded skipped, past
    the soft stop only HIGH-priority jobs start.
    """
    from .models import IS_SQLITE
    now_mono = time.monotonic()
    q = (session.query(PluginJob)
         .filter(PluginJob.status == "queued")
         .order_by(PluginJob.priority, PluginJob.phase, PluginJob.id)
         .limit(limit * 4))
    if not IS_SQLITE:
        q = q.with_for_update(skip_locked=True)
    candidates = q.all()
    claimed = []
    run_cache: Dict[str, Run] = {}
    for job in candidates:
        if len(claimed) >= limit:
            break
        run = run_cache.get(job.run_id)
        if run is None:
            run = session.query(Run).filter_by(id=job.run_id).first()
            run_cache[job.run_id] = run
        if run is None or run.status != "running":
            # orphan job: run gone or already finalized - never block the queue
            job.status = "skipped"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": "skipped",
                          "reason": "run no longer active",
                          "findings": 0, "ms": 0}
            continue
        clock = _run_clocks.get(job.run_id)
        if clock is None:
            clock = now_mono
            _run_clocks[job.run_id] = clock
        age = now_mono - clock
        if age >= SCAN_HARD_STOP_S or (
                age >= SCAN_SOFT_STOP_S and job.priority > HIGH_TIER):
            job.status = "skipped"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": "skipped",
                          "reason": _budget_skip_reason(),
                          "findings": 0, "ms": 0}
            continue
        if job.phase == 2 and _phase1_pending(session, job.run_id):
            continue  # leave queued; phase 1 still producing bus signals
        job.status = "running"
        job.worker = WORKER_ID
        job.started_at = dt.datetime.now(dt.timezone.utc)
        job.attempts = (job.attempts or 0) + 1
        claimed.append(job)
    session.commit()
    return claimed


def _get_run_ctx(run_id: str) -> Ctx:
    """Per-run plugin context, built once per worker process."""
    ctx = _run_ctxs.get(run_id)
    if ctx is not None:
        return ctx
    from .keys import load_all
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        keys = load_all(session)
        meta = (run.summary or {}).get("queue_meta", {}) if run else {}
        ctx = Ctx(run_id=run_id,
                  mode=run.mode if run else "passive",
                  http=_worker_http, cache=Cache(), keys=keys,
                  limiter=_worker_limiter,
                  module_overrides=meta.get("module_overrides", {}),
                  evidence_dir=config.EVIDENCE_DIR,
                  source_type=(run.source_type if run and run.source_type
                               else "website"))
    finally:
        try:
            session.close()
        except Exception:
            pass
    _run_ctxs[run_id] = ctx
    return ctx


def _attach_poi_meta(session, run_id: str, target) -> None:
    """Rebuild target.poi from the persisted geo finding (queue-safe).

    POI metadata used to ride on the in-memory Target object; with the
    DB queue the Target is rebuilt from its row, so the metadata comes
    from the geo finding persisted at enqueue time instead.
    """
    try:
        row = (session.query(FindingRow)
               .filter_by(run_id=run_id, target_id=target.id,
                          plugin_id="geo", key="poi").first())
        if row and row.evidence:
            ev = row.evidence
            target.poi = {"name": ev.get("name"), "address": ev.get("address"),
                          "lat": ev.get("lat"), "lon": ev.get("lon"),
                          "operator": ev.get("operator"),
                          "website": ev.get("website"),
                          "phone": ev.get("phone")}
            target.poi_type = ev.get("poi_type", "")
    except Exception:
        pass


async def _run_one_job(job_id: int) -> None:
    """Run a single claimed job: plugin -> findings -> DB -> events."""
    session = get_session()
    try:
        job = session.query(PluginJob).filter_by(id=job_id).first()
        if job is None or job.status != "running":
            return
        run_id = job.run_id
        run = session.query(Run).filter_by(id=run_id).first()
        trow = session.query(TargetRow).filter_by(id=job.target_id).first()
        plugin_cls = discover().get(job.plugin_id)
        if run is None or trow is None or plugin_cls is None:
            job.status = "failed"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": "failed",
                          "reason": "run, target, or plugin missing",
                          "findings": 0, "ms": 0}
            session.commit()
            return
        plugin = plugin_cls()
        ctx = _get_run_ctx(run_id)
        target = Target(raw=trow.raw, type=trow.type,
                        normalized=trow.normalized)
        target.id = trow.id
        if target.type == "poi":
            _attach_poi_meta(session, run_id, target)
        clock = _run_clocks.get(run_id, time.monotonic())
        deadline = clock + SCAN_BUDGET_S - SCAN_TAIL_RESERVE_S
        if plugin.accepts and target.type not in plugin.accepts:
            result = plugin._skipped(
                f"not applicable to target type '{target.type}'")
            result.duration_ms = 0
        else:
            await _emit(run_id, "plugin_start",
                        {"plugin": plugin.id, "label": plugin.label,
                         "target": target.normalized})
            result = await _run_plugin(plugin, target, ctx,
                                       deadline=deadline)
        # Persist + stream findings the moment the plugin finishes.
        rows = [_row_to_finding(f, run_id, target.id)
                for f in result.findings]
        for r in rows:
            session.add(r)
        if rows:
            try:
                session.commit()
            except Exception:
                session.rollback()
        for f, r in zip(result.findings, rows):
            try:
                ctx.publish("poc_findings", {
                    "plugin_id": f.plugin_id, "category": f.category,
                    "key": f.key, "value": f.value, "source": f.source,
                    "source_url": f.source_url, "confidence": f.confidence,
                    "evidence": dict(f.evidence or {}), "passive": f.passive,
                    "bounty_value": getattr(f, "bounty_value", "low")})
            except Exception:
                pass
            await _emit(run_id, "finding",
                        {"fid": r.id, "plugin": f.plugin_id,
                         "category": f.category, "key": f.key,
                         "value": f.value, "source": f.source,
                         "source_url": f.source_url, "evidence": f.evidence,
                         "confidence": f.confidence, "passive": f.passive,
                         "target": target.normalized})
        st = (result.status.value if hasattr(result.status, "value")
              else str(result.status))
        job.status = "done" if st in ("ok", "skipped") else "failed"
        job.finished_at = dt.datetime.now(dt.timezone.utc)
        job.result = {"status": st, "reason": result.reason,
                      "findings": len(rows),
                      "ms": result.duration_ms or 0}
        session.commit()
        await _emit(run_id, "plugin_done",
                    {"plugin": plugin.id, "status": st,
                     "reason": result.reason, "findings": len(rows),
                     "ms": result.duration_ms or 0})
        counts = _job_counts(session, run_id)
        await _emit(run_id, "progress",
                    {"done": counts["done"], "total": counts["total"],
                     "plugin": plugin.id, "target": target.normalized})
    except Exception as e:
        try:
            job = session.query(PluginJob).filter_by(id=job_id).first()
            if job is not None and job.status == "running":
                job.status = "failed"
                job.finished_at = dt.datetime.now(dt.timezone.utc)
                job.result = {"status": "failed",
                              "reason": (f"worker error: "
                                         f"{type(e).__name__}: {str(e)[:150]}"),
                              "findings": 0, "ms": 0}
                session.commit()
        except Exception:
            pass
    finally:
        try:
            session.close()
        except Exception:
            pass


async def _finalize_run(run_id: str) -> bool:
    """Finalize a run whose jobs are all settled. Atomic claim so only one
    worker finalizes. Returns True if this worker did it."""
    session = get_session()
    try:
        n = (session.query(Run).filter_by(id=run_id, status="running")
             .update({"status": "finalizing"}))
        if n != 1:
            session.rollback()
            return False
        session.commit()
        if _pending_count(session, run_id) > 0:
            # lost a race with a new claim; back to running
            (session.query(Run).filter_by(id=run_id, status="finalizing")
             .update({"status": "running"}))
            session.commit()
            return False
        from .graph import build_graph
        n_nodes, n_edges = build_graph(session, run_id)
        total = session.query(FindingRow).filter_by(run_id=run_id).count()
        jobs = session.query(PluginJob).filter_by(run_id=run_id).all()
        plugin_statuses: Dict[str, str] = {}
        skipped_budget = 0
        for j in jobs:
            r = j.result or {}
            plugin_statuses[j.plugin_id] = r.get("status", j.status)
            if (j.status == "skipped"
                    and "time budget" in (r.get("reason") or "")):
                skipped_budget += 1
        n_targets = session.query(TargetRow).filter_by(run_id=run_id).count()
        # MongoDB findings archive (best-effort; never breaks the scan)
        mongo_archived = 0
        try:
            from .dbs import mongo_archive_findings
            rows = session.query(FindingRow).filter_by(run_id=run_id).all()
            mongo_archived = mongo_archive_findings(run_id, [{
                "target_id": r.target_id, "plugin_id": r.plugin_id,
                "category": r.category, "key": r.key, "value": r.value,
                "source": r.source, "source_url": r.source_url,
                "confidence": r.confidence, "evidence": r.evidence,
                "bounty_value": r.bounty_value,
            } for r in rows])
        except Exception:
            pass
        # chain annotations for the UI (were mid-run events before)
        try:
            from . import chains as _chains
            _ctx = _run_ctxs.get(run_id)
            if _ctx is not None:
                for _t in _chains.evaluate_chains(_ctx):
                    await _emit(run_id, "chain",
                                {"chain": _t["chain"], "name": _t["name"],
                                 "producer": _t["producer"],
                                 "consumer": _t["consumer"],
                                 "signals": _t["signals"]})
        except Exception:
            pass
        run = session.query(Run).filter_by(id=run_id).first()
        summary: Dict = {"findings": total, "nodes": n_nodes,
                         "edges": n_edges, "targets": n_targets,
                         "plugins": plugin_statuses}
        if skipped_budget:
            summary["skipped_time_budget"] = skipped_budget
            summary["note"] = (f"{skipped_budget} low-priority plugins "
                               f"skipped: time budget "
                               f"({int(SCAN_BUDGET_S)}s scan ceiling)")
        if mongo_archived:
            summary["mongo_archived"] = mongo_archived
        if run:
            run.status = "done"
            run.finished_at = dt.datetime.now(dt.timezone.utc)
            run.summary = summary
            session.commit()
        run_done_data: Dict = {"run_id": run_id, "findings": total,
                               "nodes": n_nodes, "edges": n_edges}
        if skipped_budget:
            run_done_data["skipped_time_budget"] = skipped_budget
        await _emit(run_id, "run_done", run_done_data)
        _run_ctxs.pop(run_id, None)
        _run_clocks.pop(run_id, None)
        return True
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
        return False
    finally:
        try:
            session.close()
        except Exception:
            pass


async def _sweep_finalize() -> None:
    """Finalize any running runs whose jobs are all settled (covers the
    crash-between-last-job-and-finalize window). Throttled to ~5s."""
    global _last_sweep
    now = time.monotonic()
    if now - _last_sweep < 5:
        return
    _last_sweep = now
    session = get_session()
    try:
        run_ids = [r[0] for r in
                   session.query(PluginJob.run_id)
                   .filter(PluginJob.status.in_(
                       ("queued", "running", "done", "skipped", "failed")))
                   .distinct().all()]
        for rid in run_ids:
            if _pending_count(session, rid) == 0:
                await _finalize_run(rid)
    finally:
        try:
            session.close()
        except Exception:
            pass


async def _pump_once() -> bool:
    """Claim one batch of jobs and run them. Returns True if any ran."""
    session = get_session()
    try:
        concurrency = max(getattr(config, "MAX_CONCURRENCY", 5), 1)
        claimed = _claim_jobs(session, concurrency)
        # capture ids while the session is still open (commit expires attrs)
        claimed_ids = [j.id for j in claimed]
    finally:
        try:
            session.close()
        except Exception:
            pass
    if claimed_ids:
        sem = asyncio.Semaphore(
            max(getattr(config, "MAX_CONCURRENCY", 5), 1))

        async def _one(job_id: int):
            async with sem:
                await _run_one_job(job_id)

        await asyncio.gather(*(_one(i) for i in claimed_ids))
    await _sweep_finalize()
    return bool(claimed_ids)


async def queue_worker_loop() -> None:
    """Claim queued plugin jobs from Postgres and run them, forever."""
    global _worker_http, _worker_limiter
    reset_stale_queue_jobs()
    async with net.async_client(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.DEFAULT_TIMEOUT,
            follow_redirects=True) as http:
        _worker_http = http
        _worker_limiter = RateLimiter(default_rps=config.DEFAULT_RPS)
        while True:
            try:
                did_work = await _pump_once()
            except Exception:
                did_work = False
            await asyncio.sleep(0.5 if did_work else 2.0)


def _enqueue_jobs(session, run_id: str, plugins, trobj) -> int:
    """Insert one PluginJob per (plugin x target) pair. Returns job count."""
    jobs = [PluginJob(run_id=run_id, target_id=t.id, plugin_id=p.id,
                      phase=getattr(p, "phase", 1),
                      priority=priority_for(p.id), status="queued")
            for t in trobj for p in plugins]
    if jobs:
        session.bulk_save_objects(jobs)
        session.commit()
    return len(jobs)


async def _enqueue_poi_run(run_id: str, location_raw: str, mode: str,
                           plugin_ids: Optional[List[str]],
                           module_overrides: Optional[Dict[str, str]],
                           source_type: str) -> None:
    """Bank/ATM run: geocode -> POI targets + geo findings -> queue jobs."""
    import datetime as _dt
    from . import geo as _geo
    session = get_session()
    try:
        location = (location_raw or "").strip().splitlines()[0].strip()
        await _emit(run_id, "run_start",
                    {"run_id": run_id, "targets": [location],
                     "mode": mode, "source_type": source_type,
                     "plugins": plugin_ids or [], "plugin_count": 0,
                     "target_count": 0,
                     "note": f"geocoding '{location}'..."})
        coords = await _geo.geocode(location)
        if not coords:
            run = session.query(Run).filter_by(id=run_id).first()
            if run:
                run.status = "failed"
                run.finished_at = _dt.datetime.now(_dt.timezone.utc)
                run.summary = {"error": f"could not geocode location: "
                                        f"{location}",
                               "findings": 0}
                session.commit()
            await _emit(run_id, "run_done",
                        {"run_id": run_id, "findings": 0,
                         "error": f"could not geocode: {location}"})
            return
        pois = await _geo.find_pois(coords["lat"], coords["lon"],
                                    source_type)
        await _emit(run_id, "progress",
                    {"done": 0, "total": max(len(pois), 1),
                     "note": f"found {len(pois)} {source_type}(s) near "
                             f"{coords['display_name']}"})
        if not pois:
            run = session.query(Run).filter_by(id=run_id).first()
            if run:
                run.status = "done"
                run.finished_at = _dt.datetime.now(_dt.timezone.utc)
                run.summary = {"findings": 0, "pois": 0,
                               "location": coords["display_name"]}
                session.commit()
            await _emit(run_id, "run_done",
                        {"run_id": run_id, "findings": 0,
                         "note": f"no {source_type}s found near "
                                 f"{coords['display_name']}"})
            return
        # Persist each POI as a target row + a geo finding carrying the
        # OSM metadata (the queue rebuilds Target from the row, so the
        # metadata travels in the finding, not in memory).
        trobj = []
        for poi in pois:
            label = f"{poi['name']} ({poi['lat']:.5f},{poi['lon']:.5f})"
            t = Target(raw=label, type="poi",
                       normalized=f"{poi['lat']},{poi['lon']}")
            trobj.append(t)
            session.add(TargetRow(id=t.id, run_id=run_id, raw=label,
                                  type="poi",
                                  normalized=f"{poi['lat']},{poi['lon']}"))
            session.add(FindingRow(
                run_id=run_id, target_id=t.id, plugin_id="geo",
                category="location", key="poi",
                value=f"{poi['name']} - {poi.get('address', '')}",
                source="OpenStreetMap", source_url="",
                evidence={"severity": "info", "lat": poi["lat"],
                          "lon": poi["lon"], "name": poi["name"],
                          "address": poi.get("address", ""),
                          "operator": poi.get("operator", ""),
                          "website": poi.get("website", ""),
                          "phone": poi.get("phone", ""),
                          "poi_type": source_type},
                confidence=100, passive=True))
        session.commit()
        discover()
        plugins = all_plugins()
        if plugin_ids:
            plugins = [p for p in plugins if p.id in plugin_ids]
        wanted = {source_type, "ports", "banners", "dns", "tls", "headers"}
        plugins = [p for p in plugins if p.id in wanted or not plugin_ids]
        job_plugins = [p for p in plugins
                       if not p.accepts or "poi" in p.accepts
                       or "domain" in p.accepts or "ip" in p.accepts]
        meta = {"mode": mode, "plugin_ids": plugin_ids,
                "module_overrides": module_overrides or {},
                "source_type": source_type,
                "location": coords["display_name"], "pois": len(pois)}
        run = session.query(Run).filter_by(id=run_id).first()
        if run:
            run.summary = {**(run.summary or {}), "queue_meta": meta}
            session.commit()
        n_jobs = _enqueue_jobs(session, run_id, job_plugins, trobj)
        await _emit(run_id, "run_start",
                    {"run_id": run_id,
                     "targets": [t.raw for t in trobj],
                     "mode": mode, "source_type": source_type,
                     "plugins": [p.id for p in job_plugins],
                     "plugin_count": len(job_plugins),
                     "target_count": len(trobj),
                     "location": coords["display_name"],
                     "queued": True,
                     "note": (f"{n_jobs} jobs queued in Postgres; "
                              "worker picks them up")})
    finally:
        try:
            session.close()
        except Exception:
            pass


async def execute_run(run_id: str, targets_raw: str, mode: str,
                      plugin_ids: Optional[List[str]] = None,
                      module_overrides: Optional[Dict[str, str]] = None,
                      keys: Optional[Dict[str, str]] = None,
                      source_type: str = "website"):
    """Enqueue-only: insert every (plugin x target) job into Postgres and
    return immediately. The queue worker (in-process and/or standalone on
    Railway) claims and runs them; a restart resumes from the queue
    instead of killing the scan. (keys are reloaded from the DB by the
    worker per run; the passed dict is kept for signature compat.)"""
    init_db()
    RUN_EVENT_BUFFER[run_id] = []
    start_queue_worker()
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            return
        if source_type in ("bank", "atm"):
            session.close()
            await _enqueue_poi_run(run_id, targets_raw, mode, plugin_ids,
                                   module_overrides, source_type)
            return
        discover()
        classified = classify_batch(targets_raw)
        plugins = all_plugins()
        if plugin_ids:
            plugins = [p for p in plugins if p.id in plugin_ids]
        # Source-type plugins (atm, bank) are silent during website scans:
        # they only run when the user picks ATM or Bank as the source type.
        if source_type == "website":
            plugins = [p for p in plugins if p.id not in ("atm", "bank")]

        # persist targets
        trobj: List[Target] = []
        for c in classified:
            t = Target(raw=c.get("raw", ""), type=c["type"],
                       normalized=c["normalized"])
            trobj.append(t)
            session.add(TargetRow(id=t.id, run_id=run_id, raw=t.raw,
                                  type=t.type, normalized=t.normalized))
        session.commit()

        # Time estimate for the UI (same math as before).
        n_targets = max(len(trobj), 1)
        total_plugin_s = sum(PLUGIN_TIME_ESTIMATES.get(
            p.id, DEFAULT_PLUGIN_ESTIMATE_S) for p in plugins) * n_targets
        concurrency = max(getattr(config, "MAX_CONCURRENCY", 5), 1)
        estimated_s = max(int(total_plugin_s / concurrency), 10)

        meta = {"mode": mode, "plugin_ids": plugin_ids,
                "module_overrides": module_overrides or {},
                "source_type": source_type}
        run.summary = {**(run.summary or {}), "queue_meta": meta}
        session.commit()
        n_jobs = _enqueue_jobs(session, run_id, plugins, trobj)

        await _emit(run_id, "run_start",
                    {"run_id": run_id,
                     "targets": [c["normalized"] for c in classified],
                     "mode": mode, "source_type": source_type,
                     "plugins": [p.id for p in plugins],
                     "estimated_s": estimated_s,
                     "plugin_count": len(plugins),
                     "target_count": n_targets,
                     "queued": True,
                     "note": (f"{n_jobs} jobs queued in Postgres; "
                              "worker picks them up, scan survives restarts")})
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
                        {"run_id": run_id, "findings": 0,
                         "error": str(e)[:300]})
        except Exception:
            pass
    finally:
        try:
            session.close()
        except Exception:
            pass

async def launch_run(run_id: str, targets_raw: str, mode: str,
                   plugin_ids: Optional[List[str]] = None,
                   module_overrides: Optional[Dict[str, str]] = None,
                   keys: Optional[Dict[str, str]] = None,
                   source_type: str = "website") -> asyncio.Task:
    """Fire-and-forget: start execute_run as a background task."""
    return asyncio.create_task(
        execute_run(run_id, targets_raw, mode, plugin_ids, module_overrides,
                    keys, source_type))
