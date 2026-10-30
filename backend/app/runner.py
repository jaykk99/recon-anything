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
import logging
import os
import ssl
import threading
import time
import uuid
import zlib
from typing import AsyncIterator, Dict, List, Optional

import httpx

log = logging.getLogger("recon-anything.runner")

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


# Event persistence runs on a dedicated writer thread fed by a queue:
# _emit only does the in-memory fan-out and enqueues the durable copy,
# and the writer thread commits events to run_events in BATCHES (one
# commit per batch instead of one per event).
#
# Why (measured 2026-10-23 on the example.com baseline): a 195-plugin
# scan emitted 1,304 events, and the old design awaited a Neon commit
# for EVERY event inside the job tasks. The single writer serialized
# behind ~1,300 remote round-trips, _emit waits inflated plugin
# durations past their own timeouts (a 60s timeout reported 88s), and
# jobs sat "running" for many minutes in their persist phase while
# their findings were already computed - the queue looked wedged and
# the wall clock went to the scan budget instead of the work. Batching
# keeps the durable copy (subscribe() replays from run_events) with a
# sub-second lag, which the 1s replay poll already tolerates.
import queue as _queue

_event_q: "_queue.Queue" = _queue.Queue()
_event_writer_started = False
_event_writer_lock = threading.Lock()


def _persist_events_batch(items) -> None:
    """Insert a batch of (run_id, seq, event, data) with ONE commit.
    Self-healing like the old per-event path: on failure, recreate the
    schema and retry the batch once, then drop it - a DB failure must
    never break a scan."""
    def _write():
        session = get_session()
        try:
            for run_id, seq, event, data in items:
                session.add(RunEvent(run_id=run_id, seq=seq,
                                     event=event, data=data))
            session.commit()
        finally:
            session.close()

    try:
        _write()
    except Exception:
        try:
            init_db()
            _write()
        except Exception:
            pass


def _event_writer_loop() -> None:
    while True:
        batch = [_event_q.get()]
        # Coalesce: brief window to gather a batch before committing.
        deadline = time.monotonic() + 0.15
        while len(batch) < 200:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(_event_q.get(timeout=remaining))
            except _queue.Empty:
                break
        try:
            _persist_events_batch(batch)
        finally:
            for _ in batch:
                _event_q.task_done()


def _ensure_event_writer() -> None:
    global _event_writer_started
    if _event_writer_started:
        return
    with _event_writer_lock:
        if _event_writer_started:
            return
        t = threading.Thread(target=_event_writer_loop,
                             name="run-events", daemon=True)
        t.start()
        _event_writer_started = True


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
    # broke live UI updates. Enqueued for the batch writer; seq is
    # assigned here, on the event loop, so per-run ordering is exactly
    # emission order. Never awaited: event persistence must not stall
    # the plugin that emitted the event.
    RUN_SEQ[run_id] = RUN_SEQ.get(run_id, 0) + 1
    safe_data = json.loads(json.dumps(data, default=str))
    _ensure_event_writer()
    _event_q.put((run_id, RUN_SEQ[run_id], event, safe_data))


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


def _fetch_events_sync(run_id: str, after_seq: int) -> list:
    """Sync DB read of run_events after a sequence number. Called via
    asyncio.to_thread so the blocking SQLAlchemy call never stalls the
    event loop (it was starving the SSE stream into total silence)."""
    session = get_session()
    try:
        rows = (session.query(RunEvent)
                .filter(RunEvent.run_id == run_id,
                        RunEvent.seq > after_seq)
                .order_by(RunEvent.seq).all())
        # Detach plain data before the session closes.
        return [(r.seq, r.event, r.data or {}) for r in rows]
    finally:
        session.close()


async def _subscribe_db(run_id: str) -> AsyncIterator[str]:
    last_seq = 0
    rows = await asyncio.to_thread(_fetch_events_sync, run_id, 0)
    for seq, event, data in rows:
        last_seq = seq
        yield _sse(event, data)
        if event == RUN_DONE:
            return
    # Follow live: poll for new rows. 1s granularity is plenty "live"
    # for the UI and is correct across processes.
    idle = 0
    db_errors = 0
    while True:
        await asyncio.sleep(1)
        # A transient DB error (Neon waking up, a recycled socket) used
        # to end the whole stream, so the browser saw "connection lost"
        # mid-scan and reconnected from event 0. Now the stream stays
        # open: keep the client alive with a heartbeat and retry from
        # the same last_seq with a short backoff. Only after ~2 min of
        # straight failures do we give up and let the outer
        # self-heal path take over.
        try:
            rows = await asyncio.to_thread(_fetch_events_sync, run_id, last_seq)
            db_errors = 0
        except Exception:
            db_errors += 1
            if db_errors > 30:
                raise
            yield ": ping\n\n"
            await asyncio.sleep(min(2 * db_errors, 10))
            continue
        if rows:
            idle = 0
            for seq, event, data in rows:
                last_seq = seq
                yield _sse(event, data)
                if event == RUN_DONE:
                    return
        else:
            idle += 1
            # Heartbeat every ~10s of silence so no proxy hop (Render,
            # the Next.js /live proxy, mobile networks) treats the
            # stream as idle and cuts it during a quiet stretch.
            if idle >= 10:
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
# via their timeout_s class attribute. The cap was 30s under the 2026-10-18
# speed-first order; Jay's 2026-10-20 order ("it doesn't find enough, it
# needs to find more") reversed that tradeoff: slow enumerators (subdomain
# brute force, crawlers, port scans, param discovery) were being killed at
# 30s and losing their findings, so the cap is now 120s. A plugin that
# times out is still killed gracefully with a "skipped: timeout" note.
# Enforced in _run_plugin via MAX_PLUGIN_TIMEOUT_S.
DEFAULT_PLUGIN_TIMEOUT_S = 60
MAX_PLUGIN_TIMEOUT_S = 120

# Global scan time budget (seconds). Was a HARD 80s ceiling (2026-10-18
# speed-first order) - with 170+ plugins at 16-way concurrency that was
# mathematically impossible to finish: live check 2026-10-20 showed a scan
# skipping 138 of 170 plugins as "skipped: time budget" and returning only
# 25 findings. Jay's 2026-10-20 order (find more) raised it to 600s, but
# the first live verification scan still cut 79 of 170 plugins (90 ran,
# 73 findings): on the free-tier single instance (worker + API sharing
# one small CPU), real throughput is roughly 90 plugins per 600s, and the
# plugins cut last are the slow enumerators that need the most time. The
# budget is therefore 1500s (25 min). Findings still stream live in
# priority order, so the first critical finding still lands in <15s; the
# longer budget only lets every plugin actually run instead of being cut.
# The dispatcher:
#  - runs plugins in priority order (high-signal first),
#  - after SCAN_SOFT_STOP_S only HIGH-priority plugins start (the rest are
#    recorded as ok(0) "skipped: time budget", never an error),
#  - after SCAN_HARD_STOP_S no new plugin starts,
#  - caps every in-flight plugin's timeout at the remaining budget, so the
#    last job always finishes by the deadline.
# All are env-overridable for tuning.
#
# 2026-10-21 (Jay: "get scanning better and faster"): even at 1500s the
# verification scan still cut 34 of 170 plugins - the ceiling was doing
# the cutting, not plugin slowness alone: dispatch streamed fastest-first
# within each tier, so the slowest plugins (the deep enumerators) were
# still queued when the soft stop hit and got mass-skipped. Three fixes
# landed together: anti-starvation dispatch (longest jobs in each tier
# start in the first claim wave, interleaved with the fastest), worker
# concurrency 24 -> 32, and hunter expansion running incrementally
# during the scan instead of only at finalize. The budget is a ceiling,
# not a target - a scan ends when its jobs end - so the ceiling rises
# to 2400s to give slow-but-legit work (WAF-paced hosts at 1 rps, big
# wordlist sweeps, hunter frontiers) room to finish instead of being
# recorded as cut. Soft/hard stops scale with it.
SCAN_BUDGET_S = float(__import__("os").environ.get("RECON_SCAN_BUDGET_S", "2400"))
SCAN_SOFT_STOP_S = float(__import__("os").environ.get("RECON_SCAN_SOFT_STOP_S", "2000"))
SCAN_HARD_STOP_S = float(__import__("os").environ.get("RECON_SCAN_HARD_STOP_S", "2250"))
# Seconds reserved at the end of the budget for the correlation graph,
# summary persistence, and run_done emission. In-flight plugins are killed
# by (budget - SCAN_TAIL_RESERVE_S) so run_done lands within the budget.
SCAN_TAIL_RESERVE_S = float(__import__("os").environ.get("RECON_SCAN_TAIL_RESERVE_S", "60"))


async def _run_plugin(plugin, target: Target, ctx: Ctx,
                    deadline: Optional[float] = None) -> PluginResult:
    """Run one plugin with hang protection + scan-budget awareness.

    deadline: monotonic timestamp of the scan's hard budget end. The
    plugin's effective timeout is the smallest of (a) its own timeout_s,
    (b) the per-plugin cap (MAX_PLUGIN_TIMEOUT_S), and (c) the time left
    in the scan budget.
    A plugin that cannot finish in the remaining window is killed
    gracefully: ok(0) with a "skipped: timeout" note - never an error,
    never a hang. Findings always win over speed, but a timeout with a
    clear note beats a stalled scan.
    """
    if plugin.missing_keys(ctx):
        result = plugin._skipped(
            "needs API key: " + ", ".join(plugin.missing_keys(ctx)) +
            " (add it in the Keys tab to enable)")
        # Emit the job's one plugin_done here: this early return skips
        # the plugin_start/done pair below, and _run_one_job no longer
        # emits a duplicate done of its own (2026-10-23 dedupe).
        await _emit(ctx.run_id, "plugin_done",
                    {"plugin": plugin.id, "status": result.status.value,
                     "reason": result.reason, "findings": 0, "ms": 0})
        return result
    await _emit(ctx.run_id, "plugin_start",
                {"plugin": plugin.id, "label": plugin.label, "target": target.normalized})
    t0 = time.monotonic()
    # Per-plugin timeout ceiling from the plugin itself,
    # clamped to MAX_PLUGIN_TIMEOUT_S no matter what a plugin asks for.
    timeout = min(getattr(plugin, "timeout_s", DEFAULT_PLUGIN_TIMEOUT_S)
                  or DEFAULT_PLUGIN_TIMEOUT_S, MAX_PLUGIN_TIMEOUT_S)
    if deadline is not None:
        # Never let an in-flight plugin push the scan past its budget.
        timeout = min(timeout, max(deadline - time.monotonic(), 2))
    try:
        result = await asyncio.wait_for(plugin.run(target, ctx),
                                        timeout=timeout)
    except asyncio.TimeoutError:
        # Jay's rule: no errors ever. A timeout degrades gracefully - but
        # partial work is KEPT: plugins checkpoint confirmed findings via
        # Plugin._checkpoint(), and those are reported with a "partial"
        # note instead of being silently discarded. A scan that found 3
        # SQLi before the cutoff must not report zero.
        partials = list(
            getattr(plugin, "partial_findings", None) or [])
        if partials:
            result = plugin._ok(
                partials,
                f"timeout after {timeout:.0f}s - partial results: "
                f"{len(partials)} findings confirmed before the cutoff")
        else:
            result = plugin._degraded(
                f"skipped: timeout after {timeout:.0f}s - findings may be "
                f"incomplete")
        await _emit(ctx.run_id, "plugin_timeout",
                    {"plugin": plugin.id, "timeout_s": round(timeout, 1),
                     "target": target.normalized,
                     "partial_findings": len(partials)})
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
    # 2026-10-20 quota batch: web-security, protocol, and infra plugins.
    "cookie_security": 8, "csp_audit": 8, "hsts": 10, "http_methods": 8,
    "error_pages": 10, "exposed_debug": 8, "phpinfo": 10,
    "mixed_content": 8, "http2_check": 10, "graphql_probe": 15,
    "rate_limit_audit": 8, "web_manifest": 10, "sri_audit": 8,
    "html_comments": 8, "trackers": 8, "well_known_audit": 10,
    "redirect_chain": 10, "dns_infra": 20, "ipv6_check": 10,
    "ip_reputation": 15, "smtp_tls": 20, "cdn_detect": 8,
    "typosquat": 45, "tls_config": 15, "caa_audit": 8,
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
# Worker-loop watchdog: a job task alive longer than this is wedged.
# Plugin execution itself is capped at MAX_PLUGIN_TIMEOUT_S (120s) by
# asyncio.wait_for, but wait_for can only deliver cancellation at an
# await point - a plugin stuck in synchronous code (CPU-bound parsing,
# a blocking call that ignored the async contract) freezes its task
# past every cap, and before 2026-10-21 the only recovery was a
# process restart, because reset_stale_queue_jobs ran just once at
# boot. Observed live that day: a full scan froze at 154/211 for 9+
# minutes with every slot held by unsettled jobs. The loop now
# abandons + cancels such tasks (same attempts semantics as the
# stale-claim reset) and re-runs the stale sweep periodically, so a
# wedged job costs minutes, not the whole scan.
# 2026-10-26 (faster, no lost findings): 300s -> 180s. No legit plugin
# runs past its 120s cap, so 180s still leaves 60s of headroom for
# cleanup while freeing a wedged slot 2 minutes sooner.
JOB_WATCHDOG_S = int(_os.environ.get("RECON_JOB_WATCHDOG_S", "180"))
STALE_SWEEP_INTERVAL_S = 60.0

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


def _abandon_job(job_id: int) -> None:
    """Reset one wedged job: requeue it, or fail it at MAX attempts.

    Same semantics as reset_stale_queue_jobs, for a single job whose
    asyncio task the worker loop's watchdog is about to cancel. The
    cancel lands at the task's next await point; if the task is stuck
    in synchronous code it dies with the process instead, and the
    boot-time stale reset recovers the row (already requeued here, so
    it is simply claimable again).
    """
    session = get_session()
    try:
        job = session.query(PluginJob).filter_by(id=job_id).first()
        if job is None or job.status != "running":
            return
        job.attempts = (job.attempts or 0) + 1
        if job.attempts >= MAX_JOB_ATTEMPTS:
            job.status = "failed"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": "failed",
                          "reason": ("abandoned: job task exceeded the "
                                     f"{JOB_WATCHDOG_S}s watchdog limit "
                                     f"({job.attempts} attempts)"),
                          "findings": 0, "ms": 0}
        else:
            job.status = "queued"
            job.worker = None
            job.started_at = None
            job.result = None
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


def _run_selection(run) -> Optional[set]:
    """The run's explicit plugin selection (queue_meta.plugin_ids).

    Set when the user picked plugins deliberately in the UI (e.g. the
    Crypto Pack preset posts exactly the cp_* ids). Jay's rule
    (2026-10-23): SELECTED MEANS RUN - a non-empty selection is
    exempt from the scan time-budget skips and claims before
    unselected work. Returns None for unfiltered full scans.
    """
    try:
        ids = ((run.summary or {}).get("queue_meta", {})
               .get("plugin_ids") or [])
    except Exception:
        return None
    return set(ids) if ids else None


def _run_key_hunters(run) -> set:
    """The run's exposed-key hunter plugin ids (crypto-class runs).

    Recorded as queue_meta.key_hunter_ids at run creation when the
    seed targets classified as crypto/web3 (app/cryptotarget.py).
    On such runs the key hunters claim before everything else and
    are exempt from the scan time-budget skips - generic findings
    never crowd out the private-key hunt on a crypto target (Jay's
    order, 2026-10-23). Empty set for non-crypto runs.
    """
    try:
        meta = (run.summary or {}).get("queue_meta", {}) or {}
        if not meta.get("crypto_target"):
            return set()
        return set(meta.get("key_hunter_ids") or [])
    except Exception:
        return set()


def _run_seed_target_ids(session, run) -> Optional[set]:
    """The run's SEED target ids (targets the user actually asked to
    scan), or None when unknown.

    Recorded as queue_meta.seed_target_ids at run creation. Runs
    created before that field existed fall back to "every target not
    recorded as hunter-created in hunters_accum"; when neither source
    exists the run is legacy and None disables seed-first gating for
    it (pre-2026-10-23 behavior).

    Seed-first reservation (Jay's order, 2026-10-23): hunter-expanded
    targets compounded run over run (known set 631 -> 707 -> 1,226)
    until ~70% of a scan's jobs were budget-skipped and the seed's own
    expensive plugins starved. In _claim_jobs, a run's seed jobs claim
    before its hunter jobs, and hunter jobs only take slots the seed
    queue cannot use.
    """
    try:
        summary = run.summary or {}
        meta = summary.get("queue_meta", {}) or {}
        ids = meta.get("seed_target_ids")
        if ids:
            return set(ids)
        accum = summary.get("hunters_accum") or {}
        hunter_ids = accum.get("hunter_targets")
        if hunter_ids is not None:
            all_ids = {t.id for t in
                       session.query(TargetRow)
                       .filter_by(run_id=run.id).all()}
            return all_ids - set(hunter_ids)
    except Exception:
        return None
    return None


def _queued_jobs_query(session):
    """Base fetch of queued jobs (deterministic order: priority, phase,
    estimate, id). The claim pass re-orders these with _dispatch_order
    before claiming; this query only defines the candidate set.
    coalesce guards rows enqueued before estimate_s existed.
    """
    from sqlalchemy import func
    return (session.query(PluginJob)
            .filter(PluginJob.status == "queued")
            .order_by(PluginJob.priority, PluginJob.phase,
                      func.coalesce(PluginJob.estimate_s,
                                    DEFAULT_PLUGIN_ESTIMATE_S),
                      PluginJob.id))


def _dispatch_order(jobs):
    """Order queued jobs for claiming: no starvation within a tier.

    Jay's policy is unchanged at the top level: HIGH priority before
    MEDIUM before LOW, phase 1 before phase 2. The old within-tier rule
    (estimate ascending - fastest first) is what created the cut list:
    the slowest plugins in each tier were still queued when the scan
    budget's soft stop hit and were mass-skipped (34 of 170 on the
    2026-10-20 verification scan, all of them deep enumerators). Within
    a (priority, phase) tier, jobs are now interleaved longest-first /
    shortest-first (longest, shortest, 2nd longest, 2nd shortest, ...):
    the longest jobs start in the first claim waves alongside the quick
    wins, and the jobs left for the tail are mid-length ones that fit
    anywhere. Ties break by job id.
    """
    def est(j):
        return (j.estimate_s if j.estimate_s is not None
                else DEFAULT_PLUGIN_ESTIMATE_S)

    groups: Dict[tuple, List] = {}
    for j in jobs:
        groups.setdefault((j.priority, j.phase), []).append(j)
    ordered: List = []
    for key in sorted(groups):
        tier = sorted(groups[key], key=lambda j: (-est(j), j.id))
        lo, hi = 0, len(tier) - 1
        take_long = True
        while lo <= hi:
            if take_long:
                ordered.append(tier[lo])
                lo += 1
            else:
                ordered.append(tier[hi])
                hi -= 1
            take_long = not take_long
    return ordered


def _hunter_expansion_owed(session, run_id: str) -> bool:
    """True while the mid-run hunter sweep still owes this run an
    expansion pass for findings it has already produced.

    Phase-2 (chain) plugins consume the discovery bus, and the phase
    gate holds them until phase-1 JOBS settle. But hunter expansion
    runs on a 15s sweep and creates NEW phase-1 jobs (new targets)
    that also feed the bus. When phase 1 drains faster than the sweep
    cadence - dead-host fast-fail makes seed jobs settle in seconds -
    phase-2 used to fire on a half-empty bus and chain plugins found
    nothing: a silent findings loss that only shows on fast runs
    (measured 2026-10-23: sourcemap/keyharvest/jwt lost their bus-fed
    findings on a dead-host scan that finished before the first
    expansion pass). Defer while the sweep's own trigger condition
    (findings grew >= HUNTER_MIN_NEW_FINDINGS since its last pass) is
    met; the sweep runs the pass, advances the mark, and any new
    phase-1 jobs re-engage the job gate. Only runs the sweep actively
    tracks are gated (see _hunter_swept).
    """
    if run_id not in _hunter_swept:
        return False
    try:
        from .hunters.engine import ENABLED as _hunters_on
        if not _hunters_on:
            return False
    except Exception:
        return False
    try:
        n = (session.query(FindingRow)
             .filter_by(run_id=run_id).count())
    except Exception:
        return False
    return (n - _hunter_marks.get(run_id, 0)) >= HUNTER_MIN_NEW_FINDINGS


def _claim_jobs(session, limit: int):
    """Claim up to `limit` queued jobs for this worker.

    Ordering: _dispatch_order (priority tier, then phase, then the
    anti-starvation interleave). Phase-2 jobs wait until no phase-1
    jobs remain pending for their run (preserves the discovery-bus
    producer -> consumer ordering). Budget gates from the scan clock
    apply: past the hard stop jobs are recorded skipped, past the soft
    stop only HIGH-priority jobs start.

    SEED-FIRST RESERVATION (2026-10-23): claiming runs in two passes.
    Pass 1 claims only SEED jobs (targets the user asked to scan);
    pass 2 claims HUNTER jobs (targets the hunters expanded into),
    and only for runs whose seed queue is drained - every seed job
    either claimed, budget-skipped, or left queued solely by the
    phase-2 rule. The phase-deferred exception matters: a deferred
    seed phase-2 job waits on phase-1 producers, which may be hunter
    jobs themselves, so blocking hunters behind it would deadlock the
    run. Everything else about a hunter job claiming is unchanged:
    it never takes a slot a claimable seed job could have used, so
    hunter work fills leftover capacity while seed jobs run, and the
    seed's expensive plugins can no longer be starved by the frontier.

    CRYPTO KEY-HUNTER FIRST (2026-10-23): on crypto-class runs
    (queue_meta.crypto_target), the exposed-key hunters recorded
    in queue_meta.key_hunter_ids claim ahead of all other classes
    and are exempt from the budget gates - see app/cryptotarget.py.
    """
    from sqlalchemy import func

    from .models import IS_SQLITE
    now_mono = time.monotonic()
    q = _queued_jobs_query(session)
    if not IS_SQLITE:
        q = q.with_for_update(skip_locked=True)
    # The queue is bounded by design (~200 scan jobs + <=300 hunter
    # jobs), so the whole candidate set is fetched and ordered in
    # Python; the old limit*4 window could exclude the longest jobs
    # from the candidate set entirely, re-creating the starvation this
    # ordering exists to fix.
    candidates = _dispatch_order(q.all())
    run_cache: Dict[str, Run] = {}
    sel_map: Dict[str, Optional[set]] = {}
    kh_map: Dict[str, set] = {}
    seed_map: Dict[str, Optional[set]] = {}
    for rid in {j.run_id for j in candidates}:
        r = session.query(Run).filter_by(id=rid).first()
        run_cache[rid] = r
        sel_map[rid] = _run_selection(r) if r is not None else None
        kh_map[rid] = _run_key_hunters(r) if r is not None else set()
        seed_map[rid] = (_run_seed_target_ids(session, r)
                         if r is not None else None)

    def is_seed(job) -> bool:
        seeds = seed_map.get(job.run_id)
        return seeds is None or job.target_id in seeds

    # Stable sorts compose: dispatch order survives inside each
    # class; seed class sorts before hunter class; the SELECTED
    # MEANS RUN sort (2026-10-23) goes on last so an explicit plugin
    # selection still claims before everything else, and selected
    # jobs stay exempt from the budget gates below. Selections come
    # from queue_meta.plugin_ids, set at run creation.
    candidates.sort(key=lambda j: 0 if is_seed(j) else 1)
    if any(sel_map.values()):
        candidates.sort(
            key=lambda j: 0 if (sel_map.get(j.run_id)
                                and j.plugin_id in sel_map[j.run_id])
            else 1)
    # CRYPTO KEY-HUNTER FIRST (2026-10-23): on crypto-class runs
    # the exposed-key hunters sort ahead of everything else -
    # ahead of the explicit selection too, because a pack
    # selection's own secret/wallet hunters are exactly the
    # plugins that must not trail the address-format checks.
    if any(kh_map.values()):
        candidates.sort(
            key=lambda j: 0 if j.plugin_id in kh_map.get(j.run_id, ())
            else 1)
    # Per-run phase-1 pending counts, one GROUP BY for the whole pass
    # (was one COUNT query per phase-2 candidate).
    phase1_pending = dict(
        session.query(PluginJob.run_id, func.count(PluginJob.id))
        .filter(PluginJob.phase == 1,
                PluginJob.status.in_(("queued", "running")))
        .group_by(PluginJob.run_id).all())
    claimed = []

    def gate(job) -> str:
        """Per-job claim gates, shared by both passes. Returns
        "claim", "skip" (terminal skip recorded on the job), or
        "defer" (leave queued)."""
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
            return "skip"
        clock = _run_clocks.get(job.run_id)
        if clock is None:
            clock = now_mono
            _run_clocks[job.run_id] = clock
        age = now_mono - clock
        sel = sel_map.get(job.run_id)
        is_selected = bool(sel) and job.plugin_id in sel
        # Key hunters on crypto-class runs get the SELECTED MEANS
        # RUN budget treatment: the budget never starves the
        # private-key hunt on a crypto target.
        is_key_hunter = job.plugin_id in kh_map.get(job.run_id, ())
        if not (is_selected or is_key_hunter) and (
                age >= SCAN_HARD_STOP_S or (
                    age >= SCAN_SOFT_STOP_S and job.priority > HIGH_TIER)):
            job.status = "skipped"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": "skipped",
                          "reason": _budget_skip_reason(),
                          "findings": 0, "ms": 0}
            return "skip"
        if job.phase == 2 and phase1_pending.get(job.run_id, 0) > 0:
            return "defer"  # phase 1 still producing bus signals
        if job.phase == 2 and _hunter_expansion_owed(session, job.run_id):
            return "defer"  # hunter expansion still owes the bus signals
        return "claim"

    def do_claim(job) -> None:
        job.status = "running"
        job.worker = WORKER_ID
        job.started_at = dt.datetime.now(dt.timezone.utc)
        job.attempts = (job.attempts or 0) + 1
        claimed.append(job)

    # Pass 1: seed jobs only, in the order composed above.
    seed_phase_deferred: Dict[str, int] = {}
    for job in candidates:
        if len(claimed) >= limit:
            break
        if not is_seed(job):
            continue
        verdict = gate(job)
        if verdict == "claim":
            do_claim(job)
        elif verdict == "defer":
            seed_phase_deferred[job.run_id] = (
                seed_phase_deferred.get(job.run_id, 0) + 1)
    # Seed jobs still queued per run after pass 1 (claimed and
    # skipped ones no longer count). Any leftover beyond the
    # phase-deferred ones means claimable seed work is still waiting
    # (e.g. the claim limit filled): hunter jobs for that run wait.
    seed_queued_left: Dict[str, int] = {}
    for job in candidates:
        if is_seed(job) and job.status == "queued":
            seed_queued_left[job.run_id] = (
                seed_queued_left.get(job.run_id, 0) + 1)
    # Pass 2: hunter jobs, gated per run on the drained seed queue.
    for job in candidates:
        if len(claimed) >= limit:
            break
        if is_seed(job) or job.status != "queued":
            continue
        rid = job.run_id
        if (seed_queued_left.get(rid, 0)
                > seed_phase_deferred.get(rid, 0)):
            continue  # seed work for this run still has first claim
        if gate(job) == "claim":
            do_claim(job)
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
        # Crypto-class runs: plugins that consult the run context
        # (e.g. the pack's collect_texts) widen their surface when
        # this is set - see app/cryptotarget.py.
        ctx.shared["crypto_target"] = bool(meta.get("crypto_target"))
        # WAF-block accounting baseline: the limiter is shared across
        # runs in this worker, so snapshot per-host WAF stats at run
        # start; _finalize_run turns the delta into findings.
        try:
            from .classifier import domain_from_target as _dft
            _base: Dict[str, Dict] = {}
            for _t in session.query(TargetRow).filter_by(run_id=run_id):
                _h = _dft(_t.type, _t.normalized) or (
                    _t.normalized if _t.type == "ip" else None)
                if _h:
                    _base[_h] = ctx.limiter.waf_stats(_h)
            ctx.shared["_waf_base"] = _base
        except Exception:
            pass
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


def _load_job(job_id: int):
    """Phase 1 of _run_one_job as a sync helper (runs in a thread).

    Returns (run_id, plugin_id, plugin_cls, target), or None when the
    job needs nothing more (missing/not running, or the missing-run
    failure has already been recorded here).

    Speed pass 2026-10-23: this DB work used to run on the event loop
    for every job. On Postgres each query is a network round trip, so
    loading one job stalled all 32 in-flight plugin tasks; multiplied
    by ~800 jobs that was tens of seconds of serialized loop time per
    scan. Same queries, same order - just off the loop.
    """
    session = get_session()
    try:
        job = session.query(PluginJob).filter_by(id=job_id).first()
        if job is None or job.status != "running":
            return None
        run_id = job.run_id
        plugin_id = job.plugin_id
        run = session.query(Run).filter_by(id=run_id).first()
        trow = session.query(TargetRow).filter_by(id=job.target_id).first()
        plugin_cls = discover().get(plugin_id)
        if run is None or trow is None or plugin_cls is None:
            job.status = "failed"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": "failed",
                          "reason": "run, target, or plugin missing",
                          "findings": 0, "ms": 0}
            session.commit()
            return None
        target = Target(raw=trow.raw, type=trow.type,
                        normalized=trow.normalized)
        target.id = trow.id
        if target.type == "poi":
            _attach_poi_meta(session, run_id, target)
        return (run_id, plugin_id, plugin_cls, target)
    finally:
        try:
            session.close()
        except Exception:
            pass


def _mark_job_failed(job_id: int, reason: str) -> None:
    """Record a worker-level failure on a claimed job (sync helper)."""
    session = get_session()
    try:
        job = session.query(PluginJob).filter_by(id=job_id).first()
        if job is not None and job.status == "running":
            job.status = "failed"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": "failed", "reason": reason,
                          "findings": 0, "ms": 0}
            session.commit()
    except Exception:
        pass
    finally:
        try:
            session.close()
        except Exception:
            pass


def _persist_job(job_id: int, run_id: str, target_id, result):
    """Phase 3 of _run_one_job as a sync helper (runs in a thread).

    Returns (row_ids, counts, status_str). Speed pass 2026-10-23:
    findings and the job outcome now land in ONE commit (was two), and
    finding row ids are captured at flush time so the event fan-out
    does not pay a per-finding refresh query after the commit. Same
    rows, same values, same counts query - just fewer round trips and
    none of them on the event loop.
    """
    session = get_session()
    try:
        rows = [_row_to_finding(f, run_id, target_id)
                for f in result.findings]
        for r in rows:
            session.add(r)
        st = (result.status.value if hasattr(result.status, "value")
              else str(result.status))
        job = session.query(PluginJob).filter_by(id=job_id).first()
        if job is not None:
            job.status = "done" if st in ("ok", "skipped") else "failed"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            job.result = {"status": st, "reason": result.reason,
                          "findings": len(rows),
                          "ms": result.duration_ms or 0}
        try:
            session.flush()
            row_ids = [r.id for r in rows]
            session.commit()
        except Exception:
            try:
                session.rollback()
            except Exception:
                pass
            row_ids = [None] * len(rows)
        counts = _job_counts(session, run_id)
        return row_ids, counts, st
    finally:
        try:
            session.close()
        except Exception:
            pass


# Per-run timestamp of the last "progress" event emitted by _run_one_job.
_progress_marks: Dict[str, float] = {}


async def _run_one_job(job_id: int) -> None:
    """Run a single claimed job: plugin -> findings -> DB -> events.

    The DB session is NOT held across plugin execution. Plugins run
    network scans that can take minutes; holding a pooled connection for
    the whole run starved the pool (16 concurrent jobs vs 15 pooled
    connections) and every API request timed out waiting 30s for a
    connection. Load -> close -> run -> persist on a fresh session.
    The load/persist phases run in worker threads (see _load_job /
    _persist_job) so their DB round trips never block the event loop.
    """
    # Phase 1: load everything needed, then release the connection.
    loaded = await asyncio.to_thread(_load_job, job_id)
    if loaded is None:
        return
    run_id, plugin_id, plugin_cls, target = loaded

    # Phase 2: run the plugin with no DB connection held.
    plugin = plugin_cls()
    ctx = _get_run_ctx(run_id)
    clock = _run_clocks.get(run_id, time.monotonic())
    deadline = clock + SCAN_BUDGET_S - SCAN_TAIL_RESERVE_S
    ran_plugin = False
    try:
        if plugin.accepts and target.type not in plugin.accepts:
            result = plugin._skipped(
                f"not applicable to target type '{target.type}'")
            result.duration_ms = 0
        else:
            # _run_plugin emits plugin_start/plugin_done itself; the
            # duplicates that used to be emitted here as well doubled
            # the run_events write volume for every job (measured
            # 2026-10-23: 388 starts + 389 dones for 195 plugins).
            ran_plugin = True
            result = await _run_plugin(plugin, target, ctx,
                                       deadline=deadline)
    except Exception as e:
        await asyncio.to_thread(
            _mark_job_failed, job_id,
            f"worker error: {type(e).__name__}: {str(e)[:150]}")
        return

    # Phase 3: persist findings + job outcome on a fresh session
    # (in a thread), then fan out the per-finding events.
    row_ids, counts, st = await asyncio.to_thread(
        _persist_job, job_id, run_id, target.id, result)
    for f, rid in zip(result.findings, row_ids):
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
                    {"fid": rid, "plugin": f.plugin_id,
                     "category": f.category, "key": f.key,
                     "value": f.value, "source": f.source,
                     "source_url": f.source_url, "evidence": f.evidence,
                     "confidence": f.confidence, "passive": f.passive,
                     "target": target.normalized})
    if not ran_plugin:
        # Type-mismatch skip: _run_plugin never ran, so this is the only
        # plugin_done the job produces. (When _run_plugin did run, it
        # already emitted plugin_done - emitting it here too was the
        # duplicate removed 2026-10-23.)
        await _emit(run_id, "plugin_done",
                    {"plugin": plugin.id, "status": st,
                     "reason": result.reason,
                     "findings": len(result.findings),
                     "ms": result.duration_ms or 0})
    # Progress events: the UI polls run state from the DB, so a progress
    # row per job (~800/run) is pure write volume. Throttle to ~4/s per
    # run, but always emit the settling one (done == total).
    now_m = time.monotonic()
    if (counts["done"] >= counts["total"]
            or now_m - _progress_marks.get(run_id, 0.0) >= 0.25):
        _progress_marks[run_id] = now_m
        await _emit(run_id, "progress",
                    {"done": counts["done"], "total": counts["total"],
                     "plugin": plugin.id, "target": target.normalized})


# ---------------------------------------------------------------------------
# Hunter expansion: mutual exclusion + incremental (mid-run) passes
#
# hunter_expand mutates shared DB state (known set, hunt audit, the job
# queue). Two expansion passes for the same run must never overlap: the
# finalize pass (authoritative, at settle) and the incremental passes
# below. The guard is a per-run threading.Lock (the production worker
# is one process) plus, on Postgres, a session-level advisory lock on a
# dedicated connection (covers a second worker process). Acquire is
# non-blocking by default: a skipped incremental pass costs nothing,
# the finalize pass still expands everything when jobs settle.
# ---------------------------------------------------------------------------
_hunter_guards: Dict[str, threading.Lock] = {}
_hunter_guards_mu = threading.Lock()
_hunter_marks: Dict[str, int] = {}  # run_id -> findings at last pass
# Runs the incremental hunter sweep has evaluated at least once. The
# claim gate's expansion-owed check applies only to these, so bare
# claim pumps (tests, tooling) that never run the sweep keep the
# original phase-gate behavior.
_hunter_swept: set = set()
_last_hunter_sweep = 0.0
# 15s -> 3s on 2026-10-23 (speed pass round 2): at 15s the sweep
# drip-fed hunter targets to the queue and the worker sat half idle
# between passes (mean slot use 17.5 of 64); at 3s the same fixture
# run went 104.1s -> 75.1s with identical findings. The pass itself
# stays cheap at this cadence: one findings COUNT per running run,
# and expansion still only runs when >= HUNTER_MIN_NEW_FINDINGS
# arrived since the last pass.
HUNTER_SWEEP_INTERVAL_S = float(_os.environ.get("RECON_HUNTER_SWEEP_S", "3"))
HUNTER_MIN_NEW_FINDINGS = int(_os.environ.get("RECON_HUNTER_MIN_NEW", "8"))
_HUNTER_ADVISORY_NS = 727272


def _hunter_guard_lock(run_id: str) -> threading.Lock:
    with _hunter_guards_mu:
        return _hunter_guards.setdefault(run_id, threading.Lock())


class _HunterGuard:
    """Per-run hunter-expansion guard (see section note above)."""

    def __init__(self, run_id: str, wait_s: float = 0.0):
        self.run_id = run_id
        self.wait_s = max(wait_s, 0.0)
        self._lock = _hunter_guard_lock(run_id)
        self._locked = False
        self._conn = None
        self.acquired = False

    def _try_advisory(self) -> bool:
        """One advisory-lock attempt. True when held (or not applicable:
        SQLite / DB hiccup - the in-process lock is the fallback)."""
        if IS_SQLITE:
            return True
        try:
            from . import models as _models
            conn = _models.engine.connect()
            key = zlib.crc32(self.run_id.encode()) & 0x7FFFFFFF
            got = conn.exec_driver_sql(
                "SELECT pg_try_advisory_lock(%s, %s)",
                (_HUNTER_ADVISORY_NS, key)).scalar()
            if not got:
                conn.close()
                return False
            self._conn = conn
            return True
        except Exception:
            return True

    def __enter__(self):
        deadline = time.monotonic() + self.wait_s
        while True:
            if self._lock.acquire(blocking=False):
                self._locked = True
                if self._try_advisory():
                    self.acquired = True
                    return self
                self._lock.release()
                self._locked = False
            if time.monotonic() >= deadline:
                return self
            time.sleep(0.2)

    def __exit__(self, *exc):
        try:
            if self._conn is not None:
                key = zlib.crc32(self.run_id.encode()) & 0x7FFFFFFF
                self._conn.exec_driver_sql(
                    "SELECT pg_advisory_unlock(%s, %s)",
                    (_HUNTER_ADVISORY_NS, key))
                self._conn.close()
                self._conn = None
        except Exception:
            pass
        if self._locked:
            try:
                self._lock.release()
            except RuntimeError:
                pass
            self._locked = False
        return False


def _incremental_hunter_pass_sync(run_id: str) -> int:
    """One mid-run hunter expansion pass. Returns jobs enqueued.

    Runs the same hunter_expand the finalize path uses, over the
    findings persisted so far, with the depth counter FROZEN
    (advance_depth=False): asset generations stay owned by the
    settle/finalize passes, while the jobs this pass enqueues join the
    live queue immediately and overlap the main scan instead of
    starting only after every seed job settles. The accum is persisted
    back into the run summary so the finalize pass continues where
    this one left off.
    """
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if run is None or run.status != "running":
            return 0
        if _pending_count(session, run_id) == 0:
            return 0  # finalize owns the run now
        from .hunters.engine import (ENABLED as _HUNTERS_ON,
                                      hunter_expand, new_accum)
        if not _HUNTERS_ON:
            return 0
        accum = ((run.summary or {}).get("hunters_accum")) or new_accum()
        with _HunterGuard(run_id) as guard:
            if not guard.acquired:
                return 0
            n = hunter_expand(session, run, accum, advance_depth=False)
            if n > 0:
                s = dict(run.summary or {})
                s["hunters_accum"] = accum
                s["hunters_partial"] = {
                    "extra_assets": accum.get("assets_new", 0),
                    "extra_jobs": accum.get("jobs", 0),
                    "depth": accum.get("depth", 0)}
                run.summary = s
                session.commit()
            return n
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
        return 0
    finally:
        try:
            session.close()
        except Exception:
            pass


async def _sweep_hunter_expand() -> None:
    """Feed the hunters mid-scan: for every running run whose findings
    grew since the last pass, run an incremental expansion so hunter
    jobs overlap the main queue. Throttled, opportunistic."""
    global _last_hunter_sweep
    now = time.monotonic()
    if now - _last_hunter_sweep < HUNTER_SWEEP_INTERVAL_S:
        return
    _last_hunter_sweep = now
    try:
        from .hunters.engine import ENABLED as _HUNTERS_ON
        if not _HUNTERS_ON:
            return
    except Exception:
        return
    session = get_session()
    counts: Dict[str, int] = {}
    try:
        run_ids = [r[0] for r in session.query(Run.id)
                   .filter(Run.status == "running").limit(5).all()]
        for rid in run_ids:
            counts[rid] = (session.query(FindingRow)
                           .filter_by(run_id=rid).count())
    except Exception:
        return
    finally:
        try:
            session.close()
        except Exception:
            pass
    _hunter_swept.update(counts.keys())
    for rid, n_findings in counts.items():
        if (n_findings - _hunter_marks.get(rid, 0)
                >= HUNTER_MIN_NEW_FINDINGS):
            await asyncio.to_thread(_incremental_hunter_pass_sync, rid)
            _hunter_marks[rid] = n_findings
    for rid in list(_hunter_marks):
        if rid not in counts:
            _hunter_marks.pop(rid, None)
    for rid in list(_hunter_swept):
        if rid not in counts:
            _hunter_swept.discard(rid)


def _record_waf_blocks(session, run_id: str, ctx) -> int:
    """Turn WAF blocks observed during the run into findings.

    Every plugin fetch passes through the shared rate limiter, which
    classifies responses with app.waf and counts blocks per host - but a
    plugin whose fetch gets blocked just degrades quietly, so a heavily
    WAF-filtered scan used to look like "no findings". The delta against
    the run-start baseline (see _get_run_ctx) is what THIS run's traffic
    hit. One finding per affected target, skipped when the waf plugin
    already reported blocking for it. Returns findings added.
    """
    if ctx is None:
        return 0
    base = getattr(ctx, "shared", {}).get("_waf_base") or {}
    if not base:
        return 0
    from .classifier import domain_from_target
    existing = {
        f.target_id for f in
        session.query(FindingRow).filter_by(run_id=run_id)
        .filter(FindingRow.key.in_(("waf_blocking", "waf_blocked_requests")))
        .all()}
    added = 0
    for t in session.query(TargetRow).filter_by(run_id=run_id).all():
        host = domain_from_target(t.type, t.normalized) or (
            t.normalized if t.type == "ip" else None)
        if not host or host not in base or t.id in existing:
            continue
        cur = ctx.limiter.waf_stats(host)
        blocked = int(cur.get("blocked", 0)) - int(base[host].get("blocked", 0))
        if blocked <= 0:
            continue
        vendor = cur.get("vendor") or base[host].get("vendor")
        succeeded = int(cur.get("succeeded", 0)) - int(
            base[host].get("succeeded", 0))
        session.add(FindingRow(
            run_id=run_id, target_id=t.id, plugin_id="waf",
            category="web", key="waf_blocked_requests",
            value=(f"WAF blocked {blocked} scan request(s) to {host}"
                   + (f" ({vendor})" if vendor else "")),
            source="rate limiter WAF accounting", source_url=None,
            confidence=85, passive=True,
            first_seen=dt.datetime.now(dt.timezone.utc),
            evidence={"severity": "medium", "vendor": vendor,
                      "blocked": blocked, "succeeded": succeeded,
                      "note": "Per-host delta on the shared rate limiter "
                              "during this run; the waf plugin's own "
                              "fingerprint findings carry the vendor proof."},
            raw={}, bounty_value="low"))
        added += 1
    if added:
        session.flush()
    return added


def _correlate_run(session, run_id: str):
    """Cross-finding correlation: synthesize attack paths + exposure score.

    Runs once at finalize, after every plugin and hunter pass has settled,
    over the whole finding set. Produces composite "attack path" findings
    no single plugin could (persisted as plugin_id="correlation") plus a
    run-level exposure score for the summary. Detection/analysis only.

    Idempotent across re-finalizes: deletes prior correlation rows before
    re-inserting, and the engine itself ignores correlation rows when
    reading, so a hunter-triggered reopen never double-counts or feeds its
    own output back in. Best-effort: any failure returns an empty block and
    never breaks finalize.
    """
    try:
        from .correlate import correlate
    except Exception:
        return [], {}
    try:
        # Drop any correlation rows from a previous finalize of this run so
        # the pass is idempotent (hunter expansion can reopen a run).
        (session.query(FindingRow)
         .filter_by(run_id=run_id, plugin_id="correlation").delete())
        rows = session.query(FindingRow).filter_by(run_id=run_id).all()
        as_dicts = [{
            "id": r.id, "plugin": r.plugin_id, "category": r.category,
            "key": r.key, "value": r.value, "source": r.source,
            "source_url": r.source_url, "confidence": r.confidence,
            "evidence": r.evidence, "bounty_value": r.bounty_value,
        } for r in rows]
        # Attach correlation findings to the run's first target (they are
        # run-level, but FindingRow requires a target_id). Its normalized
        # value is also the host hint for verification commands.
        first_target = session.query(TargetRow).filter_by(
            run_id=run_id).first()
        tid = first_target.id if first_target else run_id
        host_hint = first_target.normalized if first_target else None
        paths, exposure = correlate(as_dicts, host_hint=host_hint)
        now = dt.datetime.now(dt.timezone.utc)
        for p in paths:
            session.add(FindingRow(
                run_id=run_id, target_id=tid, plugin_id="correlation",
                category=p["category"], key=p["key"], value=p["value"],
                source=p["source"], source_url=p.get("source_url"),
                confidence=p["confidence"], evidence=p["evidence"],
                passive=p.get("passive", True), first_seen=now,
                raw=None, bounty_value=p["bounty_value"]))
        if paths:
            session.flush()
        # Compact summary block (full detail lives on the findings).
        compact = [{
            "name": p["evidence"]["path_name"],
            "path_id": p["evidence"]["path_id"],
            "severity": p["evidence"]["severity"],
            "exploitability": p["evidence"]["exploitability"],
            "component_count": p["evidence"]["component_count"],
            "tags": p["evidence"].get("tags", []),
        } for p in paths]
        return compact, exposure
    except Exception:
        session.rollback()
        return [], {}


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
        # WAF blocks seen by ANY plugin become findings (not silent zeros).
        try:
            _record_waf_blocks(session, run_id, _run_ctxs.get(run_id))
        except Exception:
            pass
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
        # Hunter pivot pass (2026-10-20): when a run's jobs settle, the
        # 20 hunters expand the known set from its findings and queue
        # verification jobs on the new frontier. If jobs were queued,
        # the run reopens and finalizes again when they settle; the
        # depth/task budgets in hunters/engine.py bound the loop.
        hunter_section = None
        try:
            from .hunters.engine import (ENABLED as _HUNTERS_ON,
                                          finalize_hunt, hunter_expand,
                                          new_accum)
            if _HUNTERS_ON:
                # Serialize against incremental mid-run passes. If a
                # pass is in flight (or it enqueued jobs while we were
                # finalizing), back off: the sweep retries finalize once
                # the queue settles again.
                with _HunterGuard(run_id, wait_s=5.0) as _guard:
                    if not _guard.acquired or \
                            _pending_count(session, run_id) > 0:
                        (session.query(Run)
                         .filter_by(id=run_id, status="finalizing")
                         .update({"status": "running"}))
                        session.commit()
                        return False
                    _hrun = session.query(Run).filter_by(id=run_id).first()
                    _accum = ((_hrun.summary or {}).get("hunters_accum")
                              if _hrun else None) or new_accum()
                    if hunter_expand(session, _hrun, _accum) > 0:
                        _s = dict(_hrun.summary or {})
                        _s["hunters_accum"] = _accum
                        _s["hunters_partial"] = {
                            "extra_assets": _accum.get("assets_new", 0),
                            "extra_jobs": _accum.get("jobs", 0),
                            "depth": _accum.get("depth", 0)}
                        _hrun.summary = _s
                        _hrun.status = "running"
                        session.commit()
                        return True
                    hunter_section = finalize_hunt(session, _hrun, _accum)
        except Exception:
            hunter_section = None
        # Cross-finding correlation pass (attack paths + exposure score).
        # Runs here, once, after the hunter loop has fully settled (the
        # reopen paths above all return before this point), over the whole
        # finding set. Recompute `total` so the finding count includes the
        # synthesized paths.
        attack_paths, exposure = _correlate_run(session, run_id)
        if attack_paths:
            total = session.query(FindingRow).filter_by(run_id=run_id).count()
        run = session.query(Run).filter_by(id=run_id).first()
        summary: Dict = {"findings": total, "nodes": n_nodes,
                         "edges": n_edges, "targets": n_targets,
                         "plugins": plugin_statuses}
        if exposure:
            summary["exposure"] = exposure
        if attack_paths:
            summary["attack_paths"] = attack_paths
        # Bank/ATM mode: keep the mode's own record (input, locations,
        # resolved domains) in the final summary - it is the run's
        # headline, set at enqueue time and preserved here like
        # hunters_accum above.
        try:
            _prev = session.query(Run).filter_by(id=run_id).first()
            if _prev and (_prev.summary or {}).get("bankatm"):
                summary["bankatm"] = _prev.summary["bankatm"]
            # Service-created runs (Error Inbox black team): the service
            # read endpoint only serves runs tagged service=true, so the
            # tag must survive finalize — otherwise a finished service
            # run 404s on its own read endpoint (canary-caught: the run
            # finished done with 1,226 findings, then its status read
            # 404d because the fresh summary dropped the tag).
            if _prev and (_prev.summary or {}).get("service"):
                summary["service"] = True
                if (_prev.summary or {}).get("service_host"):
                    summary["service_host"] = _prev.summary["service_host"]
        except Exception:
            pass
        if hunter_section:
            summary["hunters"] = hunter_section
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
        _hunter_marks.pop(run_id, None)
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


async def _sweep_finalize(force: bool = False) -> None:
    """Finalize any running runs whose jobs are all settled (covers the
    crash-between-last-job-and-finalize window). Also heals runs left
    "running" with zero plugin jobs - e.g. a mid-scan redeploy that
    orphaned the run (seen 2026-10-20 when a direct push to master
    redeployed both Render services mid-scan): they are finalized as
    interrupted so they stop sitting "running" forever. Throttled to ~5s
    (1s when `force`d by a fresh job completion, so the run whose last
    job just settled finalizes promptly instead of waiting out the
    throttle - measured 2026-10-23: up to 5s of dead time at the tail
    of every scan).

    Speed pass 2026-10-23: candidates are the runs still in "running"
    status, not every run that ever had a job. _finalize_run only ever
    claims "running" runs (atomic status update), so finished runs
    were pure waste: a distinct-scan over the whole plugin_jobs table
    plus a pending-count per historical run, every 5s, forever - the
    cost grew with scan history on the production DB.
    """
    global _last_sweep
    now = time.monotonic()
    if now - _last_sweep < (1.0 if force else 5.0):
        return
    _last_sweep = now
    session = get_session()
    try:
        run_ids = [r[0] for r in
                   session.query(Run.id)
                   .filter(Run.status == "running").all()]
        for rid in run_ids:
            if _pending_count(session, rid) == 0:
                # A run still carrying a pending_enqueue intent has not
                # finished enqueueing yet (intent is cleared by
                # execute_run only after jobs are queued). Finalizing
                # it here would end the scan with 0 findings and orphan
                # the jobs that land a moment later — canary-caught on
                # a service scan: finalized 3s after creation, then all
                # 600 jobs skipped as "run no longer active".
                _row = session.query(Run).filter_by(id=rid).first()
                if _row and (_row.summary or {}).get(
                        "pending_enqueue") is not None:
                    continue
                await _finalize_run(rid)
        # Orphaned runs: no jobs at all, still "running", older than 10 min.
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)
        orphans = (session.query(Run)
                   .filter(Run.status == "running",
                           Run.created_at < cutoff).all())
        for run in orphans:
            n_jobs = (session.query(PluginJob)
                      .filter_by(run_id=run.id).count())
            if n_jobs == 0:
                log.warning("finalizing orphaned run %s (no jobs, "
                            "interrupted mid-scan)", run.id)
                run.status = "done"
                run.finished_at = dt.datetime.now(dt.timezone.utc)
                summary = run.summary or {}
                summary["interrupted"] = True
                summary["note"] = ("Run was interrupted mid-scan "
                                   "(service redeploy); findings found so "
                                   "far are preserved.")
                run.summary = summary
                session.commit()
    finally:
        try:
            session.close()
        except Exception:
            pass


def _claim_ids(limit: int) -> List[int]:
    """Claim up to `limit` queued jobs and return their ids (sync
    helper). The worker loop runs this via asyncio.to_thread: claiming
    used to execute on the event loop, and on Postgres every claim pass
    is several network round trips during which no in-flight plugin
    task progressed (2026-10-23 speed pass)."""
    session = get_session()
    try:
        claimed = _claim_jobs(session, limit)
        # capture ids while the session is still open (commit expires attrs)
        return [j.id for j in claimed]
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
    """Claim queued plugin jobs from Postgres and run them, forever.

    Continuous slot-filling (changed 2026-10-20): the old loop claimed a
    batch of 16 jobs and awaited ALL of them before claiming the next
    batch, so one slow plugin stalled 15 finished slots and the batch
    barrier - combined with the old 80s scan budget - meant which plugins
    got to run at all varied with timing, so findings differed every run.
    Now a slot is refilled the moment its job finishes: up to
    MAX_CONCURRENCY jobs run at once, each completion frees its slot for
    the next queued job (priority order), and every queued job runs.
    """
    global _worker_http, _worker_limiter
    # Roomier default executor (2026-10-23): several plugins park
    # blocking calls in the loop's default executor (dns AXFR, tls cert
    # grabs, fastmode socket connects). The default pool is
    # min(32, cpu+4) threads - on the small worker instance that
    # saturated under 32 concurrent jobs, so blocking calls queued
    # behind each other and plugins timed out waiting for a thread,
    # not for the network. 96 threads, env-tunable.
    try:
        import concurrent.futures as _cf
        asyncio.get_running_loop().set_default_executor(_cf.ThreadPoolExecutor(
            max_workers=int(os.environ.get("RECON_EXECUTOR_WORKERS", "96")),
            thread_name_prefix="recon-io"))
    except Exception:
        pass
    reset_stale_queue_jobs()
    async with net.async_client(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.DEFAULT_TIMEOUT,
            follow_redirects=True) as http:
        _worker_http = http
        _worker_limiter = RateLimiter(default_rps=config.DEFAULT_RPS)
        in_flight: set = set()
        # task -> (job_id, monotonic start) for the watchdog below.
        task_jobs: Dict[Any, Any] = {}
        last_stale_sweep = 0.0
        # Event-driven slot refill (2026-10-23 speed pass): job
        # completions set `wake`, so a freed slot is refilled on the
        # next loop turn instead of up to 0.5s later when the fixed
        # sleep expires. The sleep stays as an upper bound (watchdog /
        # sweep cadence), it just stops being the quantization floor
        # for every completion. last_completion also drives forced
        # finalize sweeps (see _sweep_finalize).
        wake = asyncio.Event()
        last_completion = [0.0]
        swept_mark = [0.0]

        def _swallow(task: "asyncio.Task") -> None:
            # _run_one_job handles its own errors; this only keeps a
            # stray task exception from logging "never retrieved".
            last_completion[0] = time.monotonic()
            wake.set()
            if not task.cancelled():
                task.exception()

        while True:
            try:
                wake.clear()
                in_flight = {t for t in in_flight if not t.done()}
                task_jobs = {t: v for t, v in task_jobs.items()
                             if t in in_flight}
                # Watchdog: abandon + cancel tasks alive far past the
                # per-plugin cap (see JOB_WATCHDOG_S). Cancelling a
                # task stuck in synchronous code has no effect until
                # it awaits again - the job row is already requeued,
                # so the scan proceeds on the freed slot regardless.
                now_m = time.monotonic()
                for task, (job_id, started) in list(task_jobs.items()):
                    if now_m - started > JOB_WATCHDOG_S:
                        log.warning(
                            "watchdog: abandoning job %s after %.0fs",
                            job_id, now_m - started)
                        _abandon_job(job_id)
                        task.cancel()
                        task_jobs.pop(task, None)
                        in_flight.discard(task)
                # Periodic stale-claim recovery (boot used to be the
                # only chance): frees jobs orphaned by dead workers or
                # by tasks cancelled while their rows were claimed.
                if now_m - last_stale_sweep > STALE_SWEEP_INTERVAL_S:
                    last_stale_sweep = now_m
                    await asyncio.to_thread(reset_stale_queue_jobs)
                free = (max(getattr(config, "MAX_CONCURRENCY", 5), 1)
                        - len(in_flight))
                claimed_ids = []
                if free > 0:
                    claimed_ids = await asyncio.to_thread(
                        _claim_ids, free)
                for job_id in claimed_ids:
                    task = asyncio.create_task(_run_one_job(job_id))
                    task.add_done_callback(_swallow)
                    in_flight.add(task)
                    task_jobs[task] = (job_id, time.monotonic())
                await _sweep_finalize(
                    force=last_completion[0] > swept_mark[0])
                swept_mark[0] = last_completion[0]
                await _sweep_hunter_expand()
                # Wait for the next completion (event-driven refill);
                # the timeout preserves the old 0.5s/2.0s cadence as an
                # upper bound for watchdog and sweep work. `wake` is
                # cleared at the top of the loop, so a completion that
                # lands during claiming still shortens this wait.
                try:
                    await asyncio.wait_for(
                        wake.wait(),
                        timeout=(0.5 if (claimed_ids or in_flight)
                                 else 2.0))
                except (asyncio.TimeoutError, TimeoutError):
                    pass
            except Exception:
                await asyncio.sleep(2.0)


def _calibrated_estimates(session, days: int = 7) -> Dict[str, int]:
    """Median observed plugin durations, blended with hardcoded estimates.

    Queries recent finished jobs (last `days`) and takes the per-plugin
    median of result.ms. Plugins with fewer than 3 real observations keep
    the hardcoded PLUGIN_TIME_ESTIMATES value. Medians are clamped to
    [2, 600]s so one pathological run can't permanently distort dispatch
    order. Only jobs that actually executed count (ms > 0 - skips and
    instant failures are ignored).

    This is what makes fastest-first-within-tier *accurate*: the guesses
    in PLUGIN_TIME_ESTIMATES get corrected by reality every scan.
    """
    from statistics import median
    try:
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        rows = (session.query(PluginJob.plugin_id, PluginJob.result)
                .filter(PluginJob.created_at >= cutoff,
                        PluginJob.status.in_(("done", "failed")))
                .order_by(PluginJob.id.desc()).limit(20000).all())
    except Exception:
        return {}
    samples: Dict[str, List[int]] = {}
    for pid, result in rows:
        try:
            ms = int((result or {}).get("ms") or 0)
        except (TypeError, ValueError):
            continue
        if ms > 0:
            samples.setdefault(pid, []).append(ms)
    out: Dict[str, int] = {}
    for pid, vals in samples.items():
        if len(vals) < 3:
            continue
        secs = max(2, min(600, int(median(vals) / 1000)))
        out[pid] = secs
    return out


def _enqueue_jobs(session, run_id: str, plugins, trobj,
                  bounty: bool = False,
                  estimates: Optional[Dict[str, int]] = None,
                  boost_ids: Optional[set] = None) -> int:
    """Insert one PluginJob per (plugin x target) pair. Returns job count.

    estimates overrides the hardcoded PLUGIN_TIME_ESTIMATES per plugin
    (see _calibrated_estimates) so dispatch order reflects observed
    durations. boost_ids (crypto-class runs): those plugins enqueue
    at HIGH priority regardless of their static tier - the exposed-
    key hunters lead the scan (see app/cryptotarget.py).
    """
    estimates = estimates or {}
    boost = boost_ids or set()
    jobs = [PluginJob(run_id=run_id, target_id=t.id, plugin_id=p.id,
                      phase=getattr(p, "phase", 1),
                      priority=(HIGH_TIER if p.id in boost
                                else priority_for(p.id, bounty=bounty)),
                      estimate_s=estimates.get(
                          p.id, PLUGIN_TIME_ESTIMATES.get(
                              p.id, DEFAULT_PLUGIN_ESTIMATE_S)),
                      status="queued")
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
                "seed_target_ids": [t.id for t in trobj],
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


async def _enqueue_bankatm_run(run_id: str, targets_raw: str, mode: str,
                               module_overrides: Optional[Dict[str, str]],
                               excluded_plugin_ids: Optional[List[str]] = None) -> None:
    """Bank/ATM mode: ONE input, no options (see app/bankatm.py).

    Domain input -> the financial set runs on that domain. Location
    input -> banks + ATMs near the place (OpenStreetMap), operators
    resolved to domains, the financial set runs on each unique resolved
    domain (capped); unresolved locations stay as geo findings.
    """
    import datetime as _dt
    from . import bankatm as _ba
    from . import bankdomains as _bd
    from . import geo as _geo
    session = get_session()
    try:
        parsed = _ba.parse_bankatm_input(targets_raw)
        raw_first = parsed.get("raw") or ""
        await _emit(run_id, "run_start",
                    {"run_id": run_id, "targets": [raw_first], "mode": mode,
                     "source_type": "bankatm", "plugins": [],
                     "plugin_count": 0, "target_count": 0,
                     "note": "bank/atm mode: resolving input..."})
        if not raw_first:
            run = session.query(Run).filter_by(id=run_id).first()
            if run:
                run.status = "failed"
                run.finished_at = _dt.datetime.now(_dt.timezone.utc)
                run.summary = {"error": "bank/atm mode: empty input",
                               "findings": 0}
                session.commit()
            await _emit(run_id, "run_done",
                        {"run_id": run_id, "findings": 0,
                         "error": "empty input"})
            return
        overrides = dict(module_overrides or {})
        overrides["bank"] = "authorized"
        overrides["atm"] = "authorized"
        discover()
        set_ids = _ba.financial_plugin_ids(
            [p.id for p in all_plugins()], excluded_plugin_ids)
        by_id = {p.id: p for p in all_plugins()}
        plugins = [by_id[i] for i in set_ids if i in by_id]

        if parsed["kind"] == "domain":
            t = Target(raw=raw_first, type=parsed["target_type"],
                       normalized=parsed["normalized"])
            session.add(TargetRow(id=t.id, run_id=run_id, raw=t.raw,
                                  type=t.type, normalized=t.normalized))
            session.commit()
            from .classifier import domain_from_target as _dft
            dom = _dft(parsed["target_type"], parsed["normalized"]) \
                or parsed["normalized"]
            info = {"input_kind": "domain", "input": raw_first,
                    "domain": dom, "locations": [],
                    "resolved_domains": [dom]}
            meta = {"mode": mode, "plugin_ids": set_ids,
                    "module_overrides": overrides,
                    "source_type": "bankatm",
                    "seed_target_ids": [t.id], "bankatm": info}
            run = session.query(Run).filter_by(id=run_id).first()
            if run:
                run.summary = {**(run.summary or {}),
                               "queue_meta": meta, "bankatm": info}
                session.commit()
            n_jobs = _enqueue_jobs(session, run_id, plugins, [t])
            await _emit(run_id, "run_start",
                        {"run_id": run_id, "targets": [t.raw],
                         "mode": mode, "source_type": "bankatm",
                         "plugins": set_ids,
                         "plugin_count": len(plugins), "target_count": 1,
                         "queued": True,
                         "note": (f"bank/atm mode: financial set "
                                  f"({len(plugins)} plugins) on {dom}; "
                                  f"{n_jobs} jobs queued")})
            return

        # -- location input ------------------------------------------
        location = parsed["location"]
        coords = await _geo.geocode(location)
        if not coords:
            run = session.query(Run).filter_by(id=run_id).first()
            if run:
                run.status = "failed"
                run.finished_at = _dt.datetime.now(_dt.timezone.utc)
                run.summary = {"error": f"could not geocode location: "
                                        f"{location}", "findings": 0}
                session.commit()
            await _emit(run_id, "run_done",
                        {"run_id": run_id, "findings": 0,
                         "error": f"could not geocode: {location}"})
            return
        pois = await _geo.find_bank_atm_pois(
            coords["lat"], coords["lon"], _ba.POI_RADIUS_M, _ba.MAX_POIS)
        await _emit(run_id, "progress",
                    {"done": 0, "total": max(len(pois), 1),
                     "note": f"found {len(pois)} banks/ATMs near "
                             f"{coords['display_name']}"})
        # Resolve each operator to a domain; cap unique assessed domains.
        for poi in pois:
            poi["resolved_domain"] = _bd.resolve_domain(
                name=poi.get("name", ""), operator=poi.get("operator", ""),
                brand=poi.get("brand", ""), website=poi.get("website", ""))
        unique_domains: List[str] = []
        for poi in pois:
            d = poi.get("resolved_domain")
            if d and d not in unique_domains:
                unique_domains.append(d)
        assessed = unique_domains[:_ba.MAX_DOMAINS]
        assessed_set = set(assessed)

        loc_entries = []
        for poi in pois:
            label = f"{poi['name']} ({poi['lat']:.5f},{poi['lon']:.5f})"
            t = Target(raw=label, type="poi",
                       normalized=f"{poi['lat']},{poi['lon']}")
            session.add(TargetRow(id=t.id, run_id=run_id, raw=label,
                                  type="poi",
                                  normalized=f"{poi['lat']},{poi['lon']}"))
            d = poi.get("resolved_domain")
            session.add(FindingRow(
                run_id=run_id, target_id=t.id, plugin_id="geo",
                category="location", key="poi",
                value=f"{poi['name']} - {poi.get('address', '')}",
                source="OpenStreetMap", source_url="",
                evidence={"severity": "info", "lat": poi["lat"],
                          "lon": poi["lon"], "name": poi["name"],
                          "address": poi.get("address", ""),
                          "operator": poi.get("operator", ""),
                          "brand": poi.get("brand", ""),
                          "website": poi.get("website", ""),
                          "phone": poi.get("phone", ""),
                          "poi_type": poi.get("poi_type", ""),
                          "resolved_domain": d,
                          "domain_assessed": bool(d and d in assessed_set),
                          "note": ("operator domain resolved; the "
                                   "financial set assesses it in this "
                                   "run" if d and d in assessed_set else
                                   "no public domain resolved - location "
                                   "listed for information only" if not d
                                   else "domain resolved but over the "
                                        "per-run cap; listed only")},
                confidence=100, passive=True))
            loc_entries.append({
                "name": poi["name"], "poi_type": poi.get("poi_type", ""),
                "operator": poi.get("operator", ""),
                "address": poi.get("address", ""),
                "resolved_domain": d,
                "domain_assessed": bool(d and d in assessed_set)})
        dtrobj = []
        for d in assessed:
            t = Target(raw=d, type="domain", normalized=d)
            dtrobj.append(t)
            session.add(TargetRow(id=t.id, run_id=run_id, raw=d,
                                  type="domain", normalized=d))
        session.commit()
        info = {"input_kind": "location", "input": raw_first,
                "location": coords["display_name"],
                "locations": loc_entries,
                "resolved_domains": assessed,
                "pois": len(pois),
                "caps": {"max_pois": _ba.MAX_POIS,
                         "max_domains": _ba.MAX_DOMAINS,
                         "radius_m": _ba.POI_RADIUS_M}}
        meta = {"mode": mode, "plugin_ids": set_ids,
                "module_overrides": overrides,
                "source_type": "bankatm",
                "seed_target_ids": [t.id for t in dtrobj],
                "location": coords["display_name"], "bankatm": info}
        run = session.query(Run).filter_by(id=run_id).first()
        if run:
            run.summary = {**(run.summary or {}), "queue_meta": meta,
                           "bankatm": info}
            session.commit()
        if not dtrobj:
            # Locations found but no domain to assess: the geo findings
            # ARE the result - close the run now.
            if run:
                run.status = "done"
                run.finished_at = _dt.datetime.now(_dt.timezone.utc)
                run.summary = {"findings": len(pois), "bankatm": info,
                               "note": ("no banks or ATMs found near the "
                                        "location" if not pois else
                                        "locations listed; no operator "
                                        "domain resolved to assess")}
                session.commit()
            await _emit(run_id, "run_done",
                        {"run_id": run_id, "findings": len(pois),
                         "note": f"{len(pois)} locations near "
                                 f"{coords['display_name']}; no operator "
                                 f"domain resolved"})
            return
        n_jobs = _enqueue_jobs(session, run_id, plugins, dtrobj)
        await _emit(run_id, "run_start",
                    {"run_id": run_id,
                     "targets": [t.raw for t in dtrobj],
                     "mode": mode, "source_type": "bankatm",
                     "plugins": set_ids, "plugin_count": len(plugins),
                     "target_count": len(dtrobj),
                     "location": coords["display_name"], "queued": True,
                     "note": (f"bank/atm mode: {len(pois)} locations near "
                              f"{coords['display_name']}; financial set "
                              f"on {len(dtrobj)} operator domains "
                              f"({', '.join(assessed)}); {n_jobs} jobs "
                              f"queued")})
    finally:
        try:
            session.close()
        except Exception:
            pass


def _select_run_plugins(plugin_ids, excluded_plugin_ids, source_type):
    """Pick the plugin instances for a website run, never returning empty
    when the registry has applicable plugins.

    Returns (plugins, selection_note). A selection that matches NO
    registered plugin (stale/mismatched ids from the client, a renamed or
    removed plugin) used to enqueue zero jobs, so the run finalized
    instantly with 0 findings and no explanation - the "it's not running
    anything" symptom. This falls back to the full applicable default set
    (minus this source type's silent plugins and any plan exclusions) and
    returns a human note saying why, so a scan always does something.
    Only a genuinely empty registry yields an empty list (the caller then
    fails the run loudly instead of returning a silent empty scan).
    """
    def _applicable(pool):
        out = pool
        if excluded_plugin_ids:
            ex = set(excluded_plugin_ids)
            out = [p for p in out if p.id not in ex]
        if source_type == "website":
            out = [p for p in out if p.id not in ("atm", "bank")]
        return out

    pool = all_plugins()
    # Plan gating (app/billing.py) via excluded_plugin_ids only narrows the
    # default set; an explicit plugin_ids selection is "selected means run".
    if plugin_ids:
        selected = [p for p in pool if p.id in plugin_ids]
        plugins = _applicable(selected)
        if plugins:
            return plugins, ""
        # selection matched nothing applicable -> fall back, say why
        fallback = _applicable(pool)
        if fallback:
            return (fallback,
                    "selected plugins matched nothing in the registry; "
                    "ran the full default set instead")
        return [], ""
    return _applicable(pool), ""


async def execute_run(run_id: str, targets_raw: str, mode: str,
                      plugin_ids: Optional[List[str]] = None,
                      module_overrides: Optional[Dict[str, str]] = None,
                      keys: Optional[Dict[str, str]] = None,
                      source_type: str = "website",
                      bounty: bool = False,
                      excluded_plugin_ids: Optional[List[str]] = None,
                      max_depth: Optional[int] = None):
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
        if max_depth is None:
            # Preset depth travels in the durable enqueue intent (the
            # same commit as the Run row), so every launch path -
            # direct, service, boot recovery - honors it without
            # widening launch_run's long-standing signature.
            _intent = (run.summary or {}).get("pending_enqueue") or {}
            if _intent.get("max_depth") is not None:
                max_depth = _intent["max_depth"]
        if source_type in ("bank", "atm"):
            session.close()
            await _enqueue_poi_run(run_id, targets_raw, mode, plugin_ids,
                                   module_overrides, source_type)
            return
        if source_type == "bankatm":
            session.close()
            await _enqueue_bankatm_run(run_id, targets_raw, mode,
                                       module_overrides,
                                       excluded_plugin_ids)
            return
        discover()
        classified = classify_batch(targets_raw)
        plugins, selection_note = _select_run_plugins(
            plugin_ids, excluded_plugin_ids, source_type)
        if selection_note:
            log.warning("run %s: %s (plugin_ids=%r)",
                        run_id, selection_note, plugin_ids)
        if not plugins:
            # Genuinely nothing to run (empty registry). Fail loudly with a
            # reason rather than returning a silent empty scan.
            raise RuntimeError(
                "no plugins available to run for this target/source type")

        # persist targets
        trobj: List[Target] = []
        for c in classified:
            t = Target(raw=c.get("raw", ""), type=c["type"],
                       normalized=c["normalized"])
            trobj.append(t)
            session.add(TargetRow(id=t.id, run_id=run_id, raw=t.raw,
                                  type=t.type, normalized=t.normalized))
        session.commit()

        # Time estimate for the UI: calibrated from recent real durations,
        # falling back to the hardcoded table for plugins without history.
        estimates = _calibrated_estimates(session)
        n_targets = max(len(trobj), 1)
        total_plugin_s = sum(estimates.get(
            p.id, PLUGIN_TIME_ESTIMATES.get(p.id, DEFAULT_PLUGIN_ESTIMATE_S))
            for p in plugins) * n_targets
        concurrency = max(getattr(config, "MAX_CONCURRENCY", 5), 1)
        estimated_s = max(int(total_plugin_s / concurrency), 10)

        # Crypto-class targets (Jay's order, 2026-10-23): when the
        # seed targets are crypto/web3 properties, the exposed-key
        # hunters lead the scan - claimed first, budget-exempt,
        # enqueued HIGH - and their findings rank first at read
        # time. See app/cryptotarget.py.
        from . import cryptotarget as _ct
        crypto_info = _ct.classify_crypto_targets(classified, plugin_ids)
        key_hunters = (_ct.key_hunter_ids([p.id for p in plugins])
                       if crypto_info["crypto"] else [])

        meta = {"mode": mode, "plugin_ids": plugin_ids,
                "excluded_plugin_ids": excluded_plugin_ids or [],
                "max_depth": max_depth,
                "module_overrides": module_overrides or {},
                "source_type": source_type,
                "seed_target_ids": [t.id for t in trobj],
                "crypto_target": crypto_info["crypto"],
                "crypto_reasons": crypto_info["reasons"],
                "key_hunter_ids": key_hunters,
                "estimates": "calibrated" if estimates else "static"}
        if selection_note:
            meta["selection_note"] = selection_note
        run.summary = {**(run.summary or {}), "queue_meta": meta}
        session.commit()
        n_jobs = _enqueue_jobs(session, run_id, plugins, trobj, bounty,
                               estimates=estimates,
                               boost_ids=set(key_hunters) or None)

        await _emit(run_id, "run_start",
                    {"run_id": run_id,
                     "targets": [c["normalized"] for c in classified],
                     "mode": mode, "source_type": source_type,
                     "bounty": bool(bounty),
                     "plugins": [p.id for p in plugins],
                     "estimated_s": estimated_s,
                     "plugin_count": len(plugins),
                     "target_count": n_targets,
                     "queued": True,
                     "note": ((selection_note + "; " if selection_note else "")
                              + f"{n_jobs} jobs queued in Postgres; "
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
        # Clear the durable enqueue intent (see api_start_run): normal
        # completion - jobs queued, or a terminal failed/done outcome
        # that already rewrote the summary - needs no recovery. A
        # process killed mid-enqueue never reaches this block, so its
        # intent survives for boot-time replay. Fresh session on
        # purpose: the branches above close/replace `session`.
        try:
            _s2 = get_session()
            try:
                _r = _s2.query(Run).filter_by(id=run_id).first()
                if _r and (_r.summary or {}).get("pending_enqueue") is not None:
                    _s = dict(_r.summary or {})
                    _s.pop("pending_enqueue", None)
                    _r.summary = _s
                    _s2.commit()
            finally:
                _s2.close()
        except Exception:
            pass
        try:
            session.close()
        except Exception:
            pass

async def launch_run(run_id: str, targets_raw: str, mode: str,
                   plugin_ids: Optional[List[str]] = None,
                   module_overrides: Optional[Dict[str, str]] = None,
                   keys: Optional[Dict[str, str]] = None,
                   source_type: str = "website",
                   bounty: bool = False,
                   excluded_plugin_ids: Optional[List[str]] = None,
                   max_depth: Optional[int] = None
                   ) -> asyncio.Task:
    """Fire-and-forget: start execute_run as a background task."""
    return asyncio.create_task(
        execute_run(run_id, targets_raw, mode, plugin_ids, module_overrides,
                    keys, source_type, bounty, excluded_plugin_ids,
                    max_depth=max_depth))
