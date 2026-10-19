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
from .models import Finding as FindingRow, Run, RunEvent, Target as TargetRow, get_session, init_db
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


async def execute_run(run_id: str, targets_raw: str, mode: str,
                      plugin_ids: Optional[List[str]] = None,
                      module_overrides: Optional[Dict[str, str]] = None,
                      keys: Optional[Dict[str, str]] = None,
                      source_type: str = "website"):
    """Execute a full recon run, fanning SSE events to the run's bus."""
    init_db()
    RUN_EVENT_BUFFER[run_id] = []
    session = get_session()
    try:
        await _execute_run_inner(run_id, targets_raw, mode, plugin_ids,
                                 module_overrides, keys, session, source_type)
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


async def _execute_poi_run(run_id: str, location_raw: str, mode: str,
                           plugin_ids: Optional[List[str]],
                           module_overrides: Optional[Dict[str, str]],
                           keys: Optional[Dict[str, str]],
                           session, source_type: str):
    """Bank/ATM run: location -> geocode -> POI lookup -> assess each POI.

    The location string becomes a set of POI sub-targets (type "poi").
    Each POI gets the atm/bank assessment plugins run against it.
    """
    import datetime as _dt
    from . import geo as _geo
    from .models import Finding as FindingRow

    location = (location_raw or "").strip().splitlines()[0].strip()
    await _emit(run_id, "run_start",
                {"run_id": run_id, "targets": [location],
                 "mode": mode, "source_type": source_type,
                 "plugins": plugin_ids or [], "plugin_count": 0,
                 "target_count": 0, "note": f"geocoding '{location}'..."})

    coords = await _geo.geocode(location)
    if not coords:
        run = session.query(Run).filter_by(id=run_id).first()
        if run:
            run.status = "failed"
            run.finished_at = _dt.datetime.now(_dt.timezone.utc)
            run.summary = {"error": f"could not geocode location: {location}",
                           "findings": 0}
            session.commit()
        await _emit(run_id, "run_done",
                    {"run_id": run_id, "findings": 0,
                     "error": f"could not geocode: {location}"})
        return

    pois = await _geo.find_pois(coords["lat"], coords["lon"], source_type)
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

    # Persist each POI as a target row (type "poi") so findings attach.
    from .models import Target as TargetRow
    from .plugins.base import Target as PluginTarget
    trobj = []
    for poi in pois:
        label = f"{poi['name']} ({poi['lat']:.5f},{poi['lon']:.5f})"
        t = PluginTarget(raw=label, type="poi",
                         normalized=f"{poi['lat']},{poi['lon']}")
        # stash POI metadata on the target for plugins to use
        t.poi = poi  # type: ignore[attr-defined]
        t.poi_type = source_type  # type: ignore[attr-defined]
        trobj.append(t)
        session.add(TargetRow(id=t.id, run_id=run_id, raw=label,
                              type="poi",
                              normalized=f"{poi['lat']},{poi['lon']}"))
    session.commit()

    # Run the assessment plugins against each POI.
    discover()
    plugins = all_plugins()
    if plugin_ids:
        plugins = [p for p in plugins if p.id in plugin_ids]
    # Default: the source-type assessment plugin plus infra recon that
    # accepts poi targets. Keep it focused: atm/bank + ports + banners.
    wanted = {source_type, "ports", "banners", "dns", "tls", "headers"}
    plugins = [p for p in plugins if p.id in wanted or not plugin_ids]

    await _emit(run_id, "run_start",
                {"run_id": run_id,
                 "targets": [t.raw for t in trobj],
                 "mode": mode, "source_type": source_type,
                 "plugins": [p.id for p in plugins],
                 "plugin_count": len(plugins),
                 "target_count": len(trobj),
                 "location": coords["display_name"]})

    async with net.async_client(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.DEFAULT_TIMEOUT,
            follow_redirects=True) as http:
        ctx = Ctx(run_id=run_id, mode=mode, http=http, cache=_cache,
                  keys=keys or {}, limiter=_limiter,
                  module_overrides=module_overrides or {},
                  evidence_dir=config.EVIDENCE_DIR,
                  source_type=source_type)
        sem = asyncio.Semaphore(config.MAX_CONCURRENCY)
        total_jobs = len(trobj) * len(plugins)
        completed = 0
        total_findings = 0

        async def run_one(plugin, target):
            nonlocal completed, total_findings
            async with sem:
                result = await _run_plugin(plugin, target, ctx)
            completed += 1
            await _emit(run_id, "progress",
                        {"done": completed, "total": total_jobs,
                         "plugin": plugin.id, "target": target.raw})
            poi_rows = [_row_to_finding(f, run_id, target.id) for f in result.findings]
            for r in poi_rows:
                session.add(r)
            if poi_rows:
                try:
                    session.commit()
                except Exception:
                    session.rollback()
            for f, r in zip(result.findings, poi_rows):
                total_findings += 1
                await _emit(run_id, "finding",
                            {"fid": r.id,
                             "plugin": f.plugin_id, "category": f.category,
                             "key": f.key, "value": f.value,
                             "source": f.source,
                             "source_url": f.source_url,
                             "evidence": f.evidence,
                             "confidence": f.confidence,
                             "passive": f.passive, "target": target.raw})
            # Emit a POI-level finding so the UI can list each location.
            if getattr(target, "poi", None):
                poi = target.poi
                session.add(FindingRow(
                    run_id=run_id,
                    target_id=target.id, plugin_id="geo",
                    category="location", key="poi",
                    value=f"{poi['name']} - {poi.get('address', '')}",
                    source="OpenStreetMap",
                    source_url="",
                    evidence={"severity": "info", "lat": poi["lat"],
                              "lon": poi["lon"], "name": poi["name"],
                              "address": poi.get("address", ""),
                              "operator": poi.get("operator", ""),
                              "website": poi.get("website", ""),
                              "phone": poi.get("phone", ""),
                              "poi_type": source_type},
                    confidence=100, passive=True))
                total_findings += 1
            session.commit()
            return result

        jobs = [run_one(p, t) for t in trobj for p in plugins
                if not p.accepts or "poi" in p.accepts
                or "domain" in p.accepts or "ip" in p.accepts]
        if jobs:
            await asyncio.gather(*jobs)

    from .graph import build_graph
    n_nodes, n_edges = build_graph(session, run_id)
    session.commit()
    run = session.query(Run).filter_by(id=run_id).first()
    if run:
        run.status = "done"
        run.finished_at = _dt.datetime.now(_dt.timezone.utc)
        run.summary = {"findings": total_findings, "nodes": n_nodes,
                       "edges": n_edges, "targets": len(trobj),
                       "pois": len(pois),
                       "location": coords["display_name"],
                       "source_type": source_type}
        session.commit()
    await _emit(run_id, "run_done",
                {"run_id": run_id, "findings": total_findings,
                 "nodes": n_nodes, "edges": n_edges,
                 "pois": len(pois), "source_type": source_type})


async def _execute_run_inner(run_id: str, targets_raw: str, mode: str,
                             plugin_ids: Optional[List[str]],
                             module_overrides: Optional[Dict[str, str]],
                             keys: Optional[Dict[str, str]],
                             session, source_type: str = "website"):
    run = session.query(Run).filter_by(id=run_id).first()
    if not run:
        session.close()
        return
    # Bank/ATM source types: the "target" is a location. Geocode it, find
    # nearby POIs via OpenStreetMap, then assess each one as a sub-target.
    if source_type in ("bank", "atm"):
        await _execute_poi_run(run_id, targets_raw, mode, plugin_ids,
                               module_overrides, keys, session, source_type)
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
                 "mode": mode, "source_type": source_type,
                 "plugins": [p.id for p in plugins],
                 "estimated_s": estimated_s,
                 "plugin_count": len(plugins), "target_count": n_targets})

    async with net.async_client(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.DEFAULT_TIMEOUT, follow_redirects=True) as http:
        ctx = Ctx(run_id=run_id, mode=mode, http=http, cache=_cache,
                  keys=keys or {}, limiter=_limiter,
                  module_overrides=module_overrides or {},
                  evidence_dir=config.EVIDENCE_DIR,
                  source_type=source_type)
        sem = asyncio.Semaphore(config.MAX_CONCURRENCY)

        # Split plugins by phase: phase 1 runs first, then phase 2 chain
        # plugins consume the discovery bus populated by phase 1.
        phase1 = [p for p in plugins if getattr(p, "phase", 1) == 1]
        phase2 = [p for p in plugins if getattr(p, "phase", 1) == 2]

        # Every plugin x target pair is a job. Pairs whose target type the
        # plugin doesn't accept are recorded as ok(0) "not applicable"
        # instead of skipped: Jay's rule is no skips, no errors, ever.
        pairs = [(p, t) for t in trobj for p in plugins]
        total_jobs = len(pairs)
        completed_jobs = 0

        # Dynamic ETA state: per-job time estimates vs observed durations.
        # eta_s rides on every progress event = estimated seconds remaining,
        # corrected by how fast completed plugins actually ran on this target.
        job_est = {}
        for (p, t) in pairs:
            if not p.accepts or t.type in p.accepts:
                job_est[(p.id, t.id)] = PLUGIN_TIME_ESTIMATES.get(
                    p.id, DEFAULT_PLUGIN_ESTIMATE_S)
            else:
                job_est[(p.id, t.id)] = 0.0
        total_est = sum(job_est.values())
        eta_done_est = 0.0
        eta_done_actual = 0.0

        def _eta_s() -> float:
            remaining = max(total_est - eta_done_est, 0.0)
            factor = 1.0
            if eta_done_est > 0:
                factor = min(max(eta_done_actual / eta_done_est, 0.5), 3.0)
            return max(remaining * factor / max(concurrency, 1), 0.0)

        # Run clock + budget for this scan. dispatch() below enforces the
        # 120s hard ceiling (SCAN_BUDGET_S): priority-ordered starts,
        # soft/hard stops, and per-job timeouts capped at the remaining
        # budget so the last job always lands by the deadline.
        run_clock = time.monotonic()
        # The plugin deadline leaves SCAN_TAIL_RESERVE_S at the end of the
        # budget for the correlation graph + summary, so run_done always
        # lands inside the 120s ceiling even when the last plugin uses its
        # full remaining window.
        deadline = run_clock + SCAN_BUDGET_S - SCAN_TAIL_RESERVE_S
        soft_stop = run_clock + SCAN_SOFT_STOP_S
        hard_stop = run_clock + SCAN_HARD_STOP_S

        # NOTE: no blocking homepage prefetch here. ctx.fetch_page has
        # singleflight + a shared cache, so the first plugin to read the
        # homepage pays once and the other ~35 read from cache - without
        # delaying the first plugin start (first finding lands in seconds,
        # not after a warm-up).

        # Simpler: wrap each job with progress counting
        async def wrap(plugin, target):
            nonlocal completed_jobs, eta_done_est, eta_done_actual
            try:
                async with sem:
                    result = await _run_plugin(plugin, target, ctx,
                                               deadline=deadline)
            except asyncio.CancelledError:
                raise
            except BaseException as e:
                result = plugin._error(
                    f"runner guard: {type(e).__name__}: {str(e)[:150]}")
                result.duration_ms = 0
            try:
                completed_jobs += 1
                est = job_est.get((plugin.id, target.id), DEFAULT_PLUGIN_ESTIMATE_S)
                eta_done_est += est
                eta_done_actual += (result.duration_ms or 0) / 1000.0
                # Persist + stream findings the moment the plugin finishes:
                # results appear in real time, not in one burst at run end.
                rows = [_row_to_finding(f, run_id, target.id) for f in result.findings]
                for r in rows:
                    session.add(r)
                if rows:
                    try:
                        session.commit()
                    except Exception:
                        session.rollback()
                for f, r in zip(result.findings, rows):
                    # Feed the finding bus: dedup + pocgen (phase 2) consume
                    # "poc_findings" for cross-plugin dedup and PoC guides.
                    try:
                        ctx.publish("poc_findings", {
                            "plugin_id": f.plugin_id,
                            "category": f.category,
                            "key": f.key,
                            "value": f.value,
                            "source": f.source,
                            "source_url": f.source_url,
                            "confidence": f.confidence,
                            "evidence": dict(f.evidence or {}),
                            "passive": f.passive,
                            "bounty_value": getattr(f, "bounty_value", "low"),
                        })
                    except Exception:
                        pass
                    await _emit(run_id, "finding",
                                {"fid": r.id,
                                 "plugin": f.plugin_id, "category": f.category,
                                 "key": f.key, "value": f.value,
                                 "source": f.source, "source_url": f.source_url,
                                 "evidence": f.evidence,
                                 "confidence": f.confidence,
                                 "passive": f.passive, "target": target.normalized})
                await _emit(run_id, "progress",
                            {"done": completed_jobs, "total": total_jobs,
                             "eta_s": round(_eta_s(), 1),
                             "plugin": plugin.id, "target": target.normalized})
            except asyncio.CancelledError:
                raise
            except BaseException as e:
                try:
                    await _emit(run_id, "plugin_done",
                                {"plugin": plugin.id, "status": "error",
                                 "reason": f"result handling failed: {type(e).__name__}: {str(e)[:150]}",
                                 "findings": 0, "ms": result.duration_ms or 0})
                except Exception:
                    pass
                result = plugin._error(
                    f"result handling failed: {type(e).__name__}: {str(e)[:150]}")
            return plugin, target, result

        async def wrap_na(plugin, target):
            """Not-applicable pseudo-job: ok(0) with a note, counted in progress."""
            nonlocal completed_jobs
            result = plugin._skipped(f"not applicable to target type '{target.type}'")
            result.duration_ms = 0
            completed_jobs += 1
            await _emit(run_id, "plugin_done",
                        {"plugin": plugin.id, "status": result.status.value,
                         "reason": result.reason, "findings": 0, "ms": 0})
            await _emit(run_id, "progress",
                        {"done": completed_jobs, "total": total_jobs,
                         "eta_s": round(_eta_s(), 1),
                         "plugin": plugin.id, "target": target.normalized})
            return plugin, target, result

        async def wrap_budget_cut(plugin, target):
            """Time-budget cut: ok(0) with an explicit note, never an error.

            Jay's call: a note saying plugins were "skipped: time budget"
            beats a 5-minute scan. Findings are never dropped to go faster -
            the plugin simply never started, and says so.
            """
            nonlocal completed_jobs, skipped_budget
            skipped_budget += 1
            result = plugin._skipped(
                "skipped: time budget - cut to hold the "
                f"{int(SCAN_BUDGET_S)}s scan ceiling")
            result.duration_ms = 0
            completed_jobs += 1
            await _emit(run_id, "plugin_done",
                        {"plugin": plugin.id, "status": result.status.value,
                         "reason": result.reason, "findings": 0, "ms": 0})
            await _emit(run_id, "progress",
                        {"done": completed_jobs, "total": total_jobs,
                         "eta_s": round(_eta_s(), 1),
                         "plugin": plugin.id, "target": target.normalized})
            return plugin, target, result

        async def run_phase(plist, phase_num):
            # Dispatch order: priority tier first (high-signal plugins land
            # early), then fastest-estimated within a tier. Slow
            # enumerators run last so they are the ones cut if the budget
            # runs out - findings lead, enumeration trails.
            plist = sorted(plist,
                           key=lambda p: (priority_for(p.id),
                                          PLUGIN_TIME_ESTIMATES.get(
                                              p.id, DEFAULT_PLUGIN_ESTIMATE_S)))
            ids = {p.id for p in plist}
            # (plugin, target, applicable?) in dispatch order
            job_list = []
            for (p, t) in pairs:
                if p.id not in ids:
                    continue
                applicable = not p.accepts or t.type in p.accepts
                job_list.append((p, t, applicable))
            if not job_list:
                return []
            if phase_num == 2:
                await _emit(run_id, "phase",
                            {"phase": 2,
                             "note": "chain phase: deeper probes on "
                                     "discovered assets",
                             "plugins": [p.id for p in plist]})
            # Budget-aware worker pool: keep `concurrency` jobs in flight,
            # but gate every new start on the scan clock. Past the soft
            # stop only HIGH-priority jobs start; past the hard stop none
            # do. Every started job's own timeout is capped at the
            # remaining budget inside _run_plugin, so the last job lands
            # by the deadline no matter what.
            results = []
            idx = 0
            in_flight = set()

            async def launch(p, t, applicable):
                if not applicable:
                    return await wrap_na(p, t)
                now = time.monotonic()
                if now >= hard_stop:
                    return await wrap_budget_cut(p, t)
                if now >= soft_stop and priority_for(p.id) > HIGH_TIER:
                    return await wrap_budget_cut(p, t)
                if deadline - now < 5:
                    return await wrap_budget_cut(p, t)
                return await wrap(p, t)

            while idx < len(job_list) or in_flight:
                while idx < len(job_list) and len(in_flight) < concurrency:
                    p, t, applicable = job_list[idx]
                    idx += 1
                    in_flight.add(asyncio.create_task(launch(p, t, applicable)))
                if not in_flight:
                    break
                done, _ = await asyncio.wait(in_flight,
                                             return_when=asyncio.FIRST_COMPLETED)
                in_flight -= done
                for d in done:
                    results.append(d.result())
            return results

        skipped_budget = 0
        results = await run_phase(phase1, 1)
        # Chain pass: phase-1 producers (tech_fingerprint, graphql,
        # apidiscover) -> phase-2 consumers (cms_probes, graphql_deep,
        # param_discovery). Detects triggers on the discovery bus, publishes
        # "chain" signals, and emits one SSE event per triggered chain so
        # the UI can show what fired (backend/app/chains.py).
        try:
            from . import chains as _chains
            for _t in _chains.evaluate_chains(ctx):
                await _emit(run_id, "chain",
                            {"chain": _t["chain"], "name": _t["name"],
                             "producer": _t["producer"],
                             "consumer": _t["consumer"],
                             "signals": _t["signals"]})
        except Exception:
            pass
        results = list(results) + await run_phase(phase2, 2)
        # Second chain pass for phase-2 producers (sourcemap_chain:
        # sourcemap.py -> jsdeep, which consumes "recovered_sources"
        # directly). Emits the event even though the consumer already ran.
        try:
            from . import chains as _chains2
            for _t in _chains2.evaluate_chains(ctx):
                await _emit(run_id, "chain",
                            {"chain": _t["chain"], "name": _t["name"],
                             "producer": _t["producer"],
                             "consumer": _t["consumer"],
                             "signals": _t["signals"]})
        except Exception:
            pass

    # Findings were already persisted + streamed live as each plugin
    # finished. Here we just tally per-plugin statuses for the summary.
    # DB count is the source of truth (survives phase timeouts).
    plugin_rows = {}
    for plugin, target, result in results:
        plugin_rows[plugin.id] = result
    total = session.query(FindingRow).filter_by(run_id=run_id).count()
    session.commit()

    # correlation graph
    from .graph import build_graph
    n_nodes, n_edges = build_graph(session, run_id)
    session.commit()

    run.status = "done"
    run.finished_at = dt.datetime.now(dt.timezone.utc)
    summary = {"findings": total, "nodes": n_nodes, "edges": n_edges,
               "targets": len(trobj),
               "plugins": {pid: r.status.value for pid, r in plugin_rows.items()}}
    if skipped_budget:
        summary["skipped_time_budget"] = skipped_budget
        summary["note"] = (f"{skipped_budget} low-priority plugins skipped: "
                           f"time budget ({int(SCAN_BUDGET_S)}s scan ceiling)")
    run.summary = summary
    session.commit()
    session.close()
    run_done_data = {"run_id": run_id, "findings": total,
                     "nodes": n_nodes, "edges": n_edges}
    if skipped_budget:
        run_done_data["skipped_time_budget"] = skipped_budget
    await _emit(run_id, "run_done", run_done_data)


async def launch_run(run_id: str, targets_raw: str, mode: str,
                   plugin_ids: Optional[List[str]] = None,
                   module_overrides: Optional[Dict[str, str]] = None,
                   keys: Optional[Dict[str, str]] = None,
                   source_type: str = "website") -> asyncio.Task:
    """Fire-and-forget: start execute_run as a background task."""
    return asyncio.create_task(
        execute_run(run_id, targets_raw, mode, plugin_ids, module_overrides,
                    keys, source_type))
