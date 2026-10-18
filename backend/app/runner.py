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
# via their timeout_s class attribute. Kept for reference; the runner reads
# plugin.timeout_s directly.
DEFAULT_PLUGIN_TIMEOUT_S = 90


async def _run_plugin(plugin, target: Target, ctx: Ctx) -> PluginResult:
    if plugin.missing_keys(ctx):
        return plugin._skipped(
            "needs API key: " + ", ".join(plugin.missing_keys(ctx)) +
            " (add it in the Keys tab to enable)")
    await _emit(ctx.run_id, "plugin_start",
                {"plugin": plugin.id, "label": plugin.label, "target": target.normalized})
    t0 = time.monotonic()
    # Per-plugin timeout ceiling from the plugin itself (default 90s).
    # This is hang protection only: a plugin is never killed to hit a
    # speed budget. Findings always win over speed.
    timeout = getattr(plugin, "timeout_s", 90) or 90
    try:
        result = await asyncio.wait_for(plugin.run(target, ctx),
                                        timeout=timeout)
    except asyncio.TimeoutError:
        # Jay's rule: no errors ever. A timeout degrades to ok(0) with a note.
        result = plugin._degraded(f"timed out after {timeout}s: findings may be incomplete")
        await _emit(ctx.run_id, "plugin_timeout",
                    {"plugin": plugin.id, "timeout_s": timeout,
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
    "race_detect": 20, "stealth_crawler": 45, "jwt_audit": 12,
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

        # Simpler: wrap each job with progress counting
        async def wrap(plugin, target):
            nonlocal completed_jobs, eta_done_est, eta_done_actual
            async with sem:
                result = await _run_plugin(plugin, target, ctx)
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

        async def run_phase(plist, phase_num):
            # Prioritize: fastest plugins first so quick wins land early.
            # Slow plugins run in background without blocking results.
            plist = sorted(plist,
                           key=lambda p: PLUGIN_TIME_ESTIMATES.get(
                               p.id, DEFAULT_PLUGIN_ESTIMATE_S))
            ids = {p.id for p in plist}
            wrapped = []
            for (p, t) in pairs:
                if p.id not in ids:
                    continue
                if not p.accepts or t.type in p.accepts:
                    wrapped.append(wrap(p, t))
                else:
                    wrapped.append(wrap_na(p, t))
            if not wrapped:
                return []
            if phase_num == 2:
                await _emit(run_id, "phase",
                            {"phase": 2,
                             "note": "chain phase: deeper probes on "
                                     "discovered assets",
                             "plugins": [p.id for p in plist]})
            try:
                return await asyncio.wait_for(
                    asyncio.gather(*wrapped), timeout=RUN_TIMEOUT_S)
            except asyncio.TimeoutError:
                await _emit(run_id, "progress",
                            {"done": completed_jobs, "total": total_jobs,
                             "eta_s": round(_eta_s(), 1),
                             "note": f"phase {phase_num} timed out"})
                return []

        results = await run_phase(phase1, 1)
        results = list(results) + await run_phase(phase2, 2)

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
    run.summary = {"findings": total, "nodes": n_nodes, "edges": n_edges,
                   "targets": len(trobj),
                   "plugins": {pid: r.status.value for pid, r in plugin_rows.items()}}
    session.commit()
    session.close()
    await _emit(run_id, "run_done",
                {"run_id": run_id, "findings": total,
                 "nodes": n_nodes, "edges": n_edges})

    # AI Hunter: kick off uncensored-AI test-plan analysis in the background.
    # Never blocks the scan; the UI polls for results when ready.
    try:
        from .ai_assistant import run_ai_analysis
        asyncio.create_task(run_ai_analysis(run_id))
    except Exception:
        pass  # AI analysis is best-effort; the scan itself is done


async def launch_run(run_id: str, targets_raw: str, mode: str,
                   plugin_ids: Optional[List[str]] = None,
                   module_overrides: Optional[Dict[str, str]] = None,
                   keys: Optional[Dict[str, str]] = None,
                   source_type: str = "website") -> asyncio.Task:
    """Fire-and-forget: start execute_run as a background task."""
    return asyncio.create_task(
        execute_run(run_id, targets_raw, mode, plugin_ids, module_overrides,
                    keys, source_type))
