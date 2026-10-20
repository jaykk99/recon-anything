"""ReconAnything API (FastAPI).

Routes:
  GET  /api/health
  POST /api/classify            single + batch input classification
  GET  /api/plugins             plugin registry with key status
  POST /api/runs                start a run (returns run_id)
  GET  /api/runs/{id}/stream    SSE live progress + findings
  GET  /api/runs                list runs
  GET  /api/runs/{id}           run detail + findings + summary
  GET  /api/runs/{id}/graph     correlation graph payload
  GET  /api/runs/{id}/apimap    assembled API map
  GET  /api/runs/{id}/export    ?format=json|csv|md|html
  GET  /api/diff?a=&b=          diff two runs
  GET/POST/DELETE /api/keys     API key vault
  GET/POST/DELETE /api/schedules

Single-user gate: if RECON_ACCESS_CODE is set, every /api route except
/api/health requires header X-Access-Code.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel
from typing import Dict, List, Optional

from . import config
from . import net
from .classifier import classify, classify_batch
from .diff import diff_runs
from .graph import graph_payload
from .keys import encrypt, key_status, load_all
from .models import ApiKey, Finding, Run, RunEvent, Schedule, Target, get_session, init_db
from .models import check_db, DATABASE_URL, IS_SQLITE
from .plugins.registry import describe
from .reporting import (executive_summary, findings_dump, run_progress,
                         to_csv, to_html, to_markdown)
from .runner import launch_run, subscribe

log = logging.getLogger("recon-anything")


def missing_run(run_id: str) -> HTTPException:
    """404 with an actionable message.

    On Render's free tier the default SQLite database lives on an ephemeral
    disk, so a redeploy silently wipes every run and the UI would otherwise
    show a bare "run not found". Point the user at the real fix instead.
    """
    return HTTPException(
        status_code=404,
        detail=(
            f"run {run_id} not found. It may have been wiped by a restart or "
            "redeploy (the default SQLite database on Render's free tier is "
            "ephemeral). Set DATABASE_URL to a persistent Postgres "
            "(Neon or Supabase free tier) so scans survive restarts."
        ),
    )

app = FastAPI(title="ReconAnything", version="0.1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], allow_credentials=False,
)


def gate(x_access_code: Optional[str] = Header(default=None),
         code: Optional[str] = Query(default=None)):
    # EventSource cannot set headers, so accept ?code= as a fallback
    provided = x_access_code or code
    if config.ACCESS_CODE and provided != config.ACCESS_CODE:
        raise HTTPException(status_code=401, detail="bad access code")
    return True


@app.on_event("startup")
async def _startup():
    # Start accepting requests immediately; do heavy init in background
    # so Render's health check doesn't time out on slow cold starts.
    import threading
    import asyncio
    _db_ready = asyncio.Event()
    def _bg_init():
        try:
            # Fail fast on an unreachable database: a bad DATABASE_URL must crash
            # the deploy with a clear error, not surface later as empty scans.
            check_db()
            if IS_SQLITE:
                log.warning(
                    "using ephemeral SQLite (%s): all runs are wiped on redeploy. "
                    "Set DATABASE_URL to a persistent Postgres (Neon/Supabase free "
                    "tier) to keep scans across restarts.", DATABASE_URL)
            init_db()
            # Queue recovery: jobs orphaned by a dead worker go back to queued;
            # runs that still have jobs stay "running" so the worker resumes them.
            # Only legacy stuck runs (no jobs at all - pre-queue scans) are marked
            # failed so the UI stops spinning.
            try:
                from .runner import reset_stale_queue_jobs
                from .models import PluginJob
                reset_stale_queue_jobs()
                session = get_session()
                try:
                    stuck = session.query(Run).filter_by(status="running").all()
                    for r in stuck:
                        has_jobs = (session.query(PluginJob)
                                    .filter_by(run_id=r.id).count() > 0)
                        if has_jobs:
                            continue  # the queue worker resumes this run
                        r.status = "failed"
                        r.finished_at = dt.datetime.now(dt.timezone.utc)
                        summary = dict(r.summary or {})
                        summary["error"] = ("server restarted during scan "
                                            "(deploy or crash); start a fresh scan")
                        r.summary = summary
                    if stuck:
                        session.commit()
                finally:
                    session.close()
            except Exception:
                pass
            # Prune the SSE event log so run_events does not grow forever.
            try:
                cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)
                s2 = get_session()
                try:
                    s2.query(RunEvent).filter(RunEvent.created_at < cutoff).delete()
                    s2.commit()
                finally:
                    s2.close()
            except Exception:
                pass
        except Exception as e:
            log.error("background init failed: %s", e)
        finally:
            # Signal that DB init is done (or failed); worker will try anyway
            try:
                _loop.call_soon_threadsafe(_db_ready.set)
            except Exception:
                pass
    # Run heavy init in background so the server starts accepting
    # requests immediately (Render health check won't time out).
    _loop = asyncio.get_running_loop()
    threading.Thread(target=_bg_init, daemon=True).start()
    # Start the queue worker after DB init completes (needs the event loop)
    async def _start_worker_when_ready():
        try:
            await asyncio.wait_for(_db_ready.wait(), timeout=120)
        except asyncio.TimeoutError:
            log.warning("DB init timed out, starting worker anyway")
        try:
            from .runner import start_queue_worker
            start_queue_worker()
            log.info("queue worker started")
        except Exception as e:
            log.error("failed to start queue worker: %s", e)
    asyncio.create_task(_start_worker_when_ready())


@app.get("/api/health")
def health():
    return {"ok": True, "service": "recon-anything"}


# -- classify ------------------------------------------------------------
class ClassifyIn(BaseModel):
    text: str


@app.post("/api/classify", dependencies=[Depends(gate)])
def api_classify(body: ClassifyIn):
    if "\n" in body.text.strip():
        return {"results": classify_batch(body.text)}
    return classify(body.text)


# -- plugins --------------------------------------------------------------
@app.get("/api/plugins", dependencies=[Depends(gate)])
def api_plugins():
    session = get_session()
    try:
        status = key_status(session)
    finally:
        session.close()
    plugins = describe()
    for p in plugins:
        p["key_status"] = {k: status.get(k, {"configured": False})
                           for k in p["requires_keys"]}
    return {"plugins": plugins}


# -- runs -----------------------------------------------------------------
class RunIn(BaseModel):
    targets: str
    mode: str = "active"
    plugins: Optional[List[str]] = None
    module_overrides: Optional[Dict[str, str]] = None
    source_type: str = "website"  # website | bank | atm
    bounty: bool = False  # bounty mode: prioritize high-impact vuln classes


@app.post("/api/runs", dependencies=[Depends(gate)])
async def api_start_run(body: RunIn):
    if not body.targets.strip():
        raise HTTPException(400, "targets required")
    if body.mode not in ("passive", "active"):
        raise HTTPException(400, "mode must be passive|active")
    if body.source_type not in ("website", "bank", "atm"):
        raise HTTPException(400, "source_type must be website|bank|atm")
    run_id = uuid.uuid4().hex[:12]
    session = get_session()
    try:
        session.add(Run(id=run_id, mode=body.mode, status="running",
                        source_type=body.source_type,
                        summary={"bounty": bool(body.bounty)}))
        session.commit()
        keys = load_all(session)
    finally:
        session.close()
    # Bank/ATM source types imply explicit authorization: the user picked
    # the mode on purpose. Record it as an audit finding in the run.
    overrides = dict(body.module_overrides or {})
    if body.source_type == "bank":
        overrides["bank"] = "authorized"
    elif body.source_type == "atm":
        overrides["atm"] = "authorized"
    await launch_run(run_id, body.targets, body.mode,
                     body.plugins, overrides, keys,
                     source_type=body.source_type, bounty=body.bounty)
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}/stream", dependencies=[Depends(gate)])
async def api_run_stream(run_id: str):
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise missing_run(run_id)
    finally:
        session.close()
    return StreamingResponse(subscribe(run_id), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/runs", dependencies=[Depends(gate)])
def api_list_runs(limit: int = Query(30, le=200)):
    session = get_session()
    try:
        runs = session.query(Run).order_by(Run.created_at.desc()).limit(limit).all()
        return {"runs": [
            {"id": r.id, "mode": r.mode, "status": r.status,
             "source_type": getattr(r, "source_type", None) or "website",
             "created_at": r.created_at.isoformat() if r.created_at else None,
             "summary": r.summary or {}} for r in runs]}
    finally:
        session.close()


@app.get("/api/runs/{run_id}", dependencies=[Depends(gate)])
def api_run_detail(run_id: str, show_secrets: bool = False):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=show_secrets)
        return {
            "run": {"id": run.id, "mode": run.mode, "status": run.status,
                    "source_type": getattr(run, "source_type", None) or "website",
                    "bounty": bool((run.summary or {}).get("bounty")),
                    "created_at": run.created_at.isoformat() if run.created_at else None,
                    "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    "summary": run.summary or {}},
            "targets": [{"id": t.id, "raw": t.raw, "type": t.type,
                         "normalized": t.normalized} for t in targets],
            "findings": rows,
            "executive_summary": executive_summary(rows),
            # Live progress for the UI poll fallback (SSE may be down):
            # done/total, eta_s, and currently-running plugin names.
            "progress": run_progress(session, run_id),
        }
    finally:
        session.close()


@app.get("/api/runs/{run_id}/graph", dependencies=[Depends(gate)])
def api_graph(run_id: str):
    session = get_session()
    try:
        return graph_payload(session, run_id)
    finally:
        session.close()


@app.get("/api/runs/{run_id}/apimap", dependencies=[Depends(gate)])
def api_apimap(run_id: str):
    """Application attack-surface map, grouped.

    Returns the legacy flat ``entries`` (backward compatible) plus
    ``groups``: pages, api_routes, forms, js_endpoints, websockets,
    graphql. Each entry: {url, method, status, auth, params, note}.
    """
    from urllib.parse import urlparse
    session = get_session()
    try:
        rows = session.query(Finding).filter_by(run_id=run_id).all()
        entries = {}
        for f in rows:
            if f.key in ("endpoint",) or (f.category == "api" and f.raw):
                raw = f.raw or {}
                amap = raw.get("map") if isinstance(raw, dict) else None
                if amap:
                    entries.update(amap)
                else:
                    entries[f.value] = {"note": f.source}
        # also fold api_map_entries raw
        for f in rows:
            if f.key == "api_map_entries" and f.raw and isinstance(f.raw, dict):
                entries.update(f.raw.get("map", {}))

        def _entry(url, method="", status="", auth="", params=None, note=""):
            return {"url": url, "method": method, "status": status,
                    "auth": auth, "params": params or [], "note": note or ""}

        def _params_of(f):
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            p = ev.get("params") or ev.get("parameters") or []
            return [str(x)[:60] for x in p][:20] if isinstance(p, list) else []

        def _auth_of(f):
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            for k in ("auth", "auth_required", "verdict"):
                v = ev.get(k)
                if v:
                    return str(v)[:60]
            return ""

        groups = {"pages": [], "api_routes": [], "forms": [],
                  "js_endpoints": [], "websockets": [], "graphql": []}
        seen = set()

        def _add(group, url, **kw):
            if not url or url in seen:
                return
            seen.add(url)
            groups[group].append(_entry(url, **kw))

        for f in rows:
            key, val = f.key or "", f.value or ""
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            # --- GraphQL (wire graphql_deep output into the map) ---
            if key.startswith("graphql"):
                if key in ("graphql_endpoint", "graphql_deep", "graphql",
                           "graphql_introspection", "graphql_schema_enum"):
                    fields = ev.get("fields") or ev.get("operations") or []
                    _add("graphql", val or ev.get("endpoint", ""),
                         note=f"{key}: {len(fields)} fields" if fields else key,
                         params=[str(x)[:60] for x in fields][:25] if isinstance(fields, list) else [],
                         auth=_auth_of(f))
                continue
            # --- forms (forms.py plugin) ---
            if key in ("form_inventory", "interesting_form"):
                for form in (ev.get("forms") or []):
                    if not isinstance(form, dict):
                        continue
                    action = form.get("action", "")
                    inputs = [i.get("name", "") for i in
                              (form.get("inputs") or []) if isinstance(i, dict)]
                    _add("forms", action or form.get("page", ""),
                         method=str(form.get("method", "GET")).upper(),
                         params=[str(x) for x in inputs if x][:20],
                         note=f"on {form.get('page', '')}"[:120],
                         auth=_auth_of(f))
                if key == "interesting_form" and val and val not in seen:
                    _add("forms", val, note=key, auth=_auth_of(f))
                continue
            # --- JS-discovered endpoints ---
            if key in ("js_endpoint", "endpoint"):
                url = val
                if url.startswith(("ws://", "wss://")):
                    _add("websockets", url, note=f.source or "")
                else:
                    _add("js_endpoints", url, params=_params_of(f),
                         note=f.source or "", auth=_auth_of(f))
                continue
            # --- endpoint auth probe results ---
            if key in ("unauthenticated_api", "auth_required_endpoint",
                       "endpoint_error_leak"):
                _add("api_routes", val, status=str(ev.get("status", "")),
                     auth=ev.get("verdict", "") or _auth_of(f),
                     params=_params_of(f), note=key)
                continue
            # --- API map entries from apidiscover ---
            if f.category == "api" and key in ("api_route", "api_pattern",
                                               "api_map_entries"):
                _add("api_routes", val, params=_params_of(f),
                     note=key, auth=_auth_of(f))
                continue
            # --- crawled pages ---
            if key in ("page", "crawled_page", "crawl_summary"):
                for u in (ev.get("pages") or ([val] if val.startswith("http") else [])):
                    _add("pages", u, note=key)
                continue

        # fold legacy flat entries into api_routes (deduped via seen)
        for url, meta in entries.items():
            meta = meta if isinstance(meta, dict) else {}
            if url.startswith(("ws://", "wss://")):
                _add("websockets", url, note=str(meta.get("note", "")))
            elif "/graphql" in url.lower():
                _add("graphql", url, note=str(meta.get("note", "")))
            else:
                _add("api_routes", url,
                     method=", ".join(meta.get("methods", [])) if isinstance(
                         meta.get("methods"), list) else "",
                     status=str(meta.get("status", "")),
                     auth=str(meta.get("auth", "")),
                     note=str(meta.get("note", "")))

        counts = {g: len(v) for g, v in groups.items()}
        return {"entries": entries, "count": len(entries),
                "groups": groups, "counts": counts}
    finally:
        session.close()


@app.get("/api/runs/{run_id}/export", dependencies=[Depends(gate)])
def api_export(run_id: str, format: str = "json", show_secrets: bool = False):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=show_secrets)
    finally:
        session.close()
    if format == "json":
        return {"run_id": run_id, "findings": rows}
    if format == "csv":
        return PlainTextResponse(to_csv(rows), media_type="text/csv",
                                 headers={"Content-Disposition":
                                          f"attachment; filename=recon-{run_id}.csv"})
    if format == "md":
        return PlainTextResponse(to_markdown(run, targets, rows),
                                 media_type="text/markdown",
                                 headers={"Content-Disposition":
                                          f"attachment; filename=recon-{run_id}.md"})
    if format == "html":
        return PlainTextResponse(to_html(run, targets, rows), media_type="text/html",
                                 headers={"Content-Disposition":
                                          f"attachment; filename=recon-{run_id}.html"})
    raise HTTPException(400, "format must be json|csv|md|html")


@app.get("/api/runs/{run_id}/fetch", dependencies=[Depends(gate)])
async def api_fetch_file(run_id: str, url: str = Query(..., max_length=2000)):
    """Fetch a URL found during a run so Jay can view file contents.
    Only allows URLs that appeared in this run's findings (SSRF guard)."""
    from urllib.parse import urlparse
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        rows = findings_dump(session, run_id)
    finally:
        session.close()
    allowed = set()
    for r in rows:
        for k in ("source_url", "value"):
            v = r.get(k) or ""
            if v.startswith("http"):
                # value may contain extra text, extract first URL
                candidate = v.split()[0] if k == "value" else v
                if candidate.startswith("http"):
                    allowed.add(candidate)
    if url not in allowed:
        raise HTTPException(403, "URL was not found in this run")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "only http/https allowed")
    import httpx
    try:
        async with net.async_client(timeout=20, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "ReconAnything/1.0"})
        body = resp.text[:200000]
        return {"url": url, "status": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "size": len(resp.content),
                "last_modified": resp.headers.get("last-modified", ""),
                "headers": dict(resp.headers),
                "body": body,
                "truncated": len(resp.content) > 200000}
    except Exception as e:
        raise HTTPException(502, f"fetch failed: {str(e)[:200]}")


@app.get("/api/runs/{run_id}/vulns", dependencies=[Depends(gate)])
def api_vulns(run_id: str):
    """Possible-vulnerabilities advisor: ranked attack paths from scan findings.

    Heuristic only (no LLM). PoCs are detection-only and non-destructive.
    """
    from .vuln_advisor import advise
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        rows = findings_dump(session, run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        summary = {
            "targets": [{"raw": t.raw, "type": t.type,
                         "normalized": t.normalized} for t in targets],
        }
        return {"run_id": run_id, "candidates": advise(rows, summary)}
    finally:
        session.close()


class DryRunIn(BaseModel):
    candidate_id: str
    base: str = ""


@app.post("/api/runs/{run_id}/vulns/test", dependencies=[Depends(gate)])
def api_vuln_test(run_id: str):
    """Real safe testing: run non-destructive detection probes against the
    actual target. GET/HEAD only, rate-limited, nothing modified.

    Runs in the background. Returns only the candidates that were confirmed.
    Only use against targets you are authorized to test.
    """
    from .safe_tester import run_real_tests
    from .vuln_advisor import advise
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        rows = findings_dump(session, run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        summary = {
            "targets": [{"raw": t.raw, "type": t.type,
                         "normalized": t.normalized} for t in targets],
        }
        candidates = advise(rows, summary)
        base = ""
        if targets:
            base = targets[0].normalized or targets[0].raw or ""
        report = run_real_tests(base, candidates)
        report["run_id"] = run_id
        return report
    finally:
        session.close()


@app.post("/api/runs/{run_id}/vulns/dry-run", dependencies=[Depends(gate)])
def api_vuln_dry_run(run_id: str, body: DryRunIn):
    """Safe-test terminal: narrates what a detection check WOULD do.

    Sends zero requests. Pure dry-run simulation for authorized testing prep.
    """
    from .vuln_advisor import dry_run
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
    finally:
        session.close()
    base = body.base or "TARGET"
    return {"candidate_id": body.candidate_id,
            "lines": dry_run(body.candidate_id, base)}


# -- actionable findings ------------------------------------------------------
# Subdomain liveness verification + single port probing. Both are SSRF-guarded:
# they only touch hosts/ports that appeared in the run's own findings.


class SubVerifyIn(BaseModel):
    force: bool = False


@app.post("/api/runs/{run_id}/subdomains/verify", dependencies=[Depends(gate)])
async def api_subdomain_verify(run_id: str, body: SubVerifyIn):
    """Probe every subdomain from this run's findings for HTTP liveness.

    Returns {host: {live, status, url, server, title}}. Results are cached
    in the run summary for 24h. Only hosts from this run's findings are
    probed (SSRF guard). Read-only GET requests, 8s timeout each.
    """
    import asyncio
    import re
    import time as _time
    import httpx

    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        rows = findings_dump(session, run_id)
        summary = dict(run.summary or {})
    finally:
        session.close()

    hosts: List[str] = []
    for r in rows:
        if r.get("key") == "subdomain":
            v = (r.get("value") or "").split()[0].strip().lower().rstrip(".")
            if v and re.match(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$", v) and v not in hosts:
                hosts.append(v)
    hosts = hosts[:100]

    cached = summary.get("subdomain_status") or {}
    now = _time.time()

    async def check(host: str):
        c = cached.get(host)
        if c and not body.force and now - c.get("ts", 0) < 86400:
            return host, c
        result: Dict = {"live": False, "status": 0, "url": "",
                        "server": "", "title": "", "ts": now}
        for scheme in ("https", "http"):
            try:
                async with net.async_client(
                        timeout=8, follow_redirects=True,
                        headers={"User-Agent": "ReconAnything/1.0"}) as client:
                    resp = await client.get(f"{scheme}://{host}")
                title = ""
                if resp.status_code < 400:
                    m = re.search(r"<title[^>]*>(.*?)</title>",
                                  resp.text[:50000], re.I | re.S)
                    if m:
                        title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
                result = {"live": resp.status_code < 400,
                          "status": resp.status_code,
                          "url": str(resp.url),
                          "server": resp.headers.get("server", "")[:60],
                          "title": title, "ts": now}
                if resp.status_code < 400:
                    break
            except Exception:
                continue
        return host, result

    sem = asyncio.Semaphore(10)

    async def guarded(h: str):
        async with sem:
            return await check(h)

    out = dict(cached)
    for host, res in await asyncio.gather(*[guarded(h) for h in hosts]):
        out[host] = res

    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        s = dict(run.summary or {})
        s["subdomain_status"] = out
        run.summary = s
        session.commit()
    finally:
        session.close()
    live_count = sum(1 for v in out.values() if v.get("live"))
    return {"hosts": out, "count": len(out), "live": live_count}


@app.get("/api/runs/{run_id}/probe/port", dependencies=[Depends(gate)])
async def api_probe_port(run_id: str, host: str = Query(...), port: int = Query(...)):
    """Probe a single host:port for banner/service info.

    SSRF-guarded: host must be a run target or a subdomain from this run's
    findings, and the port must appear in this run's port findings.
    Read-only: TCP connect + short banner read, plus an HTTP GET on
    web-ish ports. Nothing is written.
    """
    import asyncio
    import re
    import httpx

    host = host.strip().lower().rstrip(".")
    if not re.match(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$", host) or not (1 <= port <= 65535):
        raise HTTPException(400, "bad host or port")

    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        rows = findings_dump(session, run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
    finally:
        session.close()

    allowed_hosts = set()
    for t in targets:
        for cand in (t.normalized or "", t.raw or ""):
            m = re.search(r"([a-z0-9]([a-z0-9.\-]*[a-z0-9])?)", cand.lower())
            if m:
                allowed_hosts.add(m.group(1).rstrip("."))
    for r in rows:
        if r.get("key") == "subdomain":
            v = (r.get("value") or "").split()[0].strip().lower().rstrip(".")
            if v:
                allowed_hosts.add(v)
    allowed_ports = set()
    for r in rows:
        if r.get("key") in ("port_open", "port_suggestion"):
            m = re.search(r"port (\d+)", (r.get("value") or "").lower())
            if m:
                allowed_ports.add(int(m.group(1)))
    if host not in allowed_hosts:
        raise HTTPException(403, "host was not found in this run")
    if port not in allowed_ports:
        raise HTTPException(403, "port was not found in this run")

    result: Dict = {"host": host, "port": port, "open": False,
                    "banner": "", "http": None}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5)
        result["open"] = True
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=3)
            result["banner"] = data.decode("utf-8", "replace").strip()[:200]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)[:100]
        return result

    # Web-ish ports: grab server header + title
    if port in (80, 443, 8000, 8080, 8443, 3000, 5000, 9000, 9200, 5601):
        scheme = "https" if port in (443, 8443) else "http"
        try:
            async with net.async_client(
                    timeout=8, follow_redirects=True,
                    headers={"User-Agent": "ReconAnything/1.0"}) as client:
                resp = await client.get(f"{scheme}://{host}:{port}/")
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:50000], re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            result["http"] = {"status": resp.status_code,
                              "server": resp.headers.get("server", "")[:60],
                              "title": title,
                              "url": str(resp.url)}
            if not result["banner"]:
                result["banner"] = f"HTTP {resp.status_code} {result['http']['server']}".strip()
        except Exception as e:
            result["http"] = {"error": str(e)[:100]}
    return result




@app.get("/api/diff", dependencies=[Depends(gate)])
def api_diff(a: str, b: str):
    session = get_session()
    try:
        return diff_runs(session, a, b)
    finally:
        session.close()


# -- assistant ---------------------------------------------------------------
# Uncensored AI assistant (AI Horde keyless backend). Detection/analysis
# only: it explains findings and suggests manual steps, never exploits.


class AssistantChatIn(BaseModel):
    messages: List[Dict[str, str]]
    run_id: Optional[str] = None


@app.post("/api/assistant/chat", dependencies=[Depends(gate)])
async def api_assistant_chat(body: AssistantChatIn):
    """Free-form chat, optionally grounded in a run's findings."""
    if not body.messages:
        raise HTTPException(400, "messages required")
    from .uncensored_assistant import assistant_chat
    reply = await assistant_chat(body.messages, body.run_id)
    return {"reply": reply}


class AssistantAgentIn(BaseModel):
    run_id: str
    instruction: str


@app.post("/api/assistant/agent", dependencies=[Depends(gate)])
async def api_assistant_agent(body: AssistantAgentIn):
    """Structured AI review of a run: gaps, deeper plugins, manual tests.

    Horde polling blocks on the network, so the review runs in a thread.
    """
    import asyncio
    from .uncensored_assistant import agent_review
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=body.run_id).first():
            raise missing_run(body.run_id)
    finally:
        session.close()
    review = await asyncio.to_thread(
        asyncio.run, agent_review(body.run_id, body.instruction))
    return review


class DeepRunIn(BaseModel):
    run_id: str
    plugin_ids: List[str]


@app.post("/api/assistant/deep-run", dependencies=[Depends(gate)])
async def api_assistant_deep_run(body: DeepRunIn):
    """Launch a new run against the original run's targets, but only with
    the specified detection plugins. Returns the new run id."""
    if not body.plugin_ids:
        raise HTTPException(400, "plugin_ids required")
    from .plugins.registry import describe
    known = {p["id"] for p in describe()}
    unknown = [p for p in body.plugin_ids if p not in known]
    if unknown:
        raise HTTPException(400, f"unknown plugin ids: {', '.join(unknown)}")
    plugin_ids = [p for p in body.plugin_ids if p in known]

    session = get_session()
    try:
        orig = session.query(Run).filter_by(id=body.run_id).first()
        if not orig:
            raise missing_run(body.run_id)
        targets = session.query(Target).filter_by(run_id=body.run_id).all()
        targets_text = "\n".join(t.raw for t in targets if t.raw)
        if not targets_text:
            raise HTTPException(400, "original run has no targets")
        new_run_id = uuid.uuid4().hex[:12]
        mode = orig.mode or "passive"
        source_type = getattr(orig, "source_type", None) or "website"
        session.add(Run(id=new_run_id, mode=mode, status="running",
                        source_type=source_type,
                        summary={"note": f"deep-run of {body.run_id}",
                                 "plugins": plugin_ids}))
        session.commit()
        keys = load_all(session)
    finally:
        session.close()
    # launch_run accepts plugin_ids natively and filters the plugin list
    # before launch; detection plugins only, nothing else changes.
    await launch_run(new_run_id, targets_text, mode, plugin_ids, {}, keys,
                     source_type=source_type)
    return {"new_run_id": new_run_id}


# -- ATM ---------------------------------------------------------------------
class AtmLocateIn(BaseModel):
    query: str
    authorized: bool = False


_ATM_AUTH_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "atm_auth.log")
_ATM_LATLON_RE = re.compile(
    r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*(?:,\s*(\d+(?:\.\d+)?))?\s*$")
_OSM_UA = "ReconAnything/1.0 (ATM security assessment module; contact: owner)"


def _atm_log_auth(run_id: str, query: str) -> None:
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        with open(_ATM_AUTH_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{ts}\trun={run_id}\tquery={query}\tauthorized=true\n")
    except Exception:
        pass


def _atm_geocode(text: str):
    """Text -> (lat, lon) via public Nominatim (no key)."""
    import httpx
    try:
        r = httpx.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": text, "format": "json", "limit": 1,
                    "email": "recon-atm@example.com"},
            headers={"User-Agent": _OSM_UA}, timeout=15)
        if r.status_code != 200:
            return None, f"geocode failed (HTTP {r.status_code})"
        items = r.json()
        if not items:
            return None, "geocode found nothing for that query"
        return (float(items[0]["lat"]), float(items[0]["lon"])), None
    except Exception as e:
        return None, f"geocode error: {e}"


_OVERPASS_MIRRORS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
]


def _atm_overpass(lat: float, lon: float, radius_m: float):
    """amenity=atm nodes near (lat, lon) via public Overpass API.

    Tries mirrors in order: a single mirror being unreachable (Jay hit
    Errno 101 on overpass-api.de) must not 502 the whole lookup.
    """
    import httpx
    ql = (f'[out:json][timeout:25];'
          f'node["amenity"="atm"](around:{int(radius_m)},{lat},{lon});'
          f'out center 50;')
    last_err = None
    for url in _OVERPASS_MIRRORS:
        try:
            r = httpx.post(url, data={"data": ql},
                           headers={"User-Agent": _OSM_UA}, timeout=20)
            if r.status_code != 200:
                last_err = f"Overpass failed (HTTP {r.status_code})"
                continue
            out = []
            for el in (r.json().get("elements") or [])[:50]:
                tags = el.get("tags") or {}
                out.append({
                    "name": tags.get("name", ""),
                    "operator": tags.get("operator") or tags.get("brand") or
                                tags.get("network") or "",
                    "lat": el.get("lat"),
                    "lon": el.get("lon"),
                })
            return out, None
        except Exception as e:
            last_err = f"Overpass error: {e}"
            continue
    return None, last_err or "Overpass unreachable"


@app.post("/api/runs/{run_id}/atm/locate", dependencies=[Depends(gate)])
def api_atm_locate(run_id: str, body: AtmLocateIn):
    """Public ATM locations via OpenStreetMap (read-only).

    Hard gate: body.authorized must be true, else 403. The claim is
    logged server-side for the audit trail.
    """
    if not body.authorized:
        raise HTTPException(
            status_code=403,
            detail="ATM location lookup requires explicit written "
                   "authorization (authorized=true)")
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise missing_run(run_id)
    finally:
        session.close()

    _atm_log_auth(run_id, body.query)

    q = (body.query or "").strip()
    if not q:
        raise HTTPException(400, "query required")
    m = _ATM_LATLON_RE.match(q)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        radius = float(m.group(3)) if m.group(3) else 2000
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise HTTPException(400, "latitude/longitude out of range")
        radius = max(100, min(radius, 20000))
    else:
        (lat, lon), err = _atm_geocode(q)
        if err:
            raise HTTPException(502, err)
        radius = 2000

    results, err = _atm_overpass(lat, lon, radius)
    if err:
        raise HTTPException(502, err)
    return {"run_id": run_id, "lat": lat, "lon": lon,
            "radius_m": int(radius), "atms": results}


# -- api key vault ----------------------------------------------------------
class KeyIn(BaseModel):
    name: str
    label: str = ""
    secret: str


@app.get("/api/keys", dependencies=[Depends(gate)])
def api_keys():
    session = get_session()
    try:
        return {"keys": key_status(session),
                "encrypted": bool(config.MASTER_KEY)}
    finally:
        session.close()


@app.post("/api/keys", dependencies=[Depends(gate)])
def api_key_add(body: KeyIn):
    session = get_session()
    try:
        row = session.query(ApiKey).filter_by(name=body.name).first()
        if row:
            row.secret_enc = encrypt(body.secret)
            row.label = body.label or row.label
        else:
            session.add(ApiKey(name=body.name, label=body.label or body.name,
                               secret_enc=encrypt(body.secret)))
        session.commit()
        return {"ok": True}
    finally:
        session.close()


@app.delete("/api/keys/{name}", dependencies=[Depends(gate)])
def api_key_del(name: str):
    session = get_session()
    try:
        session.query(ApiKey).filter_by(name=name).delete()
        session.commit()
        return {"ok": True}
    finally:
        session.close()


# -- schedules ---------------------------------------------------------------
class SchedIn(BaseModel):
    target_raw: str
    cron: str
    mode: str = "passive"
    enabled: bool = True


@app.get("/api/schedules", dependencies=[Depends(gate)])
def api_sched_list():
    session = get_session()
    try:
        rows = session.query(Schedule).all()
        return {"schedules": [
            {"id": s.id, "target_raw": s.target_raw, "cron": s.cron,
             "mode": s.mode, "enabled": s.enabled,
             "last_run_id": s.last_run_id} for s in rows]}
    finally:
        session.close()


@app.post("/api/schedules", dependencies=[Depends(gate)])
def api_sched_add(body: SchedIn):
    session = get_session()
    try:
        sid = uuid.uuid4().hex[:12]
        session.add(Schedule(id=sid, target_raw=body.target_raw,
                             cron=body.cron, mode=body.mode,
                             enabled=body.enabled))
        session.commit()
        return {"ok": True, "id": sid}
    finally:
        session.close()


@app.delete("/api/schedules/{sid}", dependencies=[Depends(gate)])
def api_sched_del(sid: str):
    session = get_session()
    try:
        session.query(Schedule).filter_by(id=sid).delete()
        session.commit()
        return {"ok": True}
    finally:
        session.close()


# -- breach watch ------------------------------------------------------------
# Defensive: Jay's own addresses checked against public breach dumps
# (XposedOrNot, keyless). Never attempts logins.

_BW_DIR = Path(__file__).resolve().parent
_BW_EMAILS_FILE = _BW_DIR / "breachwatch_emails.json"
_BW_CACHE_FILE = _BW_DIR / "breachwatch_cache.json"


def _bw_load_emails() -> List[Dict]:
    try:
        data = json.loads(_BW_EMAILS_FILE.read_text())
        out = []
        for e in (data.get("emails") or []):
            addr = str(e.get("email", "")).strip().lower()
            if "@" in addr:
                out.append({"email": addr,
                            "label": str(e.get("label", ""))})
        return out
    except Exception:
        return []


def _bw_load_cache() -> Dict:
    try:
        return json.loads(_BW_CACHE_FILE.read_text())
    except Exception:
        return {}


def _bw_save_cache(cache: Dict) -> None:
    try:
        _BW_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        pass


class BreachCheckIn(BaseModel):
    email: str


@app.get("/api/breachwatch", dependencies=[Depends(gate)])
def api_breachwatch_list():
    emails = _bw_load_emails()
    cache = _bw_load_cache()
    return {"emails": [
        {"email": e["email"], "label": e["label"],
         "cached": cache.get(e["email"])} for e in emails],
        "configured": bool(emails),
        "hint": ("Copy backend/app/breachwatch_emails.json.example to "
                 "breachwatch_emails.json and add your own addresses.")
        if not emails else ""}


@app.post("/api/breachwatch/check", dependencies=[Depends(gate)])
async def api_breachwatch_check(body: BreachCheckIn):
    from .plugins.breachwatch import check_email_breaches
    email = (body.email or "").strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="not a valid email")
    import httpx
    async with httpx.AsyncClient(timeout=30) as http:
        status, breaches, note = await check_email_breaches(email, http)
    result = {
        "email": email,
        "status": status,  # breached | clean | rate_limited | unreachable | invalid
        "breaches": breaches,
        "note": note,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "guidance": ("If breached: change that password everywhere you reused "
                     "it, starting with email and banking. Enable 2FA."),
    }
    cache = _bw_load_cache()
    cache[email] = result
    _bw_save_cache(cache)
    return result
