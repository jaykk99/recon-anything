"""ReconAnything API (FastAPI).

Routes:
  GET  /api/health
  POST /api/classify            single + batch input classification
  GET  /api/plugins             plugin registry with key status
  POST /api/runs                start a run (returns run_id)
  GET  /api/runs/{id}/stream    SSE live progress + findings
  GET  /api/runs                list runs
  GET  /api/runs/{id}           run detail + findings + summary
  POST /api/runs/{id}/findings/{fid}/retest
                                findings playground: re-run that finding's
                                own plugin on its own target, compare fresh
  GET  /api/runs/{id}/graph     correlation graph payload
  GET  /api/runs/{id}/apimap    assembled API map
  GET  /api/runs/{id}/export    ?format=json|csv|md|html
  GET  /api/diff?a=&b=          diff two runs
  GET/POST/DELETE /api/keys     API key vault
  GET/POST/DELETE /api/schedules

  GET  /api/runs/{id}/agent-activity  per-run agent feed + rollup
  GET  /api/hunters             hunter roster + lifetime stats
  GET  /api/hunters/memory      per-target hunt memory (?target=)
  GET  /api/hunters/known-set   a target's full known set (?target=)
  GET  /api/hunters/knowledge   knowledge pack inventory
  GET  /api/hunters/resources   resource library catalog + cache status
  GET/POST /api/agentdata/...   agent data service (packs, known set,
                                memory, dead ends, recent finds, library)

The agents do not chat, they hunt: there is no assistant or chat route.
Hunters work through the agent data service (app/agentdata).

Gate (two modes, flipped by configuration - billing.signin_mode):
  - Sign-in mode (GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET set): the
    legacy access code is retired and NOT accepted anywhere; every
    /api route except /api/health, /api/me and /api/plans requires a
    GitHub session cookie. The owner login gets full access; other
    signed-in accounts are plan-gated customers.
  - Fallback mode (OAuth not configured): if RECON_ACCESS_CODE is
    set, every /api route except /api/health requires header
    X-Access-Code (a GitHub session is also accepted, as before).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (HTMLResponse, PlainTextResponse,
                               RedirectResponse, StreamingResponse)
from pydantic import BaseModel
from typing import Dict, List, Optional

from . import billing
from . import config
from . import net
from .classifier import classify, classify_batch
from .diff import diff_runs
from .graph import graph_payload
from .keys import encrypt, key_status, load_all
from .models import (ApiKey, Finding, FindingReveal, Order,
                     Run, RunEvent, Schedule, Target, User,
                     get_session, init_db)
from .models import check_db, DATABASE_URL, IS_SQLITE
from .plugins.registry import describe
from .reporting import (executive_summary, findings_dump, run_progress,
                         to_csv, to_html, to_markdown)
from .runner import launch_run, subscribe

log = logging.getLogger("recon-anything")


def _wake_worker() -> None:
    """Ping the standalone worker service so a free-tier instance that
    spun down wakes up and starts claiming the run just created.

    Fire-and-forget: a background thread with a short timeout, all
    errors swallowed. No-op when RECON_WORKER_URL is unset (worker
    in-process or always-on hosting)."""
    url = os.environ.get("RECON_WORKER_URL", "").rstrip("/")
    if not url:
        return

    def _ping() -> None:
        try:
            import urllib.request
            req = urllib.request.Request(url + "/", method="GET")
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:
            pass

    import threading
    threading.Thread(target=_ping, daemon=True).start()


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


def _session_user(request: Request):
    """The GitHub-signed-in customer for this request, or None.

    Identity comes from the HMAC-signed session cookie set by the
    GitHub OAuth callback (app/billing.py). Never raises.
    """
    try:
        uid = billing.parse_session_token(
            request.cookies.get(billing.SESSION_COOKIE))
        if uid is None:
            return None
        session = get_session()
        try:
            return session.query(User).filter_by(id=uid).first()
        finally:
            session.close()
    except Exception:
        return None


def resolve_actor(request: Request, provided_code: Optional[str] = None):
    """Who is calling: {"kind": "owner"|"user"|"open"|"anon",
    "user": User|None}.

    - owner: the signed-in GitHub account is the owner login - or, in
      fallback mode only, the access code matched. Full access, never
      any payment UI or plan gate.
    - user:  a signed-in customer; plan gating applies.
    - open:  fallback mode with no access code configured (local dev)
      - treated as owner.
    - anon:  nobody the gate accepts; gated routes answer 401.

    In sign-in mode (billing.signin_mode) the access code is retired:
    provided_code is ignored entirely, so the old code stops working
    the moment the GitHub OAuth env vars land - the only way in is a
    GitHub session.
    """
    if billing.signin_mode():
        user = _session_user(request)
        if user is not None:
            if billing.is_owner_login(user.github_login):
                return {"kind": "owner", "user": user}
            return {"kind": "user", "user": user}
        return {"kind": "anon", "user": None}
    if config.ACCESS_CODE and provided_code == config.ACCESS_CODE:
        return {"kind": "owner", "user": None}
    user = _session_user(request)
    if user is not None:
        if billing.is_owner_login(user.github_login):
            return {"kind": "owner", "user": user}
        return {"kind": "user", "user": user}
    if not config.ACCESS_CODE:
        return {"kind": "open", "user": None}
    return {"kind": "anon", "user": None}


def gate(request: Request,
         x_access_code: Optional[str] = Header(default=None),
         code: Optional[str] = Query(default=None)):
    # EventSource cannot set headers, so accept ?code= as a fallback.
    # In fallback mode a valid GitHub session cookie is the customer
    # alternative to the owner's access code (Jay's mode is unchanged).
    # In sign-in mode the code is retired: resolve_actor ignores it and
    # only the session cookie counts.
    provided = x_access_code or code
    actor = resolve_actor(request, provided)
    if actor["kind"] == "anon":
        if billing.signin_mode():
            raise HTTPException(status_code=401,
                                detail="sign in with GitHub required")
        raise HTTPException(status_code=401, detail="bad access code")
    request.state.actor = actor
    return True


@app.on_event("startup")
async def _startup():
    # Start accepting requests immediately; do heavy init in background
    # so Render's health check doesn't time out on slow cold starts.
    import threading
    import asyncio
    # Boot instant: _recover_pending_runs only replays runs created
    # BEFORE this process started. A run created after boot may still
    # have its original enqueue task in flight in this process, and
    # replaying it would double-enqueue; the boot cutoff rules that out.
    _boot_started = dt.datetime.now(dt.timezone.utc)
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
                        pending = (r.summary or {}).get("pending_enqueue")
                        if pending is not None:
                            has_targets = (session.query(Target)
                                           .filter_by(run_id=r.id)
                                           .count() > 0)
                            if not has_targets:
                                # Enqueue died mid-setup (deploy/crash)
                                # before writing anything: leave it
                                # "running" for _recover_pending_runs to
                                # replay at boot instead of failing a
                                # scan the user never saw start.
                                continue
                            # Targets exist but no jobs: replay would
                            # duplicate rows (random target ids), so
                            # this partial enqueue still fails loudly
                            # below, as before.
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

    # Replay enqueue intents orphaned by a deploy/crash mid-setup (see
    # api_start_run). Runs after _db_ready so boot init's failed-marking
    # has already settled the partial-enqueue cases; this task only sees
    # clean 0-target/0-job runs, which replay without duplicating rows.
    async def _recover_pending_runs():
        try:
            await asyncio.wait_for(_db_ready.wait(), timeout=120)
        except asyncio.TimeoutError:
            log.warning("DB init timed out, skipping pending-run recovery")
            return
        # Grace delay (default 180s, env-tunable for tests): a Render
        # deploy briefly runs the old and new instances side by side,
        # and the old instance may still be finishing an enqueue for a
        # run created before this boot. Replaying immediately could
        # double-enqueue it. Waiting past the deploy overlap, then
        # re-checking for jobs/targets, means a replay only ever fires
        # for an enqueue whose process is certainly dead; a run whose
        # original enqueue completed in the meantime is skipped by the
        # jobs/targets checks below.
        try:
            _delay = int(os.environ.get(
                "RECON_PENDING_RECOVERY_DELAY_S", "180"))
        except ValueError:
            _delay = 180
        if _delay > 0:
            await asyncio.sleep(_delay)
        try:
            from .models import PluginJob as _PJ
            session = get_session()
            try:
                candidates = (session.query(Run)
                              .filter_by(status="running").all())
                pending = []
                for r in candidates:
                    intent = (r.summary or {}).get("pending_enqueue")
                    if intent is None:
                        continue
                    _created = r.created_at
                    if _created is not None:
                        # SQLite returns naive datetimes; Postgres aware.
                        if _created.tzinfo is None:
                            _created = _created.replace(
                                tzinfo=dt.timezone.utc)
                        if _created >= _boot_started:
                            # created after boot: enqueue may be live
                            continue
                    if session.query(_PJ).filter_by(run_id=r.id).count():
                        continue  # worker resumes this run
                    if session.query(Target).filter_by(run_id=r.id).count():
                        continue  # partial enqueue: boot init failed it
                    pending.append((r.id, intent))
            finally:
                session.close()
            for run_id, intent in pending:
                try:
                    await launch_run(run_id, intent.get("targets", ""),
                                     intent.get("mode", "passive"),
                                     intent.get("plugins"),
                                     intent.get("module_overrides"),
                                     None,
                                     source_type=intent.get("source_type",
                                                            "website"),
                                     bounty=bool(intent.get("bounty")),
                                     excluded_plugin_ids=intent.get(
                                         "excluded_plugin_ids"))
                    _wake_worker()
                    log.info("recovered pending run %s (interrupted "
                             "enqueue replayed)", run_id)
                except Exception as e:
                    log.error("pending-run recovery failed for %s: %s",
                              run_id, e)
        except Exception as e:
            log.error("pending-run recovery failed: %s", e)
    asyncio.create_task(_recover_pending_runs())


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
    source_type: str = "website"  # website | bank | atm | bankatm
    bounty: bool = False  # bounty mode: prioritize high-impact vuln classes


@app.post("/api/runs", dependencies=[Depends(gate)])
async def api_start_run(body: RunIn, request: Request):
    if not body.targets.strip():
        raise HTTPException(400, "targets required")
    if body.mode not in ("passive", "active"):
        raise HTTPException(400, "mode must be passive|active")
    if body.source_type not in ("website", "bank", "atm", "bankatm"):
        raise HTTPException(400,
                            "source_type must be website|bank|atm|bankatm")
    # --- plan gating (customers only; owner/open mode unchanged) ------
    actor = getattr(request.state, "actor", {"kind": "open", "user": None})
    run_user_id = None
    excluded_plugin_ids: Optional[List[str]] = None
    plugins = body.plugins
    if actor["kind"] == "user":
        user = actor["user"]
        run_user_id = user.id
        plan = billing.effective_plan(user)
        limit = plan.get("scans_per_day")
        if limit is not None:
            s = get_session()
            try:
                used = (s.query(Run)
                        .filter(Run.user_id == user.id,
                                Run.created_at >= billing.today_start_utc())
                        .count())
            finally:
                s.close()
            if used >= limit:
                raise HTTPException(
                    429,
                    f"{plan['name']} plan allows {limit} scans per day. "
                    "Upgrade on /pricing for more.")
        allowed, stripped = billing.filter_plugins_for_plan(plan, plugins)
        if plugins and stripped and not allowed:
            raise HTTPException(
                403,
                "The Crypto Pack is a Pro feature. Upgrade on /pricing, "
                "or run without the cp_* plugins.")
        plugins = allowed
        if not plugins:
            from .plugins.registry import describe as _describe
            excluded_plugin_ids = billing.excluded_plugins_for_plan(
                plan, [p["id"] for p in _describe()]) or None
    # Bank/ATM source types imply explicit authorization: the user picked
    # the mode on purpose. Record it as an audit finding in the run.
    overrides = dict(body.module_overrides or {})
    if body.source_type == "bank":
        overrides["bank"] = "authorized"
    elif body.source_type == "atm":
        overrides["atm"] = "authorized"
    elif body.source_type == "bankatm":
        # Bank/ATM mode is one deliberate pick: both modules authorized.
        overrides["bank"] = "authorized"
        overrides["atm"] = "authorized"
    run_id = uuid.uuid4().hex[:12]
    session = get_session()
    try:
        # pending_enqueue: durable enqueue intent, written in the SAME
        # commit as the Run row so there is no window where a run exists
        # without a recoverable record of how to enqueue it. Bank/ATM
        # location runs spend seconds on network geocode/POI resolution
        # BEFORE writing any target or job (see _enqueue_bankatm_run):
        # a deploy/crash in that window used to leave the run at 0 jobs
        # with nothing resumable, and boot init marked it failed. The
        # intent is cleared by execute_run on normal completion (see its
        # finally block) and replayed at boot by _recover_pending_runs
        # only for runs created before this process booted with still
        # zero targets and zero jobs, so a replay can never duplicate
        # rows (target ids are random uuids) or double-run a live
        # enqueue. No new columns: it lives in the existing summary JSON.
        session.add(Run(id=run_id, mode=body.mode, status="running",
                        user_id=run_user_id,
                        source_type=body.source_type,
                        summary={"bounty": bool(body.bounty),
                                 "pending_enqueue": {
                                     "targets": body.targets,
                                     "mode": body.mode,
                                     "plugins": plugins,
                                     "module_overrides": overrides,
                                     "source_type": body.source_type,
                                     "bounty": bool(body.bounty),
                                     "excluded_plugin_ids":
                                         excluded_plugin_ids}}))
        session.commit()
        keys = load_all(session)
    finally:
        session.close()
    await launch_run(run_id, body.targets, body.mode,
                     plugins, overrides, keys,
                     source_type=body.source_type, bounty=body.bounty,
                     excluded_plugin_ids=excluded_plugin_ids)
    _wake_worker()
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
def api_list_runs(request: Request = None,
                  limit: int = Query(30, le=200),
                  summary: bool = Query(False,
                                        description="include each run's full "
                                        "summary JSON (heavy; default off)")):
    # Perf: the list view only needs light columns. The summary JSON blob
    # (executive summary, plugin stats) made this endpoint ~6s idle because
    # 30 full rows were deserialized per poll. load_only keeps the heavy
    # summary column out unless ?summary=1 is passed explicitly.
    from sqlalchemy.orm import load_only
    from sqlalchemy import func
    fields = [Run.id, Run.mode, Run.status, Run.source_type,
              Run.created_at]
    if summary:
        fields.append(Run.summary)
    session = get_session()
    try:
        q = session.query(Run).options(load_only(*fields))
        # Customers see only their own runs; the owner sees everything.
        # request is None only for direct internal calls (tests) - the
        # HTTP path always goes through the gate, which sets the actor.
        actor = (getattr(request.state, "actor", {"kind": "open"})
                 if request is not None else {"kind": "open"})
        if actor["kind"] == "user":
            q = q.filter(Run.user_id == actor["user"].id)
        runs = (q.order_by(Run.created_at.desc()).limit(limit).all())
        # One GROUP BY for findings counts (indexed on findings.run_id) so
        # the list table keeps its "findings" column without the heavy
        # per-run summary JSON.
        counts = dict(
            session.query(Finding.run_id, func.count(Finding.id))
            .filter(Finding.run_id.in_([r.id for r in runs]))
            .group_by(Finding.run_id).all()) if runs else {}
        out = []
        for r in runs:
            row = {"id": r.id, "mode": r.mode, "status": r.status,
                   "source_type": getattr(r, "source_type", None) or "website",
                   "created_at": r.created_at.isoformat()
                   if r.created_at else None,
                   "findings_count": counts.get(r.id, 0)}
            if summary:
                row["summary"] = r.summary or {}
            out.append(row)
        return {"runs": out}
    finally:
        session.close()


@app.get("/api/runs/{run_id}", dependencies=[Depends(gate)])
def api_run_detail(run_id: str, request: Request, show_secrets: bool = False):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        # Customers can only open their own runs.
        actor = getattr(request.state, "actor", {"kind": "open"})
        access = None
        if actor["kind"] == "user":
            if run.user_id != actor["user"].id:
                raise missing_run(run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=show_secrets)
        if actor["kind"] == "user":
            # Free tier: exactly 1 revealed finding per UTC day,
            # enforced here on the server, not in the UI.
            rows, access = billing.apply_reveal(
                session, actor["user"], run_id, rows,
                billing.effective_plan(actor["user"]))
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
            "access": access,
            "executive_summary": executive_summary(rows),
            # Live progress for the UI poll fallback (SSE may be down):
            # done/total, eta_s, and currently-running plugin names.
            "progress": run_progress(session, run_id),
        }
    finally:
        session.close()


@app.get("/api/runs/{run_id}/agent-activity",
         dependencies=[Depends(gate)])
def api_run_agent_activity(run_id: str, limit: int = 500):
    """Live agent-activity feed for one run: every hunt_actions row
    in order with a plain-language description and agent
    attribution, plus a per-agent rollup (actions, assets found,
    jobs queued, findings those jobs produced, status). The UI polls
    this while a scan runs so Jay can watch the agents work."""
    from .agentdata import store
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        return store.run_agent_activity(
            session, store.DEFAULT_SYSTEM, run_id, limit=limit)
    finally:
        session.close()


@app.post("/api/runs/{run_id}/findings/{finding_id}/retest",
          dependencies=[Depends(gate)])
async def api_finding_retest(run_id: str, finding_id: int):
    """Findings playground: re-run the ONE plugin that produced this
    finding, against this finding's own target, and compare fresh vs
    stored (unchanged / changed / gone / error).

    The plugin and target come from the stored finding itself - the
    caller cannot name a URL, a plugin, or a payload, so this cannot
    be used as a general request tool. Fresh findings are returned,
    never written back to the run. Rate limited per finding
    (app/playground.py). See app/playground.py for the full design.
    """
    from .playground import PlaygroundError, retest_finding
    try:
        return await retest_finding(run_id, finding_id)
    except PlaygroundError as e:
        headers = {}
        if e.retry_after:
            headers["Retry-After"] = str(int(e.retry_after) + 1)
        raise HTTPException(e.status_code, e.detail, headers=headers)


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
def api_export(run_id: str, request: Request, format: str = "json",
               show_secrets: bool = False):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise missing_run(run_id)
        actor = getattr(request.state, "actor", {"kind": "open"})
        if actor["kind"] == "user" and run.user_id != actor["user"].id:
            raise missing_run(run_id)
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=show_secrets)
        if actor["kind"] == "user":
            # Same free-tier reveal cap as the run detail view: exports
            # are not a way around the lock.
            rows, _access = billing.apply_reveal(
                session, actor["user"], run_id, rows,
                billing.effective_plan(actor["user"]))
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


# -- agent data service -------------------------------------------------------
# The learning/data layer FOR the agents (app/agentdata). Hunters call
# these functions in-process and can call the same shapes over HTTP;
# the namespace (system) keeps other agent systems' data separate.
# Same access-code gate as every other /api route.


@app.get("/api/agentdata/packs", dependencies=[Depends(gate)])
def api_agentdata_packs():
    from .agentdata import packs
    return {"packs": packs.pack_inventory()}


@app.get("/api/agentdata/packs/{name}", dependencies=[Depends(gate)])
def api_agentdata_pack(name: str):
    from .agentdata import packs
    raw = packs.pack_raw(name)
    if raw is None:
        raise HTTPException(404, "unknown pack")
    return {"name": name, "entries": packs.pack_entries(name), "raw": raw}


@app.get("/api/agentdata/known", dependencies=[Depends(gate)])
def api_agentdata_known(system: str = "recon", target: str = ""):
    from .agentdata import store
    if not target:
        raise HTTPException(400, "target required")
    session = get_session()
    try:
        assets = store.get_known_set(session, system, target)
        return {"system": system, "target": target, "count": len(assets),
                "assets": assets}
    finally:
        session.close()


class KnownIn(BaseModel):
    system: str = "recon"
    target: str
    asset_type: str
    value: str
    found_by: str = ""
    run_id: str = ""


@app.post("/api/agentdata/known", dependencies=[Depends(gate)])
def api_agentdata_known_add(body: KnownIn):
    from .agentdata import store
    session = get_session()
    try:
        _row, created = store.add_known_asset(
            session, body.system, body.target, body.asset_type, body.value,
            found_by=body.found_by, run_id=body.run_id)
        return {"ok": True, "created": created}
    finally:
        session.close()


@app.get("/api/agentdata/memory", dependencies=[Depends(gate)])
def api_agentdata_memory(system: str = "recon", target: str = ""):
    from .agentdata import store
    if not target:
        raise HTTPException(400, "target required")
    session = get_session()
    try:
        return store.get_memory(session, system, target)
    finally:
        session.close()


class DeadEndIn(BaseModel):
    system: str = "recon"
    target: str
    asset_type: str
    value: str
    run_id: str = ""
    reason: str = ""


@app.post("/api/agentdata/dead-ends", dependencies=[Depends(gate)])
def api_agentdata_dead_end(body: DeadEndIn):
    from .agentdata import store
    session = get_session()
    try:
        created = store.add_dead_end(session, body.system, body.target,
                                     body.asset_type, body.value,
                                     run_id=body.run_id, reason=body.reason)
        return {"ok": True, "created": created}
    finally:
        session.close()


@app.get("/api/agentdata/finds", dependencies=[Depends(gate)])
def api_agentdata_finds(system: str = "recon", limit: int = 50,
                        target: str = "", hunter: str = ""):
    from .agentdata import store
    session = get_session()
    try:
        return {"finds": store.recent_finds(
            session, system, limit=min(limit, 200),
            target_key=target or None, hunter=hunter or None)}
    finally:
        session.close()


@app.get("/api/agentdata/resources", dependencies=[Depends(gate)])
def api_agentdata_resources():
    from .agentdata import resources
    session = get_session()
    try:
        return {"resources": resources.catalog(session)}
    finally:
        session.close()


@app.post("/api/agentdata/resources/{resource_id}/fetch",
          dependencies=[Depends(gate)])
def api_agentdata_resource_fetch(resource_id: str):
    from .agentdata import resources
    session = get_session()
    try:
        result = resources.fetch_resource(session, resource_id)
        if not result.get("ok"):
            raise HTTPException(400, result.get("error", "fetch failed"))
        return result
    finally:
        session.close()


# -- hunters (human view, read-only, same data service) ------------------------

@app.get("/api/hunters", dependencies=[Depends(gate)])
def api_hunters():
    from .agentdata import store
    from .hunters.roles import HUNTERS
    session = get_session()
    try:
        stats = store.hunter_stats(session, store.DEFAULT_SYSTEM)
    finally:
        session.close()
    out = []
    for h in HUNTERS:
        s = stats.get(h["name"], {})
        out.append({**h, "stats": {
            "assets_discovered": s.get("assets_discovered", 0),
            "jobs_enqueued": s.get("jobs_enqueued", 0),
            "dead_ends": s.get("dead_ends", 0),
            "assets_in_known_set": s.get("assets_in_known_set", 0)}})
    return {"hunters": out, "count": len(out)}


@app.get("/api/hunters/memory", dependencies=[Depends(gate)])
def api_hunters_memory(target: str = ""):
    from .agentdata import store
    if not target:
        raise HTTPException(400, "target required")
    session = get_session()
    try:
        mem = store.get_memory(session, store.DEFAULT_SYSTEM, target)
        counts = store.known_counts(session, store.DEFAULT_SYSTEM, target)
        mem["known_set_counts"] = counts
        mem["known_set_total"] = sum(counts.values())
        return mem
    finally:
        session.close()


@app.get("/api/hunters/known-set", dependencies=[Depends(gate)])
def api_hunters_known_set(target: str = ""):
    from .agentdata import store
    if not target:
        raise HTTPException(400, "target required")
    session = get_session()
    try:
        assets = store.get_known_set(session, store.DEFAULT_SYSTEM, target)
        grouped: Dict[str, list] = {}
        for a in assets:
            grouped.setdefault(a["type"], []).append(a)
        return {"target": target, "total": len(assets),
                "counts": {k: len(v) for k, v in grouped.items()},
                "assets": assets, "grouped": grouped}
    finally:
        session.close()


@app.get("/api/hunters/knowledge", dependencies=[Depends(gate)])
def api_hunters_knowledge():
    from .agentdata import packs
    return {"packs": packs.pack_inventory()}


@app.get("/api/hunters/resources", dependencies=[Depends(gate)])
def api_hunters_resources():
    from .agentdata import resources
    session = get_session()
    try:
        return {"resources": resources.catalog(session)}
    finally:
        session.close()


# -- product: plans, GitHub sign-in, BTC checkout (app/billing.py) --------
# Owner rule: the jaykk99 GitHub account (OWNER_GITHUB_LOGIN) gets full
# access and NO payment UI data, ever - /api/me reports
# show_payment_ui=False and plan payloads for the owner carry no
# checkout fields. Free customers: exactly 1 revealed finding per UTC
# day, enforced server-side in api_run_detail / api_export above.


def _me_payload(request: Request) -> Dict:
    actor = resolve_actor(request, request.headers.get("x-access-code"))
    # The owner branches below deliberately omit checkout_enabled:
    # no payment UI data is ever served to the owner account.
    base = {"github_enabled": billing.github_enabled(),
            # Which door the UI should show: "github" in sign-in mode
            # (access code retired, no code field anywhere), else
            # "access_code" (the legacy fallback gate).
            "auth_mode": ("github" if billing.signin_mode()
                          else "access_code"),
            "free_reveals_per_day": billing.FREE_REVEALS_PER_DAY,
            "day_boundary": "UTC"}
    user = actor.get("user")
    if actor["kind"] == "owner" and user is not None:
        # Signed-in owner: suppress every scrap of payment UI data.
        return {**base, "signed_in": True, "is_owner": True,
                "show_payment_ui": False,
                "user": {"login": user.github_login},
                "plan": {"id": "owner", "name": "Owner",
                         "full_findings": True, "crypto_pack": True,
                         "scans_per_day": None}}
    if actor["kind"] == "owner":
        # Access-code session (Jay's existing mode). Payment UI is for
        # customers; the owner never sees it in his own app either.
        return {**base, "signed_in": False, "is_owner": True,
                "show_payment_ui": False, "user": None,
                "plan": {"id": "owner", "name": "Owner",
                         "full_findings": True, "crypto_pack": True,
                         "scans_per_day": None}}
    if user is None:
        return {**base, "signed_in": False, "is_owner": False,
                "show_payment_ui": True,
                "checkout_enabled": billing.checkout_enabled(),
                "user": None,
                "plan": dict(billing.PLANS["free"])}
    plan = billing.effective_plan(user)
    session = get_session()
    try:
        reveals_used = (session.query(FindingReveal)
                        .filter_by(user_id=user.id,
                                   day=billing.today_key()).count())
        scans_used = (session.query(Run)
                      .filter(Run.user_id == user.id,
                              Run.created_at >= billing.today_start_utc())
                      .count())
    finally:
        session.close()
    return {**base, "signed_in": True, "is_owner": False,
            "show_payment_ui": True,
            "checkout_enabled": billing.checkout_enabled(),
            "user": {"login": user.github_login},
            "plan": dict(plan),
            "reveals_used_today": reveals_used,
            "scans_used_today": scans_used}


@app.get("/api/me")
def api_me(request: Request):
    """Identity + plan for whoever is asking (no gate: anonymous gets
    the free-plan payload plus the sign-in/checkout availability flags
    the pricing page renders from)."""
    return _me_payload(request)


@app.get("/api/plans")
def api_plans():
    return {"plans": billing.public_plans(),
            "github_enabled": billing.github_enabled(),
            "auth_mode": ("github" if billing.signin_mode()
                          else "access_code"),
            "checkout_enabled": billing.checkout_enabled(),
            "free_rule": ("Free plan: exactly 1 revealed finding per day "
                          "(resets at UTC midnight). Scans still run in "
                          "full; the rest are shown as locked counts.")}


def _cookie_secure() -> bool:
    return os.environ.get("RECON_COOKIE_SECURE", "1") != "0"


def _github_start():
    if not billing.github_enabled():
        return RedirectResponse("/pricing?signin=soon", status_code=303)
    state, state_cookie = billing.make_state_pair()
    from urllib.parse import urlencode
    qs = urlencode({
        "client_id": os.environ["GITHUB_CLIENT_ID"],
        "scope": "read:user",
        "state": state,
        "allow_signup": "true",
    })
    resp = RedirectResponse(
        f"https://github.com/login/oauth/authorize?{qs}", status_code=303)
    resp.set_cookie("recon_oauth_state", state_cookie, max_age=600,
                    httponly=True, samesite="lax", secure=_cookie_secure())
    return resp


def _github_callback(request: Request, code: str = "",
                     state: str = ""):
    if not billing.github_enabled():
        return RedirectResponse("/pricing?signin=soon", status_code=303)
    if not code or not billing.check_state_token(
            request.cookies.get("recon_oauth_state"), state):
        return RedirectResponse("/pricing?signin=failed", status_code=303)
    import httpx
    try:
        tok = httpx.post(
            "https://github.com/login/oauth/access_token",
            data={"client_id": os.environ["GITHUB_CLIENT_ID"],
                  "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
                  "code": code},
            headers={"Accept": "application/json"}, timeout=20)
        access = tok.json().get("access_token")
        if not access:
            return RedirectResponse("/pricing?signin=failed", status_code=303)
        me = httpx.get("https://api.github.com/user",
                       headers={"Authorization": f"Bearer {access}",
                                "Accept": "application/vnd.github+json"},
                       timeout=20)
        gh = me.json()
        gh_id, gh_login = int(gh["id"]), str(gh["login"])
    except Exception:
        return RedirectResponse("/pricing?signin=failed", status_code=303)
    session = get_session()
    try:
        user = session.query(User).filter_by(github_id=gh_id).first()
        if user is None:
            user = User(github_id=gh_id, github_login=gh_login, plan="free")
            session.add(user)
            session.commit()
        elif user.github_login != gh_login:
            user.github_login = gh_login
            session.commit()
        token = billing.make_session_token(user.id)
    finally:
        session.close()
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(billing.SESSION_COOKIE, token,
                    max_age=billing.SESSION_TTL_S, httponly=True,
                    samesite="lax", secure=_cookie_secure())
    resp.delete_cookie("recon_oauth_state")
    return resp


# The brief's callback path is /auth/github/callback; the /api/* twins
# are the ones reachable through the site domain (the frontend proxies
# only /api/*), so the GitHub OAuth app should register the /api one.
@app.get("/auth/github")
@app.get("/api/auth/github")
def api_github_start():
    return _github_start()


@app.get("/auth/github/callback")
@app.get("/api/auth/github/callback")
def api_github_callback(request: Request, code: str = "", state: str = ""):
    return _github_callback(request, code=code, state=state)


@app.post("/api/auth/logout")
def api_logout():
    resp = PlainTextResponse("ok")
    resp.delete_cookie(billing.SESSION_COOKIE)
    return resp


class OrderIn(BaseModel):
    plan: str


def _order_payload(o: Order, login: Optional[str] = None) -> Dict:
    out = {"id": o.id, "plan": o.plan, "amount_usd": o.amount_usd,
           "amount_btc": o.amount_btc, "btc_address": o.btc_address,
           "status": o.status,
           "created_at": o.created_at.isoformat() if o.created_at else None,
           "paid_at": o.paid_at.isoformat() if o.paid_at else None,
           "activation": ("Your plan activates after your BTC payment "
                          "confirms and the owner approves the order "
                          "(usually same day).")}
    if login:
        out["user_login"] = login
    return out


@app.post("/api/orders", dependencies=[Depends(gate)])
def api_order_create(body: OrderIn, request: Request):
    actor = getattr(request.state, "actor", {"kind": "open", "user": None})
    if actor["kind"] == "owner":
        raise HTTPException(400, "the owner account needs no plan")
    user = actor.get("user")
    if user is None:
        raise HTTPException(401, "sign in with GitHub to buy a plan")
    plan = billing.PLANS.get((body.plan or "").lower())
    if plan is None or plan["price_usd"] <= 0:
        raise HTTPException(400, "plan must be starter, pro or agency")
    if not billing.checkout_enabled():
        # No wallet address configured: never invent one.
        return {"checkout_open": False, "status": "checkout_closed",
                "message": "Checkout opens soon."}
    rate = billing.fetch_btc_usd()
    if rate is None:
        raise HTTPException(503, "BTC rate unavailable right now; "
                                 "try again in a minute")
    amount_btc = billing.btc_amount_for_usd(plan["price_usd"], rate)
    order = Order(id=uuid.uuid4().hex[:12], user_id=user.id,
                  plan=plan["id"], amount_usd=plan["price_usd"],
                  amount_btc=str(amount_btc),
                  btc_address=billing.btc_address(), status="pending")
    session = get_session()
    try:
        session.add(order)
        session.commit()
        payload = _order_payload(order)
    finally:
        session.close()
    return {"checkout_open": True, "order": payload,
            "checkout_path": f"/checkout?order={order.id}"}


@app.get("/api/orders", dependencies=[Depends(gate)])
def api_orders_mine(request: Request):
    actor = getattr(request.state, "actor", {"kind": "open", "user": None})
    user = actor.get("user")
    if user is None:
        return {"orders": []}
    session = get_session()
    try:
        rows = (session.query(Order).filter_by(user_id=user.id)
                .order_by(Order.created_at.desc()).all())
        return {"orders": [_order_payload(o) for o in rows]}
    finally:
        session.close()


@app.get("/api/orders/{order_id}", dependencies=[Depends(gate)])
def api_order_detail(order_id: str, request: Request):
    actor = getattr(request.state, "actor", {"kind": "open", "user": None})
    session = get_session()
    try:
        o = session.query(Order).filter_by(id=order_id).first()
        if not o:
            raise HTTPException(404, "order not found")
        user = actor.get("user")
        if actor["kind"] != "owner" and (user is None or o.user_id != user.id):
            raise HTTPException(404, "order not found")
        return {"order": _order_payload(o)}
    finally:
        session.close()


def _require_owner(request: Request) -> None:
    actor = getattr(request.state, "actor", {"kind": "anon"})
    if actor["kind"] != "owner":
        raise HTTPException(403, "owner only")


@app.get("/api/admin/orders", dependencies=[Depends(gate)])
def api_admin_orders(request: Request):
    _require_owner(request)
    session = get_session()
    try:
        rows = session.query(Order).order_by(Order.created_at.desc()).all()
        logins = {u.id: u.github_login for u in session.query(User).all()}
        return {"orders": [_order_payload(o, logins.get(o.user_id))
                           for o in rows]}
    finally:
        session.close()


@app.post("/api/admin/orders/{order_id}/approve",
          dependencies=[Depends(gate)])
def api_admin_approve(order_id: str, request: Request):
    """Owner confirms a BTC payment landed: mark the order paid and
    activate the buyer's plan for PLAN_DURATION_DAYS."""
    _require_owner(request)
    session = get_session()
    try:
        o = session.query(Order).filter_by(id=order_id).first()
        if not o:
            raise HTTPException(404, "order not found")
        if o.status != "paid":
            o.status = "paid"
            o.paid_at = dt.datetime.now(dt.timezone.utc)
            buyer = session.query(User).filter_by(id=o.user_id).first()
            if buyer is not None:
                buyer.plan = o.plan
                buyer.plan_expires_at = (
                    dt.datetime.now(dt.timezone.utc)
                    + dt.timedelta(days=billing.PLAN_DURATION_DAYS))
            session.commit()
        return {"order": _order_payload(o)}
    finally:
        session.close()


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse("/pricing", status_code=303)


@app.get("/pricing", include_in_schema=False)
def pricing_page():
    """Server-rendered pricing (also reachable on the API service
    domain; the main site serves the richer Next.js page at the same
    path). Generated from billing.PLANS so the two never drift."""
    cards = []
    for p in billing.public_plans():
        feats = "".join(f"<li>{f}</li>" for f in p["features"])
        price = "Free" if p["price_usd"] == 0 else f"${p['price_usd']}/mo"
        cards.append(
            f"<section><h2>{p['name']}</h2><p class='price'>{price}</p>"
            f"<ul>{feats}</ul></section>")
    signin = ("Sign in with GitHub" if billing.github_enabled()
              else "GitHub sign-in opens soon")
    checkout = ("BTC checkout is open." if billing.checkout_enabled()
                else "BTC checkout opens soon.")
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>ReconAnything pricing</title><style>
body{{background:#0b1220;color:#e2e8f0;font-family:system-ui,sans-serif;
margin:0;padding:2rem}}h1{{color:#7dd3fc}}.price{{font-size:1.5rem}}
main{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
gap:1rem;max-width:1000px}}section{{border:1px solid #1e293b;
border-radius:8px;padding:1rem}}</style></head><body>
<h1>ReconAnything pricing</h1>
<p>Free plan: exactly 1 revealed finding per day (resets at UTC
midnight). Scans still run in full; the rest are shown as locked
counts. Paid plans are paid in BTC only. {checkout}</p>
<p><a href="/api/auth/github">{signin}</a></p>
<main>{''.join(cards)}</main></body></html>"""
    return HTMLResponse(html)
