"""ReconAnything as an MCP server (Model Context Protocol), v2.

Exposes the full scan engine to any MCP client (Claude Code, Claude
Desktop, Cursor, VS Code, Error Inbox's black team, any MCP host) over
two transports:

  stdio (local, keyless):
    python -m app.mcp_server --stdio
    Newline-delimited JSON-RPC on stdin/stdout. This is the zero-setup
    path: the server is the owner's own process, the same trust model
    as every local MCP server, so no key is ever asked for.

  streamable HTTP (hosted or shared):
    POST /mcp   JSON-RPC: initialize, ping, tools/list, tools/call
    GET  /mcp   405 (this server is stateless; no server-initiated stream)
    Mounted into the main FastAPI app at /mcp (app/main.py) and also
    runnable standalone:
      python -m app.mcp_server            # uvicorn, $MCP_PORT or 8765
      recon-mcp                           # same, after pip install
    Standalone binds 127.0.0.1 by default and runs KEYLESS on a
    localhost bind when RECON_SERVICE_KEY is unset. Bind wider
    (--host 0.0.0.0) and the service key is required again, unless
    RECON_MCP_NO_AUTH=1 explicitly opts into keyless.

Auth, in order: a set RECON_SERVICE_KEY is always enforced (either the
X-Recon-Service-Key header or "Authorization: Bearer <key>",
constant-time comparison). When it is unset on the hosted/mounted app,
a key is generated once and stored in the key file
(RECON_SERVICE_KEY_FILE, default ~/workspace/recon-mcp-service-key.txt)
with 0600 permissions, as in v1. The key value is never logged or
returned by any endpoint. Deliberate exclusion: the REST /api/keys
credential-vault CRUD is NOT exposed as MCP tools - credential
management does not belong in an MCP tool surface.

Tools wrap the same internals the REST API uses (runner.launch_run,
reporting.*, graph.graph_payload, plugins.registry, classifier,
modes, vuln_advisor, safe_tester, playground, agentdata, hunters,
diff) - the scanning engine is not reimplemented here.

Boundary: detection only, exactly like the REST API. The tools start
and read scans and run the backend's own guarded safe-test paths
(recon_test_vulns defaults to dry_run=true, which sends zero
requests); nothing here confirms exploits beyond those built-in
non-destructive probes, brute-forces, bypasses auth, or touches
private data. Authenticated-mode scans (stored credentials) are NOT
offered over MCP. The SANDBOX/LIVE app mode gate DOES apply to
recon_start_scan, same as POST /api/runs.

Protocol notes: stateless streamable HTTP (no session id is issued;
2025-03-26+ permits this), single JSON-RPC messages and batches,
notifications answered 202 with no body. The stdio transport answers
the same JSON-RPC methods, one message per line, notifications
dropped. Protocol versions offered: 2025-06-18, 2025-03-26,
2024-11-05; initialize echoes the client's version when supported,
else answers with the newest supported one.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hmac
import json
import logging
import os
import re
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import modes as app_modes
from .classifier import classify, classify_batch
from .diff import diff_runs as _diff_runs_impl
from .graph import graph_payload
from .keys import load_all
from .models import (Finding, Run, Schedule, Target, check_db,
                     get_session, init_db)
from .plugins.registry import describe
from .reporting import (executive_summary, findings_dump, run_progress,
                        to_csv, to_html, to_markdown)
from .runner import launch_run
from .agent_tools import AgentToolError as _AgentToolError
from .agent_tools import (anvil_tool as _anvil_impl,
                         cast_tool as _cast_impl,
                         deploy_fork_tool as _deploy_fork_impl,
                         explorer_tool as _explorer_impl,
                         fetch_tool as _fetch_impl,
                         forge_tool as _forge_impl,
                         fuzz_tool as _fuzz_impl,
                         multicall_tool as _multicall_impl,
                         mythril_tool as _mythril_impl,
                         search_tool as _search_impl,
                         simulate_tool as _simulate_impl,
                         slither_tool as _slither_impl,
                         time_travel_tool as _time_travel_impl,
                         write_poc as _write_poc_impl,
                         write_report as _write_report_impl)

log = logging.getLogger("recon-anything-mcp")

SERVER_NAME = "recon-anything"
SERVER_VERSION = "2.2.0"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

# ---------------------------------------------------------------------------
# Auth: service key when set / hosted, keyless for local use
# ---------------------------------------------------------------------------

_KEY_FILE_DEFAULT = "~/workspace/recon-mcp-service-key.txt"
_service_key_cache: Optional[str] = None

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
# Set by create_standalone_app() when the standalone server binds a
# localhost address. The mounted app in app/main.py never sets it, so a
# hosted deploy keeps requiring the key exactly as in v1.
_keyless_local_bind = False


def _key_file_path() -> Path:
    return Path(os.environ.get("RECON_SERVICE_KEY_FILE",
                               _KEY_FILE_DEFAULT)).expanduser()


def get_service_key() -> str:
    """The MCP service key: env first, then the generated key file.

    Generated once (token_urlsafe, 48 chars) and persisted 0600 so
    restarts and the standalone/mounted pairings all share one key.
    The value is never logged or returned by any endpoint.
    """
    global _service_key_cache
    env_key = os.environ.get("RECON_SERVICE_KEY", "").strip()
    if env_key:
        return env_key
    if _service_key_cache:
        return _service_key_cache
    path = _key_file_path()
    try:
        existing = path.read_text().strip()
        if existing:
            _service_key_cache = existing
            return existing
    except OSError:
        pass
    key = secrets.token_urlsafe(36)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL via os.open so the 0600 mode is set at creation time.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key + "\n")
        log.warning("RECON_SERVICE_KEY unset: generated a service key and "
                    "saved it to %s (mode 0600)", path)
    except FileExistsError:
        # Another process won the race; read what it wrote.
        try:
            key = path.read_text().strip()
        except OSError:
            log.warning("RECON_SERVICE_KEY unset and key file unreadable; "
                        "using an ephemeral in-memory key")
    except OSError as e:
        log.warning("RECON_SERVICE_KEY unset and key file not writable "
                    "(%s); using an ephemeral in-memory key", e)
    _service_key_cache = key
    return key


def _no_auth_opt_in() -> bool:
    return os.environ.get("RECON_MCP_NO_AUTH", "").strip().lower() in (
        "1", "true", "yes")


def auth_required() -> bool:
    """Whether HTTP requests must carry the service key.

    - RECON_SERVICE_KEY set: always enforced (v1 behavior).
    - RECON_MCP_NO_AUTH=1: never (explicit owner opt-in).
    - Standalone server bound to localhost with no key set: keyless.
      The process is the owner's own; hunting for a generated key file
      was the v1 setup friction this removes.
    - Everything else (the mounted hosted app, non-localhost binds):
      the key is required, generated into the key file as in v1.
    """
    if os.environ.get("RECON_SERVICE_KEY", "").strip():
        return True
    if _no_auth_opt_in():
        return False
    if _keyless_local_bind:
        return False
    return True


def auth_mode_label() -> str:
    if auth_required():
        return "service-key"
    if _no_auth_opt_in():
        return "none (RECON_MCP_NO_AUTH=1)"
    return "none (keyless localhost)"


def _provided_key(request: Request) -> str:
    header = request.headers.get("x-recon-service-key", "").strip()
    if header:
        return header
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _authorized(request: Request) -> bool:
    if not auth_required():
        return True
    provided = _provided_key(request)
    if not provided:
        return False
    return hmac.compare_digest(provided, get_service_key())


# ---------------------------------------------------------------------------
# Helpers shared by tools
# ---------------------------------------------------------------------------

def _wake_worker() -> None:
    """Same fire-and-forget worker ping as app/main.py (kept local to
    avoid a circular import - main.py mounts this module)."""
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


def _run_not_found(run_id: str) -> str:
    return (f"run {run_id} not found. It may have been wiped by a restart "
            "or redeploy (the default SQLite database on free tiers is "
            "ephemeral). Set DATABASE_URL to a persistent Postgres so "
            "scans survive restarts.")


def _run_row(session, run: Run, findings_count: Optional[int] = None) -> Dict:
    if findings_count is None:
        findings_count = (session.query(Finding)
                          .filter_by(run_id=run.id).count())
    return {"id": run.id, "mode": run.mode, "status": run.status,
            "env_mode": getattr(run, "env_mode", None) or "sandbox",
            "source_type": getattr(run, "source_type", None) or "website",
            "created_at": run.created_at.isoformat()
            if run.created_at else None,
            "finished_at": run.finished_at.isoformat()
            if getattr(run, "finished_at", None) else None,
            "findings_count": findings_count}


def _int_arg(args: Dict, name: str, default: int, lo: int, hi: int) -> int:
    raw = args.get(name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ToolError(f"{name} must be an integer")
    return max(lo, min(value, hi))


def _bool_arg(args: Dict, name: str, default: bool) -> bool:
    raw = args.get(name, default)
    if not isinstance(raw, bool):
        raise ToolError(f"{name} must be a boolean")
    return raw


def _str_list_arg(args: Dict, name: str) -> List[str]:
    raw = args.get(name)
    if (not isinstance(raw, list)
            or not all(isinstance(x, str) for x in raw)):
        raise ToolError(f"{name} must be a list of strings")
    return list(raw)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

class ToolError(Exception):
    """A tool-level failure: returned to the client as isError content."""


def _tool_health(_args: Dict) -> Dict:
    db_ok, db_detail = True, "ok"
    try:
        check_db()
    except Exception as e:  # DB down must not kill the handshake
        db_ok, db_detail = False, str(e)[:200]
    return {"ok": db_ok, "service": SERVER_NAME, "mcp": True,
            "version": SERVER_VERSION, "auth": auth_mode_label(),
            "db": db_detail, "plugins": len(describe()),
            "time": dt.datetime.now(dt.timezone.utc).isoformat()}


def _tool_list_plugins(_args: Dict) -> Dict:
    plugins = describe()
    return {"count": len(plugins), "plugins": plugins}


async def _tool_start_scan(args: Dict) -> Dict:
    targets = str(args.get("targets") or "").strip()
    if not targets:
        raise ToolError("targets is required (one or more domains, URLs "
                        "or IPs, newline/comma separated)")
    preset = str(args.get("preset") or "standard").lower()
    if preset not in ("quick", "standard", "deep"):
        raise ToolError("preset must be quick|standard|deep")
    mode = args.get("mode") or ("passive" if preset == "quick" else "active")
    if mode not in ("passive", "active"):
        raise ToolError("mode must be passive|active")
    source_type = str(args.get("source_type") or "website")
    if source_type not in ("website", "bank", "atm", "bankatm"):
        raise ToolError("source_type must be website|bank|atm|bankatm")
    bounty = bool(args.get("bounty", False))

    explicit = args.get("plugins")
    if explicit is not None:
        if (not isinstance(explicit, list)
                or not all(isinstance(p, str) for p in explicit)):
            raise ToolError("plugins must be a list of plugin ids")
        plugins: Optional[List[str]] = list(explicit)
    elif preset == "quick":
        plugins = [p["id"] for p in describe() if p["passive"]]
    elif preset == "deep":
        # Explicit full selection: in runner semantics an explicit list
        # means "selected means run" (budget-skip exempt).
        plugins = [p["id"] for p in describe()]
    else:  # standard: the default plugin set, same as POST /api/runs
        plugins = None

    run_id = uuid.uuid4().hex[:12]
    session = get_session()
    try:
        env_mode = app_modes.get_mode(session)
        if env_mode == app_modes.SANDBOX:
            rejected = app_modes.check_sandbox_targets(
                classify_batch(targets), app_modes.get_owned_assets(session))
            if rejected:
                raise ToolError(
                    "SANDBOX mode: targets must be Jay's own assets or "
                    "local/lab targets. Rejected: " + "; ".join(
                        f"{r['raw']} ({r['reason']})" for r in rejected)
                    + ". Switch the app to LIVE in Settings to scan "
                      "authorized external targets.")
        session.add(Run(id=run_id, mode=mode, status="running",
                        env_mode=env_mode, source_type=source_type,
                        summary={"bounty": bounty, "via": "mcp",
                                 "preset": preset}))
        session.commit()
        keys = load_all(session)
    finally:
        session.close()
    overrides: Dict[str, str] = {}
    if source_type in ("bank", "bankatm"):
        overrides["bank"] = "authorized"
    if source_type in ("atm", "bankatm"):
        overrides["atm"] = "authorized"
    await launch_run(run_id, targets, mode, plugins, overrides, keys,
                     source_type=source_type, bounty=bounty)
    _wake_worker()
    return {"run_id": run_id, "status": "running", "preset": preset,
            "mode": mode, "source_type": source_type, "env_mode": env_mode,
            "targets": targets,
            "next": "poll recon_run_status, then recon_get_findings / "
                    "recon_get_graph with this run_id"}


def _tool_list_runs(args: Dict) -> Dict:
    limit = _int_arg(args, "limit", 30, 1, 200)
    session = get_session()
    try:
        runs = (session.query(Run).order_by(Run.created_at.desc())
                .limit(limit).all())
        counts = {}
        if runs:
            from sqlalchemy import func
            counts = dict(
                session.query(Finding.run_id, func.count(Finding.id))
                .filter(Finding.run_id.in_([r.id for r in runs]))
                .group_by(Finding.run_id).all())
        return {"runs": [_run_row(session, r, counts.get(r.id, 0))
                         for r in runs]}
    finally:
        session.close()


def _get_run_or_raise(session, args: Dict) -> Run:
    run_id = str(args.get("run_id") or "").strip()
    if not run_id:
        raise ToolError("run_id is required")
    run = session.query(Run).filter_by(id=run_id).first()
    if not run:
        raise ToolError(_run_not_found(run_id))
    return run


def _tool_run_status(args: Dict) -> Dict:
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        out = _run_row(session, run)
        out["summary"] = run.summary or {}
        out["progress"] = run_progress(session, run.id)
        out["targets"] = [
            {"id": t.id, "raw": t.raw, "type": t.type,
             "normalized": t.normalized}
            for t in session.query(Target).filter_by(run_id=run.id).all()]
        return out
    finally:
        session.close()


def _tool_get_findings(args: Dict) -> Dict:
    limit = args.get("limit", 500)
    try:
        limit = max(1, min(int(limit), 5000))
    except (TypeError, ValueError):
        raise ToolError("limit must be an integer")
    min_confidence = args.get("min_confidence")
    if min_confidence is not None:
        try:
            min_confidence = float(min_confidence)
        except (TypeError, ValueError):
            raise ToolError("min_confidence must be a number between 0 and 1")
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        rows = findings_dump(session, run.id, show_secrets=False)
    finally:
        session.close()
    total = len(rows)
    if min_confidence is not None:
        rows = [r for r in rows
                if (r.get("confidence") or 0) >= min_confidence]
    bands = {"high (>=0.75)": 0, "medium (0.4-0.75)": 0,
             "low (<0.4)": 0, "unscored": 0}
    for r in rows:
        c = r.get("confidence")
        if c is None:
            bands["unscored"] += 1
        elif c >= 0.75:
            bands["high (>=0.75)"] += 1
        elif c >= 0.4:
            bands["medium (0.4-0.75)"] += 1
        else:
            bands["low (<0.4)"] += 1
    return {"run_id": run.id, "status": run.status,
            "findings_total": total, "findings_returned": min(len(rows),
                                                              limit),
            "confidence_bands": bands,
            "executive_summary": executive_summary(rows),
            "findings": rows[:limit]}


def _tool_get_graph(args: Dict) -> Dict:
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        payload = graph_payload(session, run.id)
    finally:
        session.close()
    payload["run_id"] = run.id
    payload["status"] = run.status
    payload["node_count"] = len(payload.get("nodes", []))
    payload["edge_count"] = len(payload.get("edges", []))
    return payload


def _ks_store_or_none():
    """Open the cross-run knowledge store, or None when it has no
    data yet (it is populated by ingest at run finalize)."""
    from .knowledge_store import KnowledgeStore, default_db_path
    if not os.path.exists(default_db_path()):
        return None
    return KnowledgeStore()


def _tool_query_knowledge(args: Dict) -> Dict:
    store = _ks_store_or_none()
    if store is None:
        return {"available": False,
                "note": "knowledge store has no data yet: it is "
                        "populated when a scan run finalizes"}
    since_ts = None
    since = args.get("since")
    if since is not None:
        try:
            since_ts = float(since)
        except (TypeError, ValueError):
            try:
                since_ts = dt.datetime.fromisoformat(
                    str(since).replace("Z", "+00:00")).timestamp()
            except ValueError:
                raise ToolError("since must be epoch seconds or ISO 8601")
    limit = args.get("limit", 200)
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        raise ToolError("limit must be an integer")
    is_cdn = args.get("is_cdn")
    if is_cdn is not None and not isinstance(is_cdn, bool):
        raise ToolError("is_cdn must be a boolean")
    assets = store.query_assets(
        scope=args.get("scope") or None, kind=args.get("kind") or None,
        tech_contains=args.get("tech") or None, is_cdn=is_cdn,
        ip=args.get("ip") or None, since=since_ts, limit=limit)
    return {"available": True, "count": len(assets), "assets": assets}


def _tool_get_delta(args: Dict) -> Dict:
    scope = str(args.get("scope") or "").strip()
    if not scope:
        raise ToolError("scope is required (a target root, "
                        "e.g. example.com)")
    store = _ks_store_or_none()
    if store is None:
        return {"available": False,
                "note": "knowledge store has no data yet: it is "
                        "populated when a scan run finalizes"}
    from .delta import diff, format_delta
    result = diff(store, scope, run_old=args.get("from_run") or None,
                  run_new=args.get("to_run") or None)
    result["available"] = True
    result["formatted"] = format_delta(result)
    return result


# -- v2: classify + settings ------------------------------------------------

def _tool_classify(args: Dict) -> Dict:
    text = str(args.get("text") or "")
    if not text.strip():
        raise ToolError("text is required (one target, or several "
                        "newline-separated targets)")
    if "\n" in text.strip():
        return {"results": classify_batch(text)}
    return classify(text)


def _tool_settings(args: Dict) -> Dict:
    limit = _int_arg(args, "audit_limit", 20, 1, 100)
    session = get_session()
    try:
        return {"mode": app_modes.get_mode(session),
                "owned_assets": app_modes.get_owned_assets(session),
                "audit": app_modes.audit_tail(session, limit=limit)}
    finally:
        session.close()


def _tool_set_mode(args: Dict) -> Dict:
    mode = str(args.get("mode") or "").strip().lower()
    if mode not in app_modes.MODES:
        raise ToolError("mode must be sandbox|live")
    session = get_session()
    try:
        detail = app_modes.set_mode(session, mode, actor="mcp")
    finally:
        session.close()
    return {"ok": True, "mode": mode, "detail": detail}


def _tool_set_owned_assets(args: Dict) -> Dict:
    assets = _str_list_arg(args, "assets")
    session = get_session()
    try:
        clean = app_modes.set_owned_assets(session, assets, actor="mcp")
    finally:
        session.close()
    return {"ok": True, "owned_assets": clean}


# -- v2: run detail / activity / retest -------------------------------------

def _tool_run_detail(args: Dict) -> Dict:
    """Full run detail, mirroring GET /api/runs/{id} (secrets masked;
    the REST free-tier reveal cap is a billing rule for customers and
    does not apply to the owner's MCP surface)."""
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        rows = findings_dump(session, run.id, show_secrets=False)
        out = _run_row(session, run, len(rows))
        out["summary"] = run.summary or {}
        out["bounty"] = bool((run.summary or {}).get("bounty"))
        out["targets"] = [
            {"id": t.id, "raw": t.raw, "type": t.type,
             "normalized": t.normalized}
            for t in session.query(Target).filter_by(run_id=run.id).all()]
        out["progress"] = run_progress(session, run.id)
        out["executive_summary"] = executive_summary(rows)
        out["findings"] = rows
        return out
    finally:
        session.close()


def _tool_agent_activity(args: Dict) -> Dict:
    from .agentdata import store
    limit = _int_arg(args, "limit", 500, 1, 2000)
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        return store.run_agent_activity(session, store.DEFAULT_SYSTEM,
                                        run.id, limit=limit)
    finally:
        session.close()


async def _tool_retest_finding(args: Dict) -> Dict:
    """Re-run the one plugin that produced a finding, against that
    finding's own stored target (app/playground.py). The caller cannot
    name a URL, plugin, or payload, same as the REST retest route."""
    finding_id = args.get("finding_id")
    try:
        finding_id = int(finding_id)
    except (TypeError, ValueError):
        raise ToolError("finding_id is required (integer finding id)")
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        run_id = run.id
    finally:
        session.close()
    from .playground import PlaygroundError, retest_finding
    try:
        return await retest_finding(run_id, finding_id)
    except PlaygroundError as e:
        detail = getattr(e, "detail", None) or str(e)
        raise ToolError(f"retest refused: {detail}")
    except Exception as e:
        raise ToolError(f"retest failed: {str(e)[:300]}")


# -- v2: apimap / export / fetch ---------------------------------------------

def _tool_get_apimap(args: Dict) -> Dict:
    """Application attack-surface map for a run, grouped (pages,
    api_routes, forms, js_endpoints, websockets, graphql) plus the
    legacy flat entries - the same construction as
    GET /api/runs/{id}/apimap in app/main.py."""
    from urllib.parse import urlparse  # noqa: F401  (parity with REST)
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        rows = session.query(Finding).filter_by(run_id=run.id).all()

        entries = {}
        for f in rows:
            if f.key in ("endpoint",) or (f.category == "api" and f.raw):
                raw = f.raw or {}
                amap = raw.get("map") if isinstance(raw, dict) else None
                if amap:
                    entries.update(amap)
                else:
                    entries[f.value] = {"note": f.source}
        for f in rows:
            if f.key == "api_map_entries" and f.raw \
                    and isinstance(f.raw, dict):
                entries.update(f.raw.get("map", {}))

        def _entry(url, method="", status="", auth="", params=None,
                   note=""):
            return {"url": url, "method": method, "status": status,
                    "auth": auth, "params": params or [],
                    "note": note or ""}

        def _params_of(f):
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            p = ev.get("params") or ev.get("parameters") or []
            return [str(x)[:60] for x in p][:20] \
                if isinstance(p, list) else []

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
            if key.startswith("graphql"):
                if key in ("graphql_endpoint", "graphql_deep", "graphql",
                           "graphql_introspection",
                           "graphql_schema_enum"):
                    fields = ev.get("fields") or ev.get("operations") or []
                    _add("graphql", val or ev.get("endpoint", ""),
                         note=f"{key}: {len(fields)} fields"
                         if fields else key,
                         params=[str(x)[:60] for x in fields][:25]
                         if isinstance(fields, list) else [],
                         auth=_auth_of(f))
                continue
            if key in ("form_inventory", "interesting_form"):
                for form in (ev.get("forms") or []):
                    if not isinstance(form, dict):
                        continue
                    action = form.get("action", "")
                    inputs = [i.get("name", "") for i in
                              (form.get("inputs") or [])
                              if isinstance(i, dict)]
                    _add("forms", action or form.get("page", ""),
                         method=str(form.get("method", "GET")).upper(),
                         params=[str(x) for x in inputs if x][:20],
                         note=f"on {form.get('page', '')}"[:120],
                         auth=_auth_of(f))
                if key == "interesting_form" and val and val not in seen:
                    _add("forms", val, note=key, auth=_auth_of(f))
                continue
            if key in ("js_endpoint", "endpoint"):
                url = val
                if url.startswith(("ws://", "wss://")):
                    _add("websockets", url, note=f.source or "")
                else:
                    _add("js_endpoints", url, params=_params_of(f),
                         note=f.source or "", auth=_auth_of(f))
                continue
            if key in ("unauthenticated_api", "auth_required_endpoint",
                       "endpoint_error_leak"):
                _add("api_routes", val,
                     status=str(ev.get("status", "")),
                     auth=ev.get("verdict", "") or _auth_of(f),
                     params=_params_of(f), note=key)
                continue
            if f.category == "api" and key in (
                    "api_route", "api_pattern", "api_map_entries"):
                _add("api_routes", val, params=_params_of(f),
                     note=key, auth=_auth_of(f))
                continue
            if key in ("page", "crawled_page", "crawl_summary"):
                for u in (ev.get("pages")
                          or ([val] if val.startswith("http") else [])):
                    _add("pages", u, note=key)
                continue

        for url, meta in entries.items():
            meta = meta if isinstance(meta, dict) else {}
            if url.startswith(("ws://", "wss://")):
                _add("websockets", url, note=str(meta.get("note", "")))
            elif "/graphql" in url.lower():
                _add("graphql", url, note=str(meta.get("note", "")))
            else:
                _add("api_routes", url,
                     method=", ".join(meta.get("methods", []))
                     if isinstance(meta.get("methods"), list) else "",
                     status=str(meta.get("status", "")),
                     auth=str(meta.get("auth", "")),
                     note=str(meta.get("note", "")))

        counts = {g: len(v) for g, v in groups.items()}
        return {"run_id": run.id, "entries": entries,
                "count": len(entries), "groups": groups,
                "counts": counts}
    finally:
        session.close()


def _tool_export_run(args: Dict) -> Dict:
    fmt = str(args.get("format") or "json").strip().lower()
    if fmt not in ("json", "csv", "md", "html"):
        raise ToolError("format must be json|csv|md|html")
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        targets = session.query(Target).filter_by(run_id=run.id).all()
        rows = findings_dump(session, run.id, show_secrets=False)
        if fmt == "json":
            return {"run_id": run.id, "format": "json", "findings": rows}
        content = {"csv": lambda: to_csv(rows),
                   "md": lambda: to_markdown(run, targets, rows),
                   "html": lambda: to_html(run, targets, rows)}[fmt]()
        return {"run_id": run.id, "format": fmt, "content": content}
    finally:
        session.close()


async def _tool_fetch_run_file(args: Dict) -> Dict:
    """Fetch a URL found during a run (same SSRF guard as
    GET /api/runs/{id}/fetch: only URLs in the run's own findings)."""
    url = str(args.get("url") or "").strip()
    if not url:
        raise ToolError("url is required")
    from urllib.parse import urlparse
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        rows = findings_dump(session, run.id)
    finally:
        session.close()
    allowed = set()
    for r in rows:
        for k in ("source_url", "value"):
            v = r.get(k) or ""
            if v.startswith("http"):
                candidate = v.split()[0] if k == "value" else v
                if candidate.startswith("http"):
                    allowed.add(candidate)
    if url not in allowed:
        raise ToolError("URL was not found in this run (SSRF guard: "
                        "only URLs from the run's own findings can be "
                        "fetched)")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ToolError("only http/https allowed")
    from . import net
    try:
        async with net.async_client(timeout=20,
                                    follow_redirects=True) as client:
            resp = await client.get(
                url, headers={"User-Agent": "ReconAnything/1.0"})
    except Exception as e:
        raise ToolError(f"fetch failed: {str(e)[:200]}")
    body = resp.text[:200000]
    return {"url": url, "status": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
            "size": len(resp.content),
            "last_modified": resp.headers.get("last-modified", ""),
            "headers": dict(resp.headers), "body": body,
            "truncated": len(resp.content) > 200000}


# -- v2: vuln advisor + safe tester ------------------------------------------

def _vuln_context(session, run: Run):
    rows = findings_dump(session, run.id)
    targets = session.query(Target).filter_by(run_id=run.id).all()
    summary = {"targets": [{"raw": t.raw, "type": t.type,
                            "normalized": t.normalized}
                           for t in targets]}
    return rows, targets, summary


def _tool_list_vulns(args: Dict) -> Dict:
    from .vuln_advisor import advise
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        rows, _targets, summary = _vuln_context(session, run)
        return {"run_id": run.id, "candidates": advise(rows, summary)}
    finally:
        session.close()


def _tool_test_vulns(args: Dict) -> Dict:
    """Safe-test a run's vuln candidates. dry_run defaults to TRUE:
    the advisor narrates what each detection check WOULD do and zero
    requests are sent. dry_run=false runs the backend's real safe
    tester (app/safe_tester.py): GET/HEAD only, rate-limited,
    non-destructive, only against the run's own targets."""
    dry = _bool_arg(args, "dry_run", True)
    from .vuln_advisor import advise, dry_run as _dry_run_lines
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        rows, targets, summary = _vuln_context(session, run)
        candidates = advise(rows, summary)
        base = str(args.get("base") or "")
        if not base and targets:
            base = targets[0].normalized or targets[0].raw or ""
        if dry:
            cid = args.get("candidate_id")
            if cid:
                return {"run_id": run.id, "dry_run": True,
                        "candidate_id": str(cid),
                        "lines": _dry_run_lines(str(cid),
                                                base or "TARGET")}
            return {"run_id": run.id, "dry_run": True, "base": base,
                    "candidates": [
                        {"candidate_id": c.get("id"),
                         "lines": _dry_run_lines(str(c.get("id")),
                                                 base or "TARGET")}
                        for c in candidates]}
        # Live path: harvest the real endpoints/params the scan found,
        # exactly like POST /api/runs/{id}/vulns/test.
        endpoints: List[str] = []
        params: List[str] = []
        _ep_keys = {"endpoint", "hidden_api", "api_route", "url",
                    "login_endpoint"}
        from urllib.parse import parse_qs as _parse_qs
        from urllib.parse import urlparse as _urlparse
        for r in rows:
            url = r.get("source_url") or ""
            if not (url.startswith("http://")
                    or url.startswith("https://")):
                m = re.search(r"https?://[^\s\"'<>]+",
                              str(r.get("value") or ""))
                url = m.group(0) if (m and r.get("key") in _ep_keys) \
                    else ""
            if url:
                if url not in endpoints:
                    endpoints.append(url)
                for pname in _parse_qs(_urlparse(url).query).keys():
                    if pname not in params:
                        params.append(pname)
            if r.get("key") in ("param", "params"):
                v = r.get("value")
                for pname in ([v] if isinstance(v, str) else (v or [])):
                    pn = str(pname).strip()
                    if pn and pn not in params:
                        params.append(pn)
    finally:
        session.close()
    from .safe_tester import run_real_tests
    try:
        report = run_real_tests(base, candidates,
                                endpoints=endpoints[:25],
                                params=params[:15])
    except Exception as e:
        raise ToolError(f"safe tester failed: {str(e)[:300]}")
    report["run_id"] = run.id
    report["dry_run"] = False
    return report


async def _tool_verify_subdomains(args: Dict) -> Dict:
    """Probe every subdomain from this run's findings for HTTP
    liveness (same SSRF guard, caching, and read-only GETs as
    POST /api/runs/{id}/subdomains/verify)."""
    import time as _time

    import httpx  # noqa: F401  (parity with REST import surface)
    from . import net
    force = _bool_arg(args, "force", False)
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        run_id = run.id
        rows = findings_dump(session, run_id)
        summary = dict(run.summary or {})
    finally:
        session.close()

    hosts: List[str] = []
    for r in rows:
        if r.get("key") == "subdomain":
            v = (r.get("value") or "").split()[0].strip().lower() \
                .rstrip(".")
            if v and re.match(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$", v) \
                    and v not in hosts:
                hosts.append(v)
    hosts = hosts[:100]

    cached = summary.get("subdomain_status") or {}
    now = _time.time()

    async def check(host: str):
        c = cached.get(host)
        if c and not force and now - c.get("ts", 0) < 86400:
            return host, c
        result: Dict = {"live": False, "status": 0, "url": "",
                        "server": "", "title": "", "ts": now}
        for scheme in ("https", "http"):
            try:
                async with net.async_client(
                        timeout=8, follow_redirects=True,
                        headers={"User-Agent": "ReconAnything/1.0"}) \
                        as client:
                    resp = await client.get(f"{scheme}://{host}")
                title = ""
                if resp.status_code < 400:
                    m = re.search(r"<title[^>]*>(.*?)</title>",
                                  resp.text[:50000], re.I | re.S)
                    if m:
                        title = re.sub(r"\s+", " ",
                                       m.group(1)).strip()[:80]
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
        if run is not None:
            s = dict(run.summary or {})
            s["subdomain_status"] = out
            run.summary = s
            session.commit()
    finally:
        session.close()
    live_count = sum(1 for v in out.values() if v.get("live"))
    return {"run_id": run_id, "hosts": out, "count": len(out),
            "live": live_count}


async def _tool_probe_port(args: Dict) -> Dict:
    """Probe a single host:port from this run's findings for
    banner/service info (same SSRF guard as
    GET /api/runs/{id}/probe/port). Read-only TCP connect + short
    banner read, plus an HTTP GET on web-ish ports."""
    from . import net
    host = str(args.get("host") or "").strip().lower().rstrip(".")
    try:
        port = int(args.get("port"))
    except (TypeError, ValueError):
        raise ToolError("port is required (integer 1-65535)")
    if not re.match(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$", host) \
            or not (1 <= port <= 65535):
        raise ToolError("bad host or port")

    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        rows = findings_dump(session, run.id)
        targets = session.query(Target).filter_by(run_id=run.id).all()
        run_id = run.id
    finally:
        session.close()

    allowed_hosts = set()
    for t in targets:
        for cand in (t.normalized or "", t.raw or ""):
            m = re.search(r"([a-z0-9]([a-z0-9.\-]*[a-z0-9])?)",
                          cand.lower())
            if m:
                allowed_hosts.add(m.group(1).rstrip("."))
    for r in rows:
        if r.get("key") == "subdomain":
            v = (r.get("value") or "").split()[0].strip().lower() \
                .rstrip(".")
            if v:
                allowed_hosts.add(v)
    allowed_ports = set()
    for r in rows:
        if r.get("key") in ("port_open", "port_suggestion"):
            m = re.search(r"port (\d+)", (r.get("value") or "").lower())
            if m:
                allowed_ports.add(int(m.group(1)))
    if host not in allowed_hosts:
        raise ToolError("host was not found in this run (SSRF guard)")
    if port not in allowed_ports:
        raise ToolError("port was not found in this run (SSRF guard)")

    result: Dict = {"run_id": run_id, "host": host, "port": port,
                    "open": False, "banner": "", "http": None}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5)
        result["open"] = True
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=3)
            result["banner"] = data.decode("utf-8", "replace") \
                .strip()[:200]
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

    if port in (80, 443, 8000, 8080, 8443, 3000, 5000, 9000, 9200,
                5601):
        scheme = "https" if port in (443, 8443) else "http"
        try:
            async with net.async_client(
                    timeout=8, follow_redirects=True,
                    headers={"User-Agent": "ReconAnything/1.0"}) \
                    as client:
                resp = await client.get(f"{scheme}://{host}:{port}/")
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>",
                          resp.text[:50000], re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            result["http"] = {"status": resp.status_code,
                              "server": resp.headers.get(
                                  "server", "")[:60],
                              "title": title, "url": str(resp.url)}
            if not result["banner"]:
                result["banner"] = (
                    f"HTTP {resp.status_code} "
                    f"{result['http']['server']}").strip()
        except Exception as e:
            result["http"] = {"error": str(e)[:100]}
    return result


def _tool_diff_runs(args: Dict) -> Dict:
    """Finding-level diff between two runs (app/diff.py, the
    /api/diff route). Distinct from recon_get_delta, which is the
    asset-level knowledge-store delta for a scope."""
    a = str(args.get("run_a") or "").strip()
    b = str(args.get("run_b") or "").strip()
    if not a or not b:
        raise ToolError("run_a and run_b are required")
    session = get_session()
    try:
        _get_run_or_raise(session, {"run_id": a})
        _get_run_or_raise(session, {"run_id": b})
        return _diff_runs_impl(session, a, b)
    finally:
        session.close()


# -- v2: ATM locate (public OSM data, explicit authorization gate) -----------

_ATM_LATLON_RE = re.compile(
    r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*"
    r"(?:,\s*(\d+(?:\.\d+)?))?\s*$")
_OSM_UA = ("ReconAnything/1.0 (ATM security assessment module; "
           "contact: owner)")
_ATM_AUTH_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "atm_auth.log")
_OVERPASS_MIRRORS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
]


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


def _atm_overpass(lat: float, lon: float, radius_m: float):
    """amenity=atm nodes near (lat, lon) via public Overpass API,
    mirrors tried in order (same as app/main.py)."""
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
                    "operator": tags.get("operator")
                    or tags.get("brand") or tags.get("network") or "",
                    "lat": el.get("lat"),
                    "lon": el.get("lon"),
                })
            return out, None
        except Exception as e:
            last_err = f"Overpass error: {e}"
            continue
    return None, last_err or "Overpass unreachable"


def _tool_atm_locate(args: Dict) -> Dict:
    """Public ATM locations via OpenStreetMap (read-only). Same hard
    gate as POST /api/runs/{id}/atm/locate: authorized=true is
    required and the claim is logged for the audit trail."""
    if args.get("authorized") is not True:
        raise ToolError(
            "ATM location lookup requires explicit written "
            "authorization: pass authorized=true (the claim is "
            "logged server-side, same gate as the REST endpoint)")
    session = get_session()
    try:
        run = _get_run_or_raise(session, args)
        run_id = run.id
    finally:
        session.close()
    query = str(args.get("query") or "").strip()
    if not query:
        raise ToolError("query is required (a place name or "
                        "'lat, lon[, radius_m]')")
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        with open(_ATM_AUTH_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{ts}\trun={run_id}\tquery={query}\t"
                     "authorized=true\tvia=mcp\n")
    except OSError:
        pass
    m = _ATM_LATLON_RE.match(query)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        radius = float(m.group(3)) if m.group(3) else 2000
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ToolError("latitude/longitude out of range")
        radius = max(100, min(radius, 20000))
    else:
        coords, err = _atm_geocode(query)
        if err:
            raise ToolError(err)
        lat, lon = coords
        radius = 2000
    results, err = _atm_overpass(lat, lon, radius)
    if err:
        raise ToolError(err)
    return {"run_id": run_id, "lat": lat, "lon": lon,
            "radius_m": int(radius), "atms": results}


# -- v2: schedules ------------------------------------------------------------

def _tool_list_schedules(args: Dict) -> Dict:
    session = get_session()
    try:
        rows = session.query(Schedule).all()
        return {"schedules": [
            {"id": s.id, "target_raw": s.target_raw, "cron": s.cron,
             "mode": s.mode, "enabled": s.enabled,
             "last_run_id": s.last_run_id} for s in rows]}
    finally:
        session.close()


def _tool_create_schedule(args: Dict) -> Dict:
    target_raw = str(args.get("target_raw") or "").strip()
    cron = str(args.get("cron") or "").strip()
    if not target_raw or not cron:
        raise ToolError("target_raw and cron are required")
    mode = str(args.get("mode") or "passive")
    if mode not in ("passive", "active"):
        raise ToolError("mode must be passive|active")
    enabled = _bool_arg(args, "enabled", True)
    session = get_session()
    try:
        sid = uuid.uuid4().hex[:12]
        session.add(Schedule(id=sid, target_raw=target_raw, cron=cron,
                             mode=mode, enabled=enabled))
        session.commit()
        return {"ok": True, "id": sid}
    finally:
        session.close()


def _tool_delete_schedule(args: Dict) -> Dict:
    sid = str(args.get("schedule_id") or "").strip()
    if not sid:
        raise ToolError("schedule_id is required")
    session = get_session()
    try:
        deleted = session.query(Schedule).filter_by(id=sid).delete()
        session.commit()
        return {"ok": True, "deleted": int(deleted or 0)}
    finally:
        session.close()


# -- v2: breach watch (defensive; the owner's own addresses only) ------------

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


def _tool_breachwatch(args: Dict) -> Dict:
    emails = _bw_load_emails()
    cache = _bw_load_cache()
    return {"emails": [
        {"email": e["email"], "label": e["label"],
         "cached": cache.get(e["email"])} for e in emails],
        "configured": bool(emails),
        "hint": ("Copy backend/app/breachwatch_emails.json.example to "
                 "breachwatch_emails.json and add your own addresses.")
        if not emails else ""}


async def _tool_breachwatch_check(args: Dict) -> Dict:
    from .plugins.breachwatch import check_email_breaches
    email = str(args.get("email") or "").strip().lower()
    if "@" not in email:
        raise ToolError("not a valid email")
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as http:
            status, breaches, note = await check_email_breaches(
                email, http)
    except Exception as e:
        raise ToolError(f"breach check failed: {str(e)[:200]}")
    result = {
        "email": email,
        "status": status,  # breached | clean | rate_limited |
                           # unreachable | invalid
        "breaches": breaches,
        "note": note,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "guidance": ("If breached: change that password everywhere "
                     "you reused it, starting with email and banking. "
                     "Enable 2FA."),
    }
    cache = _bw_load_cache()
    cache[email] = result
    _bw_save_cache(cache)
    return result


# -- v2: agent data + hunters -------------------------------------------------

def _tool_agentdata(args: Dict) -> Dict:
    """The agent data service (app/agentdata), one tool with views:
    packs | pack | known | memory | finds | resources | add_known |
    add_dead_end."""
    from .agentdata import packs as _packs
    from .agentdata import store as _store
    view = str(args.get("view") or "packs").strip().lower()
    system = str(args.get("system") or "recon")
    if view == "packs":
        return {"packs": _packs.pack_inventory()}
    if view == "pack":
        name = str(args.get("name") or "").strip()
        if not name:
            raise ToolError("name is required for view=pack")
        raw = _packs.pack_raw(name)
        if raw is None:
            raise ToolError(f"unknown pack: {name}")
        return {"name": name, "entries": _packs.pack_entries(name),
                "raw": raw}
    session = get_session()
    try:
        if view == "resources":
            from .agentdata import resources
            return {"resources": resources.catalog(session)}
        target = str(args.get("target") or "").strip()
        if view == "finds":
            limit = _int_arg(args, "limit", 50, 1, 200)
            return {"finds": _store.recent_finds(
                session, system, limit=limit,
                target_key=target or None,
                hunter=str(args.get("hunter") or "") or None)}
        if not target:
            raise ToolError(f"target is required for view={view}")
        if view == "known":
            assets = _store.get_known_set(session, system, target)
            return {"system": system, "target": target,
                    "count": len(assets), "assets": assets}
        if view == "memory":
            return _store.get_memory(session, system, target)
        if view == "add_known":
            asset_type = str(args.get("asset_type") or "").strip()
            value = str(args.get("value") or "").strip()
            if not asset_type or not value:
                raise ToolError("asset_type and value are required "
                                "for view=add_known")
            _row, created = _store.add_known_asset(
                session, system, target, asset_type, value,
                found_by=str(args.get("found_by") or "mcp"),
                run_id=str(args.get("run_id") or ""))
            return {"ok": True, "created": bool(created)}
        if view == "add_dead_end":
            asset_type = str(args.get("asset_type") or "").strip()
            value = str(args.get("value") or "").strip()
            if not asset_type or not value:
                raise ToolError("asset_type and value are required "
                                "for view=add_dead_end")
            created = _store.add_dead_end(
                session, system, target, asset_type, value,
                run_id=str(args.get("run_id") or ""),
                reason=str(args.get("reason") or ""))
            return {"ok": True, "created": bool(created)}
    finally:
        session.close()
    raise ToolError("view must be packs|pack|known|memory|finds|"
                    "resources|add_known|add_dead_end")


def _tool_hunters(args: Dict) -> Dict:
    """The hunters' shared state (read views + roster), one tool:
    list | memory | known_set | knowledge | resources."""
    from .agentdata import packs as _packs
    from .agentdata import store as _store
    view = str(args.get("view") or "list").strip().lower()
    if view == "knowledge":
        return {"packs": _packs.pack_inventory()}
    session = get_session()
    try:
        if view == "resources":
            from .agentdata import resources
            return {"resources": resources.catalog(session)}
        if view == "list":
            from .hunters.roles import HUNTERS
            stats = _store.hunter_stats(session, _store.DEFAULT_SYSTEM)
            out = []
            for h in HUNTERS:
                s = stats.get(h["name"], {})
                out.append({**h, "stats": {
                    "assets_discovered": s.get("assets_discovered", 0),
                    "jobs_enqueued": s.get("jobs_enqueued", 0),
                    "dead_ends": s.get("dead_ends", 0),
                    "assets_in_known_set": s.get(
                        "assets_in_known_set", 0)}})
            return {"hunters": out, "count": len(out)}
        target = str(args.get("target") or "").strip()
        if not target:
            raise ToolError(f"target is required for view={view}")
        if view == "memory":
            mem = _store.get_memory(session, _store.DEFAULT_SYSTEM,
                                    target)
            counts = _store.known_counts(session,
                                         _store.DEFAULT_SYSTEM, target)
            mem["known_set_counts"] = counts
            mem["known_set_total"] = sum(counts.values())
            return mem
        if view == "known_set":
            assets = _store.get_known_set(session,
                                          _store.DEFAULT_SYSTEM, target)
            grouped: Dict[str, list] = {}
            for a in assets:
                grouped.setdefault(a["type"], []).append(a)
            return {"target": target, "total": len(assets),
                    "counts": {k: len(v) for k, v in grouped.items()},
                    "assets": assets, "grouped": grouped}
    finally:
        session.close()
    raise ToolError("view must be list|memory|known_set|knowledge|"
                    "resources")


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

_RUN_ID_PROP = {"run_id": {"type": "string"}}
_RUN_ID_SCHEMA = {"type": "object", "properties": _RUN_ID_PROP,
                  "required": ["run_id"]}


# -- v2.2: agent write / terminal / browser / crazy tools -------------------
# Sync agent_tools impls run in a thread so long subprocess calls do not
# block the event loop. AgentToolError becomes the MCP ToolError.

async def _run_agent(fn, *a, **kw):
    try:
        return await asyncio.to_thread(fn, *a, **kw)
    except _AgentToolError as e:
        raise ToolError(str(e))


async def _tool_agent_write_poc(args: Dict) -> Dict:
    return await _run_agent(
        _write_poc_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""),
        args.get("hypothesis") or {},
        fork_block=args.get("fork_block"),
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_write_report(args: Dict) -> Dict:
    return await _run_agent(
        _write_report_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""),
        scan=args.get("scan"), probe=args.get("probe"),
        fork=args.get("fork"),
        verdict=str(args.get("verdict") or "UNVERIFIED"))


async def _tool_agent_cast(args: Dict) -> Dict:
    argv = args.get("args")
    if not isinstance(argv, list) or not argv:
        raise ToolError("args is required (list of cast arguments)")
    return await _run_agent(
        _cast_impl, [str(a) for a in argv],
        rpc_url=args.get("rpc_url"),
        timeout_s=float(args.get("timeout_s") or 60))


async def _tool_agent_forge(args: Dict) -> Dict:
    return await _run_agent(
        _forge_impl, str(args.get("action") or "test"),
        str(args.get("tree") or ""),
        target=args.get("target"),
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_anvil(args: Dict) -> Dict:
    return await _run_agent(
        _anvil_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""),
        args.get("hypothesis") or {},
        fork_block=args.get("fork_block"),
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_slither(args: Dict) -> Dict:
    return await _run_agent(
        _slither_impl, chain=args.get("chain"),
        address=args.get("address"), source=args.get("source"),
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_mythril(args: Dict) -> Dict:
    return await _run_agent(
        _mythril_impl, chain=args.get("chain"),
        address=args.get("address"), source=args.get("source"),
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_fetch(args: Dict) -> Dict:
    return await _run_agent(
        _fetch_impl, str(args.get("url") or ""),
        timeout_s=float(args.get("timeout_s") or 25))


async def _tool_agent_search(args: Dict) -> Dict:
    return await _run_agent(
        _search_impl, str(args.get("query") or ""),
        limit=int(args.get("limit") or 5),
        timeout_s=float(args.get("timeout_s") or 30))


async def _tool_agent_explorer(args: Dict) -> Dict:
    return await _run_agent(
        _explorer_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""),
        str(args.get("what") or "transactions"),
        page=int(args.get("page") or 0),
        page_size=int(args.get("page_size") or 25))


async def _tool_agent_fuzz(args: Dict) -> Dict:
    return await _run_agent(
        _fuzz_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""),
        token=args.get("token"), runs=int(args.get("runs") or 64),
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_simulate(args: Dict) -> Dict:
    steps = args.get("steps")
    if not isinstance(steps, list):
        raise ToolError("steps is required (list of step objects)")
    return await _run_agent(
        _simulate_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""), steps,
        fork_block=args.get("fork_block"),
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_time_travel(args: Dict) -> Dict:
    blocks = args.get("blocks")
    if not isinstance(blocks, list):
        raise ToolError("blocks is required (list of block numbers)")
    return await _run_agent(
        _time_travel_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""),
        str(args.get("signature") or ""),
        args=args.get("args"), blocks=[int(b) for b in blocks],
        timeout_s=float(args.get("timeout_s") or 120))


async def _tool_agent_deploy_fork(args: Dict) -> Dict:
    return await _run_agent(
        _deploy_fork_impl, str(args.get("chain") or ""),
        str(args.get("address") or ""),
        str(args.get("patched_source") or ""),
        args.get("hypothesis") or {},
        timeout_s=float(args.get("timeout_s") or 300))


async def _tool_agent_multicall(args: Dict) -> Dict:
    calls = args.get("calls")
    if not isinstance(calls, list):
        raise ToolError("calls is required (list of call objects)")
    return await _run_agent(
        _multicall_impl, str(args.get("chain") or ""), calls,
        block=args.get("block"),
        timeout_s=float(args.get("timeout_s") or 60))


TOOLS: List[Dict[str, Any]] = [
    {
        "name": "recon_health",
        "description": "Health of the ReconAnything service: database "
                       "reachability, plugin count, server time, MCP "
                       "version and auth mode.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _tool_health,
    },
    {
        "name": "recon_start_scan",
        "description": "Start a detection-only ReconAnything scan of "
                       "authorized targets and return its run_id. "
                       "Presets: quick = passive plugins only, passive "
                       "mode; standard = the default plugin set, active "
                       "mode; deep = every plugin explicitly selected "
                       "(budget-skip exempt), active mode. Honors the "
                       "app's SANDBOX/LIVE target gate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "string",
                            "description": "One or more domains, URLs or "
                                           "IPs, newline/comma separated."},
                "preset": {"type": "string",
                           "enum": ["quick", "standard", "deep"],
                           "default": "standard"},
                "mode": {"type": "string", "enum": ["passive", "active"],
                         "description": "Override the preset's mode."},
                "plugins": {"type": "array", "items": {"type": "string"},
                            "description": "Explicit plugin ids; "
                                           "overrides the preset."},
                "source_type": {"type": "string",
                                "enum": ["website", "bank", "atm",
                                         "bankatm"],
                                "default": "website"},
                "bounty": {"type": "boolean", "default": False,
                           "description": "Prioritize high-impact vuln "
                                          "classes."},
            },
            "required": ["targets"],
        },
        "handler": _tool_start_scan,
    },
    {
        "name": "recon_list_runs",
        "description": "List recent scan runs (newest first) with "
                       "status and findings counts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 30,
                          "minimum": 1, "maximum": 200},
            },
        },
        "handler": _tool_list_runs,
    },
    {
        "name": "recon_run_status",
        "description": "One run's status, live progress (done/total, "
                       "running plugins), targets and summary.",
        "inputSchema": _RUN_ID_SCHEMA,
        "handler": _tool_run_status,
    },
    {
        "name": "recon_get_findings",
        "description": "A run's findings (secrets masked) with each "
                       "finding's confidence, plus confidence-band "
                       "counts and an executive summary. Optionally "
                       "filter by min_confidence (0-1).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "limit": {"type": "integer", "default": 500,
                          "minimum": 1, "maximum": 5000},
                "min_confidence": {"type": "number", "minimum": 0,
                                   "maximum": 1},
            },
            "required": ["run_id"],
        },
        "handler": _tool_get_findings,
    },
    {
        "name": "recon_get_graph",
        "description": "A run's attack-surface correlation graph: "
                       "nodes (domains, IPs, certs, endpoints, tech, "
                       "orgs) and edges with relation, confidence and "
                       "provenance.",
        "inputSchema": _RUN_ID_SCHEMA,
        "handler": _tool_get_graph,
    },
    {
        "name": "recon_list_plugins",
        "description": "The full plugin registry: ids, labels, what "
                       "each accepts, passive/active, cost and key "
                       "requirements.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _tool_list_plugins,
    },
    {
        "name": "recon_query_knowledge",
        "description": "Query the cross-run knowledge store "
                       "(app/knowledge_store.py): assets accumulated "
                       "across every finalized run - domains, "
                       "subdomains, IPs, endpoints - each with "
                       "domain, ip, ports, tech_stack and is_cdn "
                       "fields queryable. Filter by tech substring "
                       "(the '%Nginx%' shape), is_cdn, kind, ip, "
                       "scope, or first-seen since a timestamp.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tech": {"type": "string",
                         "description": "Substring match over the "
                                        "asset's tech stack, "
                                        "e.g. 'Nginx'."},
                "is_cdn": {"type": "boolean",
                           "description": "True = behind a CDN, "
                                          "False = verified not."},
                "kind": {"type": "string",
                         "enum": ["host", "domain", "subdomain", "ip",
                                  "endpoint", "url"],
                         "description": "Asset kind filter."},
                "ip": {"type": "string",
                       "description": "Exact resolved IP match."},
                "scope": {"type": "string",
                          "description": "Target root scope, "
                                         "e.g. example.com."},
                "since": {"type": ["number", "string"],
                          "description": "Only assets first seen at "
                                         "or after this time (epoch "
                                         "seconds or ISO 8601)."},
                "limit": {"type": "integer", "default": 200,
                          "minimum": 1, "maximum": 1000},
            },
        },
        "handler": _tool_query_knowledge,
    },
    {
        "name": "recon_get_delta",
        "description": "Asset-level delta for a target scope "
                       "between its previous and latest completed "
                       "runs (app/delta.py): + NEW assets, "
                       "- REMOVED assets, ~ CHANGED tech stack / "
                       "TLS certificate / ports / status. Optionally "
                       "pass explicit from_run / to_run ids.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {"type": "string",
                          "description": "Target root scope, "
                                         "e.g. example.com."},
                "from_run": {"type": "string",
                             "description": "Older run id "
                                            "(default: previous "
                                            "completed run)."},
                "to_run": {"type": "string",
                           "description": "Newer run id (default: "
                                          "latest completed run)."},
            },
            "required": ["scope"],
        },
        "handler": _tool_get_delta,
    },
    {
        "name": "recon_classify",
        "description": "Classify a target string the way the scan "
                       "pipeline does (domain, URL, IP, email, wallet, "
                       "contract, hash, JWT, ...): returns its type "
                       "and normalized form. Pass several targets "
                       "newline-separated for a batch result.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        "handler": _tool_classify,
    },
    {
        "name": "recon_settings",
        "description": "Current app settings: the SANDBOX/LIVE scan "
                       "mode, the owned-assets allowlist used by the "
                       "SANDBOX gate, and the recent settings audit "
                       "trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "audit_limit": {"type": "integer", "default": 20,
                                "minimum": 1, "maximum": 100},
            },
        },
        "handler": _tool_settings,
    },
    {
        "name": "recon_set_mode",
        "description": "Switch the app scan mode (SANDBOX or LIVE). "
                       "Same settings action as the UI; the switch is "
                       "written to the audit log. SANDBOX restricts "
                       "scans to owned/lab targets; LIVE allows "
                       "authorized external targets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {"type": "string",
                         "enum": ["sandbox", "live"]},
            },
            "required": ["mode"],
        },
        "handler": _tool_set_mode,
    },
    {
        "name": "recon_set_owned_assets",
        "description": "Replace the owned-assets allowlist (the "
                       "owner's own domains/hosts that SANDBOX mode "
                       "may scan). The update is written to the audit "
                       "log.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assets": {"type": "array",
                           "items": {"type": "string"}},
            },
            "required": ["assets"],
        },
        "handler": _tool_set_owned_assets,
    },
    {
        "name": "recon_run_detail",
        "description": "Full detail for one run (mirrors GET "
                       "/api/runs/{id}): run row, targets, live "
                       "progress, executive summary and every finding "
                       "(secrets masked). Heavier than "
                       "recon_run_status.",
        "inputSchema": _RUN_ID_SCHEMA,
        "handler": _tool_run_detail,
    },
    {
        "name": "recon_agent_activity",
        "description": "One run's agent-activity feed: every hunter "
                       "action in order with a plain-language "
                       "description, plus a per-agent rollup (actions, "
                       "assets found, jobs queued, findings "
                       "contributed, status).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "limit": {"type": "integer", "default": 500,
                          "minimum": 1, "maximum": 2000},
            },
            "required": ["run_id"],
        },
        "handler": _tool_agent_activity,
    },
    {
        "name": "recon_retest_finding",
        "description": "Re-run the ONE plugin that produced a "
                       "finding, against that finding's own stored "
                       "target, and compare fresh vs stored "
                       "(unchanged / changed / gone / error). The "
                       "plugin and target come from the stored "
                       "finding - the caller cannot name a URL, "
                       "plugin, or payload. Rate limited per finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "finding_id": {"type": "integer"},
            },
            "required": ["run_id", "finding_id"],
        },
        "handler": _tool_retest_finding,
    },
    {
        "name": "recon_get_apimap",
        "description": "A run's application attack-surface map: the "
                       "flat endpoint entries plus groups (pages, "
                       "api_routes, forms, js_endpoints, websockets, "
                       "graphql), each entry with method, status, "
                       "auth, params and note.",
        "inputSchema": _RUN_ID_SCHEMA,
        "handler": _tool_get_apimap,
    },
    {
        "name": "recon_export_run",
        "description": "Export a run's findings in a report format: "
                       "json (structured rows), csv, md (markdown "
                       "report) or html (styled report). Secrets are "
                       "masked.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "format": {"type": "string",
                           "enum": ["json", "csv", "md", "html"],
                           "default": "json"},
            },
            "required": ["run_id"],
        },
        "handler": _tool_export_run,
    },
    {
        "name": "recon_fetch_run_file",
        "description": "Fetch a URL that appeared in a run's own "
                       "findings so its contents can be inspected. "
                       "SSRF-guarded exactly like the REST fetch "
                       "route: arbitrary URLs are refused.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "url": {"type": "string"},
            },
            "required": ["run_id", "url"],
        },
        "handler": _tool_fetch_run_file,
    },
    {
        "name": "recon_list_vulns",
        "description": "Possible-vulnerabilities advisor for a run: "
                       "ranked candidate attack paths derived from "
                       "the scan findings (heuristic, detection-only, "
                       "no requests are sent).",
        "inputSchema": _RUN_ID_SCHEMA,
        "handler": _tool_list_vulns,
    },
    {
        "name": "recon_test_vulns",
        "description": "Safe-test a run's vuln candidates. "
                       "dry_run=true (the DEFAULT) sends zero "
                       "requests: it narrates what each detection "
                       "check WOULD do. dry_run=false runs the "
                       "backend's real safe tester: GET/HEAD only, "
                       "rate-limited, non-destructive probes against "
                       "the run's own targets, returning only "
                       "confirmed candidates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "dry_run": {"type": "boolean", "default": True},
                "candidate_id": {"type": "string",
                                 "description": "Dry-run a single "
                                                "candidate id "
                                                "(from "
                                                "recon_list_vulns)."},
                "base": {"type": "string",
                         "description": "Base URL override "
                                        "(default: the run's first "
                                        "target)."},
            },
            "required": ["run_id"],
        },
        "handler": _tool_test_vulns,
    },
    {
        "name": "recon_verify_subdomains",
        "description": "Probe every subdomain from a run's findings "
                       "for HTTP liveness (live, status, server, "
                       "page title). Only hosts from the run's own "
                       "findings are probed (SSRF guard); results "
                       "are cached in the run for 24h unless "
                       "force=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["run_id"],
        },
        "handler": _tool_verify_subdomains,
    },
    {
        "name": "recon_probe_port",
        "description": "Probe a single host:port from a run's "
                       "findings for banner/service info. Both the "
                       "host and the port must appear in the run "
                       "(SSRF guard). Read-only: TCP connect + short "
                       "banner read, plus an HTTP GET on web ports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "host": {"type": "string"},
                "port": {"type": "integer", "minimum": 1,
                         "maximum": 65535},
            },
            "required": ["run_id", "host", "port"],
        },
        "handler": _tool_probe_port,
    },
    {
        "name": "recon_diff_runs",
        "description": "Finding-level diff between two runs "
                       "(app/diff.py, the /api/diff route): new, "
                       "removed and changed findings. Distinct from "
                       "recon_get_delta, which is the asset-level "
                       "knowledge-store delta for a scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_a": {"type": "string"},
                "run_b": {"type": "string"},
            },
            "required": ["run_a", "run_b"],
        },
        "handler": _tool_diff_runs,
    },
    {
        "name": "recon_atm_locate",
        "description": "Public ATM locations near a place name or "
                       "'lat, lon[, radius_m]' via OpenStreetMap "
                       "(read-only public data). Hard gate, same as "
                       "the REST route: authorized=true is required "
                       "and the claim is logged server-side.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "query": {"type": "string"},
                "authorized": {"type": "boolean", "default": False},
            },
            "required": ["run_id", "query", "authorized"],
        },
        "handler": _tool_atm_locate,
    },
    {
        "name": "recon_list_schedules",
        "description": "List the recurring-scan schedules (target, "
                       "cron expression, mode, enabled, last run).",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _tool_list_schedules,
    },
    {
        "name": "recon_create_schedule",
        "description": "Create a recurring-scan schedule for a "
                       "target (cron expression, passive/active "
                       "mode).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_raw": {"type": "string"},
                "cron": {"type": "string",
                         "description": "Cron expression, "
                                        "e.g. '0 6 * * *'."},
                "mode": {"type": "string",
                         "enum": ["passive", "active"],
                         "default": "passive"},
                "enabled": {"type": "boolean", "default": True},
            },
            "required": ["target_raw", "cron"],
        },
        "handler": _tool_create_schedule,
    },
    {
        "name": "recon_delete_schedule",
        "description": "Delete a recurring-scan schedule by id "
                       "(from recon_list_schedules).",
        "inputSchema": {
            "type": "object",
            "properties": {"schedule_id": {"type": "string"}},
            "required": ["schedule_id"],
        },
        "handler": _tool_delete_schedule,
    },
    {
        "name": "recon_breachwatch",
        "description": "Breach-watch status: the owner's monitored "
                       "email addresses and their last cached breach "
                       "check results. Defensive only - public breach "
                       "data about the owner's own addresses.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _tool_breachwatch,
    },
    {
        "name": "recon_breachwatch_check",
        "description": "Check one email address against public "
                       "breach dumps (XposedOrNot, keyless) and cache "
                       "the result. Defensive: never attempts logins, "
                       "returns breach names/dates only.",
        "inputSchema": {
            "type": "object",
            "properties": {"email": {"type": "string"}},
            "required": ["email"],
        },
        "handler": _tool_breachwatch_check,
    },
    {
        "name": "recon_agentdata",
        "description": "The agent data service the hunters share: "
                       "knowledge packs, per-target known sets and "
                       "memory, recent finds, the resource catalog, "
                       "and (write views) recording known assets / "
                       "dead ends. Pick a view: packs | pack | known "
                       "| memory | finds | resources | add_known | "
                       "add_dead_end.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "view": {"type": "string",
                         "enum": ["packs", "pack", "known", "memory",
                                  "finds", "resources", "add_known",
                                  "add_dead_end"],
                         "default": "packs"},
                "system": {"type": "string", "default": "recon",
                           "description": "Data namespace (default "
                                          "'recon')."},
                "target": {"type": "string",
                           "description": "Target scope for "
                                          "known/memory/finds/add_* "
                                          "views."},
                "name": {"type": "string",
                         "description": "Pack name for view=pack."},
                "asset_type": {"type": "string",
                               "description": "For add_known / "
                                              "add_dead_end."},
                "value": {"type": "string",
                          "description": "For add_known / "
                                         "add_dead_end."},
                "found_by": {"type": "string"},
                "run_id": {"type": "string"},
                "reason": {"type": "string",
                           "description": "For add_dead_end."},
                "hunter": {"type": "string",
                           "description": "finds filter."},
                "limit": {"type": "integer", "default": 50,
                          "minimum": 1, "maximum": 200},
            },
        },
        "handler": _tool_agentdata,
    },
    {
        "name": "recon_hunters",
        "description": "The hunter agents' roster and shared state "
                       "(read-only human view of the same data "
                       "service): list (roster + per-hunter stats) | "
                       "memory | known_set | knowledge (packs) | "
                       "resources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "view": {"type": "string",
                         "enum": ["list", "memory", "known_set",
                                  "knowledge", "resources"],
                         "default": "list"},
                "target": {"type": "string",
                           "description": "Target scope for "
                                          "memory / known_set."},
            },
        },
        "handler": _tool_hunters,
    },
    {
        "name": "agent_write_poc",
        "description": "Write a Foundry fork test for a candidate + "
                       "hypothesis, run it on a local Anvil fork, and "
                       "return the test path + result. Fork only; the "
                       "result is UNVERIFIED, never proof.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string",
                          "enum": ["bsc", "ethereum", "base",
                                   "arbitrum", "polygon"]},
                "address": {"type": "string"},
                "hypothesis": {"type": "object",
                               "properties": {
                                   "function": {"type": "string"},
                                   "args": {"type": "array"},
                                   "value_wei": {"type": "integer"},
                                   "tokens": {"type": "array",
                                              "items": {"type": "string"}},
                               },
                               "required": ["function"]},
                "fork_block": {"type": "integer"},
                "timeout_s": {"type": "number", "default": 300},
            },
            "required": ["chain", "address", "hypothesis"],
        },
        "handler": _tool_agent_write_poc,
    },
    {
        "name": "agent_write_report",
        "description": "Write a verdict report (markdown) for an "
                       "address from scan / probe / fork results. Can "
                       "NEVER stamp VERIFIED_REAL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "scan": {"type": "object"},
                "probe": {"type": "object"},
                "fork": {"type": "object"},
                "verdict": {"type": "string",
                            "enum": ["UNVERIFIED", "FALSE_POSITIVE",
                                     "TRIGGER_ONLY"],
                            "default": "UNVERIFIED"},
            },
            "required": ["chain", "address"],
        },
        "handler": _tool_agent_write_report,
    },
    {
        "name": "agent_cast",
        "description": "Bounded cast wrapper: read-only calls and "
                       "fork sends only. Refuses mainnet sends and "
                       "any private-key / mnemonic / keystore / "
                       "hardware flag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "args": {"type": "array", "items": {"type": "string"}},
                "rpc_url": {"type": "string"},
                "timeout_s": {"type": "number", "default": 60},
            },
            "required": ["args"],
        },
        "handler": _tool_agent_cast,
    },
    {
        "name": "agent_forge",
        "description": "Run forge build / test / fmt on a given tree "
                       "(tree must be under /var/tmp or ~/workspace).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string",
                           "enum": ["build", "test", "fmt"],
                           "default": "test"},
                "tree": {"type": "string"},
                "target": {"type": "string"},
                "timeout_s": {"type": "number", "default": 300},
            },
            "required": ["action", "tree"],
        },
        "handler": _tool_agent_forge,
    },
    {
        "name": "agent_anvil",
        "description": "Start a local Anvil fork at a block, run one "
                       "scripted attack step as an unfunded stranger, "
                       "stop it, report what the stranger received. "
                       "Fork only; result is UNVERIFIED.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "hypothesis": {"type": "object",
                               "properties": {
                                   "function": {"type": "string"},
                                   "args": {"type": "array"},
                                   "value_wei": {"type": "integer"},
                                   "tokens": {"type": "array",
                                              "items": {"type": "string"}},
                               },
                               "required": ["function"]},
                "fork_block": {"type": "integer"},
                "timeout_s": {"type": "number", "default": 300},
            },
            "required": ["chain", "address", "hypothesis"],
        },
        "handler": _tool_agent_anvil,
    },
    {
        "name": "agent_slither",
        "description": "Run Slither on verified source (or pasted "
                       "source) and return its findings. Read-only "
                       "static analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "source": {"type": "string"},
                "timeout_s": {"type": "number", "default": 300},
            },
        },
        "handler": _tool_agent_slither,
    },
    {
        "name": "agent_mythril",
        "description": "Run Mythril on verified source (or pasted "
                       "source) and return its findings. Read-only "
                       "static analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "source": {"type": "string"},
                "timeout_s": {"type": "number", "default": 300},
            },
        },
        "handler": _tool_agent_mythril,
    },
    {
        "name": "agent_fetch",
        "description": "Fetch one URL's text (explorers, Sourcify, "
                       "DexScreener, GitHub raw). Allowlisted hosts, "
                       "https only, 200KB cap.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "timeout_s": {"type": "number", "default": 25},
            },
            "required": ["url"],
        },
        "handler": _tool_agent_fetch,
    },
    {
        "name": "agent_search",
        "description": "Keyless web search (DuckDuckGo html) for a "
                       "contract address, topic or error string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 5,
                          "minimum": 1, "maximum": 10},
                "timeout_s": {"type": "number", "default": 30},
            },
            "required": ["query"],
        },
        "handler": _tool_agent_search,
    },
    {
        "name": "agent_explorer",
        "description": "Read-only explorer reads via the keyless "
                       "Blockscout v2 API: transactions, token "
                       "transfers, logs, holders, token info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "what": {"type": "string",
                         "enum": ["transactions", "token_transfers",
                                  "logs", "holders", "token_info"]},
                "page": {"type": "integer", "default": 0},
                "page_size": {"type": "integer", "default": 25,
                              "minimum": 1, "maximum": 50},
            },
            "required": ["chain", "address", "what"],
        },
        "handler": _tool_agent_explorer,
    },
    {
        "name": "agent_fuzz",
        "description": "Bounded invariant fuzz on a fork: random "
                       "calldata against the target, invariant = the "
                       "unfunded stranger never gains value. Verdict "
                       "always UNVERIFIED.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "token": {"type": "string"},
                "runs": {"type": "integer", "default": 64,
                         "minimum": 1, "maximum": 256},
                "timeout_s": {"type": "number", "default": 300},
            },
            "required": ["chain", "address"],
        },
        "handler": _tool_agent_fuzz,
    },
    {
        "name": "agent_simulate",
        "description": "Multi-step simulation on a fork, including "
                       "flash-loan-shaped steps funded on the fork "
                       "only. Sim-only verdict, always UNVERIFIED.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "steps": {"type": "array",
                          "items": {"type": "object"}},
                "fork_block": {"type": "integer"},
                "timeout_s": {"type": "number", "default": 300},
            },
            "required": ["chain", "address", "steps"],
        },
        "handler": _tool_agent_simulate,
    },
    {
        "name": "agent_time_travel",
        "description": "Re-run one read-only probe at historical "
                       "blocks to catch upgrade-window bugs. Archive "
                       "gaps are reported, never faked.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "signature": {"type": "string"},
                "args": {"type": "array"},
                "blocks": {"type": "array",
                           "items": {"type": "integer"}},
                "timeout_s": {"type": "number", "default": 120},
            },
            "required": ["chain", "address", "signature", "blocks"],
        },
        "handler": _tool_agent_time_travel,
    },
    {
        "name": "agent_deploy_fork",
        "description": "Deploy a patched contract to a local fork "
                       "and diff its behavior vs the original under "
                       "the same hypothesis. Fork only; verdict "
                       "always UNVERIFIED.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "address": {"type": "string"},
                "patched_source": {"type": "string"},
                "hypothesis": {"type": "object",
                               "properties": {
                                   "function": {"type": "string"},
                                   "args": {"type": "array"},
                                   "value_wei": {"type": "integer"},
                               },
                               "required": ["function"]},
                "timeout_s": {"type": "number", "default": 300},
            },
            "required": ["chain", "address", "patched_source",
                         "hypothesis"],
        },
        "handler": _tool_agent_deploy_fork,
    },
    {
        "name": "agent_multicall",
        "description": "Batch read-only calls in one round trip via "
                       "Multicall3, falling back to sequential calls. "
                       "Read-only, never a transaction.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string"},
                "calls": {"type": "array",
                          "items": {"type": "object",
                                    "properties": {
                                        "address": {"type": "string"},
                                        "function": {"type": "string"},
                                        "args": {"type": "array"},
                                    },
                                    "required": ["address",
                                                 "function"]}},
                "block": {"type": "integer"},
                "timeout_s": {"type": "number", "default": 60},
            },
            "required": ["chain", "calls"],
        },
        "handler": _tool_agent_multicall,
    },
]

_TOOL_MAP = {t["name"]: t for t in TOOLS}


def _public_tool(tool: Dict) -> Dict:
    return {"name": tool["name"], "description": tool["description"],
            "inputSchema": tool["inputSchema"]}


# ---------------------------------------------------------------------------
# JSON-RPC dispatch (shared by the HTTP and stdio transports)
# ---------------------------------------------------------------------------

def _result(req_id: Any, payload: Any) -> Dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": payload}


def _error(req_id: Any, code: int, message: str) -> Dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


async def _call_tool(name: str, args: Dict) -> Dict:
    tool = _TOOL_MAP.get(name)
    if tool is None:
        return {"content": [{"type": "text",
                             "text": f"unknown tool: {name}"}],
                "isError": True}
    try:
        handler = tool["handler"]
        if asyncio.iscoroutinefunction(handler):
            data = await handler(args)
        else:
            data = handler(args)
    except ToolError as e:
        return {"content": [{"type": "text", "text": str(e)}],
                "isError": True}
    except Exception as e:  # never leak a stack trace to the client
        log.exception("MCP tool %s failed", name)
        return {"content": [{"type": "text",
                             "text": f"{name} failed: {str(e)[:300]}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": json.dumps(data, default=str)}],
            "structuredContent": data, "isError": False}


async def _dispatch(msg: Any) -> Optional[Dict]:
    """One JSON-RPC message -> response dict, or None for notifications."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _error(None, -32600, "invalid request: expected a JSON-RPC "
                                    "2.0 object")
    method = msg.get("method")
    req_id = msg.get("id")
    is_notification = "id" not in msg
    params = msg.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = (requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                   else DEFAULT_PROTOCOL_VERSION)
        return _result(req_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "ReconAnything: detection-only attack-surface scanning "
                "of authorized targets. Start with recon_start_scan, "
                "poll recon_run_status, read results with "
                "recon_get_findings, recon_get_graph and "
                "recon_run_detail. The full backend is here: settings "
                "(recon_settings / recon_set_mode), schedules, the "
                "vuln advisor (recon_list_vulns / recon_test_vulns, "
                "dry-run by default), breach watch, and the agent "
                "data / hunter state (recon_agentdata, "
                "recon_hunters). Agent tools (agent_*) add write / "
                "terminal / browser / fork-simulation capability: "
                "agent_write_poc and agent_write_report, agent_cast / "
                "agent_forge / agent_anvil / agent_slither / "
                "agent_mythril, agent_fetch / agent_search / "
                "agent_explorer, and agent_fuzz / agent_simulate / "
                "agent_time_travel / agent_deploy_fork / "
                "agent_multicall. State-changing work runs on a local "
                "fork only; fork/sim/fuzz results are always "
                "UNVERIFIED."),
        })
    if method == "ping":
        return _result(req_id, {})
    if method == "tools/list":
        return _result(req_id,
                       {"tools": [_public_tool(t) for t in TOOLS]})
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if not name or not isinstance(args, dict):
            return _error(req_id, -32602,
                          "tools/call needs params.name and object "
                          "params.arguments")
        return _result(req_id, await _call_tool(str(name), args))
    if is_notification:
        return None  # notifications/initialized and friends: accept, drop
    return _error(req_id, -32601, f"method not found: {method}")


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

mcp_router = APIRouter()


@mcp_router.post("")
async def mcp_post(request: Request):
    if not _authorized(request):
        return JSONResponse(
            {"detail": "invalid or missing service key: send "
                       "X-Recon-Service-Key or Authorization: Bearer "
                       "<RECON_SERVICE_KEY>"},
            status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_error(None, -32700, "parse error: body must "
                                                 "be JSON"),
                            status_code=400)
    if isinstance(body, list):  # JSON-RPC batch
        responses = []
        for item in body:
            resp = await _dispatch(item)
            if resp is not None:
                responses.append(resp)
        if not responses:
            return Response(status_code=202)
        return JSONResponse(responses)
    resp = await _dispatch(body)
    if resp is None:
        return Response(status_code=202)
    return JSONResponse(resp)


@mcp_router.get("")
async def mcp_get(request: Request):
    if not _authorized(request):
        return JSONResponse({"detail": "invalid or missing service key"},
                            status_code=401)
    # Stateless server: no server-initiated SSE stream to open.
    return JSONResponse(_error(None, -32601,
                               "GET not supported: this MCP server is "
                               "stateless, POST JSON-RPC to /mcp"),
                        status_code=405)


def create_standalone_app(host: str = "127.0.0.1") -> FastAPI:
    """The MCP server as its own service (no web UI, no REST API).

    The bind host decides the default auth posture: a localhost bind
    with no RECON_SERVICE_KEY set runs keyless (see auth_required);
    anything wider keeps the v1 service-key requirement.
    """
    global _keyless_local_bind
    _keyless_local_bind = host in _LOCAL_HOSTS
    standalone = FastAPI(title="ReconAnything MCP", version=SERVER_VERSION)

    @standalone.on_event("startup")
    async def _startup() -> None:
        init_db()
        if auth_required():
            get_service_key()  # materialize the key file up front
            log.info("ReconAnything MCP server ready (auth: service key)")
        else:
            log.warning(
                "ReconAnything MCP server ready WITHOUT authentication "
                "(%s). This is the local-use mode: anyone who can reach "
                "this port can start scans. Set RECON_SERVICE_KEY to "
                "require a key.", auth_mode_label())

    @standalone.get("/")
    def _root() -> Dict:
        return {"service": "recon-anything-mcp",
                "version": SERVER_VERSION,
                "mcp_endpoint": "/mcp",
                "auth": auth_mode_label(),
                "stdio": "python -m app.mcp_server --stdio"}

    standalone.include_router(mcp_router, prefix="/mcp")
    return standalone


# ---------------------------------------------------------------------------
# Stdio transport
# ---------------------------------------------------------------------------

def _stdio_send(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def run_stdio() -> None:
    """Speak MCP over stdin/stdout: one JSON-RPC message per line.

    Keyless by design - the process is launched by the owner's own
    MCP client on the owner's own machine. All logging goes to
    stderr; stdout carries protocol messages only.
    """
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    try:
        init_db()
    except Exception:
        log.exception("stdio: database init failed")
    log.info("ReconAnything MCP stdio server ready (keyless local, "
             "version %s)", SERVER_VERSION)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            _stdio_send(_error(None, -32700,
                               "parse error: line must be JSON"))
            continue
        if isinstance(msg, list):  # JSON-RPC batch
            responses = []
            for item in msg:
                resp = asyncio.run(_dispatch(item))
                if resp is not None:
                    responses.append(resp)
            if responses:
                _stdio_send(responses)
            continue
        resp = asyncio.run(_dispatch(msg))
        if resp is not None:
            _stdio_send(resp)


def main(argv: Optional[List[str]] = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="recon-mcp",
        description="ReconAnything MCP server (detection-only). "
                    "Default: streamable HTTP on 127.0.0.1, keyless "
                    "unless RECON_SERVICE_KEY is set. --stdio for the "
                    "zero-setup local transport used by AI clients.")
    parser.add_argument("--stdio", action="store_true",
                        help="serve MCP over stdin/stdout (keyless)")
    parser.add_argument("--http", action="store_true",
                        help="serve MCP over streamable HTTP (default)")
    parser.add_argument("--host",
                        default=os.environ.get("MCP_HOST", "127.0.0.1"),
                        help="HTTP bind host (default 127.0.0.1; "
                             "keyless only on localhost binds)")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("MCP_PORT")
                                    or os.environ.get("PORT") or "8765"),
                        help="HTTP bind port (default 8765)")
    args = parser.parse_args(argv)

    if args.stdio:
        run_stdio()
        return

    import uvicorn
    logging.basicConfig(level=logging.INFO)
    if args.host not in _LOCAL_HOSTS \
            and not os.environ.get("RECON_SERVICE_KEY", "").strip() \
            and not _no_auth_opt_in():
        log.warning(
            "Binding %s with no RECON_SERVICE_KEY set: the service "
            "key is required on this bind and will be generated into "
            "the key file. Set RECON_MCP_NO_AUTH=1 to run keyless "
            "here, or bind 127.0.0.1 for keyless local use.",
            args.host)
    uvicorn.run(create_standalone_app(host=args.host),
                host=args.host, port=args.port)


if __name__ == "__main__":
    main()
