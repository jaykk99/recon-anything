"""ReconAnything as an MCP server (Model Context Protocol).

Exposes the existing scan engine to MCP clients (Claude, Error Inbox's
black team, any MCP host) over the streamable HTTP transport:

  POST /mcp   JSON-RPC: initialize, ping, tools/list, tools/call
  GET  /mcp   405 (this server is stateless; no server-initiated stream)

It is mounted into the main FastAPI app at /mcp (app/main.py) and can
also run standalone:

  python -m app.mcp_server            # uvicorn, $MCP_PORT or $PORT or 8765

Tools wrap the same internals the REST API uses (runner.launch_run,
reporting.findings_dump, graph.graph_payload, plugins.registry) - the
scanning engine is not reimplemented here.

Auth: every MCP request must carry the service key, either as the
X-Recon-Service-Key header or "Authorization: Bearer <key>". The key
comes from the RECON_SERVICE_KEY env var; when that is unset, a key is
generated once and stored in the key file (RECON_SERVICE_KEY_FILE,
default ~/workspace/recon-mcp-service-key.txt) with 0600 permissions,
so the standalone server and the mounted app share one stable key.
Comparison is constant-time. No key / wrong key = HTTP 401, before any
JSON-RPC dispatch.

Boundary: detection only, exactly like the REST API. The tools start
and read scans; nothing here confirms exploits, brute-forces, bypasses
auth, or touches private data. Authenticated-mode scans (stored
credentials) are NOT offered over MCP. The service key is the owner's
credential, so plan gating does not apply; the SANDBOX/LIVE app mode
gate DOES apply to recon_start_scan, same as POST /api/runs.

Protocol notes: stateless streamable HTTP (no session id is issued;
2025-03-26+ permits this), single JSON-RPC messages and batches,
notifications answered 202 with no body. Protocol versions offered:
2025-06-18, 2025-03-26, 2024-11-05; initialize echoes the client's
version when supported, else answers with the newest supported one.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hmac
import json
import logging
import os
import secrets
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import modes as app_modes
from .classifier import classify_batch
from .graph import graph_payload
from .keys import load_all
from .models import Finding, Run, Target, check_db, get_session, init_db
from .plugins.registry import describe
from .reporting import executive_summary, findings_dump, run_progress
from .runner import launch_run

log = logging.getLogger("recon-anything-mcp")

SERVER_NAME = "recon-anything"
SERVER_VERSION = "1.0.0"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

# ---------------------------------------------------------------------------
# Service key
# ---------------------------------------------------------------------------

_KEY_FILE_DEFAULT = "~/workspace/recon-mcp-service-key.txt"
_service_key_cache: Optional[str] = None


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


def _provided_key(request: Request) -> str:
    header = request.headers.get("x-recon-service-key", "").strip()
    if header:
        return header
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _authorized(request: Request) -> bool:
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
    limit = args.get("limit", 30)
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        raise ToolError("limit must be an integer")
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


TOOLS: List[Dict[str, Any]] = [
    {
        "name": "recon_health",
        "description": "Health of the ReconAnything service: database "
                       "reachability, plugin count, server time.",
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
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
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
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
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
]

_TOOL_MAP = {t["name"]: t for t in TOOLS}


def _public_tool(tool: Dict) -> Dict:
    return {"name": tool["name"], "description": tool["description"],
            "inputSchema": tool["inputSchema"]}


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
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
                "recon_get_findings and recon_get_graph."),
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


def create_standalone_app() -> FastAPI:
    """The MCP server as its own service (no web UI, no REST API)."""
    standalone = FastAPI(title="ReconAnything MCP", version=SERVER_VERSION)

    @standalone.on_event("startup")
    async def _startup() -> None:
        init_db()
        get_service_key()  # materialize the key file up front, if needed
        log.info("ReconAnything MCP server ready (auth: service key)")

    @standalone.get("/")
    def _root() -> Dict:
        return {"service": "recon-anything-mcp", "mcp_endpoint": "/mcp",
                "auth": "X-Recon-Service-Key header required"}

    standalone.include_router(mcp_router, prefix="/mcp")
    return standalone


def main() -> None:
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("MCP_PORT") or os.environ.get("PORT")
               or "8765")
    uvicorn.run(create_standalone_app(), host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
