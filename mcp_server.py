#!/usr/bin/env python3
"""ReconAnything MCP server (stdio).

A thin Model Context Protocol wrapper around a running ReconAnything backend,
so Claude (or any MCP client) can start scans and read findings.

Config (environment):
  RECON_API_URL      backend base URL           (default http://127.0.0.1:8000)
  RECON_ACCESS_CODE  owner access code          (default: contents of
                     .local-access-code next to this file, if present)

Only scan targets you are authorized to test.

Run:   python mcp_server.py
Claude Code:  claude mcp add recon-anything -- python /path/to/mcp_server.py
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

API_URL = os.environ.get("RECON_API_URL", "http://127.0.0.1:8000").rstrip("/")
MAX_FINDINGS = 200


def _access_code() -> str:
    code = os.environ.get("RECON_ACCESS_CODE", "").strip()
    if code:
        return code
    f = Path(__file__).resolve().parent / ".local-access-code"
    try:
        return f.read_text().strip()
    except OSError:
        return ""


def _call(method: str, path: str, body: Optional[dict] = None,
          query: Optional[dict] = None) -> Any:
    url = API_URL + path
    if query:
        url += "?" + urllib.parse.urlencode(
            {k: v for k, v in query.items() if v is not None})
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    code = _access_code()
    if code:
        req.add_header("X-Access-Code", code)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"backend returned HTTP {e.code}: {detail}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"cannot reach ReconAnything backend at {API_URL} ({e.reason}). "
            "Start it (bash local-run/linux-start.sh) or set RECON_API_URL."
        ) from None


mcp = _Server(
    "recon-anything",
    instructions=(
        "Drive a ReconAnything scanner. Typical flow: list_plugins (optional) -> "
        "start_scan -> poll get_scan_status until status is finished -> "
        "get_findings. Only scan targets the user is authorized to test; "
        "prefer mode='passive' unless active testing is clearly authorized."
    ),
)


@mcp.tool()
def list_plugins() -> List[Dict[str, Any]]:
    """List available scan plugins (id, name, description, required API keys)."""
    plugins = _call("GET", "/api/plugins")["plugins"]
    keep = ("id", "name", "description", "mode", "category", "requires_keys")
    return [{k: p[k] for k in keep if k in p} for p in plugins]


@mcp.tool()
def start_scan(targets: str, mode: str = "passive",
               plugins: Optional[List[str]] = None,
               bounty: bool = False) -> Dict[str, Any]:
    """Start a scan and return its run id.

    targets: one or more domains/URLs/IPs, newline- or space-separated.
    mode: 'passive' (no direct probing, default) or 'active'.
    plugins: optional plugin ids from list_plugins; omit to run the default set.
    bounty: prioritize high-impact vulnerability classes.
    Only use targets you are authorized to test.
    """
    body: Dict[str, Any] = {"targets": targets, "mode": mode, "bounty": bounty}
    if plugins:
        body["plugins"] = plugins
    res = _call("POST", "/api/runs", body)
    return res if isinstance(res, dict) else {"result": res}


@mcp.tool()
def get_scan_status(run_id: str) -> Dict[str, Any]:
    """Get a scan's status (running/finished/...), progress and summary."""
    d = _call("GET", f"/api/runs/{urllib.parse.quote(run_id)}")
    return {"run": d.get("run"), "progress": d.get("progress"),
            "finding_count": len(d.get("findings") or [])}


@mcp.tool()
def get_findings(run_id: str, severity: Optional[str] = None,
                 limit: int = 50) -> Dict[str, Any]:
    """Get findings for a scan, with the executive summary.

    severity: optional filter (e.g. critical, high, medium, low, info).
    limit: max findings returned (capped at 200).
    """
    d = _call("GET", f"/api/runs/{urllib.parse.quote(run_id)}")
    rows = d.get("findings") or []
    if severity:
        sev = severity.lower()
        rows = [r for r in rows if str(r.get("severity", "")).lower() == sev]
    limit = max(1, min(int(limit), MAX_FINDINGS))
    return {"total_matching": len(rows), "returned": min(len(rows), limit),
            "executive_summary": d.get("executive_summary"),
            "findings": rows[:limit]}


@mcp.tool()
def list_scans(limit: int = 20) -> Any:
    """List recent scans (id, status, targets, summary)."""
    res = _call("GET", "/api/runs")
    runs = res.get("runs", res) if isinstance(res, dict) else res
    return runs[: max(1, min(int(limit), 100))] if isinstance(runs, list) else runs


if __name__ == "__main__":
    mcp.run()
