"""Composio tools for the agent: search + execute, owner-only, audit-logged.

Composio REST v3 with COMPOSIO_API_KEY. Without a key the tools return
a clean degraded message, never a crash. With the key on file returning
401, execute/search report the re-paste unblock. Audit log records tool
slug + argument KEYS only, never values, so no secret or personal data
lands in the log.
"""

from __future__ import annotations

import datetime as dt
import os

from .http_client import client as http_client

COMPOSIO_BASE = "https://backend.composio.dev/api/v3"
AUDIT_PATH = os.environ.get(
    "RECON_AGENT_AUDIT_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "agent-audit.log"),
)


def api_key() -> str:
    return os.environ.get("COMPOSIO_API_KEY", "").strip()


def configured() -> bool:
    return bool(api_key())


def _audit(tool: str, arg_keys: list[str]) -> None:
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
        with open(AUDIT_PATH, "a") as f:
            f.write(f"{dt.datetime.utcnow().isoformat()} composio {tool} "
                    f"args={','.join(sorted(arg_keys))}\n")
    except Exception:
        pass


def _auth_note(status: int) -> str | None:
    if status == 401:
        return "Composio key is invalid (401). Jay needs to re-paste the key."
    if status == 403:
        return "Composio refused the key (403). Jay needs to re-paste the key."
    return None


def composio_search(query: str, app_name: str = "") -> str:
    """List Composio tool slugs matching a keyword (composio_search)."""
    if not configured():
        return "Composio is not configured: COMPOSIO_API_KEY is missing."
    _audit("composio_search", ["query", "app_name"])
    try:
        params: dict = {}
        if app_name:
            params["app_names"] = app_name.upper()
        with http_client(30) as c:
            r = c.get(f"{COMPOSIO_BASE}/tools", params=params,
                      headers={"x-api-key": api_key()})
        note = _auth_note(r.status_code)
        if note:
            return note
        if r.status_code >= 400:
            return f"Composio error {r.status_code}: {r.text[:300]}"
        data = r.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            return str(data)[:2000]
        needle = query.lower()
        lines = []
        for it in items:
            slug = it.get("name") or it.get("slug") or "?"
            desc = (it.get("description") or "").strip().split("\n")[0][:120]
            if needle and needle not in slug.lower() and needle not in desc.lower():
                continue
            lines.append(f"- {slug}: {desc}")
            if len(lines) >= 40:
                break
        return "\n".join(lines) if lines else "No matching Composio tools found."
    except Exception as e:
        return f"Composio call failed: {e}"


def composio_execute(tool_slug: str, arguments: dict | None = None,
                     connected_account_id: str = "") -> str:
    """Run one Composio tool action (composio_execute). Owner-only: the
    caller must already hold the owner gate on the route."""
    if not configured():
        return "Composio is not configured: COMPOSIO_API_KEY is missing."
    _audit("composio_execute", list((arguments or {}).keys()))
    try:
        body: dict = {"tool_slug": tool_slug, "arguments": arguments or {}}
        if connected_account_id:
            body["connected_account_id"] = connected_account_id
        with http_client(60) as c:
            r = c.post(f"{COMPOSIO_BASE}/tools/execute", json=body,
                       headers={"x-api-key": api_key(),
                                "Content-Type": "application/json"})
        note = _auth_note(r.status_code)
        if note:
            return note
        if r.status_code >= 400:
            return f"Composio error {r.status_code}: {r.text[:300]}"
        return str(r.json())[:4000]
    except Exception as e:
        return f"Composio call failed: {e}"
