"""Agent section routes: owner-gated only.

The gate dependency is attached in main.py at include time, so this
module never imports main (no circular import). Handlers read the actor
the gate stored on request.state: kinds "owner" and "open" (fallback
mode with no access code, which ReconAnything already treats as owner)
may use the agent; signed-in customers ("user") and anyone else get 403.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from . import allowlist as allow
from . import composio, service

router = APIRouter(tags=["agent"])


def require_agent_owner(request: Request) -> None:
    """Owner gate for the agent section. Accepts stub request objects
    with a .state.actor mapping, which the unit tests use."""
    actor = getattr(getattr(request, "state", None), "actor", None) or {}
    if actor.get("kind") not in ("owner", "open"):
        raise HTTPException(status_code=403, detail="agent section is owner-only")


@router.get("/api/agent/status")
def agent_status(request: Request):
    require_agent_owner(request)
    return {"ok": True, "app": "recon-anything-agent",
            "brain": "horde-first, keyless, never GPT/Claude/Gemini",
            "composio_configured": composio.configured(),
            "pre_authorized_hosts": sorted(allow.PRE_AUTHORIZED_HOSTS)}


class InvestigateIn(BaseModel):
    run_id: str | None = None
    url: str | None = None
    verify_limit: int = 20
    target_limit: int = 3
    expand: bool = False


@router.post("/api/agent/investigate")
def agent_investigate(body: InvestigateIn, request: Request):
    require_agent_owner(request)
    if body.run_id:
        try:
            return service.investigate_run(
                body.run_id, verify_limit=body.verify_limit,
                target_limit=body.target_limit, expand=body.expand)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
    if body.url:
        ok, why = allow.is_authorized(body.url)
        if not ok:
            raise HTTPException(status_code=403, detail=f"Target not authorized: {why}")
        from . import investigate as inv
        return inv.analyze_target(body.url)
    raise HTTPException(status_code=400, detail="run_id or url is required")


class ChatIn(BaseModel):
    message: str


@router.post("/api/agent/chat")
def agent_chat(body: ChatIn, request: Request):
    require_agent_owner(request)
    return service.chat(body.message)


class AllowIn(BaseModel):
    host: str


@router.post("/api/agent/allowlist")
def agent_allowlist(body: AllowIn, request: Request):
    require_agent_owner(request)
    try:
        allow.add_allowlist_host(body.host)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"added": body.host}
