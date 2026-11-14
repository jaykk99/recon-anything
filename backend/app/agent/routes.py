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


class PlanIn(BaseModel):
    objective: str = ""
    run_id: str | None = None
    authorized: bool = False
    commands: list[str] | None = None
    use_llm: bool = True
    min_score: int = 40
    limit: int = 5


@router.post("/api/agent/plan")
def agent_plan(body: PlanIn, request: Request):
    """Run the multi-step agent plan for a run (owner-only).

    gate -> rank -> investigate -> terminal_probe -> remediate -> verify
    -> report. Active steps run only with authorized=True and allowlisted
    targets. Resumable: calling again with the same run_id + objective
    continues the stored plan. Never runs exploit code against a target.
    """
    require_agent_owner(request)
    if not body.run_id:
        raise HTTPException(status_code=400, detail="run_id is required")
    import hashlib
    import os
    from pathlib import Path

    from .. import config
    from ..models import Target, get_session
    from ..reporting import findings_dump
    from . import plan as plan_mod

    session = get_session()
    try:
        rows = findings_dump(session, body.run_id, show_secrets=False)
        targets = [t.normalized or t.raw for t in
                   session.query(Target).filter_by(run_id=body.run_id).all()]
    finally:
        session.close()
    if not rows and not targets:
        raise HTTPException(status_code=404, detail=f"run {body.run_id} has no data")
    key = hashlib.sha1(f"{body.run_id}:{body.objective}".encode()).hexdigest()[:10]
    base = os.environ.get("RECON_AGENT_PLAN_DIR") or os.path.join(
        getattr(config, "EVIDENCE_DIR", "evidence") or "evidence", "plans")
    workdir = Path(base) / f"{body.run_id}-{key}"
    try:
        result = plan_mod.run_plan(
            workdir, objective=body.objective, run_id=body.run_id,
            targets=targets, authorized=body.authorized, findings=rows,
            commands=body.commands or [], use_llm=body.use_llm,
            min_score=body.min_score, limit=body.limit, log=lambda m: None)
    except plan_mod.PlanRefused as e:
        raise HTTPException(status_code=422, detail=str(e))
    report_md = ""
    rp = Path(result["report"].get("report", "")) if result.get("report") else None
    if rp and rp.exists():
        report_md = rp.read_text()[:100000]
    return {"run_id": body.run_id, "summary": result["summary"],
            "report_markdown": report_md}
