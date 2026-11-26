"""REST surface for autonomous campaigns.

The router is mounted behind the app's normal gate (main.py attaches
the same ``gate`` dependency the rest of /api uses), so a campaign is
only startable by an authorized actor. Starting one is explicit: the
caller declares the targets, which become the campaign's roots.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import render, resume_campaign, run_campaign
from .policy import build_scope
from .store import CampaignStore

router = APIRouter(tags=["campaigns"])

STORE = CampaignStore()


# -- payloads ---------------------------------------------------------------
class CampaignStartIn(BaseModel):
    objective: str = "find exposed secrets and access paths"
    targets: List[str] = Field(default_factory=list)
    run_id: str = ""
    exclude: List[str] = Field(default_factory=list)
    allow_active: bool = True
    allow_exploit_confirm: bool = False
    allow_auth_replay: bool = False
    max_requests: int = 60
    max_intents: int = 24
    max_rounds: int = 3
    max_seconds: float = 120.0
    per_host_rps: float = 2.0


class ApproveIn(BaseModel):
    intent_key: str = ""
    approve_all: bool = False


class ExploitScanIn(BaseModel):
    base: str
    probes: List[str] = Field(default_factory=list)
    pace_s: float = 0.5


# -- helpers ----------------------------------------------------------------
def _run_targets_and_findings(run_id: str, request: Request):
    """Seeds + existing findings from a run the caller may see."""
    from ..models import Run, Target, get_session
    from ..reporting import findings_dump

    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if run is None:
            raise HTTPException(status_code=404, detail="unknown run")
        actor = getattr(request.state, "actor", {"kind": "open"})
        if actor.get("kind") == "user" and run.user_id != actor["user"].id:
            raise HTTPException(status_code=404, detail="unknown run")
        targets = [t.normalized or t.raw
                   for t in session.query(Target).filter_by(run_id=run_id).all()]
        rows = findings_dump(session, run_id)
        return [t for t in targets if t], rows
    finally:
        session.close()


def _placeholder(campaign_id: str, objective: str, scope) -> Dict[str, Any]:
    from .planner import goals_for
    return {
        "id": campaign_id,
        "objective": objective,
        "goals": goals_for(objective),
        "status": "running",
        "reason": "campaign started",
        "created": time.time(),
        "updated": time.time(),
        "scope": scope.to_dict(),
        "budget": {},
        "summary": {},
        "kill_chain": [],
        "pending_approval": [],
        "approved": [],
        "graph": {},
    }


def _start_thread(campaign_id: str, objective: str, scope, seeds,
                  findings, approved=()) -> None:
    def work() -> None:
        try:
            result = run_campaign(objective, scope, seeds=seeds,
                                  findings=findings, campaign_id=campaign_id,
                                  approved=approved)
        except Exception as exc:  # never leave a "running" ghost
            data = STORE.load(campaign_id) or {"id": campaign_id}
            data.update(status="failed", updated=time.time(),
                        reason=f"campaign failed: {str(exc)[:400]}")
            STORE.save(data)
            return
        STORE.save(result)

    threading.Thread(target=work, daemon=True, name=f"campaign-{campaign_id}").start()


# -- campaigns --------------------------------------------------------------
@router.post("/api/campaigns")
def start_campaign(body: CampaignStartIn, request: Request) -> Dict[str, Any]:
    targets = list(body.targets)
    imported: List[Dict[str, Any]] = []
    if body.run_id:
        run_targets, imported = _run_targets_and_findings(body.run_id, request)
        targets.extend(run_targets)
    if not targets:
        raise HTTPException(status_code=400,
                            detail="declare at least one target or a run_id")

    scope, refusals = build_scope(
        targets, allow_active=body.allow_active,
        allow_exploit_confirm=body.allow_exploit_confirm,
        allow_auth_replay=body.allow_auth_replay,
        exclude=body.exclude, max_requests=body.max_requests,
        max_intents=body.max_intents, max_rounds=body.max_rounds,
        max_seconds=body.max_seconds, per_host_rps=body.per_host_rps,
    )
    if not scope.roots:
        raise HTTPException(status_code=400,
                            detail={"message": "no in-scope targets",
                                    "refusals": refusals})

    campaign_id = "cmp_" + uuid.uuid4().hex[:12]
    STORE.save(_placeholder(campaign_id, body.objective, scope))
    _start_thread(campaign_id, body.objective, scope, targets, imported)
    return {"id": campaign_id, "status": "running",
            "scope": scope.to_dict(), "refusals": refusals,
            "status_url": f"/api/campaigns/{campaign_id}",
            "report_url": f"/api/campaigns/{campaign_id}/report"}


@router.get("/api/campaigns")
def list_campaigns(limit: int = 20) -> Dict[str, Any]:
    return {"campaigns": STORE.list(limit)}


@router.get("/api/campaigns/{campaign_id}")
def get_campaign(campaign_id: str) -> Dict[str, Any]:
    data = STORE.load(campaign_id)
    if data is None:
        raise HTTPException(status_code=404, detail="unknown campaign")
    return data


@router.get("/api/campaigns/{campaign_id}/report",
            response_class=PlainTextResponse)
def campaign_report(campaign_id: str) -> str:
    data = STORE.load(campaign_id)
    if data is None:
        raise HTTPException(status_code=404, detail="unknown campaign")
    if data.get("status") == "running":
        return (f"# Campaign {campaign_id}\n\nStill running; "
                f"objective: {data.get('objective', '')}\n")
    return render(data)


@router.post("/api/campaigns/{campaign_id}/approve")
def approve_campaign(campaign_id: str, body: ApproveIn) -> Dict[str, Any]:
    data = STORE.load(campaign_id)
    if data is None:
        raise HTTPException(status_code=404, detail="unknown campaign")
    pending = [p.get("key") for p in data.get("pending_approval") or []
               if p.get("key")]
    keys = pending if body.approve_all else ([body.intent_key]
                                             if body.intent_key else [])
    if not keys:
        raise HTTPException(status_code=400,
                            detail="nothing to approve (pass intent_key or "
                                   "approve_all=true)")
    for key in keys:
        data = STORE.approve(campaign_id, key)
    data = dict(data or {})
    data.update(status="running", updated=time.time())
    STORE.save(data)

    def work() -> None:
        resumed = resume_campaign(data, approve=keys)
        STORE.save(resumed)

    threading.Thread(target=work, daemon=True,
                     name=f"campaign-resume-{campaign_id}").start()
    return {"id": campaign_id, "status": "running", "approved": keys}


# -- standalone exploit probe pack -----------------------------------------
@router.post("/api/exploit/scan")
def exploit_scan(body: ExploitScanIn) -> Dict[str, Any]:
    """Run the read-only probe pack against one explicitly named target."""
    from ..exploit_probes import scan_pack

    base = (body.base or "").strip()
    if not base:
        raise HTTPException(status_code=400, detail="base is required")
    scope, refusals = build_scope([base], allow_active=True, max_requests=60)
    ok, reason = scope.allows(base)
    if not ok:
        raise HTTPException(status_code=403,
                            detail={"message": reason, "refusals": refusals})
    result = scan_pack(base, body.probes or None,
                       pace=time.sleep, pace_s=max(0.0, body.pace_s))
    result["scope"] = scope.to_dict()
    return result
