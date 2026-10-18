"""ReconAnything API (FastAPI).

Routes:
  GET  /api/health
  GET  /api/pin-required          whether a screen-lock PIN is configured
  POST /api/pin-verify            check a PIN (constant-time compare)
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

import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel
from typing import Dict, List, Optional

from . import config
from .classifier import classify, classify_batch
from .diff import diff_runs
from .graph import graph_payload
from .keys import encrypt, key_status, load_all
from .models import ApiKey, Finding, Run, Schedule, Target, get_session, init_db
from .plugins.registry import describe
from .reporting import executive_summary, findings_dump, to_csv, to_html, to_markdown
from .runner import launch_run, subscribe

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
def _startup():
    init_db()


@app.get("/api/health")
def health():
    return {"ok": True, "service": "recon-anything"}


# -- PIN gate ------------------------------------------------------------
# Screen-lock PIN (RECON_PIN). Separate from the access code: the access code
# guards every /api route, the PIN just locks the UI. Both endpoints are
# public on purpose, they are the login step itself.

class PinIn(BaseModel):
    pin: str


def _valid_pin_format(pin: str) -> bool:
    return bool(pin) and pin.isdigit() and 4 <= len(pin) <= 8


@app.get("/api/pin-required")
def pin_required():
    return {"required": bool(config.PIN)}


@app.post("/api/pin-verify")
def pin_verify(body: PinIn):
    import hmac
    if not config.PIN:
        return {"ok": True, "detail": "no PIN configured"}
    pin = (body.pin or "").strip()
    if not _valid_pin_format(pin):
        raise HTTPException(status_code=401, detail="bad PIN")
    if not hmac.compare_digest(pin, config.PIN):
        raise HTTPException(status_code=401, detail="bad PIN")
    return {"ok": True}


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
    mode: str = "passive"
    plugins: Optional[List[str]] = None
    module_overrides: Optional[Dict[str, str]] = None


@app.post("/api/runs", dependencies=[Depends(gate)])
async def api_start_run(body: RunIn):
    if not body.targets.strip():
        raise HTTPException(400, "targets required")
    if body.mode not in ("passive", "active"):
        raise HTTPException(400, "mode must be passive|active")
    run_id = uuid.uuid4().hex[:12]
    session = get_session()
    try:
        session.add(Run(id=run_id, mode=body.mode, status="running"))
        session.commit()
        keys = load_all(session)
    finally:
        session.close()
    await launch_run(run_id, body.targets, body.mode,
                     body.plugins, body.module_overrides, keys)
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}/stream", dependencies=[Depends(gate)])
async def api_run_stream(run_id: str):
    session = get_session()
    try:
        if not session.query(Run).filter_by(id=run_id).first():
            raise HTTPException(404, "run not found")
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
            raise HTTPException(404, "run not found")
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=show_secrets)
        return {
            "run": {"id": run.id, "mode": run.mode, "status": run.status,
                    "created_at": run.created_at.isoformat() if run.created_at else None,
                    "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    "summary": run.summary or {}},
            "targets": [{"id": t.id, "raw": t.raw, "type": t.type,
                         "normalized": t.normalized} for t in targets],
            "findings": rows,
            "executive_summary": executive_summary(rows),
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
        return {"entries": entries, "count": len(entries)}
    finally:
        session.close()


@app.get("/api/runs/{run_id}/export", dependencies=[Depends(gate)])
def api_export(run_id: str, format: str = "json", show_secrets: bool = False):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise HTTPException(404, "run not found")
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


@app.get("/api/diff", dependencies=[Depends(gate)])
def api_diff(a: str, b: str):
    session = get_session()
    try:
        return diff_runs(session, a, b)
    finally:
        session.close()


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
