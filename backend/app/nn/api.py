"""HTTP surface for the NN triage scorer.

Mounted in app/main.py:
- ``router`` at /api/nn behind the app's normal gate: POST /score runs
  the plugin set against a target and returns ranked findings;
  GET /status reports the loaded model and its test metrics.
- ``viewer_router`` ungated: GET /nn serves viewer.html and
  GET /nn/viewer-data.json serves the metrics the viewer fetches.

Detection only, same as the CLI: scoring reads the target, never
sends transactions or takes funds.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .pipeline import load_model, score_finding_dicts, weights_path
from .score import run_target

router = APIRouter()
viewer_router = APIRouter()

_NN_DIR = Path(__file__).resolve().parent
_SCORE_TIMEOUT_S = int(os.environ.get("RECON_NN_SCORE_TIMEOUT_S", "300"))


class ScoreIn(BaseModel):
    target: str
    chain: str = "bsc"
    plugin_set: str = "curated"
    max_plugins: int = 40
    timeout_cap_s: int = 60
    threshold: float = 0.5


@router.get("/status")
def nn_status():
    model = load_model()
    if model is None:
        return {"trained": False,
                "message": "no weights yet; run python -m app.nn.train"}
    _net, _spec, meta = model
    layers = (meta.get("mlp") or {}).get("layers") or []
    return {
        "trained": True,
        "trained_at": meta.get("trained_at"),
        "layers": layers,
        "n_features": layers[0] if layers else None,
        "test_metrics": (meta.get("metrics") or {}).get("test"),
        "dataset": meta.get("dataset"),
        "limits": meta.get("limits"),
    }


@router.post("/score")
async def nn_score(body: ScoreIn):
    model = load_model()
    if model is None:
        raise HTTPException(status_code=503, detail=(
            "no trained weights yet; run python -m app.nn.train"))
    try:
        record = await asyncio.wait_for(
            run_target(body.target, chain=body.chain,
                       plugin_set=body.plugin_set,
                       max_plugins=body.max_plugins,
                       timeout_cap_s=body.timeout_cap_s),
            timeout=_SCORE_TIMEOUT_S)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail=(
            f"scoring timed out after {_SCORE_TIMEOUT_S}s"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    record["findings"] = score_finding_dicts(
        record["findings"], model=model, threshold=body.threshold)
    return record


@viewer_router.get("/nn")
def nn_viewer():
    html = _NN_DIR / "viewer.html"
    if not html.exists():
        raise HTTPException(status_code=404, detail="viewer not found")
    return FileResponse(html, media_type="text/html")


@viewer_router.get("/nn/viewer-data.json")
def nn_viewer_data():
    data = _NN_DIR / "viewer-data.json"
    if not data.exists():
        raise HTTPException(status_code=404, detail="not trained yet")
    return FileResponse(data, media_type="application/json")
