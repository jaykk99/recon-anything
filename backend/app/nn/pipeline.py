"""Optional pipeline wiring: score findings with the NN and attach the
scores, flag-gated and default off.

Enable with RECON_NN_SCORING=1. When off (the default) nothing changes:
no model is loaded, findings pass through untouched. When on, every
finding gets nn_score (0-1, probability the finding is worth
validating), nn_label ("worth-validating" / "likely-false-positive"),
and nn_top_features (the 3 features most responsible for the score).

Scoring never breaks a scan: any failure (missing weights, bad row)
leaves the findings unscored and is swallowed here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .features import FeatureSpec, extract, top_features
from .mlp import MLP

_ENV_FLAG = "RECON_NN_SCORING"
_WEIGHTS_NAME = "weights.json"

_cache: Dict[str, Optional[Tuple[MLP, FeatureSpec, Dict]]] = {"model": "unset"}


def nn_enabled() -> bool:
    return os.environ.get(_ENV_FLAG) == "1"


def weights_path() -> Path:
    return Path(__file__).resolve().parent / _WEIGHTS_NAME


def load_model(path: Optional[str] = None):
    """Load (net, spec, meta) from a weights file. None on any failure."""
    p = Path(path) if path else weights_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    try:
        if data.get("format") != "recon-nn-weights/1":
            return None
        net = MLP.from_dict(data["mlp"])
        spec = FeatureSpec.from_dict(data["features"])
        return net, spec, data
    except Exception:
        return None


def _get_model():
    if _cache["model"] == "unset":
        _cache["model"] = load_model()
    return _cache["model"]


def reset_model_cache() -> None:
    _cache["model"] = "unset"


def score_finding_dicts(findings: List[Dict], model=None,
                        threshold: float = 0.5) -> List[Dict]:
    """Score finding dicts in place; returns them ranked by nn_score
    (highest first). Each finding gains nn_score, nn_label and
    nn_top_features. Unscored when no model is available (returns the
    findings unchanged, unranked)."""
    if model is None:
        model = _get_model()
    if model is None:
        return list(findings)
    net, spec, _meta = model
    scored = []
    for f in findings:
        try:
            x = extract(f, spec)
            p = net.predict_proba(x)
            f["nn_score"] = round(p, 4)
            f["nn_label"] = ("worth-validating" if p >= threshold
                             else "likely-false-positive")
            f["nn_top_features"] = top_features(f, spec, net, k=3)
        except Exception:
            f["nn_score"] = None
            f["nn_label"] = "unscored"
            f["nn_top_features"] = []
        scored.append(f)
    scored.sort(key=lambda d: (d.get("nn_score") is None,
                               -(d.get("nn_score") or 0.0)))
    return scored


def _finding_to_dict(finding) -> Dict:
    """Accept a Finding dataclass or a dict; return a plain dict in
    the batches.jsonl shape the feature extractor reads."""
    if isinstance(finding, dict):
        return finding
    ev = dict(getattr(finding, "evidence", None) or {})
    return {
        "plugin": getattr(finding, "plugin_id", ""),
        "key": getattr(finding, "key", ""),
        "severity": ev.get("severity", ""),
        "bounty_value": getattr(finding, "bounty_value", "low"),
        "confidence": getattr(finding, "confidence", 0),
        "value": getattr(finding, "value", ""),
        "recipient_class": ev.get("recipient", ""),
        "chain": ev.get("chain", ""),
        "function": ev.get("function", ""),
        "evidence": ev,
    }


def attach_nn_scores(findings, model=None, threshold: float = 0.5):
    """Attach nn_score + nn_top_features to each finding.

    Dict findings get top-level nn_score / nn_label / nn_top_features.
    Finding dataclass objects get the same values inside evidence
    (evidence is the dataclass's free-form dict). Returns the findings
    unchanged when no model is available. Never raises.
    """
    try:
        if model is None:
            model = _get_model()
        if model is None:
            return findings
        net, spec, _meta = model
        for f in findings:
            try:
                d = _finding_to_dict(f)
                p = net.predict_proba(extract(d, spec))
                label = ("worth-validating" if p >= threshold
                         else "likely-false-positive")
                feats = top_features(d, spec, net, k=3)
                if isinstance(f, dict):
                    f["nn_score"] = round(p, 4)
                    f["nn_label"] = label
                    f["nn_top_features"] = feats
                else:
                    ev = getattr(f, "evidence", None)
                    if isinstance(ev, dict):
                        ev["nn_score"] = round(p, 4)
                        ev["nn_label"] = label
                        ev["nn_top_features"] = feats
            except Exception:
                continue
    except Exception:
        pass
    return findings


def maybe_score_findings(findings, model=None):
    """Pipeline hook: score only when RECON_NN_SCORING=1, else no-op.
    Never raises, never changes behaviour when disabled."""
    if not nn_enabled():
        return findings
    return attach_nn_scores(findings, model=model)
