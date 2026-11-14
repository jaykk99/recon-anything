"""Triage ranking: what the swarm investigates first.

The NN scorer (backend/app/nn, branch feat/nn-scorer) is the
preferred ranker when it is importable AND the caller supplies a
scoring function for it. This module never imports the NN itself at
module load: the swarm must run on master, where app/nn does not
exist yet. Pass ``nn_score_fn`` (finding dict -> float in [0, 1])
to use it; otherwise the heuristic below ranks.

Heuristic (fallback, and the documented baseline): value first
($100k floor, unknown value sorts after known value, never dropped),
worst severity second, fresh_7d third, finding count fourth. The
score is a plain number plus a human-readable reason, never a
verdict: triage ranks, it does not predict VERIFIED_REAL.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .rules import BOUNTY_FLOOR_USD

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def try_nn_ranker():
    """Return a finding->score callable from the NN scorer, or None.

    Wires the real scorer (``app.nn.pipeline.load_model`` +
    ``score_finding_dicts``): each finding gets the trained MLP's
    triage probability. The NN module lives on another branch; on
    master the import fails and this returns None, and the heuristic
    ranks. A missing or broken NN can never kill a swarm run, and the
    NN score is triage only: it never produces a verdict.
    """
    try:
        from ..nn.pipeline import load_model, score_finding_dicts  # type: ignore
    except Exception:  # noqa: BLE001 - NN is optional
        return None
    try:
        model = load_model()
    except Exception:  # noqa: BLE001
        return None
    if model is None:
        return None

    def _score(finding: Dict[str, Any]) -> Optional[float]:
        try:
            scored = score_finding_dicts([dict(finding)], model)
            value = (scored or [{}])[0].get("nn_score")
            return float(value) if isinstance(value, (int, float)) else None
        except Exception:  # noqa: BLE001 - one bad finding scores None
            return None

    return _score


def heuristic_score(target: Dict[str, Any],
                    findings: Optional[List[Dict[str, Any]]] = None
                    ) -> Dict[str, Any]:
    """Heuristic rank for one target. Returns {score, reason}."""
    findings = findings or []
    value = target.get("value_usd")
    try:
        value = float(value) if value is not None else None
    except (TypeError, ValueError):
        value = None
    worst_sev = min((_SEV_RANK.get(str(f.get("severity") or "info").lower(), 4)
                     for f in findings), default=4)
    fresh = bool(target.get("fresh_7d"))
    # Buckets: 0 known value >= floor, 1 unknown value, 2 known dust.
    if value is None:
        bucket, value_part = 1, 0.0
    elif value >= BOUNTY_FLOOR_USD:
        bucket, value_part = 0, -value
    else:
        bucket, value_part = 2, 0.0
    score = (bucket, value_part, worst_sev,
             0 if fresh else 1, -len(findings))
    reason = (
        f"value={'unknown' if value is None else f'${value:,.0f}'} "
        f"(bucket {bucket}), worst_severity="
        f"{['critical', 'high', 'medium', 'low', 'info'][worst_sev]}, "
        f"fresh_7d={fresh}, findings={len(findings)}")
    return {"score": score, "reason": reason, "source": "heuristic"}


def rank_targets(targets: List[Dict[str, Any]],
                 findings_by_key: Optional[Dict[str, List[Dict[str, Any]]]] = None,
                 nn_score_fn: Optional[Callable[[Dict[str, Any]], Optional[float]]] = None
                 ) -> List[Dict[str, Any]]:
    """Order targets for investigation, highest priority first.

    ``nn_score_fn`` (optional): finding -> float in [0, 1]. When
    supplied and it scores at least one finding, the NN mean score
    breaks ties inside the heuristic's value bucket instead of
    replacing the value-first order: the NN ranks, the $100k floor
    still gates the live path. Returns new dicts with ``rank_score``
    and ``rank_reason`` attached.
    """
    findings_by_key = findings_by_key or {}
    ranked = []
    for target in targets:
        key = target_key(target)
        findings = findings_by_key.get(key) or []
        h = heuristic_score(target, findings)
        nn_mean: Optional[float] = None
        if nn_score_fn is not None and findings:
            scores = [s for s in (nn_score_fn(f) for f in findings)
                      if isinstance(s, (int, float))]
            if scores:
                nn_mean = sum(scores) / len(scores)
        item = dict(target)
        item["rank_score"] = h["score"]
        item["rank_reason"] = h["reason"]
        item["rank_source"] = "heuristic" if nn_mean is None else "heuristic+nn"
        item["nn_mean"] = nn_mean
        ranked.append(item)
    ranked.sort(key=lambda t: (
        t["rank_score"][0], t["rank_score"][1],
        -(t["nn_mean"] if t["nn_mean"] is not None else 0.0),
        t["rank_score"][2], t["rank_score"][3], t["rank_score"][4]))
    return ranked


def target_key(target: Dict[str, Any]) -> str:
    """Deduplication key: chain + lowercase address."""
    chain = str(target.get("chain") or "").lower()
    address = str(target.get("address") or "").lower()
    return f"{chain}:{address}"
