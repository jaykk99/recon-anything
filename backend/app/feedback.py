"""Human verdicts on findings -> real-outcome labels for the neural engine.

A reviewer marks a finding:

  confirmed       real and worth acting on        -> label 1.0
  not_actionable  real, but not worth acting on   -> label 0.3
  false_positive  not real                        -> label 0.0
  unsure          recorded, never used as a label

Each verdict stores a snapshot of the finding as judged (masked, the same
row the UI shows), so labels survive run deletion and stay tied to the
evidence the reviewer actually saw. ``export_labels`` emits exactly the
``{"finding": ..., "label": ...}`` records app/nn_train.py reads, and
``stats`` reports how the CURRENT model ranks the labelled findings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .models import FindingFeedback

VERDICTS = ("confirmed", "not_actionable", "false_positive", "unsure")
LABEL_FOR = {"confirmed": 1.0, "not_actionable": 0.3, "false_positive": 0.0}
_SNAPSHOT_FIELDS = ("plugin", "category", "key", "value", "source",
                    "source_url", "confidence", "passive", "bounty_value",
                    "evidence")


class FeedbackError(ValueError):
    pass


def snapshot_of(row: Dict[str, Any]) -> Dict[str, Any]:
    snap = {k: row.get(k) for k in _SNAPSHOT_FIELDS}
    ev = dict(snap.get("evidence") or {}) if isinstance(snap.get("evidence"), dict) else {}
    ev.pop("nn", None)  # the model's own score is not ground truth
    snap["evidence"] = ev
    return snap


def set_verdict(session, run_id: str, row: Dict[str, Any], verdict: str,
                reviewer: str = "owner", note: Optional[str] = None
                ) -> FindingFeedback:
    """Create or update this reviewer's verdict on one finding row."""
    if verdict not in VERDICTS:
        raise FeedbackError(f"verdict must be one of {', '.join(VERDICTS)}")
    fid = int(row["id"])
    fb = (session.query(FindingFeedback)
          .filter_by(finding_id=fid, reviewer=reviewer).first())
    if fb is None:
        fb = FindingFeedback(run_id=run_id, finding_id=fid, reviewer=reviewer)
        session.add(fb)
    fb.verdict = verdict
    fb.note = (note or "")[:2000] or None
    fb.snapshot = snapshot_of(row)
    session.commit()
    return fb


def clear_verdict(session, finding_id: int, reviewer: str = "owner") -> bool:
    n = (session.query(FindingFeedback)
         .filter_by(finding_id=int(finding_id), reviewer=reviewer)
         .delete())
    session.commit()
    return bool(n)


def verdicts_for_run(session, run_id: str,
                     reviewer: Optional[str] = None) -> Dict[int, Dict[str, Any]]:
    q = session.query(FindingFeedback).filter_by(run_id=run_id)
    if reviewer is not None:
        q = q.filter_by(reviewer=reviewer)
    return {fb.finding_id: {"verdict": fb.verdict, "note": fb.note,
                            "reviewer": fb.reviewer}
            for fb in q.all()}


def export_labels(session, reviewer: Optional[str] = None
                  ) -> List[Dict[str, Any]]:
    """Labelled records for nn_train, oldest first; 'unsure' is skipped."""
    q = session.query(FindingFeedback).order_by(FindingFeedback.id)
    if reviewer is not None:
        q = q.filter_by(reviewer=reviewer)
    out = []
    for fb in q.all():
        if fb.verdict not in LABEL_FOR or not isinstance(fb.snapshot, dict):
            continue
        out.append({"finding": fb.snapshot, "label": LABEL_FOR[fb.verdict],
                    "verdict": fb.verdict, "run_id": fb.run_id,
                    "finding_id": fb.finding_id})
    return out


def as_corpus(records: List[Dict[str, Any]]
              ) -> List[Tuple[Dict[str, Any], float, str]]:
    """export_labels records -> nn_train (finding, label, group) triples."""
    return [(r["finding"], float(r["label"]),
             str(r["finding"].get("plugin") or "unknown")) for r in records]


def stats(session, reviewer: Optional[str] = None) -> Dict[str, Any]:
    q = session.query(FindingFeedback)
    if reviewer is not None:
        q = q.filter_by(reviewer=reviewer)
    counts = {v: 0 for v in VERDICTS}
    for fb in q.all():
        counts[fb.verdict] = counts.get(fb.verdict, 0) + 1
    labels = export_labels(session, reviewer)
    out: Dict[str, Any] = {"counts": counts, "labelled": len(labels),
                           "model": None}
    # Rank metrics need both classes present to mean anything.
    if len({r["label"] for r in labels}) >= 2:
        try:
            from .nn_train import evaluate_records
            out["model"] = evaluate_records(as_corpus(labels),
                                            k=min(10, len(labels)))
        except SystemExit as e:  # no weights available
            out["model_error"] = str(e)
    return out
