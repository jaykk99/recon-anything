"""Combined neuro-symbolic triage model: GNN score + symbolic rules.

One object owns the whole decision for a finding row:
graph -> GNN readout + flat vector -> head -> neural score, then the
symbolic layer vets it (veto wins, boosts/dampens shift it). Every
decision carries its fired rules, so a rank is auditable, not a
black-box number.

Weights file format "recon-nn-gnn-weights/1" holds the GNN, the head
MLP, the feature spec, the validated (kept) rules, and the training
metrics. Triage only: labels are worth-validating /
likely-false-positive, never VERIFIED_REAL.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .features import FeatureSpec
from .gnn import CombinedNet
from .graph import build_contract_index, build_graph, contract_findings_for
from .mlp import metrics_for
from .symbolic import apply_rules, combine, extract_facts, validate_rules


class CombinedModel:
    """GNN + symbolic rules, ready to score rows or live findings."""

    def __init__(self, net: CombinedNet, kept_rules: List[Dict],
                 meta: Optional[Dict] = None) -> None:
        self.net = net
        self.kept_rules = list(kept_rules)
        self.meta = dict(meta or {})

    @property
    def spec(self) -> FeatureSpec:
        return self.net.spec

    def predict_row(self, row: Dict,
                    contract_findings: Optional[Sequence[Dict]] = None,
                    threshold: float = 0.5) -> Dict:
        """Score one data.py row. Returns neural/combined scores, the
        label, fired rules, veto flag, and a graph summary."""
        graph = build_graph(row, contract_findings)
        finding = row.get("finding") or {}
        neural_p = self.net.predict_proba(graph, finding)
        facts = extract_facts(row)
        out = combine(neural_p, facts, self.kept_rules, threshold)
        # Symbolic-only score for comparison (same rules, 0.5 base).
        from .symbolic import symbolic_score
        sym_score, _ = symbolic_score(facts, self.kept_rules)
        out["symbolic_p"] = round(sym_score, 4)
        out["graph"] = {"n_nodes": len(graph["nodes"]),
                        "n_edges": len(graph["edges"]),
                        "edges": [list(e) for e in graph["edges"]],
                        "node_kinds": graph["meta"]["node_kinds"],
                        "functions": graph["meta"]["functions"],
                        "plugins": graph["meta"]["plugins"],
                        "has_implementation": graph["meta"]["has_implementation"]}
        return out

    def predict_finding(self, finding: Dict,
                        contract_findings: Optional[Sequence[Dict]] = None,
                        threshold: float = 0.5) -> Dict:
        """Score a bare finding dict (live scoring path)."""
        row = {"finding": finding,
               "chain": finding.get("chain"),
               "address": (finding.get("evidence") or {}).get("address"),
               "function": finding.get("function")}
        return self.predict_row(row, contract_findings, threshold)

    def score_rows(self, rows: Sequence[Dict],
                   index: Optional[Dict] = None,
                   threshold: float = 0.5) -> List[Dict]:
        """Score data.py rows with graph context from the contract
        index (batches.jsonl). Returns per-row prediction dicts."""
        out = []
        for row in rows:
            ctx = []
            if index is not None:
                ctx = contract_findings_for(
                    index, row.get("chain") or "", row.get("address") or "")
            out.append(self.predict_row(row, ctx, threshold))
        return out

    def evaluate(self, rows: Sequence[Dict],
                 index: Optional[Dict] = None,
                 threshold: float = 0.5) -> Dict:
        """Honest evaluation on a fixed holdout: neural-only,
        symbolic-only, and combined metrics (accuracy, ROC AUC,
        confusion, FP/WV recall), plus the disagreement ledger:
        rows where symbolic and neural disagree, with rules cited."""
        preds = self.score_rows(rows, index, threshold)
        y = [int(r["label"]) for r in rows]
        neural = [p["neural_p"] for p in preds]
        sym = [p["symbolic_p"] for p in preds]
        comb = [p["combined_p"] for p in preds]
        result = {
            "n": len(y),
            "n_positive": sum(y),
            "n_negative": len(y) - sum(y),
            "neural": metrics_for(y, neural, threshold),
            "symbolic": metrics_for(y, sym, threshold),
            "combined": metrics_for(y, comb, threshold),
            "preds": preds,
        }
        # Disagreement ledger: where the layers part ways.
        neural_right = [int(p["neural_p"] >= threshold) == t
                        for p, t in zip(preds, y)]
        sym_right = [int(p["symbolic_p"] >= threshold) == t
                     for p, t in zip(preds, y)]
        caught_by_symbolic = []
        caught_by_neural = []
        vetoed = 0
        for i, (row, p) in enumerate(zip(rows, preds)):
            if p["vetoed"]:
                vetoed += 1
            if sym_right[i] and not neural_right[i]:
                caught_by_symbolic.append({
                    "plugin": row.get("plugin"), "key": row.get("key"),
                    "label": y[i], "neural_p": p["neural_p"],
                    "combined_p": p["combined_p"],
                    "fired_rules": p["fired_rules"]})
            elif neural_right[i] and not sym_right[i]:
                caught_by_neural.append({
                    "plugin": row.get("plugin"), "key": row.get("key"),
                    "label": y[i], "neural_p": p["neural_p"],
                    "combined_p": p["combined_p"],
                    "fired_rules": p["fired_rules"]})
        result["vetoed_rows"] = vetoed
        result["caught_by_symbolic"] = caught_by_symbolic
        result["caught_by_neural"] = caught_by_neural
        return result

    def to_dict(self) -> Dict:
        data = self.net.to_dict()
        data["kept_rules"] = self.kept_rules
        data["meta"] = self.meta
        return data

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=1),
                              encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "CombinedModel":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("format") != "recon-nn-gnn-weights/1":
            raise ValueError("not a recon-nn-gnn-weights/1 file")
        net = CombinedNet.from_dict(data)
        return cls(net, data.get("kept_rules") or [],
                   data.get("meta") or {})


def load_combined_model(path: Optional[str] = None):
    """Load a CombinedModel from a weights file. None on any failure
    (scoring never breaks a scan)."""
    p = Path(path) if path else (
        Path(__file__).resolve().parent / "gnn-weights.json")
    try:
        return CombinedModel.load(str(p))
    except Exception:
        return None


def score_finding_dicts_combined(findings: List[Dict], model=None,
                                 index: Optional[Dict] = None,
                                 threshold: float = 0.5) -> List[Dict]:
    """Score finding dicts with the combined model, in place, ranked
    by combined_p (highest first). Each finding gains combined_p,
    neural_p, symbolic_p, nn_label and fired_rules. Unscored when no
    model is available (returns the findings unchanged)."""
    if model is None:
        model = load_combined_model()
    if model is None:
        return list(findings)
    scored = []
    for f in findings:
        try:
            ctx = []
            if index is not None:
                ev = f.get("evidence") or {}
                ctx = contract_findings_for(
                    index, f.get("chain") or ev.get("chain") or "",
                    ev.get("address") or "")
            pred = model.predict_finding(f, ctx, threshold)
            f["combined_p"] = pred["combined_p"]
            f["neural_p"] = pred["neural_p"]
            f["symbolic_p"] = pred["symbolic_p"]
            f["nn_label"] = pred["label"]
            f["fired_rules"] = pred["fired_rules"]
            f["vetoed"] = pred["vetoed"]
        except Exception:
            f["combined_p"] = None
            f["neural_p"] = None
            f["symbolic_p"] = None
            f["nn_label"] = "unscored"
            f["fired_rules"] = []
            f["vetoed"] = False
        scored.append(f)
    scored.sort(key=lambda d: (d.get("combined_p") is None,
                               -(d.get("combined_p") or 0.0)))
    return scored
