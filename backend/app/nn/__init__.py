"""Structural Causal Models / do-calculus for ReconAnything triage.

Pure Python stdlib: a small Pearl-style SCM engine (causal.py) over
recon findings and contracts. It answers "what if" questions the
correlation-only scorers cannot: what happens if we intervene on a
variable, and what would have happened had things gone differently.

Triage only. It never stamps VERIFIED_REAL, never executes an
exploit, never moves funds. Live probes stay read-only.
"""
from __future__ import annotations

from .causal import (
    CausalGraph,
    CounterfactualEngine,
    StructuralModel,
    average_causal_effect,
    backdoor_paths,
    build_recon_graph,
    estimate_effect,
    find_backdoor_set,
    identify_effect,
    predict_backup_infra,
    raw_conditional,
)

__all__ = [
    "CausalGraph",
    "CounterfactualEngine",
    "StructuralModel",
    "average_causal_effect",
    "backdoor_paths",
    "build_recon_graph",
    "estimate_effect",
    "find_backdoor_set",
    "identify_effect",
    "predict_backup_infra",
    "raw_conditional",
]
