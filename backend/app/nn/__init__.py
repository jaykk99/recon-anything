"""Viewable, trainable neural network scoring ReconAnything findings.

Pure Python stdlib: an MLP (mlp.py) over features extracted from real
plugin finding dicts (features.py), trained on the real labeled
candidates from the continuous scanner (data.py, train.py). The GNN
+ neuro-symbolic combined model (graph.py, gnn.py, symbolic.py,
combined.py, train_gnn.py) scores the same findings with a contract
graph and auditable rules on top of the same flat vector.

Triage only: the networks rank findings by how much they look like
past candidates that survived triage. They never stamp VERIFIED_REAL.
"""
from __future__ import annotations

from .combined import load_combined_model, score_finding_dicts_combined
from .features import FeatureSpec, extract, top_features
from .mlp import MLP
from .pipeline import (attach_nn_scores, load_model, maybe_score_findings,
                       maybe_score_gnn, nn_enabled, score_finding_dicts)

__all__ = [
    "MLP",
    "FeatureSpec",
    "extract",
    "top_features",
    "load_model",
    "score_finding_dicts",
    "attach_nn_scores",
    "maybe_score_findings",
    "nn_enabled",
    "load_combined_model",
    "score_finding_dicts_combined",
    "maybe_score_gnn",
]
