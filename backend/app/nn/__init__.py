"""Viewable, trainable neural network scoring ReconAnything findings.

Pure Python stdlib: an MLP (mlp.py) over features extracted from real
plugin finding dicts (features.py), trained on the real labeled
candidates from the continuous scanner (data.py, train.py).

Triage only: the network ranks findings by how much they look like
past candidates that survived triage. It never stamps VERIFIED_REAL.
"""
from __future__ import annotations

from .bayesian import LastLayerLaplace, score_finding as score_finding_bayesian
from .features import FeatureSpec, extract, top_features
from .mlp import MLP
from .pipeline import (attach_nn_scores, load_bayesian, load_model,
                       maybe_score_findings, nn_enabled,
                       score_finding_dicts)

__all__ = [
    "MLP",
    "FeatureSpec",
    "extract",
    "top_features",
    "load_model",
    "load_bayesian",
    "score_finding_dicts",
    "score_finding_bayesian",
    "LastLayerLaplace",
    "attach_nn_scores",
    "maybe_score_findings",
    "nn_enabled",
]
