"""Viewable, trainable neural network scoring ReconAnything findings.

Pure Python stdlib: an MLP (mlp.py) over features extracted from real
plugin finding dicts (features.py), trained on the real labeled
candidates from the continuous scanner (data.py, train.py). A
spiking variant (snn.py) scores the same features as LIF spike
trains with surrogate-gradient training; it duck-types the MLP
(predict_proba), so pipeline.load_model accepts its weights too.

Triage only: the network ranks findings by how much they look like
past candidates that survived triage. It never stamps VERIFIED_REAL.
"""
from __future__ import annotations

from .features import FeatureSpec, extract, top_features
from .mlp import MLP
from .pipeline import (attach_nn_scores, load_model, maybe_score_findings,
                       nn_enabled, score_finding_dicts)
from .snn import SNN, load_snn_model, score_finding_dicts_snn

__all__ = [
    "MLP",
    "SNN",
    "FeatureSpec",
    "extract",
    "top_features",
    "load_model",
    "load_snn_model",
    "score_finding_dicts",
    "score_finding_dicts_snn",
    "attach_nn_scores",
    "maybe_score_findings",
    "nn_enabled",
]
