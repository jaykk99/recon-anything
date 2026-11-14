"""Bayesian Program Learning + Solomonoff induction (``nn/bpl.py``).

Learns the minimal generative program explaining a deployer / wallet
behaviour trace and predicts the next event from the posterior over
programs. Pure Python stdlib, triage only, never predicts
VERIFIED_REAL.

NOTE FOR MERGE: this branch (feat/nn-bpl) is based on origin/master,
which has no ``backend/app/nn/`` package yet. The sibling branch
feat/nn-scorer adds the same ``__init__.py`` with the MLP scorer
exports; when the two branches meet, this file must be merged by hand
so both export sets survive -- neither side's exports may be dropped.
"""

from __future__ import annotations

from .bpl import (
    ALPHABET,
    Emit,
    Program,
    Prediction,
    Repeat,
    baseline_top1_accuracy,
    bpl_top1_accuracy,
    flat_program,
    frequency_next,
    infer_programs,
    learn_shared_programs,
    log_likelihood,
    log_posterior,
    markov_next,
    predict_next,
    predict_next_from_prefix,
    rank_programs,
    rank_programs_on_traces,
)

__all__ = [
    "ALPHABET",
    "Emit",
    "Program",
    "Prediction",
    "Repeat",
    "baseline_top1_accuracy",
    "bpl_top1_accuracy",
    "flat_program",
    "frequency_next",
    "infer_programs",
    "learn_shared_programs",
    "log_likelihood",
    "log_posterior",
    "markov_next",
    "predict_next",
    "predict_next_from_prefix",
    "rank_programs",
    "rank_programs_on_traces",
]
