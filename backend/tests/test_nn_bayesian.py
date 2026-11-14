"""Tests for the Bayesian triage module (app/nn/bayesian.py).

Run: python -m pytest backend/tests/test_nn_bayesian.py
(from the repo root or from backend/; sys.path is fixed up below).

What is covered:
- Laplace posterior is a real distribution: interval bounds live in
  [0, 1], lo <= mean <= hi, and the width is positive.
- Intervals WIDEN on out-of-distribution inputs: inputs whose hidden
  representation lies off the training manifold get a wider 90%
  credible interval than in-distribution inputs. Tested at the
  Laplace level with a stub net (deterministic, no training) and,
  when a trained weights file exists, on the real model with
  OOD finding dicts.
- Calibration is MEASURED, not assumed: the evaluation helpers
  return ECE / Brier / binned coverage computed from real labels,
  and the variance scale is fitted on train data only.
- The pipeline record gains mean + interval + unsure flag, the
  unsure label routes to "needs-human-review", and the output can
  never be VERIFIED_REAL.
- Persistence round-trips exactly.
"""
from __future__ import annotations

import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

import pytest

from app.nn.bayesian import (
    LastLayerLaplace,
    binned_interval_coverage,
    brier_score,
    evaluate_holdout,
    expected_calibration_error,
    fit_variance_scale,
    score_finding,
)

NN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "app", "nn")


# ---------------------------------------------------------------------
# stub net: lets tests control the hidden representation exactly
# ---------------------------------------------------------------------

class RowNet:
    """Net whose hidden activations ARE the input vector (identity)."""

    def __init__(self, w_last, b_last=0.0):
        self.weights = [[list(map(float, w_last))]]
        self.biases = [[float(b_last)]]

    def _forward(self, x):
        h = list(map(float, x))
        z = sum(w * v for w, v in zip(self.weights[0][0], h))
        z += self.biases[0][0]
        p = 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))
        return [list(map(float, x)), h, [p]], [[0.0]]


# ---------------------------------------------------------------------
# distribution basics
# ---------------------------------------------------------------------

def test_predictive_is_a_distribution():
    net = RowNet([1.0, 0.0], 0.0)
    X = [[t, 0.0] for t in (-2.0, -1.0, -0.5, 0.5, 1.0, 2.0)]
    y = [0, 0, 0, 1, 1, 1]
    lap = LastLayerLaplace(prior_precision=1.0).fit(net, X, y)
    assert lap.dim == 3  # 2 hidden units + bias
    for x in X:
        p = lap.predictive(net, x, n_samples=128, seed=7)
        assert 0.0 <= p["lo"] <= p["mean"] <= p["hi"] <= 1.0
        assert p["width"] > 0.0
        assert p["std"] >= 0.0
        assert isinstance(p["unsure"], bool)
    # In-distribution accuracy of the posterior mean is sane.
    means = [lap.predictive_mean(net, x, n_samples=128, seed=7) for x in X]
    acc = sum(1 for m, t in zip(means, y) if (m >= 0.5) == bool(t)) / len(y)
    assert acc >= 5 / 6


def test_intervals_widen_off_manifold():
    """OOD: hidden unit 2 is never active in training -> its direction
    has large posterior variance -> wider intervals."""
    net = RowNet([1.0, 0.0], 0.0)
    X = [[t, 0.0] for t in (-2.0, -1.0, -0.5, 0.5, 1.0, 2.0)]
    y = [0, 0, 0, 1, 1, 1]
    lap = LastLayerLaplace(prior_precision=1.0).fit(net, X, y)
    in_widths = [lap.predictive(net, [t, 0.0], n_samples=256, seed=7)["width"]
                 for t in (-1.5, -0.5, 0.5, 1.5)]
    ood_widths = [lap.predictive(net, [t, 3.0], n_samples=256, seed=7)["width"]
                  for t in (-1.5, -0.5, 0.5, 1.5)]
    assert sum(ood_widths) / len(ood_widths) > \
        sum(in_widths) / len(in_widths), (
        f"OOD widths {ood_widths} should exceed in-dist {in_widths}")


def test_unsure_flag_straddles_half():
    # Twelve training points (six per side) so the posterior is tight
    # enough that points far from the boundary genuinely commit; with
    # only six points the far interval still straddles 0.5 and the
    # test would assert a coin flip.
    net = RowNet([1.0, 0.0], 0.0)
    X = [[t, 0.0] for t in
         (-3.0, -2.5, -2.0, -1.5, -1.0, -0.5,
          0.5, 1.0, 1.5, 2.0, 2.5, 3.0)]
    y = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
    lap = LastLayerLaplace(prior_precision=1.0).fit(net, X, y)
    # At the decision boundary the interval must straddle 0.5.
    p = lap.predictive(net, [0.0, 0.0], n_samples=256, seed=7)
    assert p["unsure"] is True
    assert p["lo"] < 0.5 < p["hi"]
    # Far from the boundary the model commits.
    p_far = lap.predictive(net, [2.0, 0.0], n_samples=256, seed=7)
    assert p_far["unsure"] is False


# ---------------------------------------------------------------------
# calibration is measured, not assumed
# ---------------------------------------------------------------------

def test_calibration_helpers_are_honest():
    # Perfectly calibrated toy predictions: ECE and Brier near 0.
    means = [0.1] * 10 + [0.9] * 10
    labels = [0] * 9 + [1] + [1] * 9 + [0]
    assert expected_calibration_error(means, labels) < 0.05
    assert 0.0 <= brier_score(means, labels) <= 0.1
    # Terrible predictions: high ECE and Brier.
    bad = [0.9] * 10 + [0.1] * 10
    assert expected_calibration_error(bad, labels) > 0.5
    assert brier_score(bad, labels) > brier_score(means, labels)
    # Binned coverage returns a real table, not a constant.
    preds = [{"mean": m, "lo": max(0.0, m - 0.05), "hi": min(1.0, m + 0.05)}
             for m in means]
    cov = binned_interval_coverage(preds, labels)
    assert 0.0 <= cov["coverage"] <= 1.0
    assert cov["n_bins_nonempty"] >= 2
    assert len(cov["table"]) == cov["n_bins_nonempty"]


def test_variance_scale_fits_on_train_only():
    net = RowNet([1.0, 0.0], 0.0)
    X = [[t, 0.0] for t in (-2.0, -1.0, -0.5, 0.5, 1.0, 2.0)]
    y = [0, 0, 0, 1, 1, 1]
    lap = LastLayerLaplace(prior_precision=1.0).fit(net, X, y)
    res = fit_variance_scale(lap, net, X, y, n_samples=64, seed=7)
    assert res["chosen_scale"] in (0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0)
    assert 0.0 <= res["train_coverage"] <= 1.0
    assert lap.variance_scale == res["chosen_scale"]
    # The grid table is reported, not hidden.
    assert len(res["grid"]) == 8


def test_evaluate_holdout_reports_calibration():
    net = RowNet([1.0, 0.0], 0.0)
    X = [[t, 0.0] for t in (-2.0, -1.0, -0.5, 0.5, 1.0, 2.0)]
    y = [0, 0, 0, 1, 1, 1]
    lap = LastLayerLaplace(prior_precision=1.0).fit(net, X, y)
    m = evaluate_holdout(lap, net, X, y, n_samples=64, seed=7)
    b = m["bayesian"]
    assert 0.0 <= b["ece"] <= 1.0
    assert 0.0 <= b["brier"] <= 1.0
    assert 0.0 <= b["interval_coverage_bins"]["coverage"] <= 1.0
    assert b["n_unsure"] + b["confident_n"] == len(y)
    assert "confusion" in m and "roc_auc" in m


# ---------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------

def test_laplace_round_trip():
    net = RowNet([1.0, 0.0], 0.0)
    X = [[t, 0.0] for t in (-2.0, -1.0, -0.5, 0.5, 1.0, 2.0)]
    y = [0, 0, 0, 1, 1, 1]
    lap = LastLayerLaplace(prior_precision=1.0).fit(net, X, y)
    lap.set_variance_scale(1.5)
    data = lap.to_dict()
    lap2 = LastLayerLaplace.from_dict(json.loads(json.dumps(data)))
    assert lap2.w_map == lap.w_map
    assert lap2.cov == lap.cov
    assert lap2.variance_scale == 1.5
    p1 = lap.predictive(net, [1.0, 0.0], n_samples=128, seed=7)
    p2 = lap2.predictive(net, [1.0, 0.0], n_samples=128, seed=7)
    assert p1 == p2


# ---------------------------------------------------------------------
# sparse first-layer math is identical to the dense version
# ---------------------------------------------------------------------

def test_sparse_forward_matches_dense():
    """The mlp.py sparse input layer must be bit-identical to a dense
    reference forward (0.0 * w == 0.0; adding 0.0 is exact)."""
    from operator import mul

    from app.nn.mlp import MLP

    def dense_forward(net, x):
        acts = [list(map(float, x))]
        for w, b in zip(net.weights, net.biases):
            z = [sum(map(mul, row, acts[-1])) + bias
                 for row, bias in zip(w, b)]
            if w is net.weights[-1]:
                acts.append([1.0 / (1.0 + math.exp(-v)) if v >= 0
                             else math.exp(v) / (1.0 + math.exp(v))
                             for v in z])
            else:
                acts.append([math.tanh(v) for v in z])
        return acts

    rng = random.Random(0)
    net = MLP([255, 64, 32, 1], seed=42)
    maxdiff = 0.0
    for trial in range(30):
        x = [0.0] * 255
        for j in rng.sample(range(255), 23):
            x[j] = rng.uniform(-1, 1)
        if trial % 3 == 0:
            x = [rng.uniform(-1, 1) for _ in range(255)]
        a_sparse, _ = net._forward(x)
        a_dense = dense_forward(net, x)
        for la, lb in zip(a_sparse, a_dense):
            for va, vb in zip(la, lb):
                maxdiff = max(maxdiff, abs(va - vb))
    assert maxdiff == 0.0


# ---------------------------------------------------------------------
# pipeline record shape (uses the real feature extractor)
# ---------------------------------------------------------------------

def _real_model():
    """Load the shipped Bayesian weights, or skip if not trained yet."""
    path = os.path.join(NN_DIR, "weights.json")
    if not os.path.exists(path):
        pytest.skip("no trained weights yet")
    from app.nn.mlp import MLP
    from app.nn.pipeline import load_model
    model = load_model(path)
    if model is None:
        pytest.skip("weights file unreadable")
    return model


def test_score_finding_record_shape_and_never_verified_real():
    model = _real_model()
    net, spec, meta = model
    from app.nn.bayesian import LastLayerLaplace
    b = (meta or {}).get("bayesian")
    if not b:
        pytest.skip("weights have no Bayesian posterior yet")
    lap = LastLayerLaplace.from_dict(b["laplace"])
    finding = {
        "plugin": "crypto_drain_scanner",
        "key": "drain-to-caller",
        "severity": "high",
        "bounty_value": "high",
        "confidence": 90,
        "value": "0xabc",
        "recipient_class": "CALLER",
        "chain": "bsc",
        "function": "withdraw",
        "evidence": {"risk": "high", "gate_analysis": "no caller gate"},
    }
    rec = score_finding(finding, net, spec, lap)
    assert 0.0 <= rec["nn_score_lo"] <= rec["nn_score"] <= rec["nn_score_hi"] <= 1.0
    assert rec["nn_label"] in ("worth-validating", "likely-false-positive",
                               "needs-human-review")
    assert rec["nn_label"] != "VERIFIED_REAL"
    assert isinstance(rec["nn_unsure"], bool)
    assert rec["nn_unsure"] == (rec["nn_score_lo"] < 0.5 < rec["nn_score_hi"])
    assert rec["nn_top_features"]


def test_real_model_intervals_widen_on_ood_findings():
    """OOD on the real model: a finding from an UNSEEN plugin with
    moderate values gets a wider interval than a normal
    in-distribution one. (Near-OOD / ambiguous inputs widen; see
    test_extreme_inputs_saturate_intervals for the opposite case:
    maxed-out inputs saturate the sigmoid and collapse.)"""
    model = _real_model()
    net, spec, meta = model
    from app.nn.bayesian import LastLayerLaplace
    b = (meta or {}).get("bayesian")
    if not b:
        pytest.skip("weights have no Bayesian posterior yet")
    lap = LastLayerLaplace.from_dict(b["laplace"])
    in_dist = {
        "plugin": "crypto_drain_scanner",
        "key": "drain-to-caller",
        "severity": "high",
        "bounty_value": "high",
        "confidence": 90,
        "value": "0xabc",
        "recipient_class": "CALLER",
        "chain": "bsc",
        "function": "withdraw",
        "evidence": {"risk": "high", "gate_analysis": "no caller gate"},
    }
    # OOD: unseen plugin (OTHER bucket), moderate values.
    ood = dict(in_dist)
    ood.update({
        "plugin": "never_seen_plugin_xyz",
        "key": "never_seen_key_xyz",
        "severity": "medium",
        "confidence": 50,
    })
    widths_in, widths_ood = [], []
    for _ in range(5):
        widths_in.append(
            score_finding(dict(in_dist), net, spec, lap)["nn_score_width"])
        widths_ood.append(
            score_finding(dict(ood), net, spec, lap)["nn_score_width"])
    assert sum(widths_ood) / len(widths_ood) > \
        sum(widths_in) / len(widths_in), (
        f"OOD widths {widths_ood} should exceed in-dist {widths_in}")


def test_extreme_inputs_saturate_intervals():
    """KNOWN LIMIT, documented not desired: a maxed-out finding
    (unseen plugin, confidence 100, critical severity, 20 evidence
    items, 2000-char value) saturates the hidden tanh units and the
    sigmoid, so its probability interval COLLAPSES instead of
    widening (width ~0.01 vs ~0.25 in-distribution). Last-layer
    Laplace + sigmoid outputs cannot flag this kind of extreme OOD
    by interval width; the logit-scale uncertainty does not grow
    either (the saturated representation lands in a direction the
    posterior is confident about). A future logit-space OOD flag
    should flip this test. The value here is that the behaviour is
    measured and pinned, not silently assumed away."""
    model = _real_model()
    net, spec, meta = model
    from app.nn.bayesian import LastLayerLaplace
    b = (meta or {}).get("bayesian")
    if not b:
        pytest.skip("weights have no Bayesian posterior yet")
    lap = LastLayerLaplace.from_dict(b["laplace"])
    in_dist = {
        "plugin": "crypto_drain_scanner",
        "key": "drain-to-caller",
        "severity": "high",
        "bounty_value": "high",
        "confidence": 90,
        "value": "0xabc",
        "recipient_class": "CALLER",
        "chain": "bsc",
        "function": "withdraw",
        "evidence": {"risk": "high", "gate_analysis": "no caller gate"},
    }
    ood = {
        "plugin": "never_seen_plugin_xyz",
        "key": "never_seen_key_xyz",
        "severity": "critical",
        "bounty_value": "critical",
        "confidence": 100,
        "value": "x" * 2000,
        "recipient_class": "CALLER",
        "chain": "bsc",
        "function": "f" * 64,
        "plugin_finding_count": 8,
        "evidence": {f"ev_{i}": "v" for i in range(20)},
    }
    w_in = score_finding(dict(in_dist), net, spec, lap)["nn_score_width"]
    w_ood = score_finding(dict(ood), net, spec, lap)["nn_score_width"]
    assert w_ood < 0.05, f"extreme OOD width should collapse, got {w_ood}"
    assert w_ood < w_in, (
        f"extreme OOD width {w_ood} collapses below in-dist {w_in}")
