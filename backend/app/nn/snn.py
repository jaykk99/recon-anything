"""Spiking neural network (SNN) for ReconAnything triage.

Event-driven leaky integrate-and-fire (LIF) model over time-ordered
finding events. Pure Python stdlib only: no new dependencies, runs on
this CPU box and in Termux.

Design
------
* Input: the same 255-dim feature vector as the v2 MLP
  (features.extract + FeatureSpec). Each feature value in [0, 1] is
  rate-coded into a spike train over T timesteps: at each step the
  feature fires with probability equal to its value (deterministic,
  seeded Bernoulli). A finding is therefore not one static vector but
  a short event stream, which is what the SNN consumes.
* Architecture: 255 -> n_hidden LIF -> 2 LIF (one neuron per triage
  class). Membrane dynamics: v <- beta * v + I, spike when v >=
  threshold, hard reset to 0 after a spike.
* Readout: spike counts c0, c1 over the window. Score =
  sigmoid(SCALE * (c1 - c0) / T): the model's estimated probability
  the finding is worth validating.
* Learning: surrogate gradient + backpropagation through time
  (BPTT). Spikes are non-differentiable, so the backward pass uses
  the fast-sigmoid surrogate derivative
  surr'(v) = 1 / (k * |v - threshold| + 1)^2 with k = 5: wide enough
  that sub-threshold neurons still get a usable gradient (k = 25
  was tried first and starved the gradients: loss barely moved).
  unsupervised and does not fit a labeled triage objective; the
  surrogate-gradient route trains directly on the triage labels with
  the same binary cross-entropy loss as the MLP, so the two models
  are comparable. Mini-batch SGD with balanced class weights
  (the data is ~85% worth-validating).
* Event-driven / sparse: most features are 0 (only one plugin block
  is live per finding), so the forward pass only touches the inputs
  that actually spike at each step. On this box that keeps training
  to seconds per epoch instead of the minutes a dense implementation
  would take.

Scope (same as the MLP scorer): triage only. The model ranks
findings by how much they look like past candidates that survived
triage. It never predicts VERIFIED_REAL: there are zero
verified-real positives in the training data, so the model has never
seen one and must never claim one. Detection only, read-only live
probes, no transactions, no drains. crypto.com is never a target.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .data import build_dataset, load_external_rows, stratified_split
from .features import FeatureSpec, build_vocab, extract
from .mlp import MLP, metrics_for

DEFAULT_CANDIDATES = ("~/workspace/recon-continuous/results/"
                      "candidates.jsonl")
DEFAULT_BATCHES = "~/workspace/recon-continuous/results/batches.jsonl"
DEFAULT_EXTERNAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "external_findings.jsonl")

# Baselines on the fixed 145-row own holdout (seed 42), as reported
# for v1 / v2. Re-measured v2 (weights.json snapshot in this dir) is
# computed at train time when weights.json is present.
BASELINE_V1 = {"accuracy": 0.8897, "roc_auc": 0.9781, "n": 145}
BASELINE_V2 = {"accuracy": 0.9103, "roc_auc": 0.9697, "n": 145}

LIMITS = [
    "Triage only. The model ranks findings by how much they look like "
    "past candidates that survived triage. It does not verify anything.",
    "Zero verified-real positives exist in the training data, so the "
    "model never predicts VERIFIED_REAL and must never be used to claim "
    "one. A high score means 'worth a live probe', nothing more.",
    "SNNs are weaker than the MLP on this tabular triage task; the SNN "
    "is kept for its event-stream behaviour (sparse, time-ordered "
    "spikes), not because it beats the MLP.",
    "Findings from plugins or chains unseen in training fall into the "
    "OTHER bucket; the model has no opinion about them beyond the "
    "generic features.",
]


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class LIF:
    """One leaky integrate-and-fire neuron layer (vectorised by hand).

    State is a list of membrane potentials, one per neuron.
    step(currents) -> list of 0/1 spikes.
    """

    def __init__(self, n: int, beta: float = 0.9,
                 threshold: float = 1.0) -> None:
        self.n = int(n)
        self.beta = float(beta)
        self.threshold = float(threshold)
        self.v = [0.0] * self.n

    def reset(self) -> None:
        self.v = [0.0] * self.n

    def step(self, currents: Sequence[float]) -> List[int]:
        thr = self.threshold
        beta = self.beta
        v = self.v
        spikes = [0] * self.n
        for j in range(self.n):
            vj = beta * v[j] + currents[j]
            if vj >= thr:
                spikes[j] = 1
                vj = 0.0
            v[j] = vj
        return spikes


def encode_rate(x: Sequence[float], timesteps: int,
                rng: random.Random) -> List[List[int]]:
    """Rate-code a feature vector into spike trains.

    Returns one list per timestep of the input indices that spike at
    that step. Feature value = firing probability per step, so a
    strong feature fires on most steps and a weak one rarely.
    Deterministic for a given rng state.
    """
    trains: List[List[int]] = [[] for _ in range(int(timesteps))]
    for i, xi in enumerate(x):
        if xi <= 0.0:
            continue
        if xi >= 1.0:
            for t in range(int(timesteps)):
                trains[t].append(i)
            continue
        for t in range(int(timesteps)):
            if rng.random() < xi:
                trains[t].append(i)
    return trains


def encode_fixed(x: Sequence[float], timesteps: int,
                 seed: int = 12345) -> List[List[int]]:
    """Deterministic encoding for single-row scoring (predict_proba)."""
    return encode_rate(x, timesteps, random.Random(seed))


class SNN:
    """255 -> hidden LIF -> 2 LIF triage network.

    The two output neurons are the classes: index 0 =
    likely-false-positive, index 1 = worth-validating.
    """

    def __init__(self, n_in: int, n_hidden: int = 16, timesteps: int = 16,
                 beta: float = 0.9, threshold: float = 1.0,
                 seed: int = 42, lr: float = 0.05, l2: float = 1e-4,
                 surrogate_k: float = 5.0, scale: float = 8.0,
                 eval_samples: int = 5) -> None:
        if n_in < 1 or n_hidden < 1:
            raise ValueError("layer sizes must be >= 1")
        if timesteps < 1:
            raise ValueError("timesteps must be >= 1")
        self.n_in = int(n_in)
        self.n_hidden = int(n_hidden)
        self.timesteps = int(timesteps)
        self.beta = float(beta)
        self.threshold = float(threshold)
        self.seed = int(seed)
        self.lr = float(lr)
        self.l2 = float(l2)
        self.surrogate_k = float(surrogate_k)
        self.scale = float(scale)
        # predict_proba averages over this many independent encodings:
        # a single T-step rate-coded readout is noisy (one spike more
        # or less flips the count difference), so averaging is what
        # makes the score stable. Training still uses one encoding
        # per row (the noise is regularisation there).
        self.eval_samples = int(eval_samples)
        rng = random.Random(seed)
        # Init sized for sparse rate-coded input: ~14 inputs spike per
        # step on average, so weights in the 0.1-0.3 range bring a
        # hidden neuron to threshold on strong findings. Mixed sign
        # for inhibition; a small positive hidden bias keeps neurons
        # alive at the start of training.
        self.w_in: List[List[float]] = [
            [rng.uniform(-0.2, 0.3) for _ in range(self.n_in)]
            for _ in range(self.n_hidden)]
        self.b_hidden: List[float] = [0.1] * self.n_hidden
        self.w_out: List[List[float]] = [
            [rng.uniform(-0.5, 0.5) for _ in range(self.n_hidden)]
            for _ in range(2)]
        self.b_out: List[float] = [0.0, 0.0]

    # -- forward -------------------------------------------------------
    def _surrogate(self, v: float) -> float:
        d = abs(v - self.threshold)
        q = 1.0 + self.surrogate_k * d
        return 1.0 / (q * q)

    def _simulate(self, spikes_in: List[List[int]],
                  want_trace: bool = False):
        """Run one encoded finding. Returns (c0, c1, trace).

        trace (when asked) holds per-timestep v/spike lists for the
        hidden and output layers, for the backward pass.
        """
        T = self.timesteps
        beta = self.beta
        thr = self.threshold
        v_h = [0.0] * self.n_hidden
        v_o = [0.0, 0.0]
        c = [0, 0]
        trace = None
        if want_trace:
            trace = {"v_h": [], "s_h": [], "v_o": [], "s_o": []}
        w_in = self.w_in
        b_h = self.b_hidden
        w_out = self.w_out
        b_o = self.b_out
        for t in range(T):
            active = spikes_in[t]
            cur_h = list(b_h)
            for i in active:
                for j in range(self.n_hidden):
                    cur_h[j] += w_in[j][i]
            s_h = [0] * self.n_hidden
            for j in range(self.n_hidden):
                vj = beta * v_h[j] + cur_h[j]
                if vj >= thr:
                    s_h[j] = 1
                    vj = 0.0
                v_h[j] = vj
            cur_o = list(b_o)
            for j in range(self.n_hidden):
                if s_h[j]:
                    cur_o[0] += w_out[0][j]
                    cur_o[1] += w_out[1][j]
            s_o = [0, 0]
            for k in range(2):
                vk = beta * v_o[k] + cur_o[k]
                if vk >= thr:
                    s_o[k] = 1
                    c[k] += 1
                    vk = 0.0
                v_o[k] = vk
            if want_trace:
                trace["v_h"].append(list(v_h))
                trace["s_h"].append(list(s_h))
                trace["v_o"].append(list(v_o))
                trace["s_o"].append(list(s_o))
        return c[0], c[1], trace

    def spike_counts(self, spikes_in: List[List[int]]) -> Tuple[int, int]:
        c0, c1, _ = self._simulate(spikes_in, want_trace=False)
        return c0, c1

    def predict_proba(self, x: Sequence[float]) -> float:
        """Score for one feature vector (0-1, P(worth-validating)).

        Averages the spike-count readout over eval_samples
        independent encodings, so the score does not hinge on one
        noisy spike train.
        """
        total = 0.0
        for s in range(self.eval_samples):
            spikes = encode_fixed(x, self.timesteps, seed=12345 + s)
            c0, c1 = self.spike_counts(spikes)
            total += _sigmoid(self.scale * (c1 - c0) / self.timesteps)
        return total / self.eval_samples

    def predict(self, x: Sequence[float], threshold: float = 0.5) -> int:
        return 1 if self.predict_proba(x) >= threshold else 0

    def hidden_spike_rate(self, encoded_rows: Sequence[List[List[int]]]) -> float:
        """Mean hidden spikes per neuron per timestep (diagnostic)."""
        total = 0
        steps = 0
        for spikes in encoded_rows:
            _c0, _c1, trace = self._simulate(spikes, want_trace=True)
            for s_h in trace["s_h"]:
                total += sum(s_h)
                steps += self.n_hidden
        return total / max(1, steps)

    def _calibrate_bias(self, encoded_rows: Sequence[List[List[int]]],
                        target_lo: float = 0.08,
                        target_hi: float = 0.7) -> None:
        """One-time init calibration (before any gradient step).

        A LIF layer whose neurons never fire gets almost no surrogate
        gradient, so training stalls. The right bias depends on how
        many inputs spike per step, which varies by task (the real
        255-dim findings average ~14 spikes/step; a 4-dim toy has
        ~1). So before training, measure the firing rates on a sample
        and nudge the biases until both layers fire at a healthy
        rate. This is initialization only, not training: no labels
        are used, and it runs once per fit().
        """
        sample = list(encoded_rows[:200])
        if not sample:
            return
        for _ in range(20):
            rate = self.hidden_spike_rate(sample)
            if rate >= target_lo:
                break
            for j in range(self.n_hidden):
                self.b_hidden[j] += 0.15
            if max(self.b_hidden) > 1.5:
                break
        for _ in range(20):
            total = 0
            steps = 0
            for spikes in sample:
                c0, c1, _ = self._simulate(spikes, want_trace=False)
                total += c0 + c1
                steps += 2 * self.timesteps
            rate = total / max(1, steps)
            if rate >= 0.05:
                break
            for k in range(2):
                self.b_out[k] += 0.15
            if max(self.b_out) > 1.5:
                break

    # -- training ------------------------------------------------------

    # -- training ------------------------------------------------------
    def _backward(self, spikes_in, trace, y: float,
                  w_pos: float, w_neg: float):
        """Gradients of the class-weighted BCE loss for one example.

        Loss is on the spike-count readout: z = SCALE*(c1-c0)/T,
        p = sigmoid(z). dL/dz = w * (p - y). BPTT carries the output
        error back through the surrogate derivative of each layer and
        through the membrane leak to earlier timesteps.
        """
        T = self.timesteps
        beta = self.beta
        c0 = sum(s[0] for s in trace["s_o"])
        c1 = sum(s[1] for s in trace["s_o"])
        z = self.scale * (c1 - c0) / T
        p = _sigmoid(z)
        w = w_pos if y == 1.0 else w_neg
        dz = w * (p - y)
        # dL/dc1, dL/dc0
        dc1 = dz * self.scale / T
        dc0 = -dz * self.scale / T
        dc = [dc0, dc1]

        # Output-layer error per timestep: dL/dv_o.
        u_o: List[List[float]] = [[0.0, 0.0] for _ in range(T)]
        for t in range(T):
            for k in range(2):
                u_o[t][k] = dc[k] * self._surrogate(trace["v_o"][t][k])
        # Hidden-layer error per timestep, backward in time:
        # u_h[t] = surr'(v_h[t]) * (W_out^T u_o[t])
        #          + beta * (1 - s_h[t]) * u_h[t+1]
        u_h: List[List[float]] = [[0.0] * self.n_hidden for _ in range(T)]
        for t in range(T - 1, -1, -1):
            nxt = u_h[t + 1] if t + 1 < T else None
            for j in range(self.n_hidden):
                back = (self.w_out[0][j] * u_o[t][0]
                        + self.w_out[1][j] * u_o[t][1])
                val = self._surrogate(trace["v_h"][t][j]) * back
                if nxt is not None and trace["s_h"][t][j] == 0:
                    val += beta * nxt[j]
                u_h[t][j] = val

        # Gradients. W_out: u_o[t][k] * s_h[t][j]; W_in: u_h[t][j] *
        # s_in[t][i] (sparse: only active inputs).
        gw_out = [[0.0] * self.n_hidden for _ in range(2)]
        gb_out = [0.0, 0.0]
        for t in range(T):
            for k in range(2):
                gb_out[k] += u_o[t][k]
                uk = u_o[t][k]
                row = gw_out[k]
                s_h = trace["s_h"][t]
                for j in range(self.n_hidden):
                    if s_h[j]:
                        row[j] += uk
        gw_in = [[0.0] * self.n_in for _ in range(self.n_hidden)]
        gb_h = [0.0] * self.n_hidden
        for t in range(T):
            active = spikes_in[t]
            uh = u_h[t]
            for j in range(self.n_hidden):
                gb_h[j] += uh[j]
                uj = uh[j]
                if uj == 0.0:
                    continue
                grow = gw_in[j]
                for i in active:
                    grow[i] += uj
        return gw_in, gb_h, gw_out, gb_out, p

    def _bce(self, encoded, y, w_pos: float, w_neg: float) -> float:
        eps = 1e-12
        total = 0.0
        for spikes, yi in zip(encoded, y):
            c0, c1 = self.spike_counts(spikes)
            p = min(max(_sigmoid(self.scale * (c1 - c0) / self.timesteps),
                        eps), 1.0 - eps)
            w = w_pos if yi == 1.0 else w_neg
            total += -w * (yi * math.log(p) + (1.0 - yi) * math.log(1.0 - p))
        return total / max(1, len(encoded))

    def accuracy_encoded(self, encoded, y, threshold: float = 0.5) -> float:
        if not encoded:
            return 0.0
        ok = 0
        for spikes, yi in zip(encoded, y):
            c0, c1 = self.spike_counts(spikes)
            p = _sigmoid(self.scale * (c1 - c0) / self.timesteps)
            if (1 if p >= threshold else 0) == yi:
                ok += 1
        return ok / len(encoded)

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int],
            epochs: int = 10, batch_size: int = 32,
            X_val: Optional[Sequence[Sequence[float]]] = None,
            y_val: Optional[Sequence[int]] = None,
            seed: int = 42, history_every: int = 1,
            encode_seed: int = 42) -> Dict[str, List[float]]:
        """Train with mini-batch SGD on surrogate-gradient BPTT.

        Spike trains are encoded once up front (fixed rng stream) so
        every epoch sees the same event streams. Returns per-epoch
        history: loss, train_acc, val_acc (when given), plus the mean
        hidden spike rate after training.
        """
        X = [list(map(float, row)) for row in X]
        y = [float(v) for v in y]
        if not X:
            raise ValueError("empty training set")
        if len(X[0]) != self.n_in:
            raise ValueError(
                f"feature dim {len(X[0])} != network input {self.n_in}")
        rng = random.Random(encode_seed)
        encoded = [encode_rate(x, self.timesteps, rng) for x in X]
        enc_val = None
        if X_val is not None:
            rng_v = random.Random(encode_seed + 1)
            enc_val = [encode_rate(x, self.timesteps, rng_v)
                       for x in X_val]
        n_pos = sum(1 for v in y if v == 1.0)
        n_neg = len(y) - n_pos
        n = len(y)
        # Calibrate the biases once (labels not used): a dead hidden
        # layer gets no surrogate gradient and training stalls.
        self._calibrate_bias(encoded)
        # Balanced class weights (mean weight 1): the minority
        # likely-false-positive class counts as much as the majority.
        w_pos = (n / (2.0 * n_pos)) if n_pos else 1.0
        w_neg = (n / (2.0 * n_neg)) if n_neg else 1.0
        rng_shuf = random.Random(seed)
        history: Dict[str, List[float]] = {
            "loss": [], "train_acc": [], "val_acc": []}
        for epoch in range(int(epochs)):
            order = list(range(n))
            rng_shuf.shuffle(order)
            for start in range(0, n, max(1, int(batch_size))):
                idxs = order[start:start + int(batch_size)]
                gw_in = [[0.0] * self.n_in for _ in range(self.n_hidden)]
                gb_h = [0.0] * self.n_hidden
                gw_out = [[0.0] * self.n_hidden for _ in range(2)]
                gb_out = [0.0, 0.0]
                for i in idxs:
                    _c0, _c1, trace = self._simulate(encoded[i],
                                                     want_trace=True)
                    gwi, gbh, gwo, gbo, _p = self._backward(
                        encoded[i], trace, y[i], w_pos, w_neg)
                    for j in range(self.n_hidden):
                        grow = gw_in[j]
                        src = gwi[j]
                        for c in range(self.n_in):
                            grow[c] += src[c]
                        gb_h[j] += gbh[j]
                    for k in range(2):
                        grow = gw_out[k]
                        src = gwo[k]
                        for j in range(self.n_hidden):
                            grow[j] += src[j]
                        gb_out[k] += gbo[k]
                m = float(len(idxs))
                for j in range(self.n_hidden):
                    for c in range(self.n_in):
                        g = gw_in[j][c] / m
                        g += self.l2 * self.w_in[j][c]
                        self.w_in[j][c] -= self.lr * g
                    self.b_hidden[j] -= self.lr * (gb_h[j] / m)
                for k in range(2):
                    for j in range(self.n_hidden):
                        g = gw_out[k][j] / m
                        g += self.l2 * self.w_out[k][j]
                        self.w_out[k][j] -= self.lr * g
                    self.b_out[k] -= self.lr * (gb_out[k] / m)
            if epoch % max(1, int(history_every)) == 0:
                history["loss"].append(
                    self._bce(encoded, y, w_pos, w_neg))
                history["train_acc"].append(
                    self.accuracy_encoded(encoded, y))
                if enc_val is not None and y_val is not None:
                    history["val_acc"].append(
                        self.accuracy_encoded(enc_val, y_val))
        history["hidden_spike_rate"] = [
            self.hidden_spike_rate(encoded[:200])]
        return history

    # -- persistence -----------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "format": "recon-nn-snn/1",
            "n_in": self.n_in,
            "n_hidden": self.n_hidden,
            "timesteps": self.timesteps,
            "beta": self.beta,
            "threshold": self.threshold,
            "seed": self.seed,
            "lr": self.lr,
            "l2": self.l2,
            "surrogate_k": self.surrogate_k,
            "scale": self.scale,
            "eval_samples": self.eval_samples,
            "w_in": self.w_in,
            "b_hidden": self.b_hidden,
            "w_out": self.w_out,
            "b_out": self.b_out,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "SNN":
        if data.get("format") != "recon-nn-snn/1":
            raise ValueError("not a recon-nn-snn/1 weights file")
        net = cls(int(data["n_in"]), n_hidden=int(data["n_hidden"]),
                  timesteps=int(data["timesteps"]),
                  beta=float(data.get("beta", 0.9)),
                  threshold=float(data.get("threshold", 1.0)),
                  seed=int(data.get("seed", 42)),
                  lr=float(data.get("lr", 0.05)),
                  l2=float(data.get("l2", 1e-4)),
                  surrogate_k=float(data.get("surrogate_k", 5.0)),
                  scale=float(data.get("scale", 8.0)),
                  eval_samples=int(data.get("eval_samples", 5)))
        net.w_in = [[float(v) for v in row] for row in data["w_in"]]
        net.b_hidden = [float(v) for v in data["b_hidden"]]
        net.w_out = [[float(v) for v in row] for row in data["w_out"]]
        net.b_out = [float(v) for v in data["b_out"]]
        return net

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)

    @classmethod
    def load(cls, path: str) -> "SNN":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def load_snn_model(path: Optional[str] = None):
    """Load (net, spec, meta) from an snn_weights.json file.

    Same tuple shape as pipeline.load_model, so the SNN duck-types
    the MLP: pipeline.score_finding_dicts works with it unchanged
    (it only calls net.predict_proba).
    """
    p = (Path(path) if path else
         Path(__file__).resolve().parent / "snn_weights.json")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    try:
        if data.get("format") != "recon-nn-snn-weights/1":
            return None
        net = SNN.from_dict(data["snn"])
        spec = FeatureSpec.from_dict(data["features"])
        return net, spec, data
    except Exception:
        return None


def score_finding_dicts_snn(findings: List[Dict], model=None,
                            threshold: float = 0.5) -> List[Dict]:
    """Score finding dicts with the SNN (pipeline-compatible shape)."""
    from .features import top_features
    if model is None:
        model = load_snn_model()
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


def _mlp_baseline_on_holdout(weights_path: Path, test_rows):
    """Re-measure the shipped MLP weights.json on the same holdout.

    Uses the FeatureSpec stored IN weights.json: the MLP's weights
    are tied to that exact feature layout, so extracting the holdout
    with a rebuilt vocab would silently misalign the features and
    report a wrong (worse) baseline. Returns None when no MLP
    weights file is present.
    """
    try:
        data = json.loads(weights_path.read_text(encoding="utf-8"))
        if data.get("format") != "recon-nn-weights/1":
            return None
        net = MLP.from_dict(data["mlp"])
        spec = FeatureSpec.from_dict(data["features"])
        X_test = [extract(r["finding"], spec) for r in test_rows]
        y_test = [r["label"] for r in test_rows]
        scores = [net.predict_proba(x) for x in X_test]
        m = metrics_for(y_test, scores)
        m["layers"] = net.layers
        m["trained_at"] = data.get("trained_at")
        return m
    except Exception:
        return None


def train_snn(candidates_path: str, batches_path: str, out_dir: str,
              epochs: int = 10, hidden: int = 16, timesteps: int = 16,
              lr: float = 0.05, seed: int = 42, test_frac: float = 0.2,
              external_path: Optional[str] = None,
              feature_cache: Optional[str] = None) -> dict:
    """Train the SNN on own rows + external rows.

    Holdout: the FIXED own-test split, stratified_split(own 725,
    test_frac, seed 42) -> 145 rows. Training rows are the other 580
    own rows plus all external rows. External rows never enter the
    holdout: the holdout measures performance on Jay's own scanner
    rows only, exactly like the v1/v2 numbers.
    """
    cache: Optional[dict] = None
    if feature_cache and os.path.exists(feature_cache):
        try:
            cache = json.loads(Path(feature_cache).read_text(
                encoding="utf-8"))
        except Exception:
            cache = None
    if cache is not None:
        spec = FeatureSpec.from_dict(cache["features"])
        X_train = cache["X_train"]
        y_train = cache["y_train"]
        X_test = cache["X_test"]
        y_test = cache["y_test"]
        stats = cache["dataset"]
        n_train_own = cache.get("n_train_own", 0)
        own_test_rows = cache.get("test_rows")
    else:
        dataset = build_dataset(candidates_path, batches_path)
        own_rows = dataset["rows"]
        stats = dataset["stats"]
        if external_path and not os.path.exists(external_path):
            raise ValueError(f"external file not found: {external_path}")
        ext_rows: List[Dict] = []
        if external_path and os.path.exists(external_path):
            ext_rows, ext_stats = load_external_rows(external_path)
            stats.update(ext_stats)
            stats["train_rows"] = len(own_rows) + len(ext_rows)
            stats["n_positive"] = (stats["n_positive"]
                                   + ext_stats["external_positive"])
            stats["n_negative"] = (stats["n_negative"]
                                   + ext_stats["external_negative"])
        own_train, own_test = stratified_split(own_rows, test_frac, seed)
        train_rows = own_train + ext_rows
        own_test_rows = own_test
        spec = build_vocab([r["finding"] for r in train_rows])
        X_train = [extract(r["finding"], spec) for r in train_rows]
        y_train = [r["label"] for r in train_rows]
        X_test = [extract(r["finding"], spec) for r in own_test]
        y_test = [r["label"] for r in own_test]
        n_train_own = len(own_train)
        if feature_cache:
            Path(feature_cache).write_text(json.dumps({
                "features": spec.to_dict(),
                "X_train": X_train, "y_train": y_train,
                "X_test": X_test, "y_test": y_test,
                "test_rows": own_test_rows,
                "dataset": stats, "n_train_own": n_train_own,
            }), encoding="utf-8")

    n_pos = sum(y_train) + sum(y_test)
    n_neg = len(y_train) + len(y_test) - n_pos
    pos_pct = 100.0 * n_pos / max(1, len(y_train) + len(y_test))
    limits = list(LIMITS)
    limits[2] = (
        f"Label skew: the training set is {pos_pct:.0f}% worth-validating "
        f"/ {100.0 - pos_pct:.0f}% likely-false-positive "
        f"({n_pos} positive / {n_neg} negative of "
        f"{len(y_train) + len(y_test)} rows). "
        "Accuracy near the majority baseline means the model learned "
        "nothing; judge it by minority-class recall and ROC AUC instead.")

    net = SNN(spec.dim, n_hidden=hidden, timesteps=timesteps,
              seed=seed, lr=lr)
    history = net.fit(X_train, y_train, epochs=epochs, batch_size=32,
                      X_val=X_test, y_val=y_test, seed=seed)
    train_scores = [net.predict_proba(x) for x in X_train]
    test_scores = [net.predict_proba(x) for x in X_test]
    train_metrics = metrics_for(y_train, train_scores)
    test_metrics = metrics_for(y_test, test_scores)
    mlp_baseline = None
    if own_test_rows:
        mlp_baseline = _mlp_baseline_on_holdout(
            Path(out_dir) / "weights.json", own_test_rows)

    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "model": "snn-lif-surrogate-gradient",
        "layers": [spec.dim, hidden, 2],
        "timesteps": timesteps,
        "beta": net.beta,
        "threshold": net.threshold,
        "surrogate_k": net.surrogate_k,
        "scale": net.scale,
        "n_features": spec.dim,
        "feature_names": spec.feature_names(),
        "dataset": stats,
        "train_rows": len(X_train),
        "train_rows_own": n_train_own,
        "test_rows": len(X_test),
        "test_rows_note": "fixed own-test holdout, seed 42",
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "history": history,
        "baseline_v1_145": BASELINE_V1,
        "baseline_v2_145": BASELINE_V2,
        "baseline_v2_remeasured": mlp_baseline,
        "limits": limits,
        "seed": seed,
        "epochs": epochs,
        "lr": lr,
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    weights = {
        "format": "recon-nn-snn-weights/1",
        "trained_at": result["trained_at"],
        "snn": net.to_dict(),
        "features": spec.to_dict(),
        "metrics": {"train": train_metrics, "test": test_metrics},
        "dataset": stats,
        "limits": limits,
    }
    (out / "snn_weights.json").write_text(json.dumps(weights, indent=2),
                                          encoding="utf-8")
    (out / "snn_viewer_data.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    return result


def evaluate_snn(weights_path: str, candidates_path: str,
                 batches_path: str, seed: int = 42,
                 test_frac: float = 0.2) -> dict:
    """Evaluate saved SNN weights on the fixed own-145 holdout."""
    model = load_snn_model(weights_path)
    if model is None:
        raise ValueError(f"no SNN weights at {weights_path}")
    net, spec, _meta = model
    dataset = build_dataset(candidates_path, batches_path)
    own_rows = dataset["rows"]
    _own_train, own_test = stratified_split(own_rows, test_frac, seed)
    X_test = [extract(r["finding"], spec) for r in own_test]
    y_test = [r["label"] for r in own_test]
    scores = [net.predict_proba(x) for x in X_test]
    return metrics_for(y_test, scores)


def _print_report(result: dict) -> None:
    tm = result["test_metrics"]
    tr = result["train_metrics"]
    print(f"rows: train={result['train_rows']} "
          f"(own {result['train_rows_own']} + external "
          f"{result['train_rows'] - result['train_rows_own']}) "
          f"test={result['test_rows']} (fixed own holdout, seed 42)")
    print(f"features: {result['n_features']}  "
          f"layers: {result['layers']}  T={result['timesteps']}")
    print(f"train acc {tr['accuracy']:.3f}  test acc {tm['accuracy']:.3f}  "
          f"majority baseline {tm['majority_baseline_accuracy']:.3f}")
    print(f"test ROC AUC {tm['roc_auc']:.3f}")
    print(f"worth-validating: precision {tm['precision_worth_validating']:.3f} "
          f"recall {tm['recall_worth_validating']:.3f}")
    print(f"likely-false-positive: precision {tm['precision_likely_fp']:.3f} "
          f"recall {tm['recall_likely_fp']:.3f}")
    cm = tm["confusion"]
    print(f"confusion (test): tp={cm['tp']} fp={cm['fp']} "
          f"fn={cm['fn']} tn={cm['tn']}")
    print(f"v1 baseline: acc {result['baseline_v1_145']['accuracy']:.4f}  "
          f"AUC {result['baseline_v1_145']['roc_auc']:.4f}")
    print(f"v2 baseline: acc {result['baseline_v2_145']['accuracy']:.4f}  "
          f"AUC {result['baseline_v2_145']['roc_auc']:.4f}")
    rb = result.get("baseline_v2_remeasured")
    if rb:
        print(f"v2 re-measured on same holdout: acc {rb['accuracy']:.4f}  "
              f"AUC {rb['roc_auc']:.4f}  (weights {rb.get('trained_at')})")
    print("history loss: " + ", ".join(
        f"{v:.3f}" for v in result["history"]["loss"]))
    print("history val_acc: " + ", ".join(
        f"{v:.3f}" for v in result["history"]["val_acc"]))
    print("hidden spike rate: "
          f"{result['history']['hidden_spike_rate'][0]:.3f}")
    print("LIMITS: triage only; zero verified-real positives; "
          "never predicts VERIFIED_REAL.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Train / evaluate the SNN triage network.")
    ap.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    ap.add_argument("--batches", default=DEFAULT_BATCHES)
    ap.add_argument("--external", default=None,
                    help="external-findings JSONL; omit to train on "
                         "Jay's own rows only")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--hidden", type=int, default=32)
    ap.add_argument("--timesteps", type=int, default=32)
    ap.add_argument("--lr", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--feature-cache", default=None,
                    help="JSON cache for the built feature matrices "
                         "(speeds up retrains; not committed)")
    ap.add_argument("--eval-only", default=None,
                    help="evaluate saved snn_weights.json instead of "
                         "training")
    args = ap.parse_args(argv)
    if args.eval_only:
        m = evaluate_snn(args.eval_only,
                         os.path.expanduser(args.candidates),
                         os.path.expanduser(args.batches),
                         seed=args.seed, test_frac=args.test_frac)
        print(json.dumps(m, indent=2))
        return 0
    result = train_snn(os.path.expanduser(args.candidates),
                       os.path.expanduser(args.batches),
                       args.out, epochs=args.epochs, hidden=args.hidden,
                       timesteps=args.timesteps, lr=args.lr,
                       seed=args.seed, test_frac=args.test_frac,
                       external_path=(os.path.expanduser(args.external)
                                      if args.external else None),
                       feature_cache=(os.path.expanduser(args.feature_cache)
                                      if args.feature_cache else None))
    _print_report(result)
    print(f"snn weights: {os.path.join(args.out, 'snn_weights.json')}")
    print(f"snn viewer data: {os.path.join(args.out, 'snn_viewer_data.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
