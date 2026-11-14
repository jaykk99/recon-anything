"""A small multilayer perceptron in pure Python stdlib.

No torch, no sklearn, no numpy: the backend venv does not have them,
and this network has to run on Jay's Linux box and in Termux with zero
new dependencies. Lists of floats, tanh hidden units, sigmoid output,
binary cross-entropy, plain SGD with mini-batches.

This is a triage scorer, not a verifier. It ranks plugin findings by
how much they look like the candidates that survived triage in the past.
It never stamps VERIFIED_REAL: there are zero verified-real positives
in the training data, so the model has never seen one and must never
claim one.
"""
from __future__ import annotations

import json
import math
import os
import random
from operator import mul
from typing import Dict, List, Optional, Sequence, Tuple


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _tanh(z: float) -> float:
    return math.tanh(z)


def _tanh_deriv(a: float) -> float:
    # a is tanh(z); d/dz = 1 - tanh(z)^2
    return 1.0 - a * a


class MLP:
    """Feed-forward network: layers e.g. [n_in, 32, 16, 1].

    Hidden layers use tanh, the output layer uses sigmoid, so
    predict_proba returns a number in (0, 1): the model's estimated
    probability that a finding is worth validating.
    """

    def __init__(self, layers: Sequence[int], seed: int = 42,
                 lr: float = 0.05, l2: float = 1e-4) -> None:
        if len(layers) < 2:
            raise ValueError("need at least [n_in, n_out]")
        if any(n < 1 for n in layers):
            raise ValueError("layer sizes must be >= 1")
        self.layers = list(layers)
        self.lr = float(lr)
        self.l2 = float(l2)
        self.seed = int(seed)
        rng = random.Random(seed)
        self.weights: List[List[List[float]]] = []
        self.biases: List[List[float]] = []
        for fan_in, fan_out in zip(self.layers[:-1], self.layers[1:]):
            # Xavier uniform: keeps tanh units out of saturation at init.
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            self.weights.append(
                [[rng.uniform(-limit, limit) for _ in range(fan_in)]
                 for _ in range(fan_out)])
            self.biases.append([0.0 for _ in range(fan_out)])

    # -- forward ---------------------------------------------------------
    def _forward(self, x: Sequence[float], nz=None):
        """Return (activations, pre-activations); activations[0] is x.

        nz is an optional precomputed list of nonzero input indices.
        When the input is sparse (fewer than 1 in 4 inputs nonzero)
        the first layer skips the zero columns. Adding 0.0 changes
        nothing in IEEE arithmetic, so the sparse result matches the
        dense dot product to within a float ULP (the dense path uses
        CPython's compensated sum, the sparse path a plain loop).
        This is what makes an 11k-input network trainable in pure
        Python: a finding lights up ~60 inputs, not 11,573.
        """
        # Never copy the input: at 11,573 inputs, list(map(float, x))
        # on every forward pass was the whole training cost (the
        # vector is only read here, never mutated).
        acts = [x if type(x) is list else list(map(float, x))]
        pres = []
        n_in = len(acts[0])
        if nz is None:
            nz = [i for i, v in enumerate(acts[0]) if v != 0.0]
        w0, b0 = self.weights[0], self.biases[0]
        if len(nz) * 4 < n_in:
            z = []
            for row, bias in zip(w0, b0):
                s = 0.0
                for i in nz:
                    s += row[i] * acts[0][i]
                z.append(s + bias)
        else:
            z = [sum(map(mul, row, acts[0])) + bias
                 for row, bias in zip(w0, b0)]
        pres.append(z)
        single_layer = len(self.weights) == 1
        acts.append([_sigmoid(v) for v in z] if single_layer
                    else [_tanh(v) for v in z])
        for li in range(1, len(self.weights)):
            w, b = self.weights[li], self.biases[li]
            z = [sum(map(mul, row, acts[-1])) + bias
                 for row, bias in zip(w, b)]
            pres.append(z)
            if li == len(self.weights) - 1:
                acts.append([_sigmoid(v) for v in z])
            else:
                acts.append([_tanh(v) for v in z])
        return acts, pres

    def predict_proba(self, x: Sequence[float], nz=None) -> float:
        acts, _ = self._forward(x, nz=nz)
        return acts[-1][0]

    def predict(self, x: Sequence[float], threshold: float = 0.5,
                nz=None) -> int:
        return 1 if self.predict_proba(x, nz=nz) >= threshold else 0

    # -- training --------------------------------------------------------
    def _deltas(self, acts, y: float):
        """Per-layer error signals for one example (same math as
        _backward, without materialising the gradient matrices)."""
        n_layers = len(self.weights)
        deltas: List[Optional[List[float]]] = [None] * n_layers
        p = acts[-1][0]
        deltas[-1] = [p - y]
        for li in range(n_layers - 2, -1, -1):
            w_next = self.weights[li + 1]
            d_next = deltas[li + 1]
            a = acts[li + 1]  # tanh activations of this layer
            delta = []
            for j in range(len(a)):
                s = sum(map(mul, (w_next[k][j] for k in range(len(d_next))),
                            d_next))
                delta.append(s * _tanh_deriv(a[j]))
            deltas[li] = delta
        return deltas

    def _backward(self, acts, pres, y: float):
        """Gradients of the BCE loss for one example.

        Returns (grad_weights, grad_biases) in the same shapes as
        self.weights / self.biases. Output layer: with sigmoid + BCE
        the delta is simply (p - y). Hidden layers: tanh derivative.
        """
        deltas = self._deltas(acts, y)
        grad_w = []
        grad_b = []
        for li in range(len(deltas)):
            d = deltas[li]
            a_prev = acts[li]
            grad_w.append([[d[i] * a_prev[j] for j in range(len(a_prev))]
                           for i in range(len(d))])
            grad_b.append(list(d))
        return grad_w, grad_b

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int],
            epochs: int = 60, batch_size: int = 32,
            X_val: Optional[Sequence[Sequence[float]]] = None,
            y_val: Optional[Sequence[int]] = None,
            seed: int = 42, history_every: int = 1,
            checkpoint_path: Optional[str] = None,
            checkpoint_every: int = 10,
            start_epoch: int = 0,
            resume_state: Optional[Tuple[list, int]] = None) -> Dict[str, List[float]]:
        """Train with mini-batch SGD. Returns per-epoch history.

        history = {"loss": [...], "train_acc": [...], "val_acc": [...]}
        (val_acc present only when a validation set is given). Loss is
        mean binary cross-entropy over the training set. history_every
        > 1 records loss/accuracy only every Nth epoch (and the first):
        the weights are identical, only the reporting is sparser.
        Sweeps pass a large value; the shipped train run uses 1.

        Crash-proofing: checkpoint_path + checkpoint_every write the
        full weights to disk every N epochs (atomic tmp + rename) and
        at the last epoch, so a killed run loses minutes, not hours.
        start_epoch resumes a run whose first start_epoch epochs are
        already in the weights: the loop runs start_epoch..epochs.
        A resumed run re-seeds its shuffle RNG with seed+start_epoch,
        so its shuffle order differs from an uninterrupted run; the
        data, split and starting weights are identical, and the
        metrics stay honest either way.
        """
        X = [list(map(float, row)) for row in X]
        y = [float(v) for v in y]
        if not X:
            raise ValueError("empty training set")
        n_in = len(X[0])
        if n_in != self.layers[0]:
            raise ValueError(
                f"feature dim {n_in} != network input {self.layers[0]}")
        # Nonzero input columns per row, computed once: the first
        # layer's gradient is zero on every zero column, so the
        # backward pass skips them too.
        X_nz = [[i for i, v in enumerate(row) if v != 0.0]
                for row in X]
        X_val_nz = ([[i for i, v in enumerate(row) if v != 0.0]
                     for row in X_val]
                    if X_val is not None else None)
        rng = random.Random(seed + start_epoch)
        history: Dict[str, List[float]] = {
            "loss": [], "train_acc": [], "val_acc": []}
        n = len(X)
        # Gradient buffers are allocated ONCE, not per batch: at
        # 11,573 inputs the first-layer buffer is 741k floats, and
        # re-allocating it every batch was the whole training cost.
        # The first layer is updated sparsely (see _apply_batch
        # below); deeper layers are small and stay dense.
        gw_acc = [[[0.0] * len(row) for row in w]
                  for w in self.weights]
        gb_acc = [[0.0] * len(b) for b in self.biases]
        # Lazy L2 for the first layer: the dense update multiplies
        # EVERY first-layer weight by (1 - lr*l2) every batch, even
        # columns whose gradient is zero. Instead, each column
        # remembers the last batch that touched it; when it is next
        # touched, the missed decay factors are applied in one
        # pow() (exact: w *= (1-lr*l2)^k, same product the dense
        # loop would have applied k times, to a float ULP), then
        # the batch gradient is subtracted. Untouched columns are
        # settled by _settle_l2 at the end of fit. resume_state
        # restores (last_touch, batch_ctr) from a checkpoint so a
        # resumed run decays exactly what the killed run had left
        # pending.
        if resume_state is not None:
            last_touch = list(resume_state[0])
            batch_ctr = int(resume_state[1])
        else:
            last_touch = [-1] * n_in
            batch_ctr = 0
        decay = 1.0 - self.lr * self.l2
        for epoch in range(int(start_epoch), int(epochs)):
            order = list(range(n))
            rng.shuffle(order)
            for start in range(0, n, max(1, int(batch_size))):
                idxs = order[start:start + int(batch_size)]
                touched: set = set()
                for i in idxs:
                    acts, _ = self._forward(X[i], nz=X_nz[i])
                    # Fuse the gradient into the batch accumulator
                    # directly: same d[i]*a_prev[j] products _backward
                    # would build, without a throwaway matrix per
                    # example.
                    deltas = self._deltas(acts, y[i])
                    for li in range(len(deltas)):
                        d = deltas[li]
                        a_prev = acts[li]
                        gw_li = gw_acc[li]
                        if li == 0:
                            # First layer: only nonzero input columns
                            # carry gradient; the rest stay exactly 0.
                            cols = X_nz[i]
                            for c in cols:
                                touched.add(c)
                            for r in range(len(d)):
                                dr = d[r]
                                gw_r = gw_li[r]
                                for c in cols:
                                    gw_r[c] += dr * a_prev[c]
                        else:
                            for r in range(len(d)):
                                dr = d[r]
                                gw_r = gw_li[r]
                                for c in range(len(a_prev)):
                                    gw_r[c] += dr * a_prev[c]
                        gb_li = gb_acc[li]
                        for r in range(len(d)):
                            gb_li[r] += d[r]
                m = float(len(idxs))
                self._apply_batch(gw_acc, gb_acc, m, touched,
                                  last_touch, decay, batch_ctr)
                batch_ctr += 1
            if epoch % max(1, int(history_every)) == 0 or epoch == epochs - 1:
                history["loss"].append(self._bce_nz(X, X_nz, y))
                history["train_acc"].append(
                    self.accuracy_nz(X, X_nz, y))
                if X_val is not None and y_val is not None:
                    history["val_acc"].append(
                        self.accuracy_nz(X_val, X_val_nz, y_val))
            if checkpoint_path and ((epoch + 1) % max(1, int(checkpoint_every)) == 0
                                    or epoch == epochs - 1):
                _write_checkpoint(checkpoint_path, self, epoch + 1,
                                  last_touch, batch_ctr)
        self._settle_l2(last_touch, decay, batch_ctr)
        return history

    def _apply_batch(self, gw_acc, gb_acc, m: float, touched: set,
                     last_touch: List[int], decay: float,
                     batch_ctr: int) -> None:
        """Apply one batch's accumulated gradients.

        Layers 1+ are small: dense update, then zero the buffers.
        Layer 0 is wide: only touched columns are updated (lazy L2
        decay for the batches since the column was last touched,
        then the batch gradient), then only those entries are
        zeroed. Untouched columns are exactly as the dense loop
        would leave them (decay only), settled at the end of fit.
        """
        lr = self.lr
        l2 = self.l2
        # Deeper layers: dense, as before.
        for li in range(1, len(self.weights)):
            gw_li = gw_acc[li]
            w_li = self.weights[li]
            for r in range(len(w_li)):
                gw_r = gw_li[r]
                w_r = w_li[r]
                for c in range(len(w_r)):
                    g = gw_r[c] / m + l2 * w_r[c]
                    w_r[c] -= lr * g
                    gw_r[c] = 0.0
            gb_li = gb_acc[li]
            b_li = self.biases[li]
            for r in range(len(b_li)):
                b_li[r] -= lr * (gb_li[r] / m)
                gb_li[r] = 0.0
        # First layer: sparse over touched columns. One pass per
        # row: fetch the row once, then walk the touched columns
        # (decay factor per column is precomputed). Untouched
        # columns are exactly as the dense loop would leave them
        # (decay only), settled at the end of fit.
        gw0 = gw_acc[0]
        w0 = self.weights[0]
        cols = list(touched)
        if l2 > 0.0:
            facs = [decay ** (batch_ctr - last_touch[c]) for c in cols]
        else:
            facs = [1.0] * len(cols)
        for r in range(len(w0)):
            w_r = w0[r]
            g_r = gw0[r]
            for ci, c in enumerate(cols):
                w_r[c] = w_r[c] * facs[ci] - lr * (g_r[c] / m)
                g_r[c] = 0.0
        for c in cols:
            last_touch[c] = batch_ctr
        gb0 = gb_acc[0]
        b0 = self.biases[0]
        for r in range(len(b0)):
            b0[r] -= lr * (gb0[r] / m)
            gb0[r] = 0.0

    def _settle_l2(self, last_touch: List[int], decay: float,
                   batch_ctr: int) -> None:
        """End-of-fit: apply the remaining lazy L2 decay to every
        first-layer column for the batches since its last touch.
        Columns never touched decay for all batches. No-op when
        l2 == 0 or no batch ran."""
        if self.l2 <= 0.0 or batch_ctr <= 0:
            return
        w0 = self.weights[0]
        for c in range(len(w0[0])):
            missed = batch_ctr - 1 - last_touch[c]
            if missed > 0:
                factor = decay ** missed
                for r in range(len(w0)):
                    w0[r][c] *= factor

    def _bce_nz(self, X, X_nz, y) -> float:
        eps = 1e-12
        total = 0.0
        for xi, nz, yi in zip(X, X_nz, y):
            p = min(max(self.predict_proba(xi, nz=nz), eps), 1.0 - eps)
            total += -(yi * math.log(p) + (1.0 - yi) * math.log(1.0 - p))
        return total / max(1, len(X))

    def accuracy_nz(self, X, X_nz, y, threshold: float = 0.5) -> float:
        if not X:
            return 0.0
        ok = sum(1 for xi, nz, yi in zip(X, X_nz, y)
                 if self.predict(xi, threshold, nz=nz) == yi)
        return ok / len(X)

    def _bce(self, X, y) -> float:
        eps = 1e-12
        total = 0.0
        for xi, yi in zip(X, y):
            p = min(max(self.predict_proba(xi), eps), 1.0 - eps)
            total += -(yi * math.log(p) + (1.0 - yi) * math.log(1.0 - p))
        return total / max(1, len(X))

    def accuracy(self, X, y, threshold: float = 0.5) -> float:
        if not X:
            return 0.0
        ok = sum(1 for xi, yi in zip(X, y)
                 if self.predict(xi, threshold) == yi)
        return ok / len(X)

    # -- persistence -----------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "format": "recon-nn-mlp/1",
            "layers": self.layers,
            "lr": self.lr,
            "l2": self.l2,
            "seed": self.seed,
            "weights": self.weights,
            "biases": self.biases,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "MLP":
        if data.get("format") != "recon-nn-mlp/1":
            raise ValueError("not a recon-nn-mlp/1 weights file")
        net = cls(data["layers"], seed=int(data.get("seed", 42)),
                  lr=float(data.get("lr", 0.05)),
                  l2=float(data.get("l2", 1e-4)))
        net.weights = [[[float(v) for v in row] for row in mat]
                       for mat in data["weights"]]
        net.biases = [[float(v) for v in b] for b in data["biases"]]
        return net

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)

    @classmethod
    def load(cls, path: str) -> "MLP":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def _write_checkpoint(path: str, net: "MLP", epochs_done: int,
                      last_touch=None, batch_ctr: int = 0) -> None:
    """Write weights + epoch count atomically (tmp file + rename) so
    a kill mid-write never leaves a torn checkpoint behind.

    last_touch / batch_ctr are the lazy-L2 state: without them a
    resumed run would under-apply decay for columns untouched since
    the checkpoint. Old checkpoints without these fields resume with
    last_touch None (their weights were written by the dense loop,
    which applies decay to every weight every batch, so nothing is
    pending)."""
    data = {"format": "recon-nn-checkpoint/1",
            "epochs_done": int(epochs_done),
            "layers": list(net.layers),
            "mlp": net.to_dict()}
    if last_touch is not None:
        data["last_touch"] = list(last_touch)
        data["batch_ctr"] = int(batch_ctr)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def load_checkpoint(path: str) -> Tuple["MLP", int, Optional[list], int]:
    """-> (net, epochs_done, last_touch, batch_ctr). Raises
    ValueError on a bad file. last_touch is None for checkpoints
    written before lazy-L2 state was stored."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("format") != "recon-nn-checkpoint/1":
        raise ValueError(f"not a recon-nn-checkpoint/1 file: {path}")
    return (MLP.from_dict(data["mlp"]), int(data["epochs_done"]),
            data.get("last_touch"),
            int(data.get("batch_ctr", 0)))


def roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Rank-based ROC AUC (Mann-Whitney). 0.5 = chance, 1.0 = perfect.

    Pure python: sort by score, count correctly ordered pairs.
    """
    pairs = sorted(zip(scores, labels), key=lambda t: t[0])
    n_pos = sum(1 for _, lab in pairs if lab == 1)
    n_neg = len(pairs) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    # Average ranks with ties.
    rank_sum = 0.0
    i = 0
    ranks = [0.0] * len(pairs)
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # 1-based average rank
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    for r, (_, lab) in zip(ranks, pairs):
        if lab == 1:
            rank_sum += r
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def confusion_matrix(y_true: Sequence[int],
                     y_pred: Sequence[int]) -> Dict[str, int]:
    """Positive class = worth-validating (1)."""
    tn = fp = fn = tp = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 1 and p == 0:
            fn += 1
        else:
            tn += 1
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def prf(cm: Dict[str, int]) -> Dict[str, float]:
    """Precision / recall / F1 for both classes from a confusion matrix."""
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    pos_prec = tp / (tp + fp) if tp + fp else 0.0
    pos_rec = tp / (tp + fn) if tp + fn else 0.0
    neg_prec = tn / (tn + fn) if tn + fn else 0.0
    neg_rec = tn / (tn + fp) if tn + fp else 0.0

    def f1(p: float, r: float) -> float:
        return 2 * p * r / (p + r) if p + r else 0.0

    return {
        "precision_worth_validating": pos_prec,
        "recall_worth_validating": pos_rec,
        "f1_worth_validating": f1(pos_prec, pos_rec),
        "precision_likely_fp": neg_prec,
        "recall_likely_fp": neg_rec,
        "f1_likely_fp": f1(neg_prec, neg_rec),
    }


def metrics_for(y_true: Sequence[int], scores: Sequence[float],
                threshold: float = 0.5) -> Dict:
    """Full honest metric set for one scored set."""
    preds = [1 if s >= threshold else 0 for s in scores]
    cm = confusion_matrix(list(y_true), preds)
    out = {
        "n": len(y_true),
        "n_positive": sum(1 for t in y_true if t == 1),
        "n_negative": sum(1 for t in y_true if t == 0),
        "threshold": threshold,
        "accuracy": sum(1 for t, p in zip(y_true, preds) if t == p) / max(1, len(y_true)),
        "majority_baseline_accuracy": max(
            sum(1 for t in y_true if t == 1),
            sum(1 for t in y_true if t == 0)) / max(1, len(y_true)),
        "roc_auc": roc_auc(list(scores), list(y_true)),
        "confusion": cm,
    }
    out.update(prf(cm))
    return out
