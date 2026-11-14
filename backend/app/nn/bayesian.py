"""Bayesian triage: last-layer Laplace approximation over the trained
triage MLP, in pure Python stdlib.

The point-score MLP answers "how likely is this finding worth
validating" with a single number and no sense of its own ignorance.
This module replaces the point score with a distribution:

    p(y=1 | x) ~ posterior predictive, summarised as
    mean + 90% credible interval [lo, hi] + an unsure flag.

Method (last-layer Laplace, MacKay 1992; standard practice for
putting honest uncertainty on a trained net without retraining it):
1. Freeze the trained MLP as a feature extractor. For an input x,
   take the last hidden layer activations h(x) (32 tanh units) and
   append a bias term: z = [h(x), 1].
2. Refit ONLY the last-layer weights w (33 numbers) as a Bayesian
   logistic regression on z, with a Gaussian prior w ~ N(0, a^-1 I).
   The posterior mode w_map is found by Newton iterations starting
   from the MLP's own trained last-layer weights; the posterior is
   the Laplace Gaussian N(w_map, H^-1) where H is the Hessian of the
   negative log posterior at the mode.
3. At predict time, the logit w.z is a linear map of the Gaussian
   posterior, so it is exactly Gaussian: logit ~ N(w_map.z, z^T S z).
   Draw S logit samples from that 1-D Gaussian, push each through
   the sigmoid, and report the mean and the 5th/95th percentiles as
   the 90% credible interval. Same distribution as sampling weight
   vectors, O(dim^2) once per input instead of per sample.

Why last-layer only: a full Laplace over all ~18k weights needs an
18k x 18k Hessian, which is not feasible in pure Python. The last
layer carries the decision; the frozen hidden layers carry the
representation. This is the standard, honest trade-off, and it is
stated here rather than hidden.

Calibration (measured, never assumed):
- The posterior covariance may be scaled by a single factor c,
  chosen on the TRAINING split only, so that the binned 90%
  interval coverage on train lands as close to 0.90 as the grid
  allows. c = 1 means the raw Laplace posterior was already
  calibrated; the fitted value is saved with the model and reported.
- Reported on the fixed test holdout: ECE of the posterior mean
  (10 bins), Brier score, binned interval coverage, confident-row
  accuracy vs unsure-row accuracy, and the unsure rate.

Unsure flag: a finding is "unsure" when its 90% interval straddles
the 0.5 decision line (lo < 0.5 < hi). The pipeline routes unsure
findings to human review instead of auto-triaging them. The flag is
a routing signal only: it never changes a label to VERIFIED_REAL
(the model cannot output that; there are zero verified-real rows
in the training data, exactly as in the point model).

Triage only, detection only. No transactions, no live probes, no
drains. crypto.com is never a target (the scorer never targets
anything; it ranks findings the scanner already produced).
"""
from __future__ import annotations

import json
import math
import random
from typing import Dict, List, Optional, Sequence, Tuple

CREDIBLE_LEVEL = 0.90
_LO_Q = (1.0 - CREDIBLE_LEVEL) / 2.0   # 0.05
_HI_Q = 1.0 - _LO_Q                    # 0.95


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


# ---------------------------------------------------------------------
# small dense linear algebra (stdlib only; matrices here are <= 33x33)
# ---------------------------------------------------------------------

def _mat_inverse(a: List[List[float]]) -> List[List[float]]:
    """Gauss-Jordan inverse with partial pivoting. Raises on singular."""
    n = len(a)
    m = [list(map(float, row)) + [1.0 if i == j else 0.0 for j in range(n)]
         for i, row in enumerate(a)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(m[r][col]))
        if abs(m[piv][col]) < 1e-12:
            raise ValueError("singular matrix")
        m[col], m[piv] = m[piv], m[col]
        pv = m[col][col]
        m[col] = [v / pv for v in m[col]]
        for r in range(n):
            if r != col and m[r][col] != 0.0:
                f = m[r][col]
                m[r] = [v - f * w for v, w in zip(m[r], m[col])]
    return [row[n:] for row in m]


def _mat_vec_mul(a: List[List[float]], v: Sequence[float]) -> List[float]:
    return [sum(ai * vi for ai, vi in zip(row, v)) for row in a]


def _cholesky(a: List[List[float]]) -> List[List[float]]:
    """Lower-triangular L with L L^T = a (a symmetric positive-def)."""
    n = len(a)
    L = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            s = a[i][j] - sum(L[i][k] * L[j][k] for k in range(j))
            if i == j:
                if s <= 0.0:
                    raise ValueError("matrix not positive definite")
                L[i][j] = math.sqrt(s)
            else:
                L[i][j] = s / L[j][j]
    return L


def _percentile(sorted_vals: List[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = q * (len(sorted_vals) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


# ---------------------------------------------------------------------
# last-layer Laplace
# ---------------------------------------------------------------------

def last_hidden(net, x: Sequence[float]) -> List[float]:
    """Last hidden-layer activations of the MLP for one input."""
    acts, _ = net._forward(x)
    # acts[-1] is the sigmoid output; acts[-2] is the last hidden layer.
    if len(acts) < 3:
        raise ValueError("network needs at least one hidden layer")
    return list(acts[-2])


class LastLayerLaplace:
    """Gaussian posterior over the last-layer weights of a trained MLP.

    z = [last_hidden(x), 1]; logit = w . z; y ~ Bernoulli(sigmoid).
    Prior w ~ N(0, prior_precision^-1 I). Posterior N(w_map, cov)
    by Laplace at the Newton MAP. cov may be multiplied by
    variance_scale (fitted on train for interval calibration).
    """

    def __init__(self, prior_precision: float = 1.0) -> None:
        self.prior_precision = float(prior_precision)
        self.w_map: List[float] = []
        self.cov: List[List[float]] = []
        self.chol: List[List[float]] = []
        self.variance_scale: float = 1.0
        self.dim: int = 0

    @property
    def n_params(self) -> int:
        return self.dim

    def fit(self, net, X: Sequence[Sequence[float]],
            y: Sequence[int], n_newton: int = 25) -> "LastLayerLaplace":
        """Fit the posterior. net is the trained MAP MLP (frozen)."""
        Z = [[*last_hidden(net, x), 1.0] for x in X]
        y = [float(v) for v in y]
        d = len(Z[0])
        self.dim = d
        # Start from the MLP's own trained last-layer weights.
        w = [float(v) for v in net.weights[-1][0]] + \
            [float(net.biases[-1][0])]
        if len(w) != d:
            w = [0.0] * d
        a = self.prior_precision
        for _ in range(int(n_newton)):
            # Gradient g = Z^T (p - y) + a w ; Hessian H = Z^T L Z + a I
            g = [0.0] * d
            H = [[0.0] * d for _ in range(d)]
            max_step = 0.0
            for z, yi in zip(Z, y):
                p = _sigmoid(sum(wi * zi for wi, zi in zip(w, z)))
                r = p - yi
                lam = max(p * (1.0 - p), 1e-9)
                for i in range(d):
                    g[i] += r * z[i]
                    zi_lam = lam * z[i]
                    for j in range(d):
                        H[i][j] += zi_lam * z[j]
            for i in range(d):
                g[i] += a * w[i]
                H[i][i] += a
            step = _mat_vec_mul(_mat_inverse(H), g)
            w = [wi - si for wi, si in zip(w, step)]
            max_step = max(abs(s) for s in step)
            if max_step < 1e-8:
                break
        # Hessian at the mode -> posterior covariance.
        H = [[0.0] * d for _ in range(d)]
        for z, yi in zip(Z, y):
            p = _sigmoid(sum(wi * zi for wi, zi in zip(w, z)))
            lam = max(p * (1.0 - p), 1e-9)
            for i in range(d):
                zi_lam = lam * z[i]
                for j in range(d):
                    H[i][j] += zi_lam * z[j]
        for i in range(d):
            H[i][i] += a
        self.w_map = list(w)
        self.cov = _mat_inverse(H)
        self._refresh_chol()
        return self

    def _refresh_chol(self) -> None:
        scaled = [[v * self.variance_scale for v in row]
                  for row in self.cov]
        # Jitter for numerical safety; 1e-9 relative to the diagonal.
        for i in range(len(scaled)):
            scaled[i][i] += 1e-9
        self.chol = _cholesky(scaled)
        self._scaled_cov = scaled

    def set_variance_scale(self, c: float) -> None:
        self.variance_scale = float(c)
        if self.cov:
            self._refresh_chol()

    def sample_weights(self, rng: random.Random) -> List[float]:
        z = [rng.gauss(0.0, 1.0) for _ in range(self.dim)]
        Lz = _mat_vec_mul(self.chol, z)
        return [wi + li for wi, li in zip(self.w_map, Lz)]

    def predictive(self, net, x: Sequence[float],
                   n_samples: int = 256,
                   seed: int = 1234) -> Dict[str, float]:
        """Posterior predictive for one input: mean + 90% interval.

        Exact Gaussian trick: the logit w.z is a linear map of the
        Gaussian posterior, so logit ~ N(mu, var) with
        mu = w_map.z and var = z^T Sigma z. Sampling 1-D logits from
        that Gaussian and pushing them through the sigmoid gives the
        same predictive distribution as sampling weight vectors, but
        costs O(dim^2) once per input instead of O(dim^2) per sample.
        """
        z = [*last_hidden(net, x), 1.0]
        mu = sum(wi * zi for wi, zi in zip(self.w_map, z))
        Sz = _mat_vec_mul(self._scaled_cov, z)
        var = max(sum(zi * szi for zi, szi in zip(z, Sz)), 0.0)
        sd = math.sqrt(var)
        rng = random.Random(seed)
        ps = sorted(_sigmoid(rng.gauss(mu, sd))
                    for _ in range(int(n_samples)))
        mean = sum(ps) / len(ps)
        lo = _percentile(ps, _LO_Q)
        hi = _percentile(ps, _HI_Q)
        var_p = sum((p - mean) ** 2 for p in ps) / len(ps)
        return {
            "mean": mean,
            "lo": lo,
            "hi": hi,
            "std": math.sqrt(var_p),
            "width": hi - lo,
            "unsure": bool(lo < 0.5 < hi),
            "n_samples": len(ps),
        }

    def predictive_mean(self, net, x: Sequence[float],
                        n_samples: int = 256, seed: int = 1234) -> float:
        return self.predictive(net, x, n_samples, seed)["mean"]

    # -- persistence ---------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "format": "recon-nn-laplace/1",
            "prior_precision": self.prior_precision,
            "variance_scale": self.variance_scale,
            "w_map": self.w_map,
            "cov": self.cov,
            "dim": self.dim,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "LastLayerLaplace":
        if data.get("format") != "recon-nn-laplace/1":
            raise ValueError("not a recon-nn-laplace/1 record")
        obj = cls(float(data.get("prior_precision", 1.0)))
        obj.w_map = [float(v) for v in data["w_map"]]
        obj.cov = [[float(v) for v in row] for row in data["cov"]]
        obj.dim = int(data["dim"])
        obj.variance_scale = float(data.get("variance_scale", 1.0))
        obj._refresh_chol()
        return obj


# ---------------------------------------------------------------------
# calibration: measured on real labels, never assumed
# ---------------------------------------------------------------------

def expected_calibration_error(means: Sequence[float],
                               labels: Sequence[int],
                               n_bins: int = 10) -> float:
    """ECE: bin by predicted mean, |mean pred - observed freq|."""
    if not means:
        return 0.0
    bins: Dict[int, List[Tuple[float, int]]] = {}
    for p, t in zip(means, labels):
        b = min(int(p * n_bins), n_bins - 1)
        bins.setdefault(b, []).append((p, t))
    ece = 0.0
    for items in bins.values():
        mp = sum(p for p, _ in items) / len(items)
        freq = sum(t for _, t in items) / len(items)
        ece += abs(mp - freq) * len(items) / len(means)
    return ece


def brier_score(means: Sequence[float], labels: Sequence[int]) -> float:
    if not means:
        return 0.0
    return sum((p - t) ** 2 for p, t in zip(means, labels)) / len(means)


def binned_interval_coverage(preds: Sequence[Dict[str, float]],
                             labels: Sequence[int],
                             n_bins: int = 10) -> Dict:
    """Interval coverage, binned by posterior mean (equal-count bins).

    Rows are sorted by posterior mean and split into equal-count bins
    (~n/10 rows each), so every bin has enough rows for its observed
    rate to mean something. (Equal-width bins leave most bins with
    1-3 rows on a 145-row holdout, where the observed rate is 0 or 1
    by chance and the check measures noise, not calibration.)
    For each bin, the observed positive rate is compared with the
    bin's mean 90% interval [mean lo, mean hi]. A bin is covered when
    the observed rate falls inside that interval. Coverage is the
    fraction of covered bins. The table also shows the Wilson 95%
    interval for each bin's observed rate, so a reader can see when
    a miss is within binomial noise (e.g. a bin with 15/15 positives
    has observed rate 1.0, which no interval below 1.0 can contain,
    yet is fully consistent with a true rate of 0.99).
    """
    order = sorted(range(len(preds)), key=lambda i: preds[i]["mean"])
    bins: List[List[Tuple[Dict, int]]] = []
    per = max(1, len(order) // n_bins)
    for start in range(0, len(order), per):
        bins.append([(preds[i], labels[i]) for i in order[start:start + per]])
    table = []
    covered = 0
    wilson_covered = 0
    for bi, items in enumerate(bins):
        mean_lo = sum(p["lo"] for p, _ in items) / len(items)
        mean_hi = sum(p["hi"] for p, _ in items) / len(items)
        freq = sum(t for _, t in items) / len(items)
        ok = bool(mean_lo <= freq <= mean_hi)
        covered += 1 if ok else 0
        w_lo, w_hi = _wilson_interval(sum(t for _, t in items), len(items))
        # Wilson overlap: the interval is consistent with the data
        # when it overlaps the 95% Wilson interval for the observed
        # rate. This matters at the boundary: a bin with 15/15
        # positives has observed rate exactly 1.0, which no interval
        # below 1.0 can contain, yet is fully consistent with a true
        # rate of 0.99 (Wilson [0.79, 1.0] overlaps [0.99, 1.0]).
        # The strict count is the headline; Wilson is the context.
        if mean_lo <= w_hi and w_lo <= mean_hi:
            wilson_covered += 1
        table.append({"bin": bi, "n": len(items),
                      "mean_lo": round(mean_lo, 3),
                      "mean_hi": round(mean_hi, 3),
                      "observed_rate": round(freq, 3),
                      "wilson_lo": round(w_lo, 3),
                      "wilson_hi": round(w_hi, 3),
                      "covered": ok})
    return {"n_bins_nonempty": len(table),
            "bins_covered": covered,
            "coverage": (covered / len(table)) if table else 0.0,
            "wilson_coverage":
                (wilson_covered / len(table)) if table else 0.0,
            "wilson_bins_covered": wilson_covered,
            "table": table}


def _wilson_interval(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson 95% score interval for a binomial proportion."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / n + z * z / (4 * n * n))) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def fit_variance_scale(laplace: LastLayerLaplace, net,
                       X: Sequence[Sequence[float]],
                       y: Sequence[int],
                       grid: Sequence[float] = (0.25, 0.5, 0.75, 1.0,
                                                1.5, 2.0, 3.0, 5.0),
                       n_samples: int = 256,
                       seed: int = 1234) -> Dict:
    """Pick the covariance scale whose TRAIN binned 90% coverage is
    closest to 0.90 (ties broken by lower ECE). The scale is a single
    calibration knob fitted on train only; the test set never sees it.
    """
    base = laplace.variance_scale
    best = None
    results = []
    for c in grid:
        laplace.set_variance_scale(float(c))
        preds = [laplace.predictive(net, x, n_samples, seed) for x in X]
        means = [p["mean"] for p in preds]
        cov = binned_interval_coverage(preds, y)
        ece = expected_calibration_error(means, y)
        err = abs(cov["coverage"] - CREDIBLE_LEVEL)
        results.append({"scale": float(c), "coverage": cov["coverage"],
                        "ece": round(ece, 4)})
        key = (err, ece)
        if best is None or key < best[0]:
            best = (key, float(c), cov["coverage"], ece)
    laplace.set_variance_scale(best[1])
    return {"chosen_scale": best[1], "train_coverage": best[2],
            "train_ece": round(best[3], 4), "grid": results,
            "note": ("scale fitted on TRAIN only; test coverage is "
                     "reported separately and will differ")}


def evaluate_holdout(laplace: LastLayerLaplace, net,
                     X: Sequence[Sequence[float]], y: Sequence[int],
                     n_samples: int = 256, seed: int = 1234) -> Dict:
    """Full honest metric set for one scored set (test holdout)."""
    from .mlp import metrics_for  # local import: avoids cycles
    preds = [laplace.predictive(net, x, n_samples, seed) for x in X]
    means = [p["mean"] for p in preds]
    m = metrics_for(list(y), means)
    cov = binned_interval_coverage(preds, y)
    unsure = [i for i, p in enumerate(preds) if p["unsure"]]
    conf_idx = [i for i, p in enumerate(preds) if not p["unsure"]]
    conf_acc = (sum(1 for i in conf_idx
                    if (means[i] >= 0.5) == bool(y[i])) / len(conf_idx)
                if conf_idx else 0.0)
    uns_acc = (sum(1 for i in unsure
                   if (means[i] >= 0.5) == bool(y[i])) / len(unsure)
               if unsure else 0.0)
    m["bayesian"] = {
        "posterior_mean_threshold": 0.5,
        "ece": round(expected_calibration_error(means, y), 4),
        "brier": round(brier_score(means, y), 4),
        "interval_coverage_bins": cov,
        "n_unsure": len(unsure),
        "unsure_rate": round(len(unsure) / max(1, len(y)), 4),
        "confident_n": len(conf_idx),
        "confident_accuracy": round(conf_acc, 4),
        "unsure_accuracy": round(uns_acc, 4),
        "mean_width": round(sum(p["width"] for p in preds) / len(preds), 4)
        if preds else 0.0,
    }
    return m


def score_finding(finding: Dict, net, spec, laplace: LastLayerLaplace,
                  threshold: float = 0.5, n_samples: int = 256,
                  seed: int = 1234) -> Dict:
    """One finding dict -> Bayesian triage record.

    nn_score is the posterior MEAN (drop-in for the point score).
    nn_score_lo / nn_score_hi bound the 90% credible interval.
    nn_unsure routes to human review; nn_label is
    "needs-human-review" when unsure, else the usual two labels.
    Never VERIFIED_REAL.
    """
    from .features import extract, top_features
    x = extract(finding, spec)
    pred = laplace.predictive(net, x, n_samples, seed)
    mean = pred["mean"]
    if pred["unsure"]:
        label = "needs-human-review"
    else:
        label = ("worth-validating" if mean >= threshold
                 else "likely-false-positive")
    return {
        "nn_score": round(mean, 4),
        "nn_score_lo": round(pred["lo"], 4),
        "nn_score_hi": round(pred["hi"], 4),
        "nn_score_std": round(pred["std"], 4),
        "nn_score_width": round(pred["width"], 4),
        "nn_unsure": pred["unsure"],
        "nn_label": label,
        "nn_top_features": top_features(finding, spec, net, k=3),
    }
