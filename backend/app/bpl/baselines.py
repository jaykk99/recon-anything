"""Baselines for honest comparison. Same scoring interface as the BPL
programs (log-likelihood on held-out pairs), so the numbers are directly
comparable.

  - periodic: fixed median interval, most-common group/kind. No learning
    beyond three medians/modes.
  - markov: empirical first-order transitions for group and kind, plus the
    empirical interval distribution (binned log-hours). This is the
    strongest simple baseline: it memorises the training transitions.

The v1/v2 NN scorer is NOT a baseline here: it is a finding-triage
classifier (score a plugin finding), a different task from predicting the
next event in a timeline. Comparing its accuracy to event log-likelihood
would be dishonest, so it is excluded and the reason is stated here.
"""

from __future__ import annotations

import math
from collections import Counter

from .program import Program


def _median(values):
    s = sorted(values)
    if not s:
        return 0.0
    return s[len(s) // 2]


def fit_periodic(train_events):
    gaps = [(c.t - p.t) / 3600.0 for p, c in zip(train_events, train_events[1:])]
    gaps = [g for g in gaps if g > 0]
    mu = math.log(max(_median(gaps) if gaps else 24.0, 1e-3))
    groups = Counter(e.group for e in train_events)
    kinds = Counter(e.kind for e in train_events)
    top_group = groups.most_common(1)[0][0] if groups else None
    top_kind = kinds.most_common(1)[0][0] if kinds else None
    return Program(
        interval_mu=mu,
        interval_sigma=0.5,
        burst_p=0.0,
        group_probs={top_group: 1.0} if top_group else {},
        kind_probs={top_kind: 1.0} if top_kind else {},
    )


def fit_markov(train_events):
    """Empirical transitions as a Program: interval sigma widened to cover
    the observed gap spread, categoricals = observed transition counts
    (with the program's own smoothing at scoring time)."""
    gaps = [(c.t - p.t) / 3600.0 for p, c in zip(train_events, train_events[1:])]
    gaps = [g for g in gaps if g > 0]
    log_gaps = [math.log(g) for g in gaps]
    mu = sum(log_gaps) / len(log_gaps) if log_gaps else 5.0
    var = sum((x - mu) ** 2 for x in log_gaps) / len(log_gaps) if log_gaps else 1.0
    sigma = max(0.3, min(3.0, math.sqrt(var) if var > 0 else 1.0))
    groups = Counter(e.group for e in train_events)
    kinds = Counter(e.kind for e in train_events)
    n_g = sum(groups.values()) or 1
    n_k = sum(kinds.values()) or 1
    return Program(
        interval_mu=mu,
        interval_sigma=sigma,
        burst_p=0.0,
        group_probs={k: v / n_g for k, v in groups.items()},
        kind_probs={k: v / n_k for k, v in kinds.items()},
    )
