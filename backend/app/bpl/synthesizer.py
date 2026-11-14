"""Hypothesis Synthesizer: generate and mutate probabilistic programs.

Prior over programs (what a "plausible deployer" looks like before data):
  - interval_mu: centred on the empirical log-median gap of the training
    events, wide spread (lognormal prior, sigma 1.5 in log-hours);
  - interval_sigma: uniform-ish over [0.3, 2.0];
  - burst_p: usually 0, sometimes up to 0.5;
  - group/kind categoricals: symmetric Dirichlet-ish (exponential draws),
    so any distribution is reachable but flat ones are more likely;
  - stickiness: usually 0, sometimes up to 0.8.

Mutation (the MCMC proposal): pick one component at random and perturb it
a little, or resample one categorical, or flip one structural flag.
"""

from __future__ import annotations

import copy
import math
import random

from .program import Program


def _empirical_interval_stats(events):
    gaps = []
    for prev, cur in zip(events, events[1:]):
        dt_h = (cur.t - prev.t) / 3600.0
        if dt_h > 0:
            gaps.append(math.log(max(dt_h, 1e-3)))
    if not gaps:
        return 5.0, 1.0
    gaps.sort()
    med = gaps[len(gaps) // 2]
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return med, max(0.3, min(2.0, math.sqrt(var) if var > 0 else 1.0))


def _dirichlet_like(rng, keys):
    if not keys:
        return {}
    weights = [rng.expovariate(1.0) for _ in keys]
    total = sum(weights)
    return {k: w / total for k, w in zip(keys, weights)}


def random_program(rng, groups, kinds, events=None):
    """Draw a program from the prior. `events` (optional training events)
    only centres the interval prior; it does not fit the program."""
    if events:
        mu0, sig0 = _empirical_interval_stats(events)
    else:
        mu0, sig0 = 5.0, 1.0
    mu = rng.gauss(mu0, 1.5)
    mu = max(-2.0, min(8.0, mu))
    sigma = rng.uniform(0.3, 2.0)
    burst_p = rng.choice([0.0, 0.0, 0.0, rng.uniform(0.05, 0.5)])
    burst_hours = math.exp(rng.gauss(math.log(1.0), 1.0))
    burst_hours = max(0.05, min(24.0, burst_hours))
    group_sticky = rng.choice([0.0, 0.0, rng.uniform(0.1, 0.8)])
    kind_sticky = rng.choice([0.0, 0.0, rng.uniform(0.1, 0.8)])
    return Program(
        interval_mu=mu,
        interval_sigma=sigma,
        burst_p=burst_p,
        burst_hours=burst_hours,
        group_probs=_dirichlet_like(rng, groups),
        kind_probs=_dirichlet_like(rng, kinds),
        group_sticky=group_sticky,
        kind_sticky=kind_sticky,
    )


def mutate_program(program, rng, groups, kinds):
    """One small random change. Returns a NEW program (input untouched)."""
    nxt = copy.deepcopy(program)
    choice = rng.random()
    if choice < 0.18:
        nxt.interval_mu = max(-2.0, min(8.0, nxt.interval_mu + rng.gauss(0, 0.5)))
    elif choice < 0.30:
        nxt.interval_sigma = max(0.05, min(3.0, nxt.interval_sigma + rng.gauss(0, 0.25)))
    elif choice < 0.40:
        nxt.burst_p = max(0.0, min(0.9, nxt.burst_p + rng.gauss(0, 0.1)))
    elif choice < 0.48:
        nxt.burst_hours = max(0.05, min(24.0, nxt.burst_hours * math.exp(rng.gauss(0, 0.4))))
    elif choice < 0.58:
        nxt.group_sticky = max(0.0, min(0.9, nxt.group_sticky + rng.gauss(0, 0.15)))
    elif choice < 0.68:
        nxt.kind_sticky = max(0.0, min(0.9, nxt.kind_sticky + rng.gauss(0, 0.15)))
    elif choice < 0.84:
        # resample one categorical weight
        target = rng.choice(["group", "kind"])
        probs = nxt.group_probs if target == "group" else nxt.kind_probs
        keys = groups if target == "group" else kinds
        if keys:
            key = rng.choice(keys)
            probs[key] = max(0.01, probs.get(key, 0.1) * math.exp(rng.gauss(0, 0.5)))
            total = sum(probs.values())
            for k in probs:
                probs[k] /= total
    else:
        # flip one structural flag on/off
        flag = rng.choice(["burst", "group_sticky", "kind_sticky"])
        if flag == "burst":
            nxt.burst_p = 0.0 if nxt.burst_p > 0.01 else rng.uniform(0.05, 0.4)
        elif flag == "group_sticky":
            nxt.group_sticky = 0.0 if nxt.group_sticky > 0.01 else rng.uniform(0.1, 0.7)
        else:
            nxt.kind_sticky = 0.0 if nxt.kind_sticky > 0.01 else rng.uniform(0.1, 0.7)
    return nxt


def crossover_program(a, b, rng):
    """Genetic crossover: take the interval block from one parent and the
    categorical blocks from the other, at random."""
    child = copy.deepcopy(a if rng.random() < 0.5 else b)
    if rng.random() < 0.5:
        child.interval_mu = b.interval_mu
        child.interval_sigma = b.interval_sigma
        child.burst_p = b.burst_p
        child.burst_hours = b.burst_hours
    if rng.random() < 0.5:
        child.group_probs = dict(b.group_probs)
        child.group_sticky = b.group_sticky
    if rng.random() < 0.5:
        child.kind_probs = dict(b.kind_probs)
        child.kind_sticky = b.kind_sticky
    return child
