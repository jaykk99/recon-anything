"""Likelihood Engine: score a program against real observed events.

For each consecutive pair of events, the program assigns a probability to
what actually happened next:
  - inter-arrival time dt: lognormal(mu, sigma) mixture with the burst
    component (burst_p mass on a short lognormal around burst_hours);
  - next group: program's categorical (with stickiness), epsilon-smoothed
    against uniform so an unseen group is unlikely, never impossible;
  - next kind: same treatment.

log_likelihood = sum of log probabilities over the pairs.
posterior      = log_likelihood + log_prior (Solomonoff: -bits * ln 2).

Scoring is always on events the program was NOT fitted to when we report
holdout numbers; the search itself maximises the posterior on training
events only.
"""

from __future__ import annotations

import math

from .program import LN2

_EPS = 1e-6
_SQRT_2PI = math.sqrt(2.0 * math.pi)


def _lognorm_logpdf(dt_hours, mu, sigma):
    dt = max(dt_hours, 1e-3)
    x = math.log(dt)
    return (
        -math.log(dt * sigma * _SQRT_2PI)
        - ((x - mu) ** 2) / (2.0 * sigma * sigma)
    )


def _interval_logprob(program, dt_hours):
    main = _lognorm_logpdf(dt_hours, program.interval_mu, program.interval_sigma)
    if program.burst_p <= 0.0:
        return main
    burst = _lognorm_logpdf(dt_hours, math.log(max(program.burst_hours, 1e-3)), 0.5)
    a = math.log1p(-program.burst_p) + main
    b = math.log(program.burst_p) + burst
    m = max(a, b)
    return m + math.log(math.exp(a - m) + math.exp(b - m))


def _cat_logprob(p, n_outcomes):
    p = (1.0 - _EPS) * max(p, 0.0) + _EPS / max(n_outcomes, 1)
    return math.log(max(p, 1e-12))


def log_likelihood(program, events):
    """Log probability of the event stream under the program, summed over
    consecutive pairs. The first event has no predecessor and contributes 0.
    Returns -inf when the stream is too short to score."""
    if len(events) < 2:
        return float("-inf")
    n_groups = max(1, len(program.group_probs))
    n_kinds = max(1, len(program.kind_probs))
    total = 0.0
    for prev, cur in zip(events, events[1:]):
        dt_h = (cur.t - prev.t) / 3600.0
        total += _interval_logprob(program, dt_h)
        total += _cat_logprob(program.group_prob(cur.group, prev.group), n_groups)
        total += _cat_logprob(program.kind_prob(cur.kind, prev.kind), n_kinds)
    return total


def description_length_bits(program):
    return program.description_length_bits()


def posterior(program, events):
    """log P(program | events) up to a constant: log-likelihood + log-prior."""
    ll = log_likelihood(program, events)
    if ll == float("-inf"):
        return float("-inf")
    return ll + program.log_prior()


def per_event_ll(program, events):
    """Mean log-likelihood per scored pair; comparable across timelines."""
    if len(events) < 2:
        return float("-inf")
    return log_likelihood(program, events) / (len(events) - 1)
