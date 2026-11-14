"""Bayesian Program Learning (BPL) engine for ReconAnything.

A Universal Inference Engine that reverse-engineers the hidden generative
program behind a target's observed behaviour. Pure Python stdlib.

Three components:
  1. Hypothesis Synthesizer (synthesizer.py): generates probabilistic state
     machines as executable, AST-verified Python code.
  2. Likelihood Engine (likelihood.py): scores each program against real
     observed event streams (held-out events, never the training ones).
  3. Evolutionary Program Search (search.py): MCMC + genetic refinement.
     Programs that fail to predict new events are mutated; programs that
     predict accurately survive. A Kolmogorov-complexity prior (description
     length) gives shorter programs higher prior probability (Solomonoff
     induction / Occam as math).

A fitted program is a runnable digital twin (twin.py) for counterfactual
simulation. Twin outputs are labelled hypothetical counterfactuals. They
are NEVER findings, NEVER candidates, NEVER evidence about a live target.

Rules: detection only. Read-only data. No transactions, no drains, no
exploit execution, no auth bypass, no private-data access. crypto.com is
never a target. Never predicts VERIFIED_REAL.
"""

from .program import Program, verify_source, execute_program
from .synthesizer import random_program, mutate_program
from .likelihood import log_likelihood, description_length_bits, posterior
from .search import mcmc_search, genetic_refine
from .twin import DigitalTwin

__all__ = [
    "Program",
    "verify_source",
    "execute_program",
    "random_program",
    "mutate_program",
    "log_likelihood",
    "description_length_bits",
    "posterior",
    "mcmc_search",
    "genetic_refine",
    "DigitalTwin",
]
