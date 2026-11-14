"""Evolutionary Program Search: MCMC + genetic refinement.

MCMC (Metropolis-Hastings): propose a mutated program, accept it with
probability min(1, exp(posterior_new - posterior_old)). The chain wanders
the program space towards high-posterior programs; the best program seen
is kept. Deterministic given the seed.

Genetic refinement: a small population, tournament selection, crossover of
parameter blocks, mutation, elitism. Runs after (or instead of) MCMC on
the same posterior. Programs that fail to predict new events die; programs
that predict accurately survive and compound.
"""

from __future__ import annotations

import math
import random

from .likelihood import posterior
from .synthesizer import crossover_program, mutate_program, random_program


def mcmc_search(train_events, groups, kinds, seed=42, iters=3000):
    """Return (best_program, trace) where trace is a list of
    (iteration, best_posterior_so_far)."""
    rng = random.Random(seed)
    current = random_program(rng, groups, kinds, train_events)
    current_post = posterior(current, train_events)
    best = current
    best_post = current_post
    trace = [(0, best_post)]
    for i in range(1, iters + 1):
        proposal = mutate_program(current, rng, groups, kinds)
        prop_post = posterior(proposal, train_events)
        if prop_post >= current_post or rng.random() < math.exp(prop_post - current_post):
            current, current_post = proposal, prop_post
            if prop_post > best_post:
                best, best_post = proposal, prop_post
        if i % 250 == 0:
            trace.append((i, best_post))
    return best, trace


def genetic_refine(train_events, groups, kinds, seed=42, pop_size=24,
                   generations=40, start=None):
    """Return (best_program, trace). Population seeded with `start` plus
    random programs; elitism keeps the best 2 each generation."""
    rng = random.Random(seed)
    population = []
    if start is not None:
        population.append(start)
    while len(population) < pop_size:
        population.append(random_program(rng, groups, kinds, train_events))

    def score(prog):
        return posterior(prog, train_events)

    scored = sorted(((score(p), p) for p in population), key=lambda sp: -sp[0])
    best, best_post = scored[0][1], scored[0][0]
    trace = [(0, best_post)]
    for gen in range(1, generations + 1):
        children = [scored[0][1], scored[1][1]]  # elites survive
        while len(children) < pop_size:
            def tourney():
                cands = rng.sample(scored, 3)
                return max(cands, key=lambda sp: sp[0])[1]

            a, b = tourney(), tourney()
            child = crossover_program(a, b, rng)
            if rng.random() < 0.8:
                child = mutate_program(child, rng, groups, kinds)
            children.append(child)
        scored = sorted(((score(p), p) for p in children), key=lambda sp: -sp[0])
        if scored[0][0] > best_post:
            best, best_post = scored[0][1], scored[0][0]
        if gen % 5 == 0:
            trace.append((gen, best_post))
    return best, trace


def fit_program(train_events, groups, kinds, seed=42, mcmc_iters=3000,
                generations=40):
    """MCMC then genetic refinement. Returns (best, mcmc_trace, ga_trace)."""
    best, mcmc_trace = mcmc_search(train_events, groups, kinds, seed=seed,
                                   iters=mcmc_iters)
    best, ga_trace = genetic_refine(train_events, groups, kinds, seed=seed + 1,
                                    generations=generations, start=best)
    return best, mcmc_trace, ga_trace
