"""Synthetic program / trace generation for BPL tests and benchmarks.

SYNTHETIC ONLY. Nothing here touches a live chain or real data, and
nothing generated here is ever presented as a real finding. Its job is
to give the inference engine ground truth it can be checked against:
sample a program from the DSL, unroll it to a trace, optionally corrupt
a few events with channel noise, and ask the engine to recover the
program and predict held-out events.

The generator deliberately includes *phase-ambiguous* cycles such as
``[A, B, A, C]``: after an ``A`` the next event is ``B`` or ``C``
depending on where you are in the cycle, which an order-1 Markov
baseline provably cannot resolve from the previous event alone, while
a program that knows the cycle can. That is the structural advantage
BPL is supposed to have, and the benchmark measures whether it
actually shows up -- it is not assumed.
"""

from __future__ import annotations

import random
from typing import List, Sequence, Tuple

from .bpl import ALPHABET, Emit, Program, Repeat

# A small working alphabet for synthetic traces: a few deploy shapes,
# owner events, an upgrade, fund moves. Distinct enough to read, small
# enough that a frequency baseline is not hopeless.
SYNTH_EVENTS = (
    "DEPLOY:proxy:scroll",
    "DEPLOY:proxy:scroll:fresh",
    "DEPLOY:nft:scroll",
    "DEPLOY:token:optimism",
    "DEPLOY:other:scroll",
    "OWNER_SET",
    "OWNER_CLEAR",
    "UPGRADE",
    "FUND_IN:large",
    "FUND_OUT:med",
)

# Phase-ambiguous cycles: the same event has different successors
# depending on the position in the cycle.
PHASE_CYCLES: Tuple[Tuple[str, ...], ...] = (
    ("DEPLOY:proxy:scroll", "OWNER_SET",
     "DEPLOY:proxy:scroll", "UPGRADE"),
    ("DEPLOY:nft:scroll", "DEPLOY:nft:scroll", "OWNER_SET"),
    ("DEPLOY:proxy:scroll:fresh", "FUND_IN:large",
     "DEPLOY:proxy:scroll:fresh", "OWNER_CLEAR"),
    ("OWNER_SET", "UPGRADE", "OWNER_SET", "FUND_OUT:med"),
)


def sample_program(rng: random.Random) -> Program:
    """Sample a random DSL program: 1-3 phrases, each a cycle, a run
    of one event, or a flat run of distinct events."""
    ops: List[object] = []
    n_phrases = rng.choice([1, 1, 2, 2, 3])
    for _ in range(n_phrases):
        style = rng.random()
        if style < 0.45:
            # A repeated cycle (often phase-ambiguous).
            cycle = list(rng.choice(PHASE_CYCLES))
            count = rng.randint(2, 4)
            ops.append(Repeat(count, tuple(Emit(e) for e in cycle)))
        elif style < 0.7:
            # A repeated single event.
            event = rng.choice(SYNTH_EVENTS)
            count = rng.randint(2, 5)
            ops.append(Repeat(count, (Emit(event),)))
        else:
            # Flat run of 1-3 distinct events.
            for event in rng.sample(SYNTH_EVENTS, rng.randint(1, 3)):
                ops.append(Emit(event))
    return Program(tuple(ops))


def sample_trace(rng: random.Random, noise: float = 0.0,
                 program: Program | None = None
                 ) -> Tuple[Program, List[str]]:
    """Sample a program and its trace, optionally corrupting events.

    Noise replaces each event with a uniform random alphabet event
    with probability ``noise`` (never with itself). Returns
    ``(program, trace)``; the program is the ground truth.
    """
    prog = program if program is not None else sample_program(rng)
    trace = prog.expand()
    if noise > 0.0:
        trace = [e if rng.random() >= noise else _other_event(rng, e)
                 for e in trace]
    return prog, trace


def _other_event(rng: random.Random, event: str) -> str:
    choices = [e for e in ALPHABET if e != event]
    return rng.choice(choices)


def make_benchmark(n_traces: int = 200, seed: int = 42,
                   noise: float = 0.0) -> List[List[str]]:
    """A fixed synthetic benchmark set: traces with known ground truth
    programs (the programs themselves are not returned -- the caller
    that needs them should use :func:`sample_trace` directly)."""
    rng = random.Random(seed)
    return [sample_trace(rng, noise=noise)[1] for _ in range(n_traces)]


def split_benchmark(traces: Sequence[List[str]], seed: int = 42,
                    train_frac: float = 0.7
                    ) -> Tuple[List[List[str]], List[List[str]]]:
    """Deterministic train / held-out split of a trace list."""
    rng = random.Random(seed)
    idx = list(range(len(traces)))
    rng.shuffle(idx)
    cut = int(len(idx) * train_frac)
    train = [traces[i] for i in idx[:cut]]
    held = [traces[i] for i in idx[cut:]]
    return train, held
