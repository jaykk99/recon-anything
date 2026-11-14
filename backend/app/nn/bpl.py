"""Bayesian Program Learning (BPL) + Solomonoff induction for ReconAnything.

Universal inference over deployer / wallet behaviour: learn the minimal
generative program that explains an observed behaviour trace, then use the
posterior over programs to predict what happens next.

This is NOT the neighbouring work:
- ``feat/nn-bayesian`` puts uncertainty over NN *scores* (weights /
  calibration of the scorer). BPL puts a posterior over *programs* that
  generate behaviour traces. Different object, different inference.
- ``feat/nn-synthesis`` synthesises *tools* (sandboxed code generation).
  BPL learns *generative programs of behaviour* (what a deployer does
  next). A BPL-discovered program could one day seed a synthesis
  template, but the two do not overlap: synthesis writes code, BPL
  explains traces.

Model
-----
Trace: a list of event strings, e.g. ``"DEPLOY:proxy:scroll"``,
``"OWNER_SET"``, ``"UPGRADE"``, ``"FUND_IN:large"``. The alphabet is
finite and explicit (see :data:`ALPHABET`).

Program (DSL): a list of ops.
- ``Emit(event)`` -- emit one fixed event.
- ``Repeat(count, body)`` -- unroll ``body`` (a list of ops) ``count``
  times. ``count`` in 2..6, body length 1..3, nesting depth at most 1
  (a Repeat body holds only Emits). This keeps the search tractable
  on a CPU box; see ``docs/nn-bpl.md`` for the limits this imposes.

A program deterministically expands to exactly one trace (its unrolling).

Prior (Solomonoff approximation)
--------------------------------
True Solomonoff is uncomputable (prior over all Turing machines). We
approximate it over this DSL with a prefix code: the prior of a program
is ``2 ** -L(program)`` where ``L`` is its description length in bits
under a fixed code:

- 1 bit per op to say which kind it is (Emit vs Repeat),
- Emit: ``log2(|alphabet|)`` bits to name the event,
- Repeat: ``log2(5)`` bits for the count (2..6) plus the body's cost,
- 1 bit to terminate the program.

Shorter programs are exponentially preferred, exactly the Solomonoff
intuition, restricted to programs expressible in this DSL. This is an
MDL / MML prior, not a universal prior over all computable hypotheses;
the doc states that plainly.

Likelihood
----------
A noisy channel between the program's expansion ``g`` and the observed
trace ``t``: per aligned position a match has probability ``1 - eps``
and a mismatch ``eps / (A - 1)`` (``A`` = alphabet size); each extra or
missing event costs a factor ``gap`` (default 0.1). So

    log P(t | program) = matches * log(1-eps)
                         + mismatches * log(eps / (A-1))
                         + |len(g) - len(t)| * log(gap)

Posterior: ``log P(program | t) = log P(t | program) - L(program)*ln 2``
(up to a constant). Programs are ranked by this log-posterior.

Search
------
Beam search over program prefixes. A partial program is scored by its
prior cost so far; it may only be extended by ops whose expansion
matches the next observed events exactly, so every complete program
found expands to exactly the observed trace and programs are ranked
purely by description length (shortest wins -- MDL). The flat all-Emit
program is always in the beam, so search never comes up empty.
Multi-trace learning scores one candidate program against a whole set
of traces (one prior cost, likelihood summed over traces): a program
that explains many traces is rewarded for sharing its description
length across them. That is the universal-inference step.

Prediction
----------
Given a prefix trace, take the top programs by posterior on that
prefix. Each program whose expansion starts with the prefix predicts
its next event; near-miss programs still contribute, weighted by
``P(prefix | program)`` under the noise channel. Votes are aggregated
into a next-event distribution. Every prediction cites the programs
that produced it and their posterior weights.

Triage only. This never predicts VERIFIED_REAL, never touches a live
chain, never sends a transaction. Pure Python stdlib, CPU only.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Events / alphabet
# ---------------------------------------------------------------------------

DEPLOY = "DEPLOY"
OWNER_SET = "OWNER_SET"
OWNER_CLEAR = "OWNER_CLEAR"
UPGRADE = "UPGRADE"
FUND_IN = "FUND_IN"
FUND_OUT = "FUND_OUT"

EVENT_KINDS = (DEPLOY, OWNER_SET, OWNER_CLEAR, UPGRADE, FUND_IN, FUND_OUT)

# Deploy detail tokens: "<kind>:<chain>[:fresh]". Chains seen in the
# fresh-deploys data plus the chains the transition data uses.
DEPLOY_KINDS = ("proxy", "nft", "token", "other")
DEPLOY_CHAINS = ("scroll", "optimism", "linea", "avalanche",
                 "ethereum", "bsc", "base", "arbitrum", "polygon")
FUND_BUCKETS = ("small", "med", "large")


def build_alphabet() -> Tuple[str, ...]:
    """The finite event alphabet this DSL can emit."""
    events = []
    for kind in DEPLOY_KINDS:
        for chain in DEPLOY_CHAINS:
            events.append(f"{DEPLOY}:{kind}:{chain}")
            events.append(f"{DEPLOY}:{kind}:{chain}:fresh")
    events += [OWNER_SET, OWNER_CLEAR, UPGRADE]
    for bucket in FUND_BUCKETS:
        events.append(f"{FUND_IN}:{bucket}")
        events.append(f"{FUND_OUT}:{bucket}")
    return tuple(events)


ALPHABET: Tuple[str, ...] = build_alphabet()
ALPHABET_SET = frozenset(ALPHABET)

# Noise-channel parameters.
EPS = 0.05        # per-position substitution probability
GAP = 0.10        # cost factor per extra / missing event

# Search limits.
MAX_REPEAT_COUNT = 6
MIN_REPEAT_COUNT = 2
MAX_REPEAT_BODY = 4      # ops in a Repeat body (Emits only, depth <= 1)
MAX_EXPANSION = 64       # cap on unrolled trace length
DEFAULT_BEAM_WIDTH = 64
DEFAULT_MAX_PROGRAMS = 64


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Emit:
    event: str

    def __repr__(self) -> str:  # noqa: D105
        return f"Emit({self.event!r})"


@dataclass(frozen=True)
class Repeat:
    count: int
    body: Tuple["Op", ...]

    def __repr__(self) -> str:  # noqa: D105
        inner = ", ".join(repr(op) for op in self.body)
        return f"Repeat({self.count}, [{inner}])"


Op = object  # Emit | Repeat (kept loose; both are frozen dataclasses)


@dataclass(frozen=True)
class Program:
    ops: Tuple[Op, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:  # noqa: D105
        return "Program(" + "; ".join(repr(op) for op in self.ops) + ")"

    def expand(self, cap: int = MAX_EXPANSION) -> List[str]:
        """Unroll the program to the flat event trace it generates."""
        out: List[str] = []

        def _emit(op: Op) -> None:
            if isinstance(op, Emit):
                out.append(op.event)
            elif isinstance(op, Repeat):
                for _ in range(op.count):
                    for sub in op.body:
                        _emit(sub)
            if len(out) > cap:
                del out[cap:]

        for op in self.ops:
            _emit(op)
            if len(out) >= cap:
                break
        return out

    def description_length(self) -> float:
        """Description length in bits under the DSL prefix code."""
        bits = 1.0  # terminator bit
        for op in self.ops:
            bits += _op_bits(op)
        return bits

    def log_prior(self) -> float:
        """log P(program) under the Solomonoff approximation: -L * ln 2."""
        return -self.description_length() * math.log(2.0)


def _op_bits(op: Op) -> float:
    if isinstance(op, Emit):
        # 1 bit op-type + log2(|alphabet|) bits to name the event.
        return 1.0 + math.log2(len(ALPHABET))
    if isinstance(op, Repeat):
        # 1 bit op-type + log2(5) bits for count 2..6 + body cost.
        bits = 1.0 + math.log2(MAX_REPEAT_COUNT - MIN_REPEAT_COUNT + 1)
        for sub in op.body:
            bits += _op_bits(sub)
        return bits
    raise TypeError(f"unknown op: {op!r}")


def flat_program(trace: Sequence[str]) -> Program:
    """The trivial program: one Emit per observed event."""
    return Program(tuple(Emit(e) for e in trace))


# ---------------------------------------------------------------------------
# Likelihood / posterior
# ---------------------------------------------------------------------------

def log_likelihood(trace: Sequence[str], program: Program,
                   eps: float = EPS, gap: float = GAP) -> float:
    """log P(trace | program) under the noisy channel."""
    gen = program.expand()
    n = min(len(trace), len(gen))
    log_match = math.log(1.0 - eps)
    log_mismatch = math.log(eps / max(1, len(ALPHABET) - 1))
    total = 0.0
    for i in range(n):
        total += log_match if trace[i] == gen[i] else log_mismatch
    total += abs(len(trace) - len(gen)) * math.log(gap)
    return total


def log_posterior(trace: Sequence[str], program: Program,
                  eps: float = EPS, gap: float = GAP) -> float:
    """log P(program | trace) up to a constant: likelihood + prior."""
    return log_likelihood(trace, program, eps, gap) + program.log_prior()


def rank_programs(trace: Sequence[str], programs: Iterable[Program],
                  eps: float = EPS, gap: float = GAP
                  ) -> List[Tuple[Program, float]]:
    """Rank programs by log-posterior on one trace, best first."""
    ranked = [(p, log_posterior(trace, p, eps, gap)) for p in programs]
    ranked.sort(key=lambda item: item[1], reverse=True)
    return ranked


def rank_programs_on_traces(traces: Sequence[Sequence[str]],
                            programs: Iterable[Program],
                            eps: float = EPS, gap: float = GAP
                            ) -> List[Tuple[Program, float]]:
    """Rank programs by posterior on a SET of traces.

    One prior cost, likelihood summed over traces: a program that
    explains many traces earns its description length many times over.
    This is the shared-program / universal-inference step.
    """
    ranked = []
    for p in programs:
        total = p.log_prior()
        for t in traces:
            total += log_likelihood(t, p, eps, gap)
        ranked.append((p, total))
    ranked.sort(key=lambda item: item[1], reverse=True)
    return ranked


# ---------------------------------------------------------------------------
# Search: beam over program prefixes
# ---------------------------------------------------------------------------

def _repeat_candidates(trace: Sequence[str], pos: int
                       ) -> List[Tuple[Repeat, int]]:
    """Repeats whose unrolling matches trace[pos:] from `pos`.

    Returns (Repeat op, number of trace events it covers). Body length
    1..MAX_REPEAT_BODY, count 2..MAX_REPEAT_COUNT. A candidate matches
    when the first ``min(count * body_len, remaining)`` events of its
    unrolling equal the trace tail exactly. Candidates may *overshoot*
    the end of the trace by a partial repetition: that is what makes
    prediction possible -- a program inferred on a prefix whose
    unrolling runs one event past the prefix is predicting that event.
    Overshooting programs are complete (they consume the rest of the
    trace) and pay the gap penalty for the extra events in the
    posterior, so on a full trace they rank below exact programs.
    """
    out: List[Tuple[Repeat, int]] = []
    remaining = len(trace) - pos
    for body_len in range(1, MAX_REPEAT_BODY + 1):
        if body_len > remaining:
            break
        body_events = list(trace[pos:pos + body_len])
        # The periodic repetition of the body must match the tail.
        # `full` = whole repetitions that fit; `partial` = events of
        # one more repetition that the tail still matches.
        full = 0
        while (pos + (full + 1) * body_len <= len(trace)
               and list(trace[pos + full * body_len:
                              pos + (full + 1) * body_len]) == body_events):
            full += 1
        partial = 0
        tail_start = pos + full * body_len
        while (tail_start + partial < len(trace)
               and trace[tail_start + partial]
               == body_events[partial % body_len]):
            partial += 1
        # Highest count whose unrolling still matches the tail. If
        # the tail matches the periodic pattern for its whole length
        # (full * body_len + partial == remaining), ANY count is a
        # valid hypothesis: counts whose unrolling is shorter than
        # the tail cover exactly that many events, larger counts
        # overshoot the end (the prediction case). Otherwise only
        # the whole repetitions that fit are valid.
        if full * body_len + partial == remaining:
            max_count = MAX_REPEAT_COUNT
        else:
            max_count = full
        for count in range(MIN_REPEAT_COUNT, max_count + 1):
            body = tuple(Emit(e) for e in body_events)
            cover = min(count * body_len, remaining)
            out.append((Repeat(count, body), cover))
    return out


def infer_programs(trace: Sequence[str],
                   beam_width: int = DEFAULT_BEAM_WIDTH,
                   max_programs: int = DEFAULT_MAX_PROGRAMS,
                   eps: float = EPS, gap: float = GAP
                   ) -> List[Tuple[Program, float]]:
    """Beam-search programs that generate `trace`, ranked by posterior.

    Beam items are (ops, covered_events). Extensions: Emit the next
    observed event, or a Repeat whose unrolling matches the upcoming
    segment exactly. Partial programs are scored by prior cost so far
    (shorter first); complete programs are ranked by full posterior.
    The flat all-Emit program is always reachable, so the result is
    never empty. Returns [(program, log-posterior)] best first.
    """
    trace = list(trace)
    if not trace:
        return [(Program(()), 0.0)]

    # Beam: list of (ops tuple, covered count, prior-bits so far).
    # Pruning score is bits-so-far minus covered * EMIT_BITS: the
    # "excess over flat" accumulated so far. Raw bits are not
    # comparable across partial programs that covered different
    # numbers of events; the excess is -- a partial program that
    # compressed well scores low however far along it is, and at
    # completion the excess ranks programs exactly by total bits
    # (covered * EMIT_BITS is then constant for the trace).
    emit_bits = _op_bits(Emit(trace[0]))
    beam: List[Tuple[Tuple[Op, ...], int, float]] = [((), 0, 1.0)]
    complete: List[Tuple[Program, float]] = []
    seen: set = set()
    while beam:
        nxt: List[Tuple[Tuple[Op, ...], int, float]] = []
        for ops, covered, bits in beam:
            if covered >= len(trace):
                prog = Program(ops)
                key = repr(prog)
                if key not in seen:
                    seen.add(key)
                    complete.append((prog, log_posterior(trace, prog,
                                                         eps, gap)))
                continue
            # Extension 1: Emit the next observed event.
            op = Emit(trace[covered])
            nxt.append((ops + (op,), covered + 1,
                        bits + _op_bits(op)))
            # Extension 2: any Repeat matching the upcoming segment.
            for rep, cover in _repeat_candidates(trace, covered):
                nxt.append((ops + (rep,), covered + cover,
                            bits + _op_bits(rep)))
        if not nxt:
            break
        # Prune: keep the partial programs with the lowest excess
        # over flat; dedupe by (ops, covered).
        dedup: Dict[Tuple[Tuple[Op, ...], int], float] = {}
        for ops, covered, bits in nxt:
            key = (ops, covered)
            if key not in dedup or bits < dedup[key]:
                dedup[key] = bits
        beam = sorted(((ops, covered, bits)
                       for (ops, covered), bits in dedup.items()),
                      key=lambda item: item[2] - item[1] * emit_bits
                      )[:beam_width]
        # Collect any newly completed programs on this round.
        for ops, covered, _bits in beam:
            if covered >= len(trace):
                prog = Program(ops)
                key = repr(prog)
                if key not in seen:
                    seen.add(key)
                    complete.append((prog, log_posterior(trace, prog,
                                                         eps, gap)))
        if all(covered >= len(trace) for _, covered, _ in beam):
            break
    if not complete:
        prog = flat_program(trace)
        complete.append((prog, log_posterior(trace, prog, eps, gap)))
    complete.sort(key=lambda item: item[1], reverse=True)
    return complete[:max_programs]


def learn_shared_programs(traces: Sequence[Sequence[str]],
                          beam_width: int = DEFAULT_BEAM_WIDTH,
                          max_programs: int = DEFAULT_MAX_PROGRAMS,
                          per_trace_keep: int = 8,
                          eps: float = EPS, gap: float = GAP
                          ) -> List[Tuple[Program, float]]:
    """Learn programs that explain a whole set of traces at once.

    Runs :func:`infer_programs` per trace, pools the candidates, and
    re-ranks them by posterior on the full set (one prior cost, summed
    likelihood). A program shared by many traces outranks programs
    that only fit one trace.
    """
    pool: Dict[str, Program] = {}
    for trace in traces:
        if not trace:
            continue
        for prog, _ in infer_programs(trace, beam_width=beam_width,
                                      max_programs=per_trace_keep,
                                      eps=eps, gap=gap):
            pool.setdefault(repr(prog), prog)
    if not pool:
        return []
    return rank_programs_on_traces(
        traces, list(pool.values()), eps=eps, gap=gap)[:max_programs]


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Prediction:
    """One ranked next-event prediction, with its citations."""
    event: str
    weight: float
    # (program, posterior weight of that program) pairs behind it.
    citations: Tuple[Tuple[Program, float], ...]


def _prefix_loglik(prefix: Sequence[str], gen: Sequence[str],
                   eps: float = EPS) -> float:
    """log P(prefix | program) from the program's generated prefix.

    Compares the prefix against the first ``len(prefix)`` generated
    events under the match / mismatch channel only -- no gap penalty:
    events the program generates *after* the prefix are the future
    being predicted, not mismatches.
    """
    log_match = math.log(1.0 - eps)
    log_mismatch = math.log(eps / max(1, len(ALPHABET) - 1))
    total = 0.0
    for a, b in zip(prefix, gen):
        total += log_match if a == b else log_mismatch
    return total


def predict_next(prefix: Sequence[str],
                 programs: Sequence[Tuple[Program, float]],
                 top_m: int = 5,
                 eps: float = EPS, gap: float = GAP
                 ) -> List[Prediction]:
    """Predict the next event after `prefix` from posterior programs.

    Each program votes for the event its expansion emits right after
    the prefix. The vote weight is the program's posterior on THIS
    prefix: ``P(prefix | program)`` under the noise channel times the
    Solomonoff prior -- so a program whose expansion merely starts
    like the prefix still votes, but weakly, and a short program that
    fits the prefix votes strongly. (The supplied per-program
    log-posterior records how the program ranked on the trace it was
    learned from; it is not reused as a weight here, so a library
    program is never double-counted for fitting some other trace.)
    Programs whose expansion is exhausted at the prefix abstain.
    Returns the top-``top_m`` events with normalised weights and
    per-program citations. Every prediction cites the program(s)
    behind it.
    """
    prefix = list(prefix)
    votes: Dict[str, float] = {}
    cites: Dict[str, List[Tuple[Program, float]]] = {}
    for prog, _logpost in programs:
        gen = prog.expand()
        if len(gen) <= len(prefix):
            continue
        w = math.exp(_prefix_loglik(prefix, gen, eps) + prog.log_prior())
        event = gen[len(prefix)]
        votes[event] = votes.get(event, 0.0) + w
        cites.setdefault(event, []).append((prog, w))
    total = sum(votes.values())
    if total <= 0.0:
        return []
    ranked = sorted(votes.items(), key=lambda item: item[1], reverse=True)
    out: List[Prediction] = []
    for event, w in ranked[:top_m]:
        cs = sorted(cites[event], key=lambda item: item[1], reverse=True)
        out.append(Prediction(event=event, weight=w / total,
                              citations=tuple(cs)))
    return out


def predict_next_from_prefix(prefix: Sequence[str],
                             beam_width: int = DEFAULT_BEAM_WIDTH,
                             max_programs: int = DEFAULT_MAX_PROGRAMS,
                             top_m: int = 5) -> List[Prediction]:
    """Convenience: infer programs on the prefix, then predict next."""
    programs = infer_programs(prefix, beam_width=beam_width,
                              max_programs=max_programs)
    return predict_next(prefix, programs, top_m=top_m)


# ---------------------------------------------------------------------------
# Baselines (for honest comparison; not part of the BPL model)
# ---------------------------------------------------------------------------

def frequency_next(traces: Sequence[Sequence[str]]) -> List[Tuple[str, float]]:
    """Global most-common-event baseline: [(event, share)] best first."""
    counts: Dict[str, int] = {}
    total = 0
    for trace in traces:
        for event in trace:
            counts[event] = counts.get(event, 0) + 1
            total += 1
    if total == 0:
        return []
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [(event, c / total) for event, c in ranked]


def markov_next(traces: Sequence[Sequence[str]],
                prefix: Sequence[str]) -> List[Tuple[str, float]]:
    """Order-1 Markov baseline: P(next | last event), backoff to frequency.

    Learns transition counts from `traces`; predicts from the last
    event of `prefix`. If the last event was never seen, backs off to
    the global frequency distribution.
    """
    trans: Dict[str, Dict[str, int]] = {}
    for trace in traces:
        for a, b in zip(trace, trace[1:]):
            trans.setdefault(a, {}).setdefault(b, 0)
            trans[a][b] += 1
    if prefix:
        nxt = trans.get(prefix[-1])
        if nxt:
            total = sum(nxt.values())
            ranked = sorted(nxt.items(), key=lambda item: item[1],
                            reverse=True)
            return [(event, c / total) for event, c in ranked]
    return frequency_next(traces)


def baseline_top1_accuracy(traces: Sequence[Sequence[str]],
                           train: Sequence[Sequence[str]],
                           kind: str = "markov") -> float:
    """Held-out last-event accuracy of a baseline on `traces`.

    Each trace contributes one prediction: its last event, predicted
    from the preceding prefix using `train` as the background corpus.
    """
    if not traces:
        return 0.0
    correct = 0
    for trace in traces:
        if len(trace) < 2:
            continue
        prefix, actual = trace[:-1], trace[-1]
        if kind == "markov":
            ranked = markov_next(train, prefix)
        elif kind == "frequency":
            ranked = frequency_next(train)
        else:
            raise ValueError(f"unknown baseline kind: {kind}")
        if ranked and ranked[0][0] == actual:
            correct += 1
    n = sum(1 for t in traces if len(t) >= 2)
    return correct / n if n else 0.0


def bpl_top1_accuracy(traces: Sequence[Sequence[str]],
                      beam_width: int = DEFAULT_BEAM_WIDTH,
                      max_programs: int = DEFAULT_MAX_PROGRAMS
                      ) -> float:
    """Held-out last-event accuracy of BPL prediction on `traces`.

    Each trace contributes one prediction: its last event, predicted
    from the preceding prefix by programs inferred on that prefix
    alone (no peeking at the held-out event, no training corpus).
    """
    correct = 0
    n = 0
    for trace in traces:
        if len(trace) < 2:
            continue
        n += 1
        preds = predict_next_from_prefix(trace[:-1], beam_width=beam_width,
                                         max_programs=max_programs, top_m=1)
        if preds and preds[0].event == trace[-1]:
            correct += 1
    return correct / n if n else 0.0
