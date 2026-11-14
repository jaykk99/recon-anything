"""BPL + Solomonoff tests: prior, planted-program recovery, prediction
vs Markov / frequency baselines. Pure stdlib, no network, synthetic
traces only (ground truth known by construction)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.bpl import (  # noqa: E402
    Emit,
    Program,
    Repeat,
    baseline_top1_accuracy,
    bpl_top1_accuracy,
    flat_program,
    infer_programs,
    learn_shared_programs,
    log_likelihood,
    log_posterior,
    predict_next_from_prefix,
)
from app.nn.synth import (  # noqa: E402
    make_benchmark,
    sample_trace,
    split_benchmark,
)

A = "DEPLOY:proxy:scroll"
B = "OWNER_SET"
C = "UPGRADE"
D = "DEPLOY:nft:scroll"


def test_prior_prefers_shorter_of_two_equivalent_programs():
    trace = [A, B, A, B, A, B]
    flat = flat_program(trace)
    short = Program((Repeat(3, (Emit(A), Emit(B))),))
    assert short.expand() == flat.expand() == trace
    assert short.description_length() < flat.description_length()
    assert short.log_prior() > flat.log_prior()
    # Same expansion => same likelihood, so the posterior must follow
    # the prior: the shorter program wins.
    assert log_posterior(trace, short) > log_posterior(trace, flat)
    ranked = infer_programs(trace)
    assert ranked[0][0] == short
    assert ranked[0][0].expand() == trace


def test_inference_recovers_planted_program():
    # Planted: a phase-ambiguous cycle repeated, then a tail event.
    planted = Program((
        Repeat(3, (Emit(A), Emit(B), Emit(A), Emit(C))),
        Emit(D),
    ))
    trace = planted.expand()
    assert len(trace) == 13
    ranked = infer_programs(trace)
    best, _ = ranked[0]
    assert best.expand() == trace
    # The recovered program must be at least as short as the planted
    # one (it found the minimal form, not the flat spelling).
    assert best.description_length() <= planted.description_length()
    assert any(isinstance(op, Repeat) for op in best.ops)


def test_inference_recovers_planted_program_with_noise_free_trace():
    # A second planted shape: repeated single event + flat tail.
    planted = Program((
        Repeat(4, (Emit(A),)),
        Emit(B),
        Emit(C),
    ))
    trace = planted.expand()
    ranked = infer_programs(trace)
    best, _ = ranked[0]
    assert best.expand() == trace
    assert best.description_length() <= planted.description_length()


def test_likelihood_penalises_mismatch():
    trace = [A, B, A, B]
    exact = Program((Repeat(2, (Emit(A), Emit(B))),))
    wrong = Program((Repeat(2, (Emit(A), Emit(C))),))
    assert log_likelihood(trace, exact) > log_likelihood(trace, wrong)
    # ... and a program that generates extra events is penalised too.
    longer = Program((Repeat(2, (Emit(A), Emit(B))), Emit(A)))
    assert log_likelihood(trace, exact) > log_likelihood(trace, longer)


def test_flat_program_always_found_on_uncompressible_trace():
    # No repetition at all: the only exact program is the flat one.
    trace = [A, B, C, D, "FUND_IN:large"]
    ranked = infer_programs(trace)
    assert ranked[0][0].expand() == trace
    assert ranked[0][0] == flat_program(trace)


def test_empty_trace():
    ranked = infer_programs([])
    assert ranked[0][0] == Program(())
    assert ranked[0][0].expand() == []


def test_prediction_cites_programs_and_sums_to_one():
    prefix = [A, B, A, B, A]
    preds = predict_next_from_prefix(prefix, top_m=3)
    assert preds, "no prediction for a clean repeating prefix"
    total = sum(p.weight for p in preds)
    assert abs(total - 1.0) < 1e-9
    top = preds[0]
    assert top.event == B  # the cycle says B follows A here
    assert top.citations, "prediction must cite its programs"
    for prog, w in top.citations:
        gen = prog.expand()
        assert gen[:len(prefix)] == prefix
        assert gen[len(prefix)] == top.event
        assert w > 0.0


def test_prediction_beats_markov_and_frequency_baselines():
    # Synthetic held-out traces with known ground-truth programs.
    # The generator uses phase-ambiguous cycles, which order-1
    # Markov cannot resolve but a program can.
    traces = make_benchmark(n_traces=120, seed=7, noise=0.0)
    train, held = split_benchmark(traces, seed=7, train_frac=0.7)
    held = [t for t in held if len(t) >= 2]
    assert len(held) >= 20
    bpl_acc = bpl_top1_accuracy(held)
    markov_acc = baseline_top1_accuracy(held, train, kind="markov")
    freq_acc = baseline_top1_accuracy(held, train, kind="frequency")
    assert bpl_acc > markov_acc, (
        f"BPL {bpl_acc:.3f} did not beat Markov {markov_acc:.3f}")
    assert bpl_acc > freq_acc, (
        f"BPL {bpl_acc:.3f} did not beat frequency {freq_acc:.3f}")


def test_shared_program_explains_many_traces():
    # Three identical traces: the shared program should be the
    # compressed one, and its multi-trace posterior must beat the
    # flat program's by more than a single trace's worth -- the
    # description length is paid once, the likelihood three times.
    trace = [A, B, A, B, A, B]
    traces = [trace, list(trace), list(trace)]
    ranked = learn_shared_programs(traces)
    best, best_post = ranked[0]
    assert best.expand() == trace
    assert any(isinstance(op, Repeat) for op in best.ops)
    flat = flat_program(trace)
    flat_post = sum(log_likelihood(t, flat) for t in traces) \
        + flat.log_prior()
    assert best_post > flat_post


def test_sampled_programs_roundtrip_through_inference():
    # Ten random planted programs, noise-free: inference must recover
    # a program that expands to the trace and is no longer than the
    # planted one, every time.
    import random
    rng = random.Random(123)
    for _ in range(10):
        planted, trace = sample_trace(rng, noise=0.0)
        best, _ = infer_programs(trace, max_programs=8)[0]
        assert best.expand() == trace
        assert best.description_length() <= planted.description_length() \
            + 1e-9
