"""Honest evaluation of the BPL engine.

Two parts, kept strictly separate and labelled as such:

1. REAL DATA (the first domain Jay ordered): deployer / wallet
   behaviour from the continuous scanner's own files -- per-creator
   deploy sequences from ``fresh-deploys-more-chains.jsonl`` and
   owner flips from ``state/transition_events.jsonl``. The real data
   is thin (most creators deployed exactly once) and noisy; this
   script reports coverage and prediction accuracy on it WITHOUT
   dressing it up, and says plainly where it cannot support a claim.

2. SYNTHETIC BENCHMARK: traces generated from known DSL programs
   (``synth.py``) with ground truth. This is the primary benchmark
   for the inference machinery itself. Synthetic results are
   synthetic and are labelled as such everywhere they appear.

Usage (run from ``backend/``):
    python3 -m app.nn.evaluate_bpl [fresh.jsonl] [transitions.jsonl] \
        [candidates.jsonl]

Reads only. Prints a report to stdout. Pure stdlib.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from app.nn.bpl import (  # noqa: E402
    ALPHABET,
    Repeat,
    baseline_top1_accuracy,
    bpl_top1_accuracy,
    flat_program,
    frequency_next,
    infer_programs,
    learn_shared_programs,
    markov_next,
)
from app.nn.synth import make_benchmark, split_benchmark  # noqa: E402

DEFAULT_FRESH = os.path.expanduser(
    "~/workspace/recon-continuous/targets-2026-11-12/"
    "fresh-deploys-more-chains.jsonl")
DEFAULT_TRANS = os.path.expanduser(
    "~/workspace/recon-continuous/state/transition_events.jsonl")
DEFAULT_CANDS = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")


# ---------------------------------------------------------------------------
# Real-data trace builders
# ---------------------------------------------------------------------------

def deploy_kind(name: Optional[str]) -> str:
    """Map a contract name to a DEPLOY detail kind token."""
    n = (name or "").lower()
    if "proxy" in n:
        return "proxy"
    if "erc721" in n or "nft" in n or "721" in n:
        return "nft"
    if "token" in n:
        return "token"
    return "other"


def load_jsonl(path: str) -> List[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue  # torn row: skip, never fatal
    return rows


def build_deploy_traces(rows: List[dict]) -> Tuple[List[List[str]], Counter]:
    """One trace per creator: their deploys ordered by first_seen."""
    by_creator: Dict[str, List[dict]] = {}
    for row in rows:
        creator = (row.get("creator") or "").lower()
        if not creator:
            continue
        by_creator.setdefault(creator, []).append(row)
    traces = []
    kinds = Counter()
    for creator, rs in by_creator.items():
        rs.sort(key=lambda r: (r.get("first_seen_utc") or "",
                               r.get("block") or 0))
        trace = []
        for r in rs:
            kind = deploy_kind(r.get("name"))
            kinds[kind] += 1
            chain = (r.get("chain") or "unknown").lower()
            event = f"DEPLOY:{kind}:{chain}"
            if r.get("fresh_7d"):
                event += ":fresh"
            trace.append(event)
        traces.append(trace)
    return traces, kinds


def build_transition_traces(rows: List[dict]) -> List[List[str]]:
    """One single-event trace per owner flip (that is all the data
    has: one owner change per address, no sequence)."""
    traces = []
    for r in rows:
        before = r.get("before") or {}
        after = r.get("after") or {}
        if before.get("owner") is None and after.get("owner"):
            traces.append(["OWNER_SET"])
        elif after.get("owner") is None and before.get("owner"):
            traces.append(["OWNER_CLEAR"])
        else:
            traces.append(["OWNER_SET"])
    return traces


def build_combined_traces(deploy_rows: List[dict],
                          trans_rows: List[dict]) -> List[List[str]]:
    """Per-address traces joining a deploy with a later owner flip,
    where the same address appears in both files. Ordered by time."""
    deploy_by_addr: Dict[str, List[dict]] = {}
    for r in deploy_rows:
        addr = (r.get("address") or "").lower()
        if addr:
            deploy_by_addr.setdefault(addr, []).append(r)
    traces = []
    for r in trans_rows:
        addr = (r.get("address") or "").lower()
        if addr not in deploy_by_addr:
            continue
        events = []
        for d in sorted(deploy_by_addr[addr],
                        key=lambda x: x.get("first_seen_utc") or ""):
            kind = deploy_kind(d.get("name"))
            chain = (d.get("chain") or "unknown").lower()
            ev = f"DEPLOY:{kind}:{chain}"
            if d.get("fresh_7d"):
                ev += ":fresh"
            events.append((d.get("first_seen_utc") or "", ev))
        before = r.get("before") or {}
        after = r.get("after") or {}
        owner_ev = ("OWNER_SET" if before.get("owner") is None
                    and after.get("owner") else "OWNER_CLEAR")
        events.append((r.get("detected_at") or "", owner_ev))
        events.sort(key=lambda item: item[0])
        traces.append([ev for _, ev in events])
    return traces


# ---------------------------------------------------------------------------
# Real-data evaluation
# ---------------------------------------------------------------------------

def evaluate_real(traces: List[List[str]], label: str) -> None:
    """Coverage + held-out last-event prediction on real traces."""
    n = len(traces)
    lengths = Counter(len(t) for t in traces)
    oov = [e for t in traces for e in t if e not in ALPHABET]
    print(f"\n--- {label}: {n} traces ---")
    print(f"length histogram: {dict(sorted(lengths.items()))}")
    print(f"out-of-alphabet events: {len(oov)}"
          + (f" e.g. {sorted(set(oov))[:5]}" if oov else ""))
    if n == 0:
        return
    # Coverage: compressible = best program shorter than flat.
    compressible = 0
    with_repeat = 0
    ratios = []
    for t in traces:
        best, _ = infer_programs(t, max_programs=4)[0]
        flat = flat_program(t)
        ratios.append(best.description_length()
                      / flat.description_length())
        if best.description_length() < flat.description_length() - 1e-9:
            compressible += 1
            if any(isinstance(op, Repeat) for op in best.ops):
                with_repeat += 1
    print(f"compressible (best program shorter than flat): "
          f"{compressible}/{n} = {compressible / n:.3f}")
    print(f"  of those, using a Repeat: {with_repeat}")
    print(f"mean description-length ratio (best/flat): "
          f"{sum(ratios) / len(ratios):.3f}  (1.0 = no compression)")
    # Held-out last-event prediction, leave-one-out for the baselines
    # (BPL uses only the trace's own prefix, so it needs no training
    # corpus and no leave-one-out).
    held = [t for t in traces if len(t) >= 2]
    print(f"predictable traces (len >= 2): {len(held)}")
    if len(held) < 2:
        print("too few predictable traces for a comparison; "
              "no accuracy claim is made")
        return
    bpl_acc = bpl_top1_accuracy(held)
    # Leave-one-out Markov / frequency.
    m_ok = f_ok = 0
    for i, trace in enumerate(held):
        train = held[:i] + held[i + 1:]
        prefix, actual = trace[:-1], trace[-1]
        ranked = markov_next(train, prefix)
        if ranked and ranked[0][0] == actual:
            m_ok += 1
        ranked = frequency_next(train)
        if ranked and ranked[0][0] == actual:
            f_ok += 1
    print(f"held-out last-event top-1 (n={len(held)}): "
          f"BPL={bpl_acc:.3f}  Markov(LOO)={m_ok / len(held):.3f}  "
          f"Frequency(LOO)={f_ok / len(held):.3f}  "
          f"Random~{1 / max(1, len(set(e for t in held for e in t))):.3f}")


def evaluate_synthetic() -> None:
    """Primary benchmark: synthetic traces, known ground truth."""
    print("\n--- SYNTHETIC BENCHMARK (ground truth known) ---")
    for seed, n, noise in [(7, 120, 0.0), (42, 200, 0.0),
                           (123, 200, 0.0), (42, 200, 0.05)]:
        traces = make_benchmark(n_traces=n, seed=seed, noise=noise)
        train, held = split_benchmark(traces, seed=seed, train_frac=0.7)
        held = [t for t in held if len(t) >= 2]
        bpl_acc = bpl_top1_accuracy(held)
        m_acc = baseline_top1_accuracy(held, train, kind="markov")
        f_acc = baseline_top1_accuracy(held, train, kind="frequency")
        print(f"seed={seed} noise={noise} n_held={len(held)}: "
              f"BPL={bpl_acc:.3f}  Markov={m_acc:.3f}  "
              f"Frequency={f_acc:.3f}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    fresh_path = args[0] if len(args) > 0 else DEFAULT_FRESH
    trans_path = args[1] if len(args) > 1 else DEFAULT_TRANS
    cand_path = args[2] if len(args) > 2 else DEFAULT_CANDS
    print("BPL + Solomonoff evaluation")
    print("REAL data: fresh-deploys + transition events "
          "(thin, noisy -- see numbers, not claims)")
    print("SYNTHETIC data: generated programs with known ground truth "
          "(primary benchmark for the inference machinery)")

    fresh_rows = load_jsonl(fresh_path)
    trans_rows = load_jsonl(trans_path)
    print(f"\nloaded fresh-deploys: {len(fresh_rows)} rows from {fresh_path}")
    print(f"loaded transitions: {len(trans_rows)} rows from {trans_path}")
    deploy_traces, kinds = build_deploy_traces(fresh_rows)
    print(f"deploy kind tokens: {dict(kinds)}")
    trans_traces = build_transition_traces(trans_rows)
    combined = build_combined_traces(fresh_rows, trans_rows)
    print(f"deploy traces (per creator): {len(deploy_traces)}")
    print(f"transition traces (per address, len 1): {len(trans_traces)}")
    print(f"combined deploy+owner traces (address in both files): "
          f"{len(combined)}")

    # candidates.jsonl is finding-level data, not behaviour traces:
    # report overlap only, never learn programs from it.
    try:
        cand_rows = load_jsonl(cand_path)
        cand_addrs = {(r.get("address") or "").lower()
                      for r in cand_rows}
        deploy_addrs = {(r.get("address") or "").lower()
                        for r in fresh_rows}
        trans_addrs = {(r.get("address") or "").lower()
                       for r in trans_rows}
        print(f"candidates: {len(cand_rows)} rows; "
              f"addresses overlapping fresh-deploys: "
              f"{len(cand_addrs & deploy_addrs)}, overlapping "
              f"transitions: {len(cand_addrs & trans_addrs)} "
              f"(finding-level data -- not used for program learning)")
    except OSError as exc:
        print(f"candidates file unreadable ({exc}); skipped")

    evaluate_real(deploy_traces, "REAL deploy traces (per creator)")
    evaluate_real(combined, "REAL combined deploy+owner traces")
    if trans_traces:
        print("\n--- REAL transition traces: "
              f"{len(trans_traces)} traces, all length 1 ---")
        print("no sequence to learn from and nothing to predict; "
              "owner flips are single events, not behaviour traces")

    # What did the engine actually learn on the real deploy traces?
    learnable = [t for t in deploy_traces if len(t) >= 2]
    if learnable:
        print("\n--- top shared programs on REAL deploy traces "
              f"(len>=2, n={len(learnable)}) ---")
        for prog, post in learn_shared_programs(
                learnable, max_programs=5, per_trace_keep=4):
            print(f"  logpost={post:.1f}  {prog!r}")

    evaluate_synthetic()
    print("\nDone. Synthetic numbers are synthetic; real numbers are "
          "real and thin -- see docs/nn-bpl.md for what each supports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
