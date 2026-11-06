#!/usr/bin/env python3
"""Benchmark harness: runs the money-path analyzer set + the
auto-validator over benchmark/corpus.py cases and scores them
against the hand-labeled ground truth.

Usage:
  score.py --backend ~/workspace/wt/<tree>/backend \
           --out results.json [--label baseline]

Detector layer: a case is a detector HIT when at least one
analyzer emits a candidate-grade finding on the flagged function
(severity high/critical and not trigger-only; recipient-first
items must carry report_class="candidate"; drain findings must
not classify the recipient FIXED / HOLDER-SELF). Cases marked
function_match="any" accept a candidate on any function of the
target contract (vault/oracle analyzers attribute to the pricing
helper, not the entry).

Validator layer: validate_candidate() fed the case's source plus
the honest live evidence in the manifest (probe outcome and
balances a gathering lane would read for this ground truth).

Bytecode layer: analyze_logic_bytecode() output checked for
(1) any capability finding, (2) selector attribution fields,
(3) eth_call probe sketches, (4) minimal-proxy surfacing.
"""
import argparse
import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import depth_benchmark_corpus as corpus  # noqa: E402


def _candidate_grade(f, family):
    sev = str(f.get("severity", "")).lower()
    if sev not in ("high", "critical"):
        return False
    if family == "recipient_first":
        return f.get("report_class") == "candidate"
    if f.get("report_class") == "trigger_only":
        return False
    if family == "crypto_drain" and \
            f.get("recipient") in ("FIXED", "HOLDER-SELF"):
        return False
    return True


def run_source_case(case, mods):
    cl, cd, rf, deeps, av, so = mods
    src, cname, fn = case["source"], case["contract_name"], \
        case["function"]
    hits = {}   # analyzer id -> [finding summaries]
    raw = {}

    def record(analyzer, family, findings):
        cand, trig = [], []
        for f in findings:
            entry = {"kind": f.get("kind") or f.get("id") or "",
                     "function": f.get("function", ""),
                     "severity": f.get("severity", ""),
                     "report_class": f.get("report_class"),
                     "recipient": f.get("recipient")}
            on_fn = entry["function"] == fn or \
                case.get("function_match") == "any"
            if _candidate_grade(f, family) and on_fn:
                cand.append(entry)
            elif on_fn:
                trig.append(entry)
        if cand:
            hits[analyzer] = cand
        if cand or trig:
            raw[analyzer] = {"candidate": cand, "other": trig}

    record("contract_logic", "contract_logic",
           cl.analyze_logic_source(src, "", cname))
    record("crypto_drain", "crypto_drain",
           cd.analyze_drain_source(src))
    for spec_id in rf.ANALYZERS:
        record(f"recipient_first:{spec_id}", "recipient_first",
               rf.analyze_recipient_source(src, spec_id, "", cname))
    for mod_name, fn_name, specs, mod in deeps:
        analyze = getattr(mod, fn_name)
        for spec in specs:
            sid = spec["id"] if isinstance(spec, dict) else spec.id
            record(f"{mod_name}:{sid}", "deep",
                   analyze(src, spec, "", cname))
    record("spot_oracle", "deep",
           so.analyze_spot_oracle_source(src, "", cname))

    detector_hit = bool(hits)
    verdict = None
    vdetail = None
    if case.get("expect_validator"):
        ev = case.get("evidence", {})
        cand = {"address": "0x00000000000000000000000000000000000000aa",
                "chain": "ethereum",
                "function": fn,
                "kind": "access_control_flaw",
                "source": src,
                "contract_name": cname,
                "probe": {"status": ev.get("probe", "success"),
                          "via": "benchmark"},
                "balances": ev.get("balances", {})}
        v = av.validate_candidate(cand)
        verdict = v["verdict"]
        vdetail = {"recipient": v.get("recipient"),
                   "gated": v.get("gated"),
                   "missing": v.get("missing"),
                   "reason": v.get("reason", "")[:240]}
    return {"id": case["id"],
            "expect_detector_candidate":
                case["expect_detector_candidate"],
            "detector_hit": detector_hit,
            "hit_by": sorted(hits),
            "raw": raw,
            "expect_validator": case.get("expect_validator"),
            "validator_verdict": verdict,
            "validator_detail": vdetail,
            "gap": case.get("gap"),
            "note": case.get("note", "")}


def run_bytecode_case(case, mods):
    cl, cc = mods
    findings = cl.analyze_logic_bytecode(case["hex"])
    info = cc.analyze_bytecode(case["hex"])
    attribution = any(
        isinstance(f, dict) and
        ("selector_paths" in f or "probe_sketches" in f)
        for f in findings)
    sketches = any(
        isinstance(f, dict) and f.get("probe_sketches")
        for f in findings)
    proxy_surfaced = any(
        isinstance(f, dict) and
        (f.get("minimal_proxy_impl") or
         (case.get("expect_proxy") and
          case["expect_proxy"][2:] in
          json.dumps(f).lower()))
        for f in findings)
    # Selector-level attribution: every expected selector ->
    # capability pair must be recoverable from the findings
    # themselves (the selector string and the opcode name in the
    # same finding payload).
    sel_ok = True
    for sel, caps in (case.get("selector_capabilities") or
                      {}).items():
        for cap in caps:
            found = any(
                isinstance(f, dict) and
                sel[2:] in json.dumps(f).lower() and
                cap.lower() in json.dumps(f).lower()
                for f in findings)
            sel_ok = sel_ok and found
    return {"id": case["id"],
            "expect_capability": case["expect_capability"],
            "capability_detected": bool(findings),
            "expect_attribution": case["expect_attribution"],
            "attribution": attribution,
            "selector_attribution_ok": sel_ok,
            "probe_sketches": sketches,
            "expect_proxy": case.get("expect_proxy"),
            "proxy_surfaced": proxy_surfaced,
            "cc_selectors": info.get("selectors"),
            "cc_minimal_proxy_impl": info.get("minimal_proxy_impl"),
            "findings": findings}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    args = ap.parse_args()
    sys.path.insert(0, args.backend)
    from app.plugins import contract_logic as cl
    from app.plugins import contract_chain as cc
    from app.plugins import crypto_drain as cd
    from app.plugins import recipient_first as rf
    from app.plugins import auto_validator as av
    from app.plugins import spot_oracle as so
    from app.plugins.cryptopack_util import keccak256
    corpus.BYTECODE_CASES = corpus.build_bytecode_cases(keccak256)
    deeps = []
    for i in range(1, 11):
        mod_name = "deep_audit" if i == 1 else f"deep_audit{i}"
        fn_name = "analyze_deep_source" if i == 1 else \
            f"analyze_deep{i}_source"
        mod = importlib.import_module(f"app.plugins.{mod_name}")
        deeps.append((mod_name, fn_name, mod.SPECS, mod))
    mods = (cl, cd, rf, deeps, av, so)

    results = {"label": args.label, "backend": args.backend,
               "source_cases": [], "bytecode_cases": []}
    for case in corpus.SOURCE_CASES:
        results["source_cases"].append(run_source_case(case, mods))
    for case in corpus.BYTECODE_CASES:
        results["bytecode_cases"].append(
            run_bytecode_case(case, (cl, cc)))
    Path(args.out).write_text(json.dumps(results, indent=1,
                                         default=str))

    # console summary
    tp = fp = fn_ = tn = 0
    print(f"== detector layer ({args.label}) ==")
    for r in results["source_cases"]:
        exp, hit = r["expect_detector_candidate"], r["detector_hit"]
        if exp and hit:
            tp += 1; mark = "TP"
        elif exp and not hit:
            fn_ += 1; mark = "MISS"
        elif not exp and hit:
            fp += 1; mark = "FP"
        else:
            tn += 1; mark = "TN"
        print(f"{mark:4s} {r['id']:36s} by={','.join(r['hit_by'])}")
    print(f"detector: TP {tp}  MISS {fn_}  FP {fp}  TN {tn}")
    print(f"== validator layer ({args.label}) ==")
    vok = vbad = 0
    for r in results["source_cases"]:
        if not r["expect_validator"]:
            continue
        ok = r["validator_verdict"] == r["expect_validator"]
        vok += ok; vbad += (not ok)
        print(f"{'OK ' if ok else 'BAD'} {r['id']:36s} "
              f"expect={r['expect_validator']} "
              f"got={r['validator_verdict']} "
              f"missing={(r['validator_detail'] or {}).get('missing')}")
    print(f"validator: OK {vok}  BAD {vbad}")
    print(f"== bytecode layer ({args.label}) ==")
    for r in results["bytecode_cases"]:
        print(f"{r['id']:24s} capability "
              f"{r['capability_detected']}/{r['expect_capability']} "
              f"attribution {r['attribution']} "
              f"selector_map {r['selector_attribution_ok']} "
              f"sketches {r['probe_sketches']} "
              f"proxy {r['proxy_surfaced']}")


if __name__ == "__main__":
    main()
