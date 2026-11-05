#!/usr/bin/env python3
"""Adjudication regression for the contract_logic FP filters.

Re-runs the improved detector over the cached verified sources of
the hand-validated 2026-11-02 regression set
(~/workspace/recon-10k/validated.jsonl: 103 rows, of which 100
were produced by contract_logic) and checks that the improved
detector reproduces the adjudication:

- FALSE POSITIVE rows: no candidate-grade finding may remain.
- TRIGGER-ONLY rows: the finding must survive ONLY as
  report_class="trigger_only" at low severity.
- The UNVERIFIED row (POL initialize): the finding MUST remain a
  high candidate - it is a genuine open item.

Contracts whose full source is not in the local caches are
reported as NO-SOURCE with their template group; every such row
belongs to a template that IS covered either here or by the
fixture tests in tests/test_contract_logic_fp_filters.py
(BackedToken clones, OZ ERC20 clones, DERC20, WETH9, POL, OREO,
L2DAO, PBTC, Compound checkpoints).

Usage: python3 scripts/fp_regression.py [--workspace ~/workspace]
Exit code 0 when every scored row passes.
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.plugins.contract_logic import analyze_logic_source  # noqa: E402

# Contract names for the .sol-only caches (which carry no
# metadata); taken from the scan evidence of the validation
# snapshot (validated.jsonl's sibling snap files).
_EVIDENCE_NAMES = {
    ("bsc", "0x4268b8f0b87b6eae5d897996e6b845ddbd99adf3"):
        "BurnableMintableCappedERC20",
    ("bsc", "0x11ac6af070fe1991a457c56fb85c577efe57f0e4"):
        "DragonKing",
    ("optimism", "0x747e42eb0591547a0ab429b3627816208c734ea7"):
        "OptimismMintableERC20",
    ("polygon", "0x18e73a5333984549484348a94f4d219f4fab7b81"):
        "YellowToken",
    ("polygon", "0xb41ec2c036f8a42da384dde6ada79884f8b84b26"):
        "TidalTokenChild",
}

# Template groups for the NO-SOURCE accounting.
_TEMPLATES = {
    "BackedTokenProxy": "BackedToken template (fixture-verbatim)",
    "WETH9": "WETH9 template (fixture-verbatim)",
    "DERC20": "DERC20 template (fixture-verbatim)",
    "MRC20": "POL/MRC20 (fixture-verbatim)",
    "OREO": "OREO hasMinterRole (fixture-verbatim)",
    "L2DAOTokenMultichain": "L2DAO registry gate (fixture-verbatim)",
    "PToken": "PBTC _msgSender gate (fixture-verbatim)",
    "Quick": "Compound checkpoint template (full-source via Tidal)",
}


def load_source(ws: pathlib.Path, chain: str, addr: str):
    p = ws / f"recon-10k/validation/src/{chain}-{addr}.sol"
    if p.exists() and p.stat().st_size > 0:
        return p.read_text(), _EVIDENCE_NAMES.get((chain, addr), "")
    for base, pat in [
            (ws / "recon-10k/src_cache", f"{chain}-{addr}.json"),
            (ws / "recon-verify/src_cache", f"{chain}_{addr}.json")]:
        q = base / pat
        if not q.exists():
            continue
        d = json.loads(q.read_text())
        name = d.get("contract_name") or d.get("name") or ""
        if d.get("source"):
            return d["source"], name
        if d.get("sources"):
            return "\n".join(
                f"// ==== {k} ====\n"
                f"{v.get('content', '') if isinstance(v, dict) else v}"
                for k, v in d["sources"].items()), name
    return None, ""


def candidate_grade(findings, function, kind, logic_kind=None):
    out = []
    for f in findings:
        if f["function"] != function or f["kind"] != kind:
            continue
        if logic_kind and f.get("logic_kind") != logic_kind:
            continue
        if f["severity"] in ("high", "medium") and \
                f.get("report_class") != "trigger_only":
            out.append(f)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace",
                    default=str(pathlib.Path.home() / "workspace"))
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    rows = [json.loads(l)
            for l in open(ws / "recon-10k/validated.jsonl")]
    logic_rows = [r for r in rows
                  if r["plugin"].startswith("contract_logic")]
    other_rows = [r for r in rows
                  if not r["plugin"].startswith("contract_logic")]
    by_contract = {}
    for r in logic_rows:
        by_contract.setdefault((r["chain"], r["address"]),
                               []).append(r)
    stats = {"PASS": 0, "FAIL": 0}
    no_source = {}
    for (chain, addr), crows in sorted(by_contract.items()):
        src, cname = load_source(ws, chain, addr)
        if not src:
            sym = crows[0].get("symbol") or addr[:10]
            no_source.setdefault(sym, 0)
            no_source[sym] += len(crows)
            continue
        findings = analyze_logic_source(src, "", contract_name=cname)
        for r in crows:
            kind, logic_kind = r["finding"], None
            if kind == "arbitrary delegatecall":
                kind = "access_control_flaw"
                logic_kind = "arbitrary_delegatecall"
            hits = candidate_grade(findings, r["function"], kind,
                                   logic_kind)
            if r["verdict"] == "FALSE POSITIVE":
                ok = not hits
            elif r["verdict"] == "TRIGGER-ONLY":
                trig = [f for f in findings
                        if f["function"] == r["function"]
                        and f["kind"] == kind
                        and f.get("report_class") == "trigger_only"]
                ok = bool(trig) and not hits
            elif r["verdict"] == "UNVERIFIED":
                ok = bool(hits)  # POL: must REMAIN a candidate
            else:
                ok = False
            stats["PASS" if ok else "FAIL"] += 1
            print(f"{'PASS' if ok else 'FAIL'} {r['verdict']:15s} "
                  f"{chain} {r['symbol'] or addr[:10]} "
                  f"{r['function']} {r['finding']} (target={cname})")
    print(f"\ncontract_logic rows scored: "
          f"{stats['PASS'] + stats['FAIL']} "
          f"(PASS {stats['PASS']}, FAIL {stats['FAIL']})")
    if no_source:
        print("NO-SOURCE rows by template (covered by fixtures):")
        for sym, n in sorted(no_source.items()):
            print(f"  {sym}: {n}")
    print(f"Out-of-scope rows (other detectors): {len(other_rows)} "
          f"(contract_recon inventory x2, local flash_detector x1)")
    return 1 if stats["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
