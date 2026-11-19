#!/usr/bin/env python3
"""Measure the 5 Round-1 FP detector families over the Round-1 target
sources, for one backend checkout.

Detection only. Runs the 5 plugins the Round-1 adjudication blamed
(evm_cfg_basic_block_reconstructor, symbolic_z3_storage_taint_tracer,
recipient_mint_to_caller, eip712_separator_unbound,
unchecked_math_user_input) over the 10 Round-1 targets that produced
candidates, and counts candidate-equivalent findings (high/critical +
CALLER / CALLER-SUPPLIED, same rule as scan_fullreg.py).

Usage:
  python measure_fix.py --backend /path/to/backend --out measure-baseline.json
  python measure_fix.py --backend /path/to/backend --out measure-gates2.json
"""
import argparse
import asyncio
import datetime
import json
import os
import sys
from collections import Counter
from pathlib import Path

os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

HOME = Path(__file__).resolve().parent

PLUGIN_IDS = [
    "evm_cfg_basic_block_reconstructor",
    "symbolic_z3_storage_taint_tracer",
    "recipient_mint_to_caller",
    "eip712_separator_unbound",
    "unchecked_math_user_input",
]

# The 10 Round-1 targets that produced candidates (chain, address, name).
TARGETS = [
    ("cronos", "0xc21223249CA28397B4B6541dfFaEcC539BfF0c59", "Bridged USDC (USDC.e)"),
    ("cronos", "0x66e428c3f67a68878562e79A0234c1F83c208770", "Bridged USDT"),
    ("cronos", "0xe44Fd7fCb2b1581822D0c862B68222998a0c299a", "Wrapped Ether (WETH)"),
    ("cronos", "0x062E66477Faf219F25D27dCED647BF57C3107d52", "Bridged WBTC"),
    ("cronos", "0xF2001B145b43032AAF5Ee2884e456CCd805F677D", "Crypto.com Bridged DAI"),
    ("cronos", "0xB888d8Dd1733d72681b30c00ee76BDE93ae7aa93", "ATOM (IBC-bridged)"),
    ("ethereum", "0x7e772ed6e4bfeae80f2d58e4254f6b6e96669253", "LiquidETHV1 (CDCETH impl)"),
    ("cronos", "0xddcde8de19284cc5aab6db5ac6af1dcda175f5e2", "CDCWrappedBTC (CDCBTC impl)"),
    ("cronos", "0xaE50f345502aD3395DB0099d38692f609F829B58", "Expedition Gear NFT (ExpGear)"),
    ("cronos", "0xcCEf054E827A5e867194aD2cfBf8A83545D00cBF", "Match Ready Lions NFT"),
]

# Expected Round-1 candidate set: (plugin, address-lower, function).
# From the Round-1 candidates-*.jsonl files when present next to
# this script; otherwise reconstructed from the committed
# measure-baseline.json (matched + silenced rows = the 36).
EXPECTED = set()
for _f in HOME.glob("candidates-*.jsonl"):
    for _line in _f.read_text(errors="replace").splitlines():
        if not _line.strip():
            continue
        _r = json.loads(_line)
        EXPECTED.add((_r["plugin"], _r["address"].lower(), _r.get("function", "")))
if not EXPECTED and (HOME / "measure-baseline.json").exists():
    _base = json.loads((HOME / "measure-baseline.json").read_text())
    for _row in _base.get("matched_expected", []) + _base.get("missing_expected_silenced", []):
        EXPECTED.add(tuple(_row))


def recipient_class(f):
    ev = f.get("evidence") or {}
    if not ev:
        ev = f
    rc = str(ev.get("report_class") or "").lower()
    rec = str(ev.get("recipient") or "").upper()
    if rc == "candidate":
        return rec if rec in ("CALLER", "CALLER-SUPPLIED") else "CALLER-SUPPLIED"
    if rc == "trigger_only":
        return "TRIGGER_ONLY"
    if rec in ("CALLER", "CALLER-SUPPLIED"):
        return rec
    if rec in ("FIXED", "HOLDER-SELF", "HOLDER_SELF"):
        return rec
    return "UNKNOWN"


class Cache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    backend = os.path.abspath(args.backend)
    sys.path.insert(0, backend)

    import httpx  # noqa: E402
    from app.plugins.base import Ctx, Target  # noqa: E402
    from app.plugins.registry import discover, all_plugins  # noqa: E402
    from app.ratelimit import RateLimiter  # noqa: E402
    from app.plugins import contract_chain as cc  # noqa: E402

    CRONOS_RPCS = (
        "https://cronos.drpc.org",
        "https://evm.cronos.org",
        "https://cronos-evm-rpc.publicnode.com",
        "https://evm-cronos.crypto.org",
    )
    if "cronos" not in cc.CHAINS:
        cc.CHAINS["cronos"] = cc.ChainConfig(
            id="cronos", name="Cronos", chain_id=25,
            rpc_urls=CRONOS_RPCS,
            blockscout_api="https://cronos.blockscout.com/api",
            explorer_address="https://cronoscan.com/address/{addr}",
            native="CRO")
        cc.CHAIN_ALIASES.update({"cronos": "cronos", "cro": "cronos"})
    try:
        from app import rpc_pool as _rpc_pool  # noqa: E402
        _rpc_pool.EXTRA_KEYLESS_RPCS["cronos"] = CRONOS_RPCS
    except Exception:
        pass

    registry = discover()
    by_id = {p.id: p for p in all_plugins()}
    missing = [pid for pid in PLUGIN_IDS if pid not in by_id]
    if missing:
        print(f"MISSING PLUGINS: {missing}", flush=True)
        return 2

    limiter = RateLimiter(default_rps=10.0)

    async def run_all():
        rows = []
        errors = []
        async with httpx.AsyncClient(timeout=30) as http:
            for chain, address, name in TARGETS:
                raw = f"{chain}:{address}"
                for pid in PLUGIN_IDS:
                    plugin = by_id[pid]
                    ctx = Ctx(run_id="measure-round1-fix", mode="passive",
                              http=http, cache=Cache(), keys={},
                              limiter=limiter, source_type="website")
                    target = Target(raw=raw, type="crypto_wallet", normalized=raw)
                    timeout = min(int(getattr(plugin, "timeout_s", 60) or 60), 120)
                    if getattr(plugin, "lane", "fast") != "fast":
                        timeout = 180
                    try:
                        res = await asyncio.wait_for(plugin.run(target, ctx), timeout=timeout)
                        findings = res.findings or []
                    except Exception as e:  # noqa: BLE001
                        errors.append({"plugin": pid, "address": address, "error": f"{type(e).__name__}: {e}"[:300]})
                        print(f"ERROR {pid} {address}: {type(e).__name__}: {e}"[:300], flush=True)
                        continue
                    for f in findings:
                        ev = f.evidence or {}
                        rec = {
                            "plugin": pid, "key": f.key,
                            "severity": str(ev.get("severity") or f.bounty_value or "").lower(),
                            "function": str(ev.get("function") or ""),
                            "recipient": str(ev.get("recipient") or ""),
                            "report_class": str(ev.get("report_class") or ""),
                            "chain": chain, "address": address, "name": name,
                        }
                        rec["recipient_class"] = recipient_class(rec)
                        rec["evidence"] = {"recipient": rec["recipient"],
                                           "report_class": rec["report_class"]}
                        rows.append(rec)
                    print(f"done {pid} {name}: {len(findings)} findings", flush=True)
        return rows, errors

    rows = asyncio.run(run_all())
    findings_rows, errors = rows

    candidates = [r for r in findings_rows
                  if r["severity"] in ("high", "critical")
                  and r["recipient_class"] in ("CALLER", "CALLER-SUPPLIED")]
    got = {(r["plugin"], r["address"].lower(), r["function"]) for r in candidates}
    per_plugin = Counter(r["plugin"] for r in candidates)
    per_plugin_findings = Counter(r["plugin"] for r in findings_rows)
    result = {
        "label": args.label or args.backend,
        "backend": backend,
        "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "plugin_ids": PLUGIN_IDS,
        "targets": [{"chain": c, "address": a, "name": n} for c, a, n in TARGETS],
        "total_findings": len(findings_rows),
        "findings_per_plugin": {p: per_plugin_findings.get(p, 0) for p in PLUGIN_IDS},
        "total_candidates": len(candidates),
        "candidates_per_plugin": {p: per_plugin.get(p, 0) for p in PLUGIN_IDS},
        "expected_total": len(EXPECTED),
        "matched_expected": sorted(got & EXPECTED),
        "missing_expected_silenced": sorted(EXPECTED - got),
        "extra_candidates_not_in_round1": sorted(got - EXPECTED),
        "errors": errors,
        "candidates": candidates,
        "all_findings": findings_rows,
    }
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = HOME / out_path
    out_path.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in (
        "label", "total_findings", "findings_per_plugin",
        "total_candidates", "candidates_per_plugin", "expected_total",
        "errors")}, indent=2), flush=True)
    print(f"silenced (expected but gone): {len(EXPECTED - got)}", flush=True)
    for row in sorted(EXPECTED - got):
        print(f"  SILENCED {row}", flush=True)
    print(f"still firing (expected): {len(got & EXPECTED)}", flush=True)
    for row in sorted(got & EXPECTED):
        print(f"  STILL {row}", flush=True)
    print(f"extra: {sorted(got - EXPECTED)}", flush=True)
    print(f"wrote {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
