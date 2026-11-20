"""Live-use run for deep_audit29 (AI dev, 2026-11-20).

Runs the 4 new detectors plus relevant existing ones against the
locally cached verified sources in ~/workspace/recon-verify/src_cache
and ~/workspace/recon-10k/src_cache (deduplicated by address).
Detection only: static analysis of cached source, no network,
no transactions. Writes one JSON object per fire to
runs/2026-11-20-deep-audit29-fires.jsonl in the worktree (falls back
to /tmp when the disk-quota wave blocks the worktree write).
"""
import glob
import json
import os
import re
import sys
import traceback

WT = "/home/hatch/workspace/wt/recon-dev-2026-11-20/backend"
sys.path.insert(0, WT)

from app.plugins import deep_audit2 as da2  # noqa: E402
from app.plugins import deep_audit3 as da3  # noqa: E402
from app.plugins import deep_audit5 as da5  # noqa: E402
from app.plugins import deep_audit6 as da6  # noqa: E402
from app.plugins import deep_audit10 as da10  # noqa: E402
from app.plugins import deep_audit11 as da11  # noqa: E402
from app.plugins import deep_audit20 as da20  # noqa: E402
from app.plugins import deep_audit23 as da23  # noqa: E402
from app.plugins import deep_audit24 as da24  # noqa: E402
from app.plugins import deep_audit25 as da25  # noqa: E402
from app.plugins import deep_audit29 as da29  # noqa: E402
from app.plugins import business_logic as bl  # noqa: E402
from app.plugins import recipient_first as rf  # noqa: E402
from app.plugins import bsc_access as access  # noqa: E402
from app.plugins import bsc_mev_bridge as mevb  # noqa: E402
from app.plugins import bsc_staking as stk  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402

OUT = ("/home/hatch/workspace/wt/recon-dev-2026-11-20/runs/"
       "2026-11-20-deep-audit29-fires.jsonl")
OUT_FALLBACK = "/tmp/2026-11-20-deep-audit29-fires.jsonl"

DETECTORS = []
for spec in da29.SPECS:
    DETECTORS.append((spec.id, spec, da29.analyze_deep29_source))
for pid in ("recipient_overdraw_withdraw",
            "recipient_unbacked_claim"):
    DETECTORS.append((pid, pid, lambda src, spec, compiler="",
                      contract_name="":
                      rf.analyze_recipient_source(src, spec)))
for spec in da2.SPECS:
    if spec.id in ("fee_on_transfer_overcredit",
                   "bridge_replay_unbound_digest"):
        DETECTORS.append((spec.id, spec, da2.analyze_deep2_source))
for spec in da3.SPECS:
    if spec.id in ("eip712_digest_unbound_to_payload",
                   "share_transfer_cancel_desync"):
        DETECTORS.append((spec.id, spec, da3.analyze_deep3_source))
for spec in da5.SPECS:
    if spec.id in ("signature_nonce_unconsumed",):
        DETECTORS.append((spec.id, spec, da5.analyze_deep5_source))
for spec in da6.SPECS:
    if spec.id in ("unchecked_math_user_input",):
        DETECTORS.append((spec.id, spec, da6.analyze_deep6_source))
for spec in da10.SPECS:
    if spec.id in ("liquidation_bonus_to_borrower",):
        DETECTORS.append((spec.id, spec, da10.analyze_deep10_source))
for spec in da11.SPECS:
    if spec.id in ("liquidation_residual_collateral_reborrow",):
        DETECTORS.append((spec.id, spec, da11.analyze_deep11_source))
for spec in da20.SPECS:
    if spec.id in ("liquidation_caller_supplied_price",):
        DETECTORS.append((spec.id, spec, da20.analyze_deep20_source))
for spec in da23.SPECS:
    if spec.id in ("internal_transfer_credit_without_debit",):
        DETECTORS.append((spec.id, spec, da23.analyze_deep23_source))
for spec in da24.SPECS:
    if spec.id in ("bridge_release_value_unbound_to_proof",):
        DETECTORS.append((spec.id, spec, da24.analyze_deep24_source))
for spec in da25.SPECS:
    if spec.id in ("multicall_arbitrary_delegatecall",):
        DETECTORS.append((spec.id, spec, da25.analyze_deep25_source))
for spec in bl.SPECS:
    if spec.id in ("reward_distribution_manipulation",):
        DETECTORS.append((spec.id, spec,
                          bl.analyze_business_logic_source))
for spec in mevb.SPECS:
    if spec.id in ("bridge_wrapped_token_mint_unbacked",
                   "bridge_withdrawer_identity_spoof",
                   "bridge_deposit_event_spoofing"):
        DETECTORS.append(
            (spec.id, spec,
             lambda src, spec, compiler="", contract_name="":
             analyze_bsc_source(src, spec)))
for spec in stk.SPECS:
    if spec.id in ("staking_total_shares_mismatch",):
        DETECTORS.append(
            (spec.id, spec,
             lambda src, spec, compiler="", contract_name="":
             analyze_bsc_source(src, spec)))
for spec in access.SPECS:
    if spec.id in ("access_control_arbitrary_call_injection",):
        DETECTORS.append(
            (spec.id, spec,
             lambda src, spec, compiler="", contract_name="":
             analyze_bsc_source(src, spec)))


def parse_filename(path):
    base = os.path.basename(path)[:-len(".json")]
    m = re.match(r"^([A-Za-z0-9]+)[-_](0x[0-9a-fA-F]{40})$", base)
    if not m:
        return None, None
    return m.group(1).lower(), m.group(2).lower()


def main():
    sources = {}  # address -> (chain, source, contract_name)
    for d in ("/home/hatch/workspace/recon-verify/src_cache",
              "/home/hatch/workspace/recon-10k/src_cache"):
        for path in sorted(glob.glob(os.path.join(d, "*.json"))):
            chain, addr = parse_filename(path)
            if not addr or addr in sources:
                continue
            try:
                data = json.load(open(path))
            except Exception:
                continue
            if data.get("ok") is False:
                continue
            src = data.get("source") or ""
            if not src or "{" not in src:
                continue
            sources[addr] = (chain, src,
                             data.get("contract_name") or
                             data.get("name") or "")
    print(f"unique sources with code: {len(sources)}")

    fires = []
    errors = 0
    scanned = 0
    for addr, (chain, src, cname) in sorted(sources.items()):
        scanned += 1
        for pid, spec, fn in DETECTORS:
            try:
                hits = fn(src, spec, contract_name=cname)
            except Exception:
                errors += 1
                if errors <= 5:
                    traceback.print_exc()
                continue
            for h in hits or []:
                fires.append({
                    "plugin": pid,
                    "chain": chain,
                    "address": addr,
                    "kind": h.get("kind"),
                    "function": h.get("function"),
                    "recipient": h.get("recipient"),
                    "report_class": h.get("report_class"),
                    "severity": h.get("severity"),
                    "contract_name": cname,
                    "detail": (h.get("detail") or "")[:600],
                })
    dedup = {}
    for f in fires:
        k = (f["plugin"], f["chain"], f["address"], f["kind"],
             f["function"])
        dedup.setdefault(k, f)
    print(f"scanned: {scanned}, analyzer errors: {errors}, "
          f"raw fires: {len(fires)}, deduped fires: {len(dedup)}")
    from collections import Counter
    print("by plugin:", dict(Counter(
        f["plugin"] for f in dedup.values())))
    print("by report_class:", dict(Counter(
        f["report_class"] for f in dedup.values())))
    out = OUT
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as fh:
            for f in sorted(dedup.values(),
                            key=lambda x: (x["plugin"], x["chain"],
                                           x["address"])):
                fh.write(json.dumps(f) + "\n")
    except OSError as e:
        print(f"worktree write blocked ({e}); falling back to "
              f"{OUT_FALLBACK}")
        out = OUT_FALLBACK
        with open(out, "w") as fh:
            for f in sorted(dedup.values(),
                            key=lambda x: (x["plugin"], x["chain"],
                                           x["address"])):
                fh.write(json.dumps(f) + "\n")
    print(f"wrote {out} ({len(dedup)} lines)")


if __name__ == "__main__":
    main()
