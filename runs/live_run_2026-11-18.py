"""Live-use run for deep_audit25 (AI dev, 2026-11-18).

Runs the 5 new detectors plus relevant existing ones against the
locally cached verified sources in ~/workspace/recon-verify/src_cache
and ~/workspace/recon-10k/src_cache (deduplicated by address).
Detection only: static analysis of cached source, no network,
no transactions. Writes one JSON object per fire to
runs/2026-11-18-fires.jsonl in the worktree (falls back to
/srv/quota-tmp when the disk-quota wave blocks the worktree write).
"""
import glob
import json
import os
import re
import sys
import traceback

WT = "/home/hatch/workspace/wt/quota/2026-11-18-recon-anything/backend"
sys.path.insert(0, WT)

from app.plugins import deep_audit2 as da2  # noqa: E402
from app.plugins import deep_audit5 as da5  # noqa: E402
from app.plugins import deep_audit8 as da8  # noqa: E402
from app.plugins import deep_audit10 as da10  # noqa: E402
from app.plugins import deep_audit15 as da15  # noqa: E402
from app.plugins import deep_audit20 as da20  # noqa: E402
from app.plugins import deep_audit22 as da22  # noqa: E402
from app.plugins import deep_audit24 as da24  # noqa: E402
from app.plugins import deep_audit25 as da25  # noqa: E402
from app.plugins import bsc_gamefi as gamefi  # noqa: E402
from app.plugins import bsc_mev_bridge as mevb  # noqa: E402
from app.plugins import bsc_staking as staking  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402

OUT = ("/home/hatch/workspace/wt/quota/2026-11-18-recon-anything/"
       "runs/2026-11-18-fires.jsonl")
OUT_FALLBACK = "/srv/quota-tmp/2026-11-18-fires.jsonl"

DETECTORS = []
for spec in da25.SPECS:
    DETECTORS.append((spec.id, spec, da25.analyze_deep25_source))
for spec in da24.SPECS:
    if spec.id in ("merkle_proof_unbounded_leaf_index",):
        DETECTORS.append((spec.id, spec, da24.analyze_deep24_source))
for spec in da20.SPECS:
    if spec.id in ("merkle_claim_no_claimed_marker",
                   "auction_bid_no_prior_refund"):
        DETECTORS.append((spec.id, spec, da20.analyze_deep20_source))
for spec in da22.SPECS:
    if spec.id in ("claim_guard_wrong_key_replay",):
        DETECTORS.append((spec.id, spec, da22.analyze_deep22_source))
for spec in da15.SPECS:
    if spec.id in ("claim_callback_before_claimed_flag",):
        DETECTORS.append((spec.id, spec, da15.analyze_deep15_source))
for spec in da8.SPECS:
    if spec.id in ("multicall_value_reuse",
                   "merkle_leaf_single_hash"):
        DETECTORS.append((spec.id, spec, da8.analyze_deep8_source))
for spec in da10.SPECS:
    if spec.id in ("multicall_2771_sender_spoof",):
        DETECTORS.append((spec.id, spec, da10.analyze_deep10_source))
for spec in da5.SPECS:
    if spec.id in ("erc721_mint_without_receiver_check",):
        DETECTORS.append((spec.id, spec, da5.analyze_deep5_source))
for spec in da2.SPECS:
    if spec.id in ("eip7702_unverified_delegate",):
        DETECTORS.append((spec.id, spec, da2.analyze_deep2_source))
for spec in mevb.SPECS:
    if spec.id in ("bridge_deposit_event_spoofing",):
        DETECTORS.append(
            (spec.id, spec,
             lambda src, spec, compiler="", contract_name="":
             analyze_bsc_source(src, spec)))
for spec in gamefi.SPECS:
    if spec.id in ("bep721_mint_index_overflow",
                   "bep721_reentrancy_on_safe_mint",
                   "gamefi_state_desync_reward_claim",
                   "marketplace_expired_order_execution"):
        DETECTORS.append(
            (spec.id, spec,
             lambda src, spec, compiler="", contract_name="":
             analyze_bsc_source(src, spec)))
for spec in staking.SPECS:
    if spec.id in ("masterchef_deposit_fee_skimming",
                   "staking_total_shares_mismatch",
                   "staking_reward_compounding_reentrancy"):
        DETECTORS.append(
            (spec.id, spec,
             lambda src, spec, compiler="", contract_name="":
             analyze_bsc_source(src, spec)))
for pid in ("recipient_mint_to_caller",
            "recipient_unbacked_claim"):
    DETECTORS.append(
        (pid, pid,
         lambda src, spec, compiler="", contract_name="":
         analyze_recipient_source(src, spec, compiler,
                                  contract_name)))


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
