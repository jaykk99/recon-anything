"""Live-use run for deep_audit32 (AI dev, 2026-11-23).

Runs the 5 new detectors plus relevant existing ones against the
locally cached verified sources in ~/workspace/recon-verify/src_cache
and ~/workspace/recon-10k/src_cache (deduplicated by address).
Detection only: static analysis of cached source, no network,
no transactions. Writes one JSON object per fire to
runs/2026-11-23-deep-audit32-fires.jsonl in the worktree (falls back
to /tmp when the disk-quota wave blocks the worktree write).
NOTE: runs/2026-11-22-deep-audit30-fires.jsonl already holds the batch-30 run
and is deliberately NOT overwritten by this script. The batch-30
hook-fee pair lives in unmerged PR #208, so it is not importable
from this worktree; it was run over the same corpus from the
Nov 22 worktree in a scratch run (see the daily report).
"""
import glob
import json
import os
import re
import sys
import traceback

WT = "/home/hatch/workspace/wt/recon-dev-2026-11-23/backend"
sys.path.insert(0, WT)

from app.plugins import deep_audit2 as da2  # noqa: E402
from app.plugins import recipient_first as rf  # noqa: E402
from app.plugins import deep_audit3 as da3  # noqa: E402
from app.plugins import deep_audit20b as da20b  # noqa: E402
from app.plugins import deep_audit21 as da21  # noqa: E402
from app.plugins import deep_audit23 as da23  # noqa: E402
from app.plugins import deep_audit as da1  # noqa: E402
from app.plugins import deep_audit28 as da28  # noqa: E402
from app.plugins import deep_audit32 as da32  # noqa: E402
from app.plugins import bsc_access as access  # noqa: E402
from app.plugins import bsc_mev_bridge as mevb  # noqa: E402
from app.plugins import deep_audit6 as da6  # noqa: E402
from app.plugins import cryptopack_protocol as cpp  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402

OUT = ("/home/hatch/workspace/wt/recon-dev-2026-11-23/runs/"
       "2026-11-23-deep-audit32-fires.jsonl")
OUT_FALLBACK = "/tmp/2026-11-23-deep-audit32-fires.jsonl"

DETECTORS = []
for spec in da32.SPECS:
    DETECTORS.append((spec.id, spec, da32.analyze_deep32_source))
for spec in mevb.SPECS:
    DETECTORS.append(
        (spec.id, spec,
         lambda src, spec, compiler="", contract_name="":
         analyze_bsc_source(src, spec)))
for spec in da1.SPECS:
    if spec.id in ("aa_validation_ungated", "vault_share_inflation"):
        DETECTORS.append((spec.id, spec, da1.analyze_deep_source))
for pid in ("recipient_overdraw_withdraw",
            "recipient_unbacked_claim",
            "recipient_rescue_to_param"):
    DETECTORS.append((pid, pid, lambda src, spec, compiler="",
                      contract_name="":
                      rf.analyze_recipient_source(src, spec)))
for spec in da2.SPECS:
    if spec.id in ("fee_on_transfer_overcredit",
                   "hook_cei_reentrancy"):
        DETECTORS.append((spec.id, spec, da2.analyze_deep2_source))
for spec in da3.SPECS:
    if spec.id in ("eip712_digest_unbound_to_payload",
                   "v4_hook_shared_delta_take_pair"):
        DETECTORS.append((spec.id, spec, da3.analyze_deep3_source))
for spec in da20b.SPECS:
    if spec.id in ("cover_capacity_counts_unpaid_prior_period",):
        DETECTORS.append((spec.id, spec,
                          da20b.analyze_deep20_source))
for spec in da21.SPECS:
    if spec.id in ("period_start_checkpoint_zeroes_payout_cap",
                   "rescue_marks_future_bucket_claimed"):
        DETECTORS.append((spec.id, spec,
                          da21.analyze_deep21_source))
for spec in da23.SPECS:
    if spec.id in ("stale_capacity_snapshot_after_payout",):
        DETECTORS.append((spec.id, spec,
                          da23.analyze_deep23_source))
for spec in da28.SPECS:
    if spec.id in ("share_price_excludes_subthreshold_collateral",
                   "period_exit_writes_new_period_exposure_snapshot"):
        DETECTORS.append((spec.id, spec, da28.analyze_deep28_source))
for spec in da6.SPECS:
    if spec.id in ("chainlink_price_unbounded",):
        DETECTORS.append((spec.id, spec, da6.analyze_deep6_source))
for spec in access.SPECS:
    if spec.id in ("access_control_arbitrary_call_injection",):
        DETECTORS.append(
            (spec.id, spec,
             lambda src, spec, compiler="", contract_name="":
             analyze_bsc_source(src, spec)))


def _cp_proto_slippage(src, spec, compiler="", contract_name=""):
    return [{"kind": "cp_proto_unbounded_slippage",
             "severity": "medium",
             "function": f.get("function", ""),
             "code": f.get("snippet", ""),
             "detail": f.get("detail", ""),
             "gate_analysis": ""}
            for f in cpp.audit_protocol_source(src)
            if f["check"] == "unbounded_slippage"]


DETECTORS.append(("cp_proto_unbounded_slippage", "cp_proto",
                  _cp_proto_slippage))


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
