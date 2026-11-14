"""Live-use run for deep_audit21 (AI dev, 2026-11-14).

Runs the 5 new detectors plus relevant existing ones against the locally
cached verified sources in ~/workspace/recon-verify/src_cache and
~/workspace/recon-10k/src_cache (deduplicated by address).
Detection only: static analysis of cached source, no network,
no transactions. Writes one JSON object per fire to
runs/2026-11-14-fires.jsonl in the worktree (falls back to /tmp when the
disk-quota wave blocks the worktree write).
"""
import glob
import json
import os
import re
import sys
import traceback

WT = "/home/hatch/workspace/wt/recon-dev-2026-11-14/backend"
sys.path.insert(0, WT)

from app.plugins import deep_audit as da1  # noqa: E402
from app.plugins import deep_audit2 as da2  # noqa: E402
from app.plugins import deep_audit4 as da4  # noqa: E402
from app.plugins import deep_audit6 as da6  # noqa: E402
from app.plugins import deep_audit12 as da12  # noqa: E402
from app.plugins import deep_audit13 as da13  # noqa: E402
from app.plugins import deep_audit15 as da15  # noqa: E402
from app.plugins import deep_audit21 as da21  # noqa: E402
from app.plugins import bsc_mev_bridge as mevb  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402

OUT = ("/home/hatch/workspace/wt/recon-dev-2026-11-14/runs/"
       "2026-11-14-fires.jsonl")
OUT_FALLBACK = "/tmp/2026-11-14-fires.jsonl"

DETECTORS = []
for spec in da21.SPECS:
    DETECTORS.append((spec.id, spec, da21.analyze_deep21_source))
# Relevant existing detectors: nearest neighbours + the usual
# live-run set (vault, fee-on-transfer, sweep, bridge mint,
# settlement, zero-amount, TWAP window, post-slash offset,
# share-transfer desync).
for spec in da1.SPECS:
    if spec.id == "vault_share_inflation":
        DETECTORS.append((spec.id, spec, da1.analyze_deep_source))
for spec in da2.SPECS:
    if spec.id == "fee_on_transfer_overcredit":
        DETECTORS.append((spec.id, spec, da2.analyze_deep2_source))
for spec in da4.SPECS:
    if spec.id == "share_transfer_cancel_desync":
        DETECTORS.append((spec.id, spec, da4.analyze_deep4_source))
for spec in da6.SPECS:
    if spec.id == "twap_observe_window_short":
        DETECTORS.append((spec.id, spec, da6.analyze_deep6_source))
for spec in da12.SPECS:
    if spec.id in ("zero_amount_withdrawal_full_balance",
                   "scheduled_settlement_books_unpaid"):
        DETECTORS.append((spec.id, spec, da12.analyze_deep12_source))
for spec in da13.SPECS:
    if spec.id == "residual_balance_sweep_ungated":
        DETECTORS.append((spec.id, spec, da13.analyze_deep13_source))
for spec in da15.SPECS:
    if spec.id == "post_slash_erc4626_offset_inversion":
        DETECTORS.append((spec.id, spec, da15.analyze_deep15_source))
for spec in mevb.SPECS:
    if spec.id == "bridge_wrapped_token_mint_unbacked":
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
