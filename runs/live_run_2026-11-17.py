"""Live-use run for deep_audit20 (daily quota grind, 2026-11-17).

Runs the 5 new batch-20 detectors against the locally cached
verified sources in ~/workspace/recon-verify/src_cache and
~/workspace/recon-10k/src_cache (deduplicated by address).
Detection only: static analysis of cached source, no network,
no transactions. Writes one JSON object per fire to
runs/2026-11-17-fires.jsonl in the worktree (falls back to /tmp
when the disk-quota wave blocks the worktree write).
"""
import glob
import json
import os
import re
import sys
import traceback

WT = "/home/hatch/workspace/wt/quota/2026-11-17-recon-anything/backend"
sys.path.insert(0, WT)

from app.plugins import deep_audit20 as da20  # noqa: E402

OUT = ("/home/hatch/workspace/wt/quota/2026-11-17-recon-anything/runs/"
       "2026-11-17-fires.jsonl")
OUT_FALLBACK = "/tmp/2026-11-17-fires.jsonl"

DETECTORS = []
for spec in da20.SPECS:
    DETECTORS.append((spec.id, spec, da20.analyze_deep20_source))


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
    for addr, (chain, src, name) in sorted(sources.items()):
        for pid, spec, fn in DETECTORS:
            try:
                hits = fn(src, spec, "", contract_name=name)
            except Exception:
                errors += 1
                traceback.print_exc()
                continue
            for h in hits:
                fires.append({"address": addr, "chain": chain,
                              "contract_name": name, "plugin": pid,
                              "function": h.get("function"),
                              "severity": h.get("severity"),
                              "report_class": h.get("report_class"),
                              "recipient": h.get("recipient"),
                              "detail": (h.get("detail") or "")[:600],
                              "code": (h.get("code") or "")[:400]})
    print(f"fires: {len(fires)} errors: {errors}")
    by_plugin = {}
    for f in fires:
        by_plugin[f["plugin"]] = by_plugin.get(f["plugin"], 0) + 1
    print(f"per-plugin: {by_plugin}")
    out = OUT
    try:
        with open(out, "w") as fh:
            for f in fires:
                fh.write(json.dumps(f) + "\n")
    except OSError:
        out = OUT_FALLBACK
        with open(out, "w") as fh:
            for f in fires:
                fh.write(json.dumps(f) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
