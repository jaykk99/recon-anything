"""Build the bigger external set (caps 1,200) for Job 2 batch 2.

Runs build_external_dataset with xanoutas + audit-findings caps
raised 450 -> 1,200 (the documented 3,422-row variant), from the
fetched rows (nn-logs/job2/*-rows.jsonl) and the local
scabench/defihack JSON. Sherlock-invalid rows are NOT re-fetched
(the original gh search script is gone and its exact query is
unknown): the 293 mapped Sherlock rows are carried over verbatim
from the current external_findings.jsonl (same real rows, same
labels, same provenance; their per-repo plugin counts were computed
on this same set, so they stay valid).

Usage: python3 nn-logs/build_external_3422.py
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "backend")))

from app.nn.build_external_dataset import main as build_main  # noqa: E402

NN_DIR = os.path.normpath(os.path.join(_HERE, "..", "backend", "app", "nn"))
JOB2_DIR = os.path.join(_HERE, "job2")
SOURCES = os.path.expanduser("~/workspace/nn-multichain-sources")
OUT = os.path.join(JOB2_DIR, "external-3422.jsonl")
CURRENT_EXT = os.path.join(NN_DIR, "external_findings.jsonl")


def main():
    for p in [os.path.join(JOB2_DIR, "xanoutas-rows.jsonl"),
              os.path.join(JOB2_DIR, "auditfindings-rows.jsonl")]:
        assert os.path.exists(p) and os.path.getsize(p) > 0, \
            f"missing fetched rows: {p} (run fetch_external_rows.py first)"
    rc = build_main([
        "--scabench", os.path.join(SOURCES, "scabench.json"),
        "--xanoutas", os.path.join(JOB2_DIR, "xanoutas-rows.jsonl"),
        "--xanoutas-cap", "1200",
        "--defihack", os.path.join(SOURCES, "defihack.json"),
        "--audit-findings",
        os.path.join(JOB2_DIR, "auditfindings-rows.jsonl"),
        "--audit-findings-cap", "1200",
        "--out", OUT,
    ])
    assert rc == 0, f"builder failed: {rc}"
    # Carry over the 293 Sherlock-invalid rows verbatim.
    sherlock = []
    with open(CURRENT_EXT, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if (r.get("source") or {}).get("dataset") == "sherlock-invalid":
                sherlock.append(r)
    print(f"carrying over {len(sherlock)} sherlock-invalid rows verbatim",
          flush=True)
    assert len(sherlock) == 293, f"expected 293, got {len(sherlock)}"
    with open(OUT, "a", encoding="utf-8") as fh:
        for r in sherlock:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    n = sum(1 for _ in open(OUT, encoding="utf-8"))
    print(f"wrote {n} rows to {OUT}", flush=True)
    print("BUILD-3422-DONE", flush=True)


if __name__ == "__main__":
    main()
