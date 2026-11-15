"""Quick check: v3 context joins actually hit on real rows.
Prints dataset stats + context coverage + a sample context dict.
Run detached: nohup python3 -m app.nn.check-v3-context > ../nn-logs/check-v3-context.log 2>&1 &
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.nn.data import build_dataset
from app.nn.features import build_vocab, extract

CAND = os.path.expanduser("~/workspace/recon-continuous/results/candidates.jsonl")
BATCH = os.path.expanduser("~/workspace/recon-continuous/results/batches.jsonl")
FRESH = os.path.expanduser("~/workspace/recon-continuous/targets-2026-11-12/fresh-deploys-more-chains.jsonl")
TRANS = os.path.expanduser("~/workspace/recon-continuous/state/transition_events.jsonl")

ds = build_dataset(CAND, BATCH, fresh_deploys_path=FRESH, transitions_path=TRANS)
print("STATS", json.dumps(ds["stats"], indent=1), flush=True)
rows = ds["rows"]
reg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "registry-plugin-ids.json")))
spec = build_vocab([r["finding"] for r in rows], registry_plugins=reg)
print("SPEC dim", spec.dim, "plugins", len(spec.plugins), "keys", len(spec.keys), flush=True)
import collections
nz_counts = collections.Counter()
ctx_hit = 0
for r in rows:
    v = extract(r["finding"], spec)
    assert len(v) == spec.dim
    nz = sum(1 for x in v if x != 0.0)
    nz_counts[nz] += 1
    ctx = r["finding"].get("context") or {}
    if ctx.get("n_findings"):
        ctx_hit += 1
print("rows with batch context:", ctx_hit, "of", len(rows), flush=True)
print("nonzero-count histogram (top 10):", nz_counts.most_common(10), flush=True)
# show one real context dict
for r in rows:
    ctx = r["finding"].get("context") or {}
    if ctx.get("deployer_present") or ctx.get("owner_events"):
        print("SAMPLE-ROW", r["chain"], r["address"], r["plugin"], json.dumps(ctx), flush=True)
        break
print("CHECK-DONE", flush=True)
