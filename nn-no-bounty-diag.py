"""Diagnostic: best config (120 ep, 64,32, std external) with the
bounty_value feature zeroed everywhere. bounty_value is label-
correlated in the external set (built from the severity that set the
label) and near-constant on Jay's own rows, so it may be inflating
the mixed test and biasing live scores. If the own-test holds or
improves without it, the feature should be dropped from the spec.
"""
import sys
sys.path.insert(0, "/home/hatch/workspace/wt/nn-scorer/backend")

from app.nn.data import build_dataset, load_external_rows, stratified_split
from app.nn.features import build_vocab, extract
from app.nn.mlp import MLP, metrics_for

own = build_dataset("/home/hatch/workspace/recon-continuous/results/candidates.jsonl",
                     "/home/hatch/workspace/recon-continuous/results/batches.jsonl")
own_train, own_test = stratified_split(own["rows"], 0.2, 42)
ext, _ = load_external_rows("/home/hatch/workspace/wt/nn-scorer/backend/app/nn/external_findings.jsonl")
train_rows = own_train + ext
spec = build_vocab([r["finding"] for r in train_rows])
names = spec.feature_names()
bi = names.index("bounty_value")
print(f"dim={spec.dim} bounty_value index={bi}", flush=True)

def vecs(rows):
    out = []
    for r in rows:
        v = extract(r["finding"], spec)
        v[bi] = 0.0
        out.append(v)
    return out

Xtr = vecs(train_rows)
ytr = [r["label"] for r in train_rows]
Xte = vecs(own_test)
yte = [r["label"] for r in own_test]
net = MLP([spec.dim, 64, 32, 1], seed=42, lr=0.05)
net.fit(Xtr, ytr, epochs=120, batch_size=32, seed=42, history_every=1000)
m = metrics_for(yte, [net.predict_proba(x) for x in Xte])
cm = m["confusion"]
print(f"NO-BOUNTY 120ep 64,32: acc={m['accuracy']:.4f} base={m['majority_baseline_accuracy']:.4f} "
      f"auc={m['roc_auc']:.4f} fp-recall={m['recall_likely_fp']:.3f} "
      f"wv-recall={m['recall_worth_validating']:.3f} "
      f"cm tp={cm['tp']} fp={cm['fp']} fn={cm['fn']} tn={cm['tn']}", flush=True)
