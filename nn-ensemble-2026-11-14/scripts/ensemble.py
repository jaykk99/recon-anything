"""Combine the three member score files into ensemble metrics.

Pure Python stdlib. No model code, no training, no test-set fitting:
the ensembles are fixed rules applied to member scores that were
themselves produced only from training rows + the fixed holdout.

Inputs: three JSONL files (v2 / hypergraph / multimodal), one line
per test row: {key, label, score}. Rows are aligned by the full key
(chain, address, plugin, key, label); labels must agree across all
three files and n must be 145.

Outputs:
- <out_prefix>-combined.jsonl: one line per row with all three
  member scores plus avg3, majority vote and avg(multi+hyper).
- <out_prefix>-metrics.json: acc / AUC / confusion / WV recall /
  FP recall for every member and every ensemble, plus agreement
  counts and the rows where the ensembles disagree with multimodal.

Ensembles:
- avg3: mean of the three member probabilities, threshold 0.5.
- majority: majority of the three member 0.5-threshold votes
  (ties impossible with 3 voters).
- avg_multi_hyper (diagnostic only): mean of multimodal + hypergraph.
- avg_v2_multi, avg_v2_hyper (diagnostics): pairwise means.

Usage: python3 ensemble.py <v2.jsonl> <hyper.jsonl> <multi.jsonl>
         <out_prefix>
"""
import json
import sys


def roc_auc(scores, labels):
    """Rank-based ROC AUC (Mann-Whitney), ties get 0.5 credit."""
    pairs = sorted(zip(scores, labels), key=lambda t: t[0])
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    # rank with tie averaging, 1-based
    total = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            j += 1
        rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            if pairs[k][1] == 1:
                total += rank
        i = j
    return (total - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def metrics(y, scores, name):
    pred = [1 if s >= 0.5 else 0 for s in scores]
    tp = sum(1 for a, p in zip(y, pred) if a == 1 and p == 1)
    fp = sum(1 for a, p in zip(y, pred) if a == 0 and p == 1)
    fn = sum(1 for a, p in zip(y, pred) if a == 1 and p == 0)
    tn = sum(1 for a, p in zip(y, pred) if a == 0 and p == 0)
    n = len(y)
    return {
        "name": name,
        "n": n,
        "accuracy": round((tp + tn) / n, 4),
        "correct": tp + tn,
        "roc_auc": round(roc_auc(scores, y), 4),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "wv_recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "fp_recall": round(tn / (tn + fp), 4) if tn + fp else 0.0,
        "wv_precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "fp_precision": round(tn / (tn + fn), 4) if tn + fn else 0.0,
    }


def main():
    v2_path, hyper_path, multi_path, prefix = sys.argv[1:5]

    def load(path):
        return [json.loads(line) for line in open(path, encoding="utf-8")
                if line.strip()]

    v2_rows = load(v2_path)
    hyper_rows = load(hyper_path)
    multi_rows = load(multi_path)
    # Align POSITIONALLY in split order: the 5-field key is not unique
    # (4 keys occur twice among the 145 rows), so dict-keying would
    # collapse rows. The raw split-order key sequences must be
    # identical across all three files (same split, same order).
    for name, rows in (("v2", v2_rows), ("hypergraph", hyper_rows),
                       ("multimodal", multi_rows)):
        assert len(rows) == 145, f"{name} rows {len(rows)} != 145"
    keys = [tuple(r["key"]) for r in v2_rows]
    assert [tuple(r["key"]) for r in hyper_rows] == keys, \
        "hypergraph split-order keys differ from v2"
    assert [tuple(r["key"]) for r in multi_rows] == keys, \
        "multimodal split-order keys differ from v2"
    y = []
    s_v2, s_hyper, s_multi = [], [], []
    for kv, kh, km in zip(v2_rows, hyper_rows, multi_rows):
        assert kv["label"] == kh["label"] == km["label"], \
            f"label mismatch on {kv['key']}"
        y.append(kv["label"])
        s_v2.append(kv["score"])
        s_hyper.append(kh["score"])
        s_multi.append(km["score"])
    n_pos = sum(y)
    print(f"aligned n=145 pos={n_pos} neg={145 - n_pos} "
          f"baseline={max(n_pos, 145 - n_pos) / 145:.4f}", flush=True)

    avg3 = [(a + b + c) / 3.0 for a, b, c in zip(s_v2, s_hyper, s_multi)]
    # Majority vote: the ranking score is the vote FRACTION (0, 1/3,
    # 2/3, 1), so its ROC AUC is meaningful; threshold 0.5 on it is
    # exactly ">= 2 of 3 votes". A 0/1 score would collapse the AUC
    # to the binary-output value and would not be comparable to the
    # continuous-score AUCs, so the fraction is used, not 0/1.
    maj = [sum(1 for s in (a, b, c) if s >= 0.5) / 3.0
           for a, b, c in zip(s_v2, s_hyper, s_multi)]
    avg_mh = [(b + c) / 2.0 for b, c in zip(s_hyper, s_multi)]
    avg_vm = [(a + c) / 2.0 for a, c in zip(s_v2, s_multi)]
    avg_vh = [(a + b) / 2.0 for a, b in zip(s_v2, s_hyper)]

    results = {
        "holdout": {"n": 145, "pos": n_pos, "neg": 145 - n_pos,
                    "baseline": round(max(n_pos, 145 - n_pos) / 145, 4),
                    "seed": 42, "threshold": 0.5},
        "members": [
            metrics(y, s_v2, "v2 255-64-32-1"),
            metrics(y, s_hyper, "hypergraph 255-16-16-1"),
            metrics(y, s_multi, "multimodal 290-64-32-1"),
        ],
        "ensembles": [
            metrics(y, avg3, "ensemble avg3 (equal mean of 3)"),
            metrics(y, maj, "ensemble majority vote (3 voters)"),
            metrics(y, avg_mh, "diagnostic avg multimodal+hypergraph"),
            metrics(y, avg_vm, "diagnostic avg v2+multimodal"),
            metrics(y, avg_vh, "diagnostic avg v2+hypergraph"),
        ],
    }
    # Agreement / disagreement diagnostics.
    def votes(s):
        return [1 if x >= 0.5 else 0 for x in s]

    vv, vh, vm = votes(s_v2), votes(s_hyper), votes(s_multi)
    results["agreement"] = {
        "all_three_agree": sum(1 for a, b, c in zip(vv, vh, vm)
                               if a == b == c),
        "all_three_correct": sum(
            1 for a, b, c, t in zip(vv, vh, vm, y) if a == b == c == t),
        "multimodal_correct_others_wrong": sum(
            1 for a, b, c, t in zip(vv, vh, vm, y)
            if c == t and a != t and b != t),
        "multimodal_wrong_others_right": sum(
            1 for a, b, c, t in zip(vv, vh, vm, y)
            if c != t and a == t and b == t),
        "unanimous_wrong": sum(
            1 for a, b, c, t in zip(vv, vh, vm, y)
            if a == b == c and a != t),
    }
    # Rows where an ensemble flips multimodal's call, with truth.
    flips = []
    for k, t, a3, m, c in zip(keys, y, avg3, maj, vm):
        m_vote = 1 if m >= 0.5 else 0
        if (1 if a3 >= 0.5 else 0) != c or m_vote != c:
            flips.append({"key": list(k), "label": t,
                          "avg3_score": round(a3, 4),
                          "majority_vote": m_vote,
                          "multimodal_vote": int(c),
                          "avg3_correct": (1 if a3 >= 0.5 else 0) == t,
                          "majority_correct": m_vote == t})
    results["flips_vs_multimodal"] = flips

    with open(prefix + "-combined.jsonl", "w", encoding="utf-8") as fh:
        for k, t, a, b, c, a3, m, mh in zip(
                keys, y, s_v2, s_hyper, s_multi, avg3, maj, avg_mh):
            fh.write(json.dumps({
                "key": list(k), "label": t,
                "v2": a, "hypergraph": b, "multimodal": c,
                "avg3": a3, "majority": (1 if m >= 0.5 else 0),
                "majority_fraction": m,
                "avg_multi_hyper": mh}) + "\n")
    with open(prefix + "-metrics.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    for m in results["members"] + results["ensembles"]:
        cm = m["confusion"]
        print(f"{m['name']}: acc={m['accuracy']:.4f} "
              f"auc={m['roc_auc']:.4f} "
              f"tp={cm['tp']} fp={cm['fp']} fn={cm['fn']} tn={cm['tn']} "
              f"wv_rec={m['wv_recall']:.3f} fp_rec={m['fp_recall']:.3f}",
              flush=True)
    print(f"agreement: {results['agreement']}", flush=True)
    print(f"flips vs multimodal: {len(flips)} rows", flush=True)


if __name__ == "__main__":
    main()
