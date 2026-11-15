"""Resume the FRESH multimodal retrain from its epoch-60 checkpoint.

Context: the fresh-retrain chain (run_retrain.sh) was killed by a
service restart at 2026-11-15 ~00:10 UTC with the multimodal run at
epoch 60/120. The checkpoint (results/fresh/multi/mlp-checkpoint.json,
recon-nn-mlp/1 + epochs_done=60) survived in the persistent workspace.
This script resumes from it instead of redoing 60 epochs, per the
checkpoint/resume rule.

What it does, exactly:
- Rebuilds the SAME dataset / split / vocab / embedder as train()
  (Nov 12 backup candidates, holdout own, seed 42, train 2,502 rows).
- Loads the epoch-60 weights with MLP.from_dict.
- Trains 60 more epochs (seed 42, lr 0.05, batch 32), checkpointing
  every 20 epochs to mlp-checkpoint-resumed.json (the epoch-60 file
  is left untouched), then writes the final weights with
  epochs_done=120.
- Replicates train()'s post-fit evaluation + weights/viewer writing
  (metrics, permutation importance, kNN/blend/retrieval/coverage).

HONEST CAVEAT, recorded in the output: fit() reseeds its shuffle RNG
from seed 42 on every call, so the resumed 60 epochs replay the
epoch 0-59 shuffle sequence on top of epoch-60 weights. This run is
therefore a valid independent retrain on the SAME training rows, but
it is NOT a bit-reproduction of the reval multimodal run (whose
epochs 60-119 used the continuing RNG stream). Exact reproduction
was already established by rescoring the reval weights; the fresh
chain is a robustness confirmation, not a second bit-reproduction.

Usage: run from the nn-reval-multi worktree backend dir:
  python3 resume_multi.py <out_dir>
"""
import datetime as dt
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.getcwd())

from app.nn.data import build_dataset, load_external_rows, stratified_split  # noqa: E402
from app.nn.features import build_vocab, extract  # noqa: E402
from app.nn.mlp import MLP, _write_checkpoint, metrics_for  # noqa: E402
from app.nn.multimodal import (BLEND_KNN, BLEND_MLP, EXTRA_DIM, KNN_K,  # noqa: E402
                               MultimodalEmbedder)
from app.nn.train import (LIMITS, _modality_coverage,  # noqa: E402
                          _refresh_viewer, permutation_importance)

CAND = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCH = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(os.getcwd(), "app", "nn",
                        "external_findings.jsonl")
CKPT60 = os.path.expanduser(
    "~/workspace/wt/nn-ensemble/nn-ensemble-2026-11-14/results/fresh/"
    "multi/mlp-checkpoint.json")


def main() -> None:
    out_dir = sys.argv[1]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(CKPT60, encoding="utf-8") as fh:
        ckpt = json.load(fh)
    assert ckpt.get("epochs_done") == 60, ckpt.get("epochs_done")
    assert ckpt.get("layers") == [290, 64, 32, 1], ckpt.get("layers")
    net = MLP.from_dict(ckpt)
    print(f"resumed multimodal from epoch 60, layers={net.layers}",
          flush=True)

    dataset = build_dataset(CAND, BATCH)
    own_rows = dataset["rows"]
    stats = dataset["stats"]
    ext_rows, ext_stats = load_external_rows(EXTERNAL)
    stats.update(ext_stats)
    stats["train_rows"] = len(own_rows) + len(ext_rows)
    stats["n_positive"] = (sum(1 for r in own_rows if r["label"] == 1)
                           + sum(1 for r in ext_rows if r["label"] == 1))
    stats["n_negative"] = (sum(1 for r in own_rows if r["label"] == 0)
                           + sum(1 for r in ext_rows if r["label"] == 0))
    own_train, test_rows = stratified_split(own_rows, 0.2, 42)
    train_rows = own_train + ext_rows
    stats["holdout"] = "own"
    stats["own_test_rows"] = len(test_rows)
    assert len(train_rows) == 2502 and len(test_rows) == 145, (
        len(train_rows), len(test_rows))
    spec = build_vocab([r["finding"] for r in train_rows])
    X_train = [extract(r["finding"], spec) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract(r["finding"], spec) for r in test_rows]
    y_test = [r["label"] for r in test_rows]
    embedder = MultimodalEmbedder().fit(train_rows)
    embedder.build_index(train_rows)
    X_train = [x + embedder.feature_block(r) for x, r in
               zip(X_train, train_rows)]
    X_test = [x + embedder.feature_block(r) for x, r in
              zip(X_test, test_rows)]

    n_all = len(train_rows) + len(test_rows)
    n_pos = sum(y_train) + sum(y_test)
    n_neg = n_all - n_pos
    pos_pct = 100.0 * n_pos / max(1, n_all)
    limits = list(LIMITS)
    limits[2] = (
        f"Label skew: the training set is {pos_pct:.0f}% worth-validating "
        f"/ {100.0 - pos_pct:.0f}% likely-false-positive "
        f"({n_pos} positive / {n_neg} negative of {n_all} rows). "
        "Accuracy near the majority baseline means the model learned "
        "nothing; judge it by minority-class recall and ROC AUC instead.")

    history = net.fit(X_train, y_train, epochs=60, batch_size=32,
                      X_val=X_test, y_val=y_test, seed=42,
                      checkpoint_path=os.path.join(
                          out_dir, "mlp-checkpoint-resumed.json"),
                      checkpoint_every=20)
    # Cumulative checkpoint: 60 (restored) + 60 (resumed) = 120.
    _write_checkpoint(os.path.join(out_dir, "mlp-checkpoint.json"),
                      net, 120)
    train_scores = [net.predict_proba(x) for x in X_train]
    test_scores = [net.predict_proba(x) for x in X_test]
    train_metrics = metrics_for(y_train, train_scores)
    test_metrics = metrics_for(y_test, test_scores)
    importance = permutation_importance(net, spec, X_test, y_test, 42)
    from app.nn.mlp import roc_auc  # noqa: E402
    import random  # noqa: E402
    base_auc = roc_auc(test_scores, y_test)
    rng = random.Random(42)
    Xp = [list(x) for x in X_test]
    a = spec.dim
    col_vals = [x[a:a + EXTRA_DIM] for x in Xp]
    rng.shuffle(col_vals)
    for row, vals in zip(Xp, col_vals):
        row[a:a + EXTRA_DIM] = vals
    mm_auc = roc_auc([net.predict_proba(x) for x in Xp], y_test)
    importance.append({"group": "multimodal_embeddings",
                       "auc_drop": round(base_auc - mm_auc, 4)})
    importance.sort(key=lambda d: d["auc_drop"], reverse=True)

    knn_scores = [embedder.knn_score(embedder.embed(r)["dense"], KNN_K)
                  for r in test_rows]
    blend_scores = [BLEND_MLP * m + BLEND_KNN * k for m, k in
                    zip(test_scores, knn_scores)]
    retrieval = embedder.retrieval_precision_at_k(test_rows, k=5)
    multimodal_result = {
        "knn_only_metrics": metrics_for(y_test, knn_scores),
        "blend_metrics": metrics_for(y_test, blend_scores),
        "blend_mlp_weight": BLEND_MLP,
        "blend_knn_weight": BLEND_KNN,
        "knn_k": KNN_K,
        "retrieval": retrieval,
        "coverage": _modality_coverage(embedder, train_rows, test_rows),
    }
    layers = [len(X_train[0]), 64, 32, 1]
    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "layers": layers,
        "n_features": len(X_train[0]),
        "n_v2_features": spec.dim,
        "n_multimodal_features": EXTRA_DIM,
        "feature_names": (spec.feature_names()
                          + (["mm_proj:%d" % i for i in range(32)]
                             + ["mm_present:source", "mm_present:bytecode",
                                "mm_present:finding"])),
        "dataset": stats,
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "history": history,
        "feature_importance": importance,
        "limits": limits,
        "seed": 42,
        "epochs": 120,
        "resumed_from_epoch": 60,
        "resume_note": ("Resumed from epoch-60 checkpoint after a "
                        "service restart killed run_retrain.sh; the "
                        "resumed 60 epochs replay the seed-42 shuffle "
                        "sequence from epoch 0, so this is an "
                        "independent retrain on the same rows, not a "
                        "bit-reproduction of the reval run."),
        "lr": 0.05,
        "external": stats.get("external_rows", 0),
        "holdout": "own",
        "multimodal": multimodal_result,
    }
    weights = {
        "format": "recon-nn-weights/1",
        "trained_at": result["trained_at"],
        "mlp": net.to_dict(),
        "features": spec.to_dict(),
        "metrics": {"train": train_metrics, "test": test_metrics},
        "dataset": stats,
        "limits": limits,
        "holdout": "own",
        "multimodal": embedder.to_dict(),
        "multimodal_metrics": multimodal_result,
    }
    (out / "weights.json").write_text(json.dumps(weights, indent=2),
                                      encoding="utf-8")
    (out / "viewer-data.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    _refresh_viewer(out / "viewer.html", result)
    tm = test_metrics
    print(f"rows: train={len(train_rows)} test={len(test_rows)}",
          flush=True)
    print(f"train acc {train_metrics['accuracy']:.3f}  "
          f"test acc {tm['accuracy']:.3f}  majority baseline "
          f"{tm['majority_baseline_accuracy']:.3f}", flush=True)
    print(f"test ROC AUC {tm['roc_auc']:.3f}", flush=True)
    cm = tm["confusion"]
    print(f"confusion (test): tp={cm['tp']} fp={cm['fp']} "
          f"fn={cm['fn']} tn={cm['tn']}", flush=True)
    print(f"multimodal blend (0.7 MLP + 0.3 kNN): acc "
          f"{multimodal_result['blend_metrics']['accuracy']:.3f}  "
          f"AUC {multimodal_result['blend_metrics']['roc_auc']:.3f}",
          flush=True)
    print("RESUMED-MULTI-DONE", flush=True)


if __name__ == "__main__":
    main()
