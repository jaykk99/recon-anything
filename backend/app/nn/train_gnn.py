"""Train + evaluate the GNN + neuro-symbolic combined triage model.

    python -m app.nn.train_gnn [--epochs 30] [--external PATH]
    python -m app.nn.train_gnn --smoke   # 200 rows, 2 epochs, timing check

Protocol (same fixed holdout as the v2 retrain, so the numbers
compare honestly):
- own rows: recon-continuous/results/candidates.jsonl joined to
  batches.jsonl (data.build_dataset). Stratified split, seed 42:
  test = 145 rows (124 worth-validating / 21 likely-FP); train = 580.
- train rows = own-train 580 + external 1,922 (public audit
  findings, all label 1). Test rows are own-only, never external.
- symbolic rules are validated on own-train only (the real triage
  distribution); rules that fail validation are dropped, never kept.
- metrics: accuracy, ROC AUC, confusion, FP/WV recall for
  neural-only, symbolic-only, and combined.

Writes gnn-weights.json + viewer-data-gnn.json next to this module
when the filesystem allows it; on a write failure it warns and
still prints the full report (weights are reproducible from seed
42 + the fixed data, so a re-run regenerates them).

Triage only: labels are worth-validating / likely-false-positive,
never VERIFIED_REAL.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

# Allow running as `python -m app.nn.train_gnn` from backend/ and as a
# plain script (tests import it as app.nn.train_gnn).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.nn.combined import CombinedModel  # noqa: E402
from app.nn.data import (  # noqa: E402
    build_dataset, load_external_rows, stratified_split)
from app.nn.features import build_vocab  # noqa: E402
from app.nn.gnn import CombinedNet  # noqa: E402
from app.nn.graph import build_contract_index, build_graph, contract_findings_for  # noqa: E402
from app.nn.symbolic import validate_rules  # noqa: E402

V1_BASELINE = {"test_acc": 0.8897, "roc_auc": 0.9781,
               "layers": "81-32-16-1"}
V2_BASELINE = {"test_acc": 0.9103, "roc_auc": 0.9697,
               "layers": "255-64-32-1"}

DEFAULT_CANDIDATES = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")
DEFAULT_BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
DEFAULT_EXTERNAL = os.path.expanduser(
    "~/workspace/wt/nn-scorer/backend/app/nn/external_findings.jsonl")


def _find_external(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    local = Path(__file__).resolve().parent / "external_findings.jsonl"
    if local.exists():
        return str(local)
    if os.path.exists(DEFAULT_EXTERNAL):
        return DEFAULT_EXTERNAL
    return None


def _eval_only(args) -> int:
    """Load trained weights, re-evaluate on the fixed holdout, and
    rewrite viewer-data-gnn.json (used to refresh the viewer after a
    code change without retraining)."""
    from app.nn.combined import load_combined_model
    out_dir = Path(args.out_dir) if args.out_dir else (
        Path(__file__).resolve().parent)
    model = load_combined_model(str(out_dir / "gnn-weights.json"))
    if model is None:
        print("no trained GNN weights found. Train first:\n"
              "  python -m app.nn.train_gnn", file=sys.stderr)
        return 2
    print("loading own dataset ...", flush=True)
    own = build_dataset(args.candidates, args.batches)
    own_train, own_test = stratified_split(own["rows"], test_frac=0.2,
                                           seed=args.seed)
    n_test_pos = sum(1 for r in own_test if r["label"] == 1)
    n_test_neg = len(own_test) - n_test_pos
    assert len(own_test) == 145 and n_test_pos == 124 and n_test_neg == 21, (
        "DATA DRIFT: the fixed holdout is not 145 rows (124 pos / "
        f"21 neg) anymore — got {len(own_test)} ({n_test_pos} / "
        f"{n_test_neg}). candidates.jsonl changed since the training "
        "run; re-train instead of eval-only so the numbers stay "
        "comparable to v1/v2.")
    print("building contract index from batches ...", flush=True)
    index = build_contract_index(args.batches)
    print("evaluating on the fixed own-test holdout ...", flush=True)
    evaluation = model.evaluate(own_test, index)
    demo = None
    for row, pred in zip(own_test, evaluation["preds"]):
        if (pred["combined_p"] >= 0.5
                and pred["graph"]["has_implementation"]):
            demo = {"row": {k: row.get(k) for k in
                            ("plugin", "key", "chain", "address",
                             "function", "label", "verdict")},
                    "prediction": pred}
            break
    kept, dropped = validate_rules(own_train)
    graph_meta = model.meta.get("graph", {})
    viewer = {"model": "gnn-neurosymbolic",
              "architecture": {
                  "node_dim": graph_meta.get("node_dim", 32),
                  "gnn_hidden": graph_meta.get("hidden", 16),
                  "gnn_layers": graph_meta.get("layers", 2),
                  "head": graph_meta.get("head", []),
                  "feature_dim": model.spec.dim},
              "evaluation": evaluation,
              "rules_kept": model.kept_rules,
              "rules_dropped": dropped,
              "demo": demo, "history": {},
              "baselines": {"v1_mlp": V1_BASELINE,
                            "v2_mlp": V2_BASELINE},
              "meta": model.meta}
    (out_dir / "viewer-data-gnn.json").write_text(
        json.dumps(viewer, indent=2, default=str), encoding="utf-8")
    print(json.dumps(
        {k: evaluation[k] for k in ("neural", "symbolic", "combined")},
        indent=2, default=str))
    print(f"wrote {out_dir / 'viewer-data-gnn.json'}", flush=True)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Train the GNN + neuro-symbolic triage model.")
    ap.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    ap.add_argument("--batches", default=DEFAULT_BATCHES)
    ap.add_argument("--external", default=None)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default=None,
                    help="where to write gnn-weights.json + "
                         "viewer-data-gnn.json (default: the nn/ dir)")
    ap.add_argument("--smoke", action="store_true",
                    help="tiny run: 200 train rows, 2 epochs")
    ap.add_argument("--eval-only", action="store_true",
                    help="skip training: load gnn-weights.json, evaluate "
                         "on the fixed holdout, rewrite viewer-data-gnn.json")
    args = ap.parse_args(argv)
    t0 = time.time()

    if args.eval_only:
        return _eval_only(args)

    print("loading own dataset ...", flush=True)
    own = build_dataset(args.candidates, args.batches)
    own_rows = own["rows"]
    print(f"own rows: {len(own_rows)} "
          f"({own['stats']['n_positive']} pos / "
          f"{own['stats']['n_negative']} neg)", flush=True)
    own_train, own_test = stratified_split(own_rows, test_frac=0.2,
                                           seed=args.seed)
    n_test_pos = sum(1 for r in own_test if r["label"] == 1)
    n_test_neg = len(own_test) - n_test_pos
    print(f"fixed holdout: test={len(own_test)} "
          f"({n_test_pos} pos / {n_test_neg} neg), "
          f"train={len(own_train)}", flush=True)
    assert len(own_test) == 145 and n_test_pos == 124 and n_test_neg == 21, (
        f"holdout drifted: {len(own_test)} rows, {n_test_pos} pos, "
        f"{n_test_neg} neg (expected 145 / 124 / 21)")

    ext_path = _find_external(args.external)
    ext_rows: list = []
    if ext_path and os.path.exists(ext_path):
        ext_rows, ext_stats = load_external_rows(ext_path)
        print(f"external rows: {len(ext_rows)} from {ext_path} "
              f"({ext_stats['external_positive']} pos / "
              f"{ext_stats['external_negative']} neg)", flush=True)
    else:
        print("external rows: none found (training on own rows only)",
              flush=True)

    train_rows = list(own_train) + list(ext_rows)
    if args.smoke:
        train_rows = train_rows[:200]
        args.epochs = 2
        print("SMOKE RUN: 200 train rows, 2 epochs", flush=True)

    spec = build_vocab(train_rows)
    print(f"feature spec dim: {spec.dim} "
          f"({len(spec.plugins)} plugins, {len(spec.keys)} keys)",
          flush=True)

    print("building contract index from batches ...", flush=True)
    index = build_contract_index(args.batches)
    print(f"contract index: {index['stats']['contracts']} contracts, "
          f"{index['stats']['batch_findings']} findings", flush=True)

    print("building graphs ...", flush=True)
    t_graph = time.time()
    train_graphs = []
    for row in train_rows:
        ctx = contract_findings_for(index, row.get("chain") or "",
                                    row.get("address") or "")
        train_graphs.append(build_graph(row, ctx))
    print(f"train graphs: {len(train_graphs)} in "
          f"{time.time() - t_graph:.1f}s "
          f"(mean nodes "
          f"{sum(len(g['nodes']) for g in train_graphs) / len(train_graphs):.2f}, "
          f"mean edges "
          f"{sum(len(g['edges']) for g in train_graphs) / len(train_graphs):.2f})",
          flush=True)

    print("validating symbolic rules on own-train ...", flush=True)
    kept, dropped = validate_rules(own_train)
    print(f"rules kept: {[r['name'] for r in kept]}", flush=True)
    print(f"rules dropped: {[r['name'] for r in dropped]}", flush=True)

    net = CombinedNet(spec, seed=args.seed, lr=args.lr)
    y_train = [int(r["label"]) for r in train_rows]
    train_findings = [r["finding"] for r in train_rows]
    print(f"training {args.epochs} epochs, batch {args.batch_size} ...",
          flush=True)
    t_train = time.time()
    history = net.fit(train_graphs, train_findings, y_train,
                      epochs=args.epochs, batch_size=args.batch_size,
                      seed=args.seed)
    print(f"trained in {time.time() - t_train:.1f}s; final train loss "
          f"{history['loss'][-1]:.4f}, train acc "
          f"{history['train_acc'][-1]:.4f}", flush=True)

    model = CombinedModel(net, kept, meta={
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "train_rows": len(train_rows),
        "own_train": len(own_train),
        "external_rows": len(ext_rows),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "lr": args.lr,
        "seed": args.seed,
        "graph": {"node_dim": 32, "hidden": 16, "layers": 2,
                  "head": [16 + spec.dim, 32, 1]},
    })
    print("evaluating on the fixed own-test holdout ...", flush=True)
    t_eval = time.time()
    evaluation = model.evaluate(own_test, index)
    print(f"evaluated in {time.time() - t_eval:.1f}s", flush=True)

    # Demo row for the viewer: a combined worth-validating test row
    # with a proxy (shows the graph + fired rules at their best).
    demo = None
    for row, pred in zip(own_test, evaluation["preds"]):
        if (pred["combined_p"] >= 0.5
                and pred["graph"]["has_implementation"]):
            demo = {"row": {k: row.get(k) for k in
                            ("plugin", "key", "chain", "address",
                             "function", "label", "verdict")},
                    "prediction": pred}
            break

    weights = model.to_dict()
    weights_json = json.dumps(weights)
    report = {
        "model": "gnn-neurosymbolic",
        "architecture": {"node_dim": 32, "gnn_hidden": 16,
                         "gnn_layers": 2,
                         "head": [16 + spec.dim, 32, 1],
                         "feature_dim": spec.dim},
        "data": {"own_rows": len(own_rows),
                 "own_train": len(own_train),
                 "own_test": len(own_test),
                 "external_rows": len(ext_rows),
                 "test_pos": n_test_pos, "test_neg": n_test_neg},
        "baselines": {"v1_mlp": V1_BASELINE, "v2_mlp": V2_BASELINE},
        "history": history,
        "evaluation": evaluation,
        "rules_kept": kept,
        "rules_dropped": dropped,
        "demo": demo,
        "weights_sha256": hashlib.sha256(
            weights_json.encode()).hexdigest(),
        "weights_bytes": len(weights_json),
        "total_seconds": round(time.time() - t0, 1),
    }
    print(json.dumps(report, indent=2, default=str))

    out_dir = Path(args.out_dir) if args.out_dir else (
        Path(__file__).resolve().parent)
    try:
        (out_dir / "gnn-weights.json").write_text(weights_json,
                                                  encoding="utf-8")
        viewer = {"model": "gnn-neurosymbolic",
                  "architecture": report["architecture"],
                  "evaluation": evaluation,
                  "rules_kept": kept, "rules_dropped": dropped,
                  "demo": demo, "history": history,
                  "baselines": report["baselines"],
                  "meta": model.meta}
        (out_dir / "viewer-data-gnn.json").write_text(
            json.dumps(viewer, indent=2, default=str), encoding="utf-8")
        print(f"wrote {out_dir / 'gnn-weights.json'} "
              f"({len(weights_json)} bytes)", flush=True)
        print(f"wrote {out_dir / 'viewer-data-gnn.json'}", flush=True)
    except Exception as e:  # noqa: BLE001 - write block: report anyway
        print(f"WARNING: could not write weights/viewer files: {e}\n"
              "Metrics above are the real result; re-run to persist "
              "weights once writes work again.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
