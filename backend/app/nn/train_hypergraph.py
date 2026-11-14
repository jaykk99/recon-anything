"""Train the hypergraph triage network on the real labeled candidates.

    python -m app.nn.train_hypergraph [--candidates PATH] [--batches PATH]
                                      [--out DIR] [--epochs N]
                                      [--hidden 16] [--lr 0.1]
                                      [--baseline/--no-baseline]

Same data recipe as the MLP trainer (train.py), but the holdout is
the FIXED own-rows holdout: the own findings are split stratified,
seed 42, test_frac 0.2. The own-row count is whatever
candidates.jsonl holds at run time: 725 rows (145 test, 124
worth-validating / 21 likely-false-positive) when the branch was
built, 723 rows (144 test, 123 / 21) after candidates.jsonl was
re-adjudicated upstream on 2026-11-14 08:53 UTC (4 rows removed,
including the 2 VERIFIED_REAL rows). The 1,922 external rows join
the TRAIN set only, so the test set is Jay's own rows and nothing
else. Hypergraphs are built separately on the train rows and on
the test rows: an edge joining a train node to a test node would
leak test information into training. Because the holdout shifted by
one row, the quoted v1/v2 numbers (measured on the 145-row
holdout) are near but not exact comparators; the retrained MLP
baseline in the same run IS on the same split, so that head-to-head
is exact.

Also trains the v2 MLP baseline (255-64-32-1, lr 0.05, 60 epochs,
batch 32) on the exact same split, so the hypergraph numbers and
the baseline numbers are apples-to-apples. Pass --no-baseline to
skip the MLP retrain (it takes ~25 min on this box).

Writes hypergraph-weights.json + viewer-data.json into the out dir
(default: this package dir) and refreshes the embedded metrics
block in viewer.html. The shipped weights.json in this package is
the hypergraph model (format recon-nn-hypergraph/1); pipeline.py
loads both the MLP and the hypergraph formats.

Honest limits, printed with the metrics and baked into the viewer:
same as the MLP trainer (triage only, zero verified-real
positives, never predicts VERIFIED_REAL), plus the hypergraph's
own: most findings sit in no hyperedge at all, so most of the
model's behaviour is the self path; judge it by minority-class
recall and ROC AUC on the 145-row own holdout, not by accuracy
(the majority baseline there is 85.5%).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

from .data import build_dataset, load_external_rows, stratified_split
from .features import FeatureSpec, build_vocab, extract
from .hypergraph import HypergraphNN, build_hypergraph
from .mlp import MLP, metrics_for

DEFAULT_CANDIDATES = ("~/workspace/recon-continuous/results/"
                      "candidates.jsonl")
DEFAULT_BATCHES = "~/workspace/recon-continuous/results/batches.jsonl"
DEFAULT_EXTERNAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "external_findings.jsonl")

LIMITS = [
    "Triage only. The model ranks findings by how much they look like "
    "past candidates that survived triage. It does not verify anything.",
    "Zero verified-real positives exist in the training data, so the "
    "model never predicts VERIFIED_REAL and must never be used to claim "
    "one. A high score means 'worth a live probe', nothing more.",
    # Index 2 is replaced at train time with the real label skew.
    "Label skew: see the dataset stats.",
    "Hypergraph coverage is thin: most findings sit in no hyperedge "
    "(one finding per target), so most nodes score on the self path "
    "only. The hyperedge context helps only where links exist; see "
    "the hypergraph stats for the real coverage.",
    "No call-graph hyperedges exist yet: the own data has zero "
    "cross_contract_call_graph rows, so no related-contract links "
    "are available to build them from.",
    "Findings from plugins or chains unseen in training fall into the "
    "OTHER bucket; the model has no opinion about them beyond the "
    "generic features.",
]

VIEWER_START = "<!-- NN-DATA-START -->"
VIEWER_END = "<!-- NN-DATA-END -->"


def _write_text_retry(path: Path, text: str,
                      attempts: int = 60, delay: int = 10) -> None:
    """Write a file, retrying through the sandbox's intermittent
    write failures (write() returns EPERM in bursts under load).
    Raises the last error if every attempt fails."""
    last: Optional[Exception] = None
    for _ in range(attempts):
        try:
            path.write_text(text, encoding="utf-8")
            return
        except OSError as e:  # noqa: BLE001 - retry, then raise
            last = e
            import time
            time.sleep(delay)
    raise last  # type: ignore[misc]


def train(candidates_path: str, batches_path: str, out_dir: str,
          epochs: int = 200, hidden: int = 16, lr: float = 0.5,
          seed: int = 42, test_frac: float = 0.2,
          external_path: str | None = None,
          baseline: bool = True) -> dict:
    dataset = build_dataset(candidates_path, batches_path)
    own_rows = dataset["rows"]
    stats = dataset["stats"]
    if external_path and not os.path.exists(external_path):
        raise ValueError(f"external file not found: {external_path}")
    ext_rows, ext_stats = ([], {})
    if external_path and os.path.exists(external_path):
        ext_rows, ext_stats = load_external_rows(external_path)
        stats.update(ext_stats)
    if len(own_rows) < 20:
        raise ValueError(f"only {len(own_rows)} own rows; refusing")

    # Fixed own-rows holdout: stratified split of the OWN rows only.
    own_train, own_test = stratified_split(own_rows, test_frac, seed)
    train_rows = own_train + ext_rows
    stats["train_rows"] = len(train_rows)
    stats["own_train_rows"] = len(own_train)
    stats["own_test_rows"] = len(own_test)
    stats["n_positive"] = sum(1 for r in train_rows if r["label"] == 1)
    stats["n_negative"] = sum(1 for r in train_rows if r["label"] == 0)

    spec = build_vocab([r["finding"] for r in train_rows])
    X_train = [extract(r["finding"], spec) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract(r["finding"], spec) for r in own_test]
    y_test = [r["label"] for r in own_test]

    # Hypergraphs built separately per split: no train/test leakage.
    tr_edges, tr_stats = build_hypergraph(train_rows)
    te_edges, te_stats = build_hypergraph(own_test)

    n_pos = sum(y_train) + sum(y_test)
    n_neg = len(train_rows) + len(own_test) - n_pos
    pos_pct = 100.0 * n_pos / max(1, len(train_rows) + len(own_test))
    limits = list(LIMITS)
    limits[2] = (
        f"Label skew: the training set is {pos_pct:.0f}% worth-validating "
        f"/ {100.0 - pos_pct:.0f}% likely-false-positive "
        f"({n_pos} positive / {n_neg} negative of "
        f"{len(train_rows) + len(own_test)} rows). "
        "Accuracy near the majority baseline means the model learned "
        "nothing; judge it by minority-class recall and ROC AUC instead.")

    net = HypergraphNN(spec.dim, hidden=hidden, lr=lr, seed=seed)
    print("training hypergraph "
          f"({epochs} epochs, hidden {hidden}, lr {lr}) ...", flush=True)
    # Step-decay schedule, not a flat lr: flat lr 0.5 escapes the
    # majority plateau fast (loss 0.43 -> 0.13 by epoch 30) but then
    # overshoots catastrophically (loss 0.50, acc back to majority
    # at epoch 35) and oscillates. So: hot while the model is still
    # near the majority prediction, cool once it starts fitting.
    # Chunks are multiples of history_every (5) so the history
    # stays evenly spaced.
    history = {"loss": [], "train_acc": []}
    remaining = epochs
    for chunk_lr, chunk_epochs in ((lr, 30), (lr * 0.3, 70),
                                   (lr * 0.1, None)):
        if remaining <= 0:
            break
        n_ep = chunk_epochs if chunk_epochs is not None else remaining
        n_ep = min(n_ep, remaining)
        if n_ep <= 0:
            continue
        net.lr = chunk_lr
        print(f"hypergraph lr {chunk_lr:.3f} for {n_ep} epochs ...",
              flush=True)
        h = net.fit(X_train, y_train, tr_edges, epochs=n_ep,
                    verbose=True)
        history["loss"] += h["loss"]
        history["train_acc"] += h["train_acc"]
        remaining -= n_ep
    train_probs = net.predict_proba_nodes(X_train, tr_edges)
    test_probs = net.predict_proba_nodes(X_test, te_edges)
    train_metrics = metrics_for(y_train, train_probs)
    test_metrics = metrics_for(y_test, test_probs)

    # Ablation: the same trained model with hyperedges removed at
    # eval time. If the edges carry signal, this is worse.
    noedge_probs = net.predict_proba_nodes(X_test, [])
    noedge_metrics = metrics_for(y_test, noedge_probs)

    # Covered-vs-singleton slice on the test set: nodes that sit in
    # a hyperedge vs nodes that score on the self path only.
    covered = sorted({m for e in te_edges for m in e["members"]})
    covered_set = set(covered)
    singleton = [i for i in range(len(y_test)) if i not in covered_set]
    covered_metrics = metrics_for(
        [y_test[i] for i in covered], [test_probs[i] for i in covered])
    singleton_metrics = metrics_for(
        [y_test[i] for i in singleton],
        [test_probs[i] for i in singleton])

    baseline_metrics = None
    baseline_train_metrics = None
    baseline_history = None
    if baseline:
        # The v2 recipe is 60 epochs; the hypergraph's 200 epochs
        # are its own budget (one full-batch step per epoch vs the
        # MLP's ~78 mini-batch steps per epoch). Do NOT pass the
        # driver's epochs here: a 200-epoch MLP is a different
        # model from v2.
        baseline_epochs = 60
        print("training MLP v2 baseline "
              f"({baseline_epochs} epochs, 255-64-32-1, lr 0.05) ...",
              flush=True)
        mlp = MLP([spec.dim, 64, 32, 1], seed=seed, lr=0.05)
        baseline_history = mlp.fit(X_train, y_train, epochs=baseline_epochs,
                                   batch_size=32, X_val=X_test,
                                   y_val=y_test, seed=seed,
                                   history_every=5)
        baseline_train_metrics = metrics_for(
            y_train, [mlp.predict_proba(x) for x in X_train])
        baseline_metrics = metrics_for(
            y_test, [mlp.predict_proba(x) for x in X_test])

    result = {
        "model": "hypergraph",
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "layers": [spec.dim, hidden, hidden, 1],
        "hidden": hidden,
        "n_features": spec.dim,
        "feature_names": spec.feature_names(),
        "dataset": stats,
        "train_rows": len(train_rows),
        "test_rows": len(own_test),
        "own_train_rows": len(own_train),
        "own_test_rows": len(own_test),
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "noedge_ablation_metrics": noedge_metrics,
        "covered_test_metrics": covered_metrics,
        "singleton_test_metrics": singleton_metrics,
        "hypergraph_train": tr_stats,
        "hypergraph_test": te_stats,
        "baseline_mlp_v2_test_metrics": baseline_metrics,
        "baseline_mlp_v2_train_metrics": baseline_train_metrics,
        "baseline_mlp_v2_history": baseline_history,
        "history": history,
        "limits": limits,
        "seed": seed,
        "epochs": epochs,
        "lr": lr,
        "external": stats.get("external_rows", 0),
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    weights = {
        "format": "recon-nn-hypergraph/1",
        "trained_at": result["trained_at"],
        "hypergraph": net.to_dict(),
        "features": spec.to_dict(),
        "metrics": {"train": train_metrics, "test": test_metrics,
                    "noedge_ablation": noedge_metrics},
        "hypergraph_stats": {"train": tr_stats, "test": te_stats},
        "dataset": stats,
        "limits": limits,
    }
    _write_text_retry(out / "hypergraph-weights.json",
                      json.dumps(weights, indent=2))
    # The package's weights.json IS the hypergraph model on this
    # branch, so pipeline.load_model() picks it up by default. The
    # v2 MLP weights stay on feat/nn-scorer; this branch ships the
    # hypergraph as its model.
    _write_text_retry(out / "weights.json",
                      json.dumps(weights, indent=2))
    _write_text_retry(out / "viewer-data.json",
                      json.dumps(result, indent=2))
    _refresh_viewer(out / "viewer.html", result)
    return result


def _refresh_viewer(viewer_path: Path, result: dict) -> None:
    """Replace the embedded metrics JSON block in viewer.html so the
    file shows the real numbers even when opened as file://."""
    if not viewer_path.exists():
        return
    text = viewer_path.read_text(encoding="utf-8")
    if VIEWER_START not in text or VIEWER_END not in text:
        return
    block = (VIEWER_START + "\n<script type=\"application/json\" "
             "id=\"nn-data\">\n" + json.dumps(result, indent=2) +
             "\n</script>\n" + VIEWER_END)
    before, _sep, rest = text.partition(VIEWER_START)
    _mid, _sep2, after = rest.partition(VIEWER_END)
    _write_text_retry(viewer_path, before + block + after)


def _print_report(result: dict) -> None:
    tm = result["test_metrics"]
    tr = result["train_metrics"]
    print(f"rows: train={result['train_rows']} test={result['test_rows']} "
          f"(own test {result['own_test_rows']}, "
          f"pos {result['dataset']['n_positive']} / "
          f"neg {result['dataset']['n_negative']} in train)")
    print(f"features: {result['n_features']}  layers: {result['layers']}")
    print(f"hypergraph train: {result['hypergraph_train']['n_edges']} "
          f"edges, {result['hypergraph_train']['nodes_covered']}/"
          f"{result['hypergraph_train']['nodes_total']} nodes covered")
    print(f"hypergraph test: {result['hypergraph_test']['n_edges']} "
          f"edges, {result['hypergraph_test']['nodes_covered']}/"
          f"{result['hypergraph_test']['nodes_total']} nodes covered")
    print(f"train acc {tr['accuracy']:.3f}  test acc {tm['accuracy']:.3f}  "
          f"majority baseline {tm['majority_baseline_accuracy']:.3f}")
    print(f"test ROC AUC {tm['roc_auc']:.3f}")
    print(f"worth-validating: precision {tm['precision_worth_validating']:.3f} "
          f"recall {tm['recall_worth_validating']:.3f}")
    print(f"likely-false-positive: precision {tm['precision_likely_fp']:.3f} "
          f"recall {tm['recall_likely_fp']:.3f}")
    cm = tm["confusion"]
    print(f"confusion (test): tp={cm['tp']} fp={cm['fp']} "
          f"fn={cm['fn']} tn={cm['tn']}")
    nm = result["noedge_ablation_metrics"]
    print(f"no-edge ablation: test acc {nm['accuracy']:.3f} "
          f"AUC {nm['roc_auc']:.3f}")
    bm = result.get("baseline_mlp_v2_test_metrics")
    if bm:
        print(f"MLP v2 baseline (same split): test acc {bm['accuracy']:.3f} "
              f"AUC {bm['roc_auc']:.3f}  "
              f"WV recall {bm['recall_worth_validating']:.3f}  "
              f"FP recall {bm['recall_likely_fp']:.3f}")
    print("LIMITS: triage only; zero verified-real positives; "
          "never predicts VERIFIED_REAL.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Train the ReconAnything hypergraph triage network.")
    ap.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    ap.add_argument("--batches", default=DEFAULT_BATCHES)
    ap.add_argument("--external", default=DEFAULT_EXTERNAL,
                    help="external-findings JSONL; use --no-external "
                         "to train on Jay's own rows only")
    ap.add_argument("--no-external", action="store_true")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--hidden", type=int, default=16)
    ap.add_argument("--lr", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--no-baseline", action="store_true",
                    help="skip the MLP v2 baseline retrain")
    args = ap.parse_args(argv)
    result = train(os.path.expanduser(args.candidates),
                   os.path.expanduser(args.batches),
                   args.out, epochs=args.epochs, hidden=args.hidden,
                   lr=args.lr, seed=args.seed, test_frac=args.test_frac,
                   external_path=(None if args.no_external
                                  else os.path.expanduser(args.external)),
                   baseline=not args.no_baseline)
    _print_report(result)
    print(f"weights: {os.path.join(args.out, 'hypergraph-weights.json')}")
    print(f"viewer data: {os.path.join(args.out, 'viewer-data.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
