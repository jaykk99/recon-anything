"""Train the triage network on the real labeled candidates.

    python -m app.nn.train [--candidates PATH] [--batches PATH]
                           [--out DIR] [--epochs N] [--hidden 32,16]
                           [--own-holdout] [--no-tda]

Trains an MLP to predict triage priority: worth-validating (label 1,
verdict UNVERIFIED) vs likely-false-positive (label 0, verdict
FALSE_POSITIVE or TRIGGER_ONLY). Writes weights.json + viewer-data.json
into the out dir (default: this package dir) and refreshes the embedded
metrics block in viewer.html.

Evaluation protocol (the honest one):
- --own-holdout splits Jay's OWN rows first (stratified, seed 42,
  test_frac 0.2 -> 145 test rows) and trains on own-train + all
  external rows. The test set is Jay's own data only, so the external
  rows (which are easier: judge-confirmed findings with clean
  signals) cannot inflate the score. This is the protocol the v1
  (acc 0.8897, AUC 0.9781) and v2 (acc 0.9103, AUC 0.9697) numbers
  were reported on, and the one the TDA comparison uses.
- Without --own-holdout the combined set is split (v2's shipped
  530-row test, which mixes external rows in). Kept for
  backward compatibility; do not compare its numbers with the
  own-holdout numbers.
- --no-tda trains the v2 control (255 features, no TDA block) on the
  same split and seed, so the TDA-vs-v2 delta is apples to apples.

Honest limits, printed with the metrics and baked into the viewer:
- the data is 85% worth-validating / 15% likely-false-positive, so a
  model that predicts "worth validating" for everything already scores
  ~85% accuracy. Accuracy alone means nothing here: the test metrics
  report precision/recall on the minority class and ROC AUC, and the
  majority-baseline accuracy is printed next to the real one.
- there are ZERO verified-real positives in the data. The model never
  predicts VERIFIED_REAL and must never be used to claim one.
- the TDA block sees a real call graph on only a handful of rows
  (7 of 727 own rows have a target with >0 callees); on the rest the
  graph is a measured-empty single node or absent. A TDA delta near
  zero on this data means the graphs are absent, not that topology
  cannot matter: the features are live for targets whose call-graph
  plugin actually returns edges.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import sys
import time
from pathlib import Path

from .data import build_dataset, load_external_rows, stratified_split
from .features import FeatureSpec, build_vocab, extract
from .mlp import MLP, metrics_for, roc_auc
from .tda import TDA_FEATURE_NAMES

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
    "Findings from plugins or chains unseen in training fall into the "
    "OTHER bucket; the model has no opinion about them beyond the "
    "generic features.",
    # Index 4 is replaced at train time with the real TDA coverage.
    "TDA coverage: see the dataset stats.",
]

VIEWER_START = "<!-- NN-DATA-START -->"
VIEWER_END = "<!-- NN-DATA-END -->"


def _write_text_retry(path: Path, text: str, tries: int = 180,
                      delay: float = 20.0) -> bool:
    """Write a file, retrying on OSError (the sandbox write gate
    sometimes refuses writes for minutes at a time). Returns True on
    success. Prints progress to stdout so a stalled run is visible."""
    for attempt in range(1, tries + 1):
        try:
            path.write_text(text, encoding="utf-8")
            if attempt > 1:
                print(f"wrote {path} on attempt {attempt}", flush=True)
            return True
        except OSError as e:
            if attempt == 1 or attempt % 10 == 0:
                print(f"write {path} attempt {attempt}/{tries} failed "
                      f"({e}); retrying in {delay}s", flush=True)
            time.sleep(delay)
    print(f"FAILED to write {path} after {tries} attempts", flush=True)
    return False


def permutation_importance(net: MLP, spec: FeatureSpec,
                           X_test, y_test, seed: int = 42):
    """Grouped permutation importance: AUC drop when a feature group
    is shuffled in the test set. Positive drop = the group matters."""
    base_scores = [net.predict_proba(x) for x in X_test]
    base_auc = roc_auc(base_scores, y_test)
    rng = random.Random(seed)
    out = []
    for group, (a, b) in sorted(spec.groups().items()):
        Xp = [list(x) for x in X_test]
        col_vals = [x[a:b] for x in Xp]
        rng.shuffle(col_vals)
        for row, vals in zip(Xp, col_vals):
            row[a:b] = vals
        auc = roc_auc([net.predict_proba(x) for x in Xp], y_test)
        out.append({"group": group, "auc_drop": round(base_auc - auc, 4)})
    out.sort(key=lambda d: d["auc_drop"], reverse=True)
    return out


def train(candidates_path: str, batches_path: str, out_dir: str,
          epochs: int = 60, hidden: str = "32,16", lr: float = 0.05,
          seed: int = 42, test_frac: float = 0.2,
          limit: int | None = None,
          external_path: str | None = None,
          use_tda: bool = True, own_holdout: bool = False,
          write_tries: int = 120, write_delay: float = 15.0) -> dict:
    dataset = build_dataset(candidates_path, batches_path, limit=limit)
    own_rows = dataset["rows"]
    stats = dataset["stats"]
    ext_rows: list = []
    if external_path and not os.path.exists(external_path):
        # Never silently train own-only when an external file was asked
        # for: a wrong relative path once shipped the wrong model.
        raise ValueError(f"external file not found: {external_path}")
    if external_path and os.path.exists(external_path):
        ext_rows, ext_stats = load_external_rows(external_path)
        stats.update(ext_stats)
    n_own = len(own_rows)
    if own_holdout:
        # Fixed own-test holdout: split Jay's rows first, train on
        # own-train + all external rows, test on own-test only.
        own_train, test_rows = stratified_split(own_rows, test_frac, seed)
        train_rows = own_train + ext_rows
        protocol = "own-holdout"
    else:
        rows = own_rows + ext_rows
        train_rows, test_rows = stratified_split(rows, test_frac, seed)
        protocol = "combined-split"
    stats["train_rows"] = len(train_rows) + len(test_rows)
    stats["n_positive"] = sum(1 for r in train_rows + test_rows
                              if r["label"] == 1)
    stats["n_negative"] = sum(1 for r in train_rows + test_rows
                              if r["label"] == 0)
    if len(train_rows) + len(test_rows) < 20:
        raise ValueError(
            f"only {len(train_rows) + len(test_rows)} rows; refusing")
    spec = build_vocab([r["finding"] for r in train_rows], use_tda=use_tda)
    X_train = [extract(r["finding"], spec) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract(r["finding"], spec) for r in test_rows]
    y_test = [r["label"] for r in test_rows]

    # Honest skew line, computed from the real combined set.
    n_pos = sum(y_train) + sum(y_test)
    n_neg = len(train_rows) + len(test_rows) - n_pos
    n_all = len(train_rows) + len(test_rows)
    pos_pct = 100.0 * n_pos / max(1, n_all)
    limits = list(LIMITS)
    limits[2] = (
        f"Label skew: the training set is {pos_pct:.0f}% worth-validating "
        f"/ {100.0 - pos_pct:.0f}% likely-false-positive "
        f"({n_pos} positive / {n_neg} negative of {n_all} rows). "
        "Accuracy near the majority baseline means the model learned "
        "nothing; judge it by minority-class recall and ROC AUC instead.")
    limits[4] = (
        f"TDA coverage: {stats.get('rows_with_call_graph', 0)} of {n_own} "
        f"own rows carry a call-graph record, "
        f"{stats.get('rows_with_nontrivial_graph', 0)} with a non-empty "
        "graph (>0 callees or multihop edges). External rows carry no "
        "graph. A near-zero TDA delta on this data means the graphs "
        "are absent, not that topology cannot matter.")

    layers = [spec.dim] + [int(h) for h in hidden.split(",") if h] + [1]
    net = MLP(layers, seed=seed, lr=lr)
    history = net.fit(X_train, y_train, epochs=epochs, batch_size=32,
                      X_val=X_test, y_val=y_test, seed=seed)
    train_scores = [net.predict_proba(x) for x in X_train]
    test_scores = [net.predict_proba(x) for x in X_test]
    train_metrics = metrics_for(y_train, train_scores)
    test_metrics = metrics_for(y_test, test_scores)
    importance = permutation_importance(net, spec, X_test, y_test, seed)

    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "layers": layers,
        "n_features": spec.dim,
        "n_tda_features": len(TDA_FEATURE_NAMES) if use_tda else 0,
        "use_tda": use_tda,
        "protocol": protocol,
        "feature_names": spec.feature_names(),
        "dataset": stats,
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "history": history,
        "feature_importance": importance,
        "limits": limits,
        "seed": seed,
        "epochs": epochs,
        "lr": lr,
        "external": stats.get("external_rows", 0),
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    weights = {
        "format": "recon-nn-weights/1",
        "trained_at": result["trained_at"],
        "mlp": net.to_dict(),
        "features": spec.to_dict(),
        "metrics": {"train": train_metrics, "test": test_metrics},
        "dataset": stats,
        "limits": limits,
        "protocol": protocol,
        "use_tda": use_tda,
    }
    _write_text_retry(out / "weights.json",
                      json.dumps(weights, indent=2),
                      tries=write_tries, delay=write_delay)
    _write_text_retry(out / "viewer-data.json",
                      json.dumps(result, indent=2),
                      tries=write_tries, delay=write_delay)
    _refresh_viewer(out / "viewer.html", result,
                    tries=write_tries, delay=write_delay)
    return result


def _refresh_viewer(viewer_path: Path, result: dict,
                    tries: int = 120, delay: float = 15.0) -> None:
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
    _write_text_retry(viewer_path, before + block + after,
                      tries=tries, delay=delay)


def _print_report(result: dict) -> None:
    tm = result["test_metrics"]
    tr = result["train_metrics"]
    print(f"protocol: {result['protocol']}  use_tda: {result['use_tda']}")
    print(f"rows: train={result['train_rows']} test={result['test_rows']} "
          f"(pos {result['dataset']['n_positive']} / "
          f"neg {result['dataset']['n_negative']})")
    print(f"features: {result['n_features']} "
          f"(tda {result['n_tda_features']})  layers: {result['layers']}")
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
    print("feature importance (AUC drop): " + ", ".join(
        f"{d['group']}={d['auc_drop']:.3f}"
        for d in result["feature_importance"][:6]))
    print("LIMITS: triage only; zero verified-real positives; "
          "never predicts VERIFIED_REAL.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Train the ReconAnything triage network.")
    ap.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    ap.add_argument("--batches", default=DEFAULT_BATCHES)
    ap.add_argument("--external", default=None,
                    help="external-findings JSONL (built by "
                         "build_external_dataset.py); omit to train on "
                         "Jay's own rows only")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--hidden", default="32,16")
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--own-holdout", action="store_true",
                    help="split Jay's own rows first; test on the "
                         "fixed 145-row own holdout only")
    ap.add_argument("--no-tda", action="store_true",
                    help="train the v2 control: 255 features, no TDA "
                         "block (same split and seed)")
    args = ap.parse_args(argv)
    result = train(os.path.expanduser(args.candidates),
                   os.path.expanduser(args.batches),
                   args.out, epochs=args.epochs, hidden=args.hidden,
                   lr=args.lr, seed=args.seed, test_frac=args.test_frac,
                   limit=args.limit,
                   external_path=(os.path.expanduser(args.external)
                                  if args.external else None),
                   use_tda=not args.no_tda,
                   own_holdout=args.own_holdout)
    _print_report(result)
    print(f"weights: {os.path.join(args.out, 'weights.json')}")
    print(f"viewer data: {os.path.join(args.out, 'viewer-data.json')}")
    # Metrics-only JSON line: the numbers survive even if the file
    # writes above were still retrying when the run was collected.
    print("TRAIN-RESULT-JSON " + json.dumps({
        "protocol": result["protocol"],
        "use_tda": result["use_tda"],
        "layers": result["layers"],
        "n_features": result["n_features"],
        "train_rows": result["train_rows"],
        "test_rows": result["test_rows"],
        "train_metrics": result["train_metrics"],
        "test_metrics": result["test_metrics"],
        "feature_importance": result["feature_importance"],
        "dataset": result["dataset"],
        "epochs": result["epochs"],
        "seed": result["seed"],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
