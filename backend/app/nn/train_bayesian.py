"""Train the Bayesian triage model: MAP MLP + last-layer Laplace.

    python -m app.nn.train_bayesian [--candidates PATH] [--batches PATH]
        [--external PATH] [--out DIR] [--epochs N] [--hidden 64,32]
        [--map-weights PATH]

What it does, in order:
1. Builds the own labeled rows (data.build_dataset) and splits them
   with seed 42 into own_train (580) / own_test (145). The 145-row
   own test set is the FIXED holdout every model version is judged
   on; nothing in this script ever trains on it.
2. Trains the MAP MLP on own_train + all external rows (2,502 rows),
   same hyperparams as v2 ([255, 64, 32, 1], lr 0.05, 60 epochs,
   seed 42). Pass --map-weights to reuse a checkpoint instead of
   retraining (same seed + data => same weights; the checkpoint
   only saves wall-clock time).
3. Fits the last-layer Laplace posterior on the TRAIN rows only
   (bayesian.LastLayerLaplace).
4. Calibrates the posterior covariance scale on a held-out 10%
   slice of the TRAIN rows only (stratified, seed 43): the scale
   whose binned 90% interval coverage is closest to 0.90. The
   scale is NOT fitted on the rows the MAP trained on directly:
   the MAP memorises train (train ECE 0.003), so a scale fitted
   there understates the width unseen rows need. The test set
   never sees this step.
5. Evaluates on the fixed 145-row own holdout: posterior-mean
   accuracy / ROC AUC / confusion matrix, ECE, Brier, binned
   interval coverage, unsure rate, confident vs unsure accuracy.
   The point MLP's numbers on the same 145 rows are printed next
   to them, so the comparison is apples-to-apples.
6. Writes weights.json (same recon-nn-weights/1 format plus a
   "bayesian" block: laplace posterior + calibration + method) and
   viewer-data.json into the out dir, and refreshes viewer.html.

Triage only. Never predicts VERIFIED_REAL: there are zero
verified-real positives in the training data. Detection only,
read-only; this script trains a scorer, it runs no probes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

from .bayesian import (LastLayerLaplace, brier_score,
                       evaluate_holdout, expected_calibration_error,
                       fit_variance_scale)
from .data import build_dataset, load_external_rows, stratified_split
from .features import FeatureSpec, build_vocab, extract
from .mlp import MLP, metrics_for
from .train import DEFAULT_BATCHES, DEFAULT_CANDIDATES, LIMITS, _refresh_viewer

DEFAULT_EXTERNAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "external_findings.jsonl")

# v1 / v2 headline numbers on the same fixed 145-row own holdout,
# for the printed comparison. They are reference constants, not
# recomputed here; the v1/v2 weights are not in this repo.
REFERENCE = {
    "v1_81-32-16-1": {"accuracy": 0.8897, "roc_auc": 0.9781},
    "v2_255-64-32-1": {"accuracy": 0.9103, "roc_auc": 0.9697},
}


def train_map(X_train, y_train, X_test, y_test, layers, seed=42,
              lr=0.05, epochs=60):
    net = MLP(layers, seed=seed, lr=lr)
    history = net.fit(X_train, y_train, epochs=epochs, batch_size=32,
                      X_val=X_test, y_val=y_test, seed=seed)
    return net, history


def train_bayesian(candidates_path: str, batches_path: str, out_dir: str,
                   epochs: int = 60, hidden: str = "64,32",
                   lr: float = 0.05, seed: int = 42,
                   external_path: str | None = None,
                   map_weights_path: str | None = None,
                   prior_precision: float = 1.0,
                   n_samples: int = 256) -> dict:
    dataset = build_dataset(candidates_path, batches_path)
    own_rows = dataset["rows"]
    stats = dataset["stats"]
    if external_path and not os.path.exists(external_path):
        raise ValueError(f"external file not found: {external_path}")
    ext_rows: list = []
    if external_path and os.path.exists(external_path):
        ext_rows, ext_stats = load_external_rows(external_path)
        stats.update(ext_stats)
        stats["train_rows"] = len(own_rows) + len(ext_rows)
        stats["n_positive"] = (sum(1 for r in own_rows if r["label"] == 1)
                               + ext_stats["external_positive"])
        stats["n_negative"] = (sum(1 for r in own_rows if r["label"] == 0)
                               + ext_stats["external_negative"])
    own_train, own_test = stratified_split(own_rows, 0.2, seed)
    train_rows = own_train + ext_rows
    spec = build_vocab([r["finding"] for r in train_rows])
    X_train = [extract(r["finding"], spec) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract(r["finding"], spec) for r in own_test]
    y_test = [r["label"] for r in own_test]

    layers = [spec.dim] + [int(h) for h in hidden.split(",") if h] + [1]
    if map_weights_path:
        with open(map_weights_path, encoding="utf-8") as fh:
            ckpt = json.load(fh)
        net = MLP.from_dict(ckpt["mlp"])
        if net.layers != layers:
            raise ValueError(
                f"checkpoint layers {net.layers} != {layers}")
        history = ckpt.get("history", {})
    else:
        net, history = train_map(X_train, y_train, X_test, y_test,
                                 layers, seed=seed, lr=lr, epochs=epochs)

    # Point-model numbers on the fixed holdout (same 145 rows).
    point_scores = [net.predict_proba(x) for x in X_test]
    point_metrics = metrics_for(y_test, point_scores)
    point_metrics["ece"] = round(
        expected_calibration_error(point_scores, y_test), 4)
    point_metrics["brier"] = round(brier_score(point_scores, y_test), 4)

    # Bayesian posterior: fit on TRAIN only. The Laplace fit uses
    # 90% of train; the covariance scale is fitted on the held-out
    # 10% calibration slice (stratified, seed 43). Fitting the scale
    # on the same rows the MAP memorised would understate the width
    # the model needs on unseen rows (train ECE 0.003 vs test ECE
    # 0.07: the MAP fits train almost perfectly). The 145-row
    # holdout never takes part in either step.
    laplace_rows, calib_rows = stratified_split(train_rows, 0.1,
                                                seed + 1)
    X_lap = [extract(r["finding"], spec) for r in laplace_rows]
    y_lap = [r["label"] for r in laplace_rows]
    X_cal = [extract(r["finding"], spec) for r in calib_rows]
    y_cal = [r["label"] for r in calib_rows]
    laplace = LastLayerLaplace(
        prior_precision=prior_precision).fit(net, X_lap, y_lap)
    calibration = fit_variance_scale(laplace, net, X_cal, y_cal,
                                     n_samples=128, seed=seed)
    calibration["calibration_rows"] = len(calib_rows)
    calibration["laplace_fit_rows"] = len(laplace_rows)
    bayes_metrics = evaluate_holdout(laplace, net, X_test, y_test,
                                     n_samples=n_samples, seed=seed)

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
    limits.append(
        "Bayesian: the score is a posterior MEAN with a 90% credible "
        "interval; findings whose interval straddles 0.5 are flagged "
        "unsure (nn_unsure) and routed to human review instead of "
        "auto-triage. The interval is calibrated on the training "
        "split only; test coverage is reported, not assumed.")

    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "method": ("last-layer Laplace approximation over the trained "
                   "MAP MLP (see backend/docs/nn-bayesian.md)"),
        "layers": layers,
        "n_features": spec.dim,
        "feature_names": spec.feature_names(),
        "dataset": stats,
        "train_rows": len(train_rows),
        "own_train_rows": len(own_train),
        "test_rows": len(own_test),
        "test_holdout": "own rows only, stratified split seed 42",
        "train_metrics": metrics_for(y_train,
                                     [net.predict_proba(x) for x in X_train]),
        "test_metrics_point": point_metrics,
        "test_metrics_bayesian": bayes_metrics,
        "reference": REFERENCE,
        "calibration": calibration,
        "prior_precision": prior_precision,
        "variance_scale": laplace.variance_scale,
        "history": history,
        "limits": limits,
        "seed": seed,
        "epochs": epochs,
        "lr": lr,
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    weights = {
        "format": "recon-nn-weights/1",
        "trained_at": result["trained_at"],
        "mlp": net.to_dict(),
        "features": spec.to_dict(),
        "metrics": {"train": result["train_metrics"],
                    "test": point_metrics,
                    "test_bayesian": bayes_metrics},
        "dataset": stats,
        "limits": limits,
        "bayesian": {
            "method": result["method"],
            "laplace": laplace.to_dict(),
            "calibration": calibration,
            "prior_precision": prior_precision,
        },
    }
    (out / "weights.json").write_text(json.dumps(weights, indent=2),
                                      encoding="utf-8")
    (out / "viewer-data.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    _refresh_viewer(out / "viewer.html", result)
    return result


def _print_report(result: dict) -> None:
    tm = result["test_metrics_bayesian"]
    pm = result["test_metrics_point"]
    b = tm["bayesian"]
    print(f"holdout: own-test {result['test_rows']} rows "
          f"(seed {result['seed']}, train {result['train_rows']})")
    print(f"features: {result['n_features']}  layers: {result['layers']}")
    print(f"POINT  test acc {pm['accuracy']:.4f}  AUC {pm['roc_auc']:.4f}  "
          f"ECE {pm['ece']:.4f}  Brier {pm['brier']:.4f}")
    print(f"BAYES  test acc {tm['accuracy']:.4f}  AUC {tm['roc_auc']:.4f}  "
          f"ECE {b['ece']:.4f}  Brier {b['brier']:.4f}")
    print(f"  reference v1 acc 0.8897 AUC 0.9781 | "
          f"v2 acc 0.9103 AUC 0.9697")
    cm = tm["confusion"]
    print(f"  confusion (bayes mean): tp={cm['tp']} fp={cm['fp']} "
          f"fn={cm['fn']} tn={cm['tn']}")
    print(f"  worth-validating recall {tm['recall_worth_validating']:.3f}  "
          f"likely-FP recall {tm['recall_likely_fp']:.3f}")
    cov = b["interval_coverage_bins"]
    print(f"  90% interval coverage (binned, strict): {cov['coverage']:.2f} "
          f"({cov['bins_covered']}/{cov['n_bins_nonempty']} bins); "
          f"Wilson-overlap {cov['wilson_coverage']:.2f} "
          f"({cov['wilson_bins_covered']}/{cov['n_bins_nonempty']}) - "
          f"see docs: bins of all-positive rows have observed rate "
          f"exactly 1.0, which no interval below 1.0 can contain")
    print(f"  unsure: {b['n_unsure']} rows ({b['unsure_rate']:.1%}) -> "
          f"human review; confident acc {b['confident_accuracy']:.3f} "
          f"vs unsure acc {b['unsure_accuracy']:.3f}")
    print(f"  variance scale (fit on 250-row calibration slice): "
          f"{result['calibration']['chosen_scale']} "
          f"(slice coverage {result['calibration']['train_coverage']:.2f}; "
          f"grid was flat - see docs)")
    print("LIMITS: triage only; zero verified-real positives; "
          "never predicts VERIFIED_REAL.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Train the Bayesian triage model (MAP + Laplace).")
    ap.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    ap.add_argument("--batches", default=DEFAULT_BATCHES)
    ap.add_argument("--external", default=DEFAULT_EXTERNAL)
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--hidden", default="64,32")
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--map-weights", default=None,
                    help="reuse a MAP checkpoint (JSON with mlp + "
                         "history) instead of retraining the MAP")
    ap.add_argument("--prior-precision", type=float, default=1.0)
    ap.add_argument("--n-samples", type=int, default=256)
    args = ap.parse_args(argv)
    result = train_bayesian(
        os.path.expanduser(args.candidates),
        os.path.expanduser(args.batches),
        args.out, epochs=args.epochs, hidden=args.hidden,
        lr=args.lr, seed=args.seed,
        external_path=(os.path.expanduser(args.external)
                       if args.external else None),
        map_weights_path=(os.path.expanduser(args.map_weights)
                          if args.map_weights else None),
        prior_precision=args.prior_precision,
        n_samples=args.n_samples)
    _print_report(result)
    print(f"weights: {os.path.join(args.out, 'weights.json')}")
    print(f"viewer data: {os.path.join(args.out, 'viewer-data.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
