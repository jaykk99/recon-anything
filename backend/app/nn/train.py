"""Train the triage network on the real labeled candidates.

    python -m app.nn.train [--candidates PATH] [--batches PATH]
                           [--out DIR] [--epochs N] [--hidden 32,16]

Trains an MLP to predict triage priority: worth-validating (label 1,
verdict UNVERIFIED) vs likely-false-positive (label 0, verdict
FALSE_POSITIVE or TRIGGER_ONLY). Writes weights.json + viewer-data.json
into the out dir (default: this package dir) and refreshes the embedded
metrics block in viewer.html.

Honest limits, printed with the metrics and baked into the viewer:
- the data is 85% worth-validating / 15% likely-false-positive, so a
  model that predicts "worth validating" for everything already scores
  ~85% accuracy. Accuracy alone means nothing here: the test metrics
  report precision/recall on the minority class and ROC AUC, and the
  majority-baseline accuracy is printed next to the real one.
- there are ZERO verified-real positives in the data. The model never
  predicts VERIFIED_REAL and must never be used to claim one.

Evaluation is on the FIXED own-test holdout: Jay's own rows are
split first (stratified, seed 42, 20% -> 580 train / 145 test) and
external rows go entirely to training, never to the test set. That
is the same holdout the v1 (0.8897 / 0.9781) and v2 (0.9103 / 0.9697)
numbers were measured on, so the numbers here compare directly.
Per-chain slices of that holdout are reported too; chains with too
few test rows report their counts only, never a dressed-up metric.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import sys
from pathlib import Path

from .data import build_dataset, load_external_rows, stratified_split
from .features import FeatureSpec, build_vocab, derive_domain, extract, normalize_chain
from .mlp import MLP, metrics_for, roc_auc

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
    "Multichain coverage is uneven by design: several chains "
    "(Litecoin, Bitcoin Cash, Dash, Toncoin, Sui, Aptos, XRP, "
    "Avalanche) have no real labeled rows in the public corpora "
    "fetched for v3 and were EXCLUDED, not faked. Their chain "
    "one-hots exist but carry no learned signal.",
    "NVD CVE rows are all label 1 (a published CVE is a confirmed "
    "vulnerability); there is no honest negative set for web / "
    "hardware / node CVEs, so those domains skew positive and the "
    "model may over-score them. Judge web/hardware scores with "
    "that in mind.",
]

VIEWER_START = "<!-- NN-DATA-START -->"
VIEWER_END = "<!-- NN-DATA-END -->"


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


def per_chain_metrics(rows, scores) -> Dict[str, Dict]:
    """Metrics per normalised chain on one scored set.

    Chains with < 5 rows report counts only (n / positives /
    negatives) and no accuracy/AUC — a 1-row "100%" would be a lie.
    Domain counts ride along for the record.
    """
    by_chain: Dict[str, List[int]] = {}
    by_domain: Dict[str, int] = {}
    for i, r in enumerate(rows):
        chain = normalize_chain(str(r.get("chain") or "other"))
        by_chain.setdefault(chain, []).append(i)
        dom = derive_domain(r.get("finding") or {})
        by_domain[dom] = by_domain.get(dom, 0) + 1
    out: Dict[str, Dict] = {}
    for chain, idxs in sorted(by_chain.items()):
        y = [rows[i]["label"] for i in idxs]
        s = [scores[i] for i in idxs]
        entry: Dict[str, object] = {
            "n": len(idxs),
            "n_positive": sum(y),
            "n_negative": len(y) - sum(y),
        }
        if len(idxs) >= 5:
            m = metrics_for(y, s)
            entry.update({
                "accuracy": round(m["accuracy"], 4),
                "roc_auc": round(m["roc_auc"], 4),
                "majority_baseline_accuracy": round(
                    m["majority_baseline_accuracy"], 4),
                "recall_worth_validating": round(
                    m["recall_worth_validating"], 4),
                "recall_likely_fp": round(m["recall_likely_fp"], 4),
                "confusion": m["confusion"],
            })
        out[chain] = entry
    out["_domains_test"] = by_domain
    return out


def per_chain_train_counts(rows) -> Dict[str, Dict]:
    """Training-row counts per normalised chain + domain (all rows)."""
    by_chain: Dict[str, Dict[str, int]] = {}
    by_domain: Dict[str, int] = {}
    for r in rows:
        chain = normalize_chain(str(r.get("chain") or "other"))
        slot = by_chain.setdefault(chain, {"n": 0, "pos": 0, "neg": 0})
        slot["n"] += 1
        if r["label"] == 1:
            slot["pos"] += 1
        else:
            slot["neg"] += 1
        dom = derive_domain(r.get("finding") or {})
        by_domain[dom] = by_domain.get(dom, 0) + 1
    return {"chains": by_chain, "domains": by_domain}


def train(candidates_path: str, batches_path: str, out_dir: str,
          epochs: int = 60, hidden: str = "32,16", lr: float = 0.05,
          seed: int = 42, test_frac: float = 0.2,
          limit: int | None = None,
          external_path: str | None = None,
          history_every: int = 1) -> dict:
    dataset = build_dataset(candidates_path, batches_path, limit=limit)
    own_rows = dataset["rows"]
    stats = dataset["stats"]
    if external_path and not os.path.exists(external_path):
        # Never silently train own-only when an external file was asked
        # for: a wrong relative path once shipped the wrong model.
        raise ValueError(f"external file not found: {external_path}")
    ext_rows: List[Dict] = []
    if external_path and os.path.exists(external_path):
        ext_rows, ext_stats = load_external_rows(external_path)
        stats.update(ext_stats)
    # FIXED own-test holdout (same 145 rows, seed 42, as v1/v2):
    # split Jay's own rows FIRST, then add every external row to
    # training only. External rows never enter the test set, so the
    # test numbers compare directly with v1/v2.
    own_train, own_test = stratified_split(own_rows, test_frac, seed)
    train_rows = own_train + ext_rows
    test_rows = own_test
    stats["train_rows"] = len(train_rows)
    stats["n_positive"] = sum(1 for r in train_rows if r["label"] == 1)
    stats["n_negative"] = sum(1 for r in train_rows if r["label"] == 0)
    stats["own_train_rows"] = len(own_train)
    stats["own_test_rows"] = len(own_test)
    if len(train_rows) < 20:
        raise ValueError(f"only {len(train_rows)} training rows; refusing")
    spec = build_vocab([r["finding"] for r in train_rows])
    X_train = [extract(r["finding"], spec) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract(r["finding"], spec) for r in test_rows]
    y_test = [r["label"] for r in test_rows]

    # Honest skew line, computed from the real combined TRAINING set
    # (own-train + external). The test set is Jay's own 145 only.
    n_pos = sum(y_train)
    n_neg = len(train_rows) - n_pos
    pos_pct = 100.0 * n_pos / max(1, len(train_rows))
    limits = list(LIMITS)
    limits[2] = (
        f"Label skew: the training set is {pos_pct:.0f}% worth-validating "
        f"/ {100.0 - pos_pct:.0f}% likely-false-positive "
        f"({n_pos} positive / {n_neg} negative of {len(train_rows)} "
        "rows). Accuracy near the majority baseline means the model "
        "learned nothing; judge it by minority-class recall and ROC "
        "AUC instead.")

    layers = [spec.dim] + [int(h) for h in hidden.split(",") if h] + [1]
    net = MLP(layers, seed=seed, lr=lr)
    # history_every only thins the reported loss/accuracy curves;
    # the weights are identical for any value (see test_mlp).
    # The shipped v3 run uses 10: on a contended box the per-epoch
    # full-set forward passes cost ~30% of an epoch for curves
    # nobody reads per-epoch.
    history = net.fit(X_train, y_train, epochs=epochs, batch_size=32,
                      X_val=X_test, y_val=y_test, seed=seed,
                      history_every=history_every)
    train_scores = [net.predict_proba(x) for x in X_train]
    test_scores = [net.predict_proba(x) for x in X_test]
    train_metrics = metrics_for(y_train, train_scores)
    test_metrics = metrics_for(y_test, test_scores)
    importance = permutation_importance(net, spec, X_test, y_test, seed)
    per_chain = per_chain_metrics(test_rows, test_scores)
    train_counts = per_chain_train_counts(train_rows)

    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "layers": layers,
        "n_features": spec.dim,
        "feature_names": spec.feature_names(),
        "dataset": stats,
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "per_chain_test": per_chain,
        "per_chain_train_counts": train_counts,
        "history": history,
        "feature_importance": importance,
        "limits": limits,
        "seed": seed,
        "epochs": epochs,
        "history_every": history_every,
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
        "metrics": {"train": train_metrics, "test": test_metrics,
                    "per_chain_test": per_chain},
        "dataset": stats,
        "limits": limits,
    }
    (out / "weights.json").write_text(json.dumps(weights, indent=2),
                                      encoding="utf-8")
    (out / "viewer-data.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
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
    viewer_path.write_text(before + block + after, encoding="utf-8")


def _print_report(result: dict) -> None:
    tm = result["test_metrics"]
    tr = result["train_metrics"]
    print(f"rows: train={result['train_rows']} test={result['test_rows']} "
          f"(pos {result['dataset']['n_positive']} / "
          f"neg {result['dataset']['n_negative']})")
    print(f"features: {result['n_features']}  layers: {result['layers']}")
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
    print("per-chain test (fixed own 145; n<5 reports counts only):")
    for chain, m in sorted(result.get("per_chain_test", {}).items()):
        if chain.startswith("_"):
            continue
        if "accuracy" in m:
            print(f"  {chain:<12} n={m['n']:>3} pos={m['n_positive']:>3} "
                  f"neg={m['n_negative']:>2} acc={m['accuracy']:.3f} "
                  f"auc={m['roc_auc']:.3f} base="
                  f"{m['majority_baseline_accuracy']:.3f} "
                  f"fp_rec={m['recall_likely_fp']:.3f}")
        else:
            print(f"  {chain:<12} n={m['n']:>3} pos={m['n_positive']:>3} "
                  f"neg={m['n_negative']:>2} (too few to measure)")
    print("per-chain train rows (all training rows):")
    for chain, c in sorted(
            result.get("per_chain_train_counts", {}).get("chains", {}).items()):
        print(f"  {chain:<12} n={c['n']:>4} pos={c['pos']:>4} "
              f"neg={c['neg']:>3}")
    print("per-domain train rows: "
          + ", ".join(f"{d}={n}" for d, n in sorted(
              result.get("per_chain_train_counts", {}).get("domains", {}).items())))
    print("LIMITS: triage only; zero verified-real positives; "
          "never predicts VERIFIED_REAL.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Train the ReconAnything triage network.")
    ap.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    ap.add_argument("--batches", default=DEFAULT_BATCHES)
    ap.add_argument("--external", default=None,
                    help="external-findings JSONL (v3: "
                         "external_findings_multichain.jsonl from "
                         "build_multichain_dataset.py; v2 file also "
                         "works); omit to train on Jay's own rows only")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--hidden", default="32,16")
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--history-every", type=int, default=1,
                    help="record loss/accuracy curves every Nth epoch "
                         "(weights are identical for any value)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)
    result = train(os.path.expanduser(args.candidates),
                   os.path.expanduser(args.batches),
                   args.out, epochs=args.epochs, hidden=args.hidden,
                   lr=args.lr, seed=args.seed, test_frac=args.test_frac,
                   limit=args.limit,
                   external_path=(os.path.expanduser(args.external)
                                  if args.external else None),
                   history_every=args.history_every)
    _print_report(result)
    print(f"weights: {os.path.join(args.out, 'weights.json')}")
    print(f"viewer data: {os.path.join(args.out, 'viewer-data.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
