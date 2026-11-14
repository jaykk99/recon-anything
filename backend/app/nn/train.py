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
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import sys
from pathlib import Path

from .data import (build_dataset, load_external_rows, stratified_split)
from .features import FeatureSpec, build_vocab, extract
from .mlp import MLP, load_checkpoint, metrics_for, roc_auc

DEFAULT_CANDIDATES = ("~/workspace/recon-continuous/results/"
                      "candidates.jsonl")
DEFAULT_BATCHES = "~/workspace/recon-continuous/results/batches.jsonl"
DEFAULT_EXTERNAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "external_findings.jsonl")
DEFAULT_FRESH_DEPLOYS = ("~/workspace/recon-continuous/"
                         "targets-2026-11-12/fresh-deploys-more-chains.jsonl")
DEFAULT_TRANSITIONS = ("~/workspace/recon-continuous/state/"
                       "transition_events.jsonl")

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


def train(candidates_path: str, batches_path: str, out_dir: str,
          epochs: int = 60, hidden: str = "32,16", lr: float = 0.05,
          seed: int = 42, test_frac: float = 0.2,
          limit: int | None = None,
          external_path: str | None = None,
          eval_mode: str = "combined",
          checkpoint_path: str | None = None,
          checkpoint_every: int = 10,
          resume_path: str | None = None,
          registry_ids: list | None = None,
          history_every: int = 1,
          fresh_deploys_path: str | None = None,
          transitions_path: str | None = None) -> dict:
    """Train the triage network.

    eval_mode "combined" (default, v1/v2 behaviour): split the
    own+external rows together; the test set mixes Jay's rows with
    audit rows, which flatters the numbers because audit rows are
    easier. eval_mode "own-holdout": split Jay's own rows first
    (seed 42 -> 580 train / 145 test), train on own-train + all
    external rows, test ONLY on Jay's 145 holdout rows. Own-holdout
    is the honest primary metric: it measures the model on Jay's
    own scanner output, which is what it will score in production.
    """
    dataset = build_dataset(candidates_path, batches_path, limit=limit,
                            fresh_deploys_path=fresh_deploys_path,
                            transitions_path=transitions_path)
    rows = dataset["rows"]
    stats = dataset["stats"]
    if external_path and not os.path.exists(external_path):
        # Never silently train own-only when an external file was asked
        # for: a wrong relative path once shipped the wrong model.
        raise ValueError(f"external file not found: {external_path}")
    ext_rows: list = []
    if external_path and os.path.exists(external_path):
        ext_rows, ext_stats = load_external_rows(external_path)
        stats.update(ext_stats)
        stats["train_rows"] = len(rows) + len(ext_rows)
        stats["n_positive"] = (sum(1 for r in rows if r["label"] == 1)
                               + sum(1 for r in ext_rows if r["label"] == 1))
        stats["n_negative"] = (sum(1 for r in rows if r["label"] == 0)
                               + sum(1 for r in ext_rows if r["label"] == 0))
    if len(rows) + len(ext_rows) < 20:
        raise ValueError(
            f"only {len(rows) + len(ext_rows)} training rows; refusing")
    if eval_mode == "own-holdout":
        train_rows, test_rows = stratified_split(rows, test_frac, seed)
        train_rows = train_rows + ext_rows
    elif eval_mode == "combined":
        train_rows, test_rows = stratified_split(rows + ext_rows,
                                                 test_frac, seed)
    else:
        raise ValueError(f"unknown eval_mode: {eval_mode!r}")
    spec = build_vocab([r["finding"] for r in train_rows],
                       registry_plugins=registry_ids)
    X_train = [extract(r["finding"], spec) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract(r["finding"], spec) for r in test_rows]
    y_test = [r["label"] for r in test_rows]

    # Honest skew line, computed from the real combined set.
    n_pos = sum(y_train) + sum(y_test)
    n_neg = len(rows) - n_pos
    pos_pct = 100.0 * n_pos / max(1, len(rows))
    limits = list(LIMITS)
    limits[2] = (
        f"Label skew: the training set is {pos_pct:.0f}% worth-validating "
        f"/ {100.0 - pos_pct:.0f}% likely-false-positive "
        f"({n_pos} positive / {n_neg} negative of {len(rows)} rows). "
        "Accuracy near the majority baseline means the model learned "
        "nothing; judge it by minority-class recall and ROC AUC instead.")

    layers = [spec.dim] + [int(h) for h in hidden.split(",") if h] + [1]
    if resume_path:
        net, start_epoch, ckpt_touch, ckpt_ctr = load_checkpoint(resume_path)
        if list(net.layers) != list(layers):
            raise ValueError(
                f"checkpoint layers {net.layers} != {layers}; "
                "resume only works for the same spec/hidden sizes")
        resume_state = ((list(ckpt_touch), int(ckpt_ctr))
                        if ckpt_touch is not None else None)
        print(f"resumed from {resume_path} at epoch {start_epoch}")
    else:
        net = MLP(layers, seed=seed, lr=lr)
        start_epoch = 0
        resume_state = None
    history = net.fit(X_train, y_train, epochs=epochs, batch_size=32,
                      X_val=X_test, y_val=y_test, seed=seed,
                      history_every=history_every,
                      checkpoint_path=checkpoint_path,
                      checkpoint_every=checkpoint_every,
                      start_epoch=start_epoch,
                      resume_state=resume_state)
    train_scores = [net.predict_proba(x) for x in X_train]
    test_scores = [net.predict_proba(x) for x in X_test]
    train_metrics = metrics_for(y_train, train_scores)
    test_metrics = metrics_for(y_test, test_scores)
    importance = permutation_importance(net, spec, X_test, y_test, seed)

    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "layers": layers,
        "n_features": spec.dim,
        "eval_mode": eval_mode,
        "registry_plugins": len(spec.plugins),
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
    print(f"eval: {result.get('eval_mode', 'combined')}  "
          f"registry plugins: {result.get('registry_plugins', '?')}")
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
    ap.add_argument("--eval", default="combined",
                    choices=["combined", "own-holdout"],
                    help="combined: split own+external together (v1/v2 "
                         "behaviour, flatters the numbers). own-holdout: "
                         "test only on Jay's 145 own holdout rows.")
    ap.add_argument("--checkpoint", default=None,
                    help="write weights checkpoints here every "
                         "--checkpoint-every epochs (crash-proofing)")
    ap.add_argument("--checkpoint-every", type=int, default=10)
    ap.add_argument("--resume", default=None,
                    help="checkpoint file to resume from (same spec and "
                         "hidden sizes only)")
    ap.add_argument("--history-every", type=int, default=1)
    ap.add_argument("--registry-ids", default=None,
                    help="JSON list of plugin ids for the full-registry "
                         "spec (11,573 inputs). Default: top-K plugin "
                         "blocks from the training rows with the v3 "
                         "context families on (301 inputs). 'none' = "
                         "the same as the default. The full-registry "
                         "spec is opt-in because it scored worse than "
                         "v2 on the own-holdout metric; see "
                         "NN-V2-SWEEP-RECORD.md.")
    ap.add_argument("--fresh-deploys",
                    default=os.path.expanduser(DEFAULT_FRESH_DEPLOYS))
    ap.add_argument("--transitions",
                    default=os.path.expanduser(DEFAULT_TRANSITIONS))
    args = ap.parse_args(argv)
    registry_ids = None
    if args.registry_ids == "none":
        registry_ids = None
    elif args.registry_ids:
        reg_path = os.path.expanduser(args.registry_ids)
        if not os.path.exists(reg_path):
            raise ValueError(f"registry file not found: {reg_path}")
        with open(reg_path, encoding="utf-8") as fh:
            registry_ids = json.load(fh)
    # Default (no --registry-ids): top-K plugin blocks from the
    # training rows, v2-style, with the v3 context families on.
    # The full-registry spec (11,573 inputs) scored WORSE than v2
    # on the honest own-holdout metric (0.882 vs 0.9103: the extra
    # capacity memorised the 2,501 training rows), so it is opt-in
    # only, via an explicit --registry-ids path. See
    # NN-V2-SWEEP-RECORD.md.
    result = train(os.path.expanduser(args.candidates),
                   os.path.expanduser(args.batches),
                   args.out, epochs=args.epochs, hidden=args.hidden,
                   lr=args.lr, seed=args.seed, test_frac=args.test_frac,
                   limit=args.limit,
                   external_path=(os.path.expanduser(args.external)
                                  if args.external else None),
                   eval_mode=args.eval,
                   checkpoint_path=args.checkpoint,
                   checkpoint_every=args.checkpoint_every,
                   resume_path=(os.path.expanduser(args.resume)
                                if args.resume else None),
                   registry_ids=registry_ids,
                   history_every=args.history_every,
                   fresh_deploys_path=os.path.expanduser(args.fresh_deploys),
                   transitions_path=os.path.expanduser(args.transitions))
    _print_report(result)
    print(f"weights: {os.path.join(args.out, 'weights.json')}")
    print(f"viewer data: {os.path.join(args.out, 'viewer-data.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
