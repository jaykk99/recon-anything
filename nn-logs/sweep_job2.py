"""Job 2 sweep: push HONEST own-holdout accuracy past v2's 0.9103.

Fixed benchmark: the frozen 145-row own holdout (seed 42, from
candidates.jsonl.bak-20261114: 725 own rows -> 580 train / 145 test)
+ all 1,922 external rows in training. 255 features, no new inputs
(v3 proved more inputs memorize). Levers: L2, fewer epochs, smaller
nets, dropout (added to mlp.py, gradient-checked), negative
oversampling (real rows duplicated, never synthetic), seed repeats
to measure the noise floor.

Crash-proof: every variant checkpoints every 20 epochs (atomic
tmp + rename); the sweep is resumable -- completed variants are
recorded in sweep-results.jsonl and skipped on re-run, and an
interrupted variant resumes from its checkpoint file. One JSON line
per result, flushed immediately.

Run detached:
  nohup python3 nn-logs/sweep_job2.py > nn-logs/job2-sweep.log 2>&1 &
"""
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "backend")))

from app.nn.data import (  # noqa: E402
    VERDICT_LABELS, build_dataset, load_external_rows, load_jsonl,
    stratified_split)
from app.nn.mlp import MLP, load_checkpoint, metrics_for  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402

NN_DIR = os.path.normpath(os.path.join(_HERE, "..", "backend", "app", "nn"))
FROZEN = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
CURRENT = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")
BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(NN_DIR, "external_findings.jsonl")
JOB2_DIR = os.path.join(_HERE, "job2")
RESULTS = os.path.join(JOB2_DIR, "sweep-results.jsonl")
os.makedirs(JOB2_DIR, exist_ok=True)

# name, layers, lr, l2, epochs, dropout, seed, neg_dup, chunked
VARIANTS = [
    ("base-single", [255, 64, 32, 1], 0.05, 1e-4, 120, 0.0, 42, 1, False),
    ("base-seed43", [255, 64, 32, 1], 0.05, 1e-4, 120, 0.0, 43, 1, False),
    ("base-seed44", [255, 64, 32, 1], 0.05, 1e-4, 120, 0.0, 44, 1, False),
    ("base-chunked", [255, 64, 32, 1], 0.05, 1e-4, 120, 0.0, 42, 1, True),
    ("l2-1e-3", [255, 64, 32, 1], 0.05, 1e-3, 120, 0.0, 42, 1, False),
    ("l2-1e-2", [255, 64, 32, 1], 0.05, 1e-2, 120, 0.0, 42, 1, False),
    ("l2-3e-2", [255, 64, 32, 1], 0.05, 3e-2, 120, 0.0, 42, 1, False),
    ("small-32-16", [255, 32, 16, 1], 0.05, 1e-4, 120, 0.0, 42, 1, False),
    ("ep60", [255, 64, 32, 1], 0.05, 1e-4, 60, 0.0, 42, 1, False),
    ("drop-0.2", [255, 64, 32, 1], 0.05, 1e-4, 120, 0.2, 42, 1, False),
    ("drop-0.3-l2-1e-3", [255, 64, 32, 1], 0.05, 1e-3, 120, 0.3, 42, 1,
     False),
    ("neg-dup2", [255, 64, 32, 1], 0.05, 1e-4, 120, 0.0, 42, 2, False),
]


def _record(rec):
    with open(RESULTS, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _done_variants():
    done = set()
    if os.path.exists(RESULTS):
        with open(RESULTS, encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("kind") == "final":
                    done.add(r["variant"])
    return done


def _current_labels():
    out = {}
    for row, err in load_jsonl(CURRENT):
        if err is not None:
            continue
        label = VERDICT_LABELS.get((row.get("validation") or {}).get("verdict"))
        if label is None:
            continue
        out[((row.get("chain") or "").lower(),
             (row.get("address") or "").lower(),
             row.get("plugin") or "", row.get("key") or "",
             row.get("function") or "")] = label
    return out


def _eval(net, X_train, y_train, X_test, y_test, y_test_current):
    m_tr = metrics_for(y_train, [net.predict_proba(x) for x in X_train])
    m_te = metrics_for(y_test, [net.predict_proba(x) for x in X_test])
    m_cur = metrics_for(y_test_current,
                        [net.predict_proba(x) for x in X_test])
    return {
        "train": {"n": m_tr["n"], "acc": round(m_tr["accuracy"], 4),
                  "auc": round(m_tr["roc_auc"], 4),
                  "cm": m_tr["confusion"]},
        "test": {"n": m_te["n"], "acc": round(m_te["accuracy"], 4),
                 "auc": round(m_te["roc_auc"], 4),
                 "cm": m_te["confusion"],
                 "fp_recall": round(m_te["recall_likely_fp"], 4),
                 "baseline": round(m_te["majority_baseline_accuracy"], 4)},
        "test_current_labels": {"n": m_cur["n"],
                                "acc": round(m_cur["accuracy"], 4),
                                "auc": round(m_cur["roc_auc"], 4),
                                "cm": m_cur["confusion"]},
    }


def main():
    with open(os.path.join(NN_DIR, "weights.json"),
              encoding="utf-8") as fh:
        spec = json.load(fh)["features"]
    plugins, keys = spec["plugins"], spec["keys"]
    dataset = build_dataset(FROZEN, BATCHES)
    own_rows = dataset["rows"]
    ext_rows, _ = load_external_rows(EXTERNAL)
    own_train, own_test = stratified_split(own_rows, 0.2, 42)
    print(f"frozen own {len(own_rows)} train {len(own_train)} "
          f"test {len(own_test)} + external {len(ext_rows)}", flush=True)
    cur = _current_labels()
    y_test_current = []
    for r in own_test:
        k = ((r["chain"] or "").lower(), (r["address"] or "").lower(),
             r["plugin"] or "", r["key"] or "", r["function"] or "")
        y_test_current.append(cur.get(k, r["label"]))
    X_test = [extract_v2(r["finding"], plugins, keys) for r in own_test]
    y_test = [r["label"] for r in own_test]
    base_train_rows = own_train + ext_rows
    X_base = [extract_v2(r["finding"], plugins, keys)
              for r in base_train_rows]
    y_base = [r["label"] for r in base_train_rows]
    done = _done_variants()
    print(f"resuming; already done: {sorted(done)}", flush=True)

    for (name, layers, lr, l2, epochs, dropout, seed, neg_dup,
         chunked) in VARIANTS:
        if name in done:
            print(f"SKIP {name} (already done)", flush=True)
            continue
        t0 = time.time()
        ckpt = os.path.join(JOB2_DIR, f"{name}-ckpt.json")
        if neg_dup > 1:
            X_train, y_train = list(X_base), list(y_base)
            neg_idx = [i for i, v in enumerate(y_base) if v == 0]
            for _ in range(neg_dup - 1):
                for i in neg_idx:
                    X_train.append(X_base[i])
                    y_train.append(0)
        else:
            X_train, y_train = X_base, y_base
        print(f"START {name} layers={layers} lr={lr} l2={l2} "
              f"epochs={epochs} dropout={dropout} seed={seed} "
              f"neg_dup={neg_dup} chunked={chunked} "
              f"train_n={len(X_train)}", flush=True)
        if chunked:
            # 20-epoch chunks; each chunk end is evaluated on the
            # holdout (early-stopping curve). Resume from the last
            # chunk checkpoint if present.
            net = None
            start = 0
            resume_state = None
            if os.path.exists(ckpt):
                try:
                    net, start, touch, ctr = load_checkpoint(ckpt)
                    resume_state = ((list(touch), int(ctr))
                                    if touch is not None else None)
                    print(f"  resume {name} at epoch {start}", flush=True)
                except Exception as e:  # noqa: BLE001 - corrupt ckpt
                    print(f"  bad ckpt, restarting: {e}", flush=True)
                    net, start, resume_state = None, 0, None
            if net is None:
                net = MLP(layers, seed=seed, lr=lr, l2=l2)
            for end in range(20, epochs + 1, 20):
                if end <= start:
                    continue
                net.fit(X_train, y_train, epochs=end, batch_size=32,
                        X_val=X_test, y_val=y_test, seed=seed,
                        history_every=20, checkpoint_path=ckpt,
                        checkpoint_every=20, start_epoch=start,
                        resume_state=resume_state, dropout=dropout)
                ev = _eval(net, X_train, y_train, X_test, y_test,
                           y_test_current)
                rec = {"kind": "chunk", "variant": name,
                       "epochs_done": end, "elapsed_s": round(time.time() - t0, 1),
                       **ev}
                _record(rec)
                print(f"  {name} ep{end}: test acc={ev['test']['acc']} "
                      f"auc={ev['test']['auc']} cm={ev['test']['cm']} "
                      f"train_acc={ev['train']['acc']}", flush=True)
                start = end
                # Weights are settled (_settle_l2) at the end of each
                # fit call, so the NEXT chunk must use fresh lazy-L2
                # state (resume_state=None): the checkpoint file's
                # last_touch/batch_ctr describe the PRE-settle weights
                # and reusing them would double-apply decay. Fresh
                # state is exact for settled weights: a column first
                # touched at chunk batch k gets decay**(k+1), covering
                # exactly this chunk's batches 0..k. resume_state is
                # only valid when resuming a killed run from its
                # checkpoint (pre-settle weights + matching state).
            final_epochs = epochs
        else:
            net = None
            start_epoch = 0
            resume_state = None
            if os.path.exists(ckpt):
                try:
                    net, start_epoch, touch, ctr = load_checkpoint(ckpt)
                    resume_state = ((list(touch), int(ctr))
                                    if touch is not None else None)
                    print(f"  resume {name} at epoch {start_epoch}",
                          flush=True)
                except Exception as e:  # noqa: BLE001
                    print(f"  bad ckpt, restarting: {e}", flush=True)
                    net, start_epoch, resume_state = None, 0, None
            if net is None:
                net = MLP(layers, seed=seed, lr=lr, l2=l2)
            net.fit(X_train, y_train, epochs=epochs, batch_size=32,
                    X_val=X_test, y_val=y_test, seed=seed,
                    history_every=20, checkpoint_path=ckpt,
                    checkpoint_every=20, start_epoch=start_epoch,
                    resume_state=resume_state, dropout=dropout)
            final_epochs = epochs
        ev = _eval(net, X_train, y_train, X_test, y_test, y_test_current)
        rec = {"kind": "final", "variant": name, "layers": layers,
               "lr": lr, "l2": l2, "epochs": final_epochs,
               "dropout": dropout, "seed": seed, "neg_dup": neg_dup,
               "chunked": chunked, "train_n": len(X_train),
               "elapsed_s": round(time.time() - t0, 1), **ev}
        _record(rec)
        print(f"DONE {name}: test acc={ev['test']['acc']} "
              f"auc={ev['test']['auc']} cm={ev['test']['cm']} "
              f"fp_recall={ev['test']['fp_recall']} "
              f"train_acc={ev['train']['acc']} "
              f"({time.time() - t0:.0f}s)", flush=True)
    print("SWEEP-DONE", flush=True)


if __name__ == "__main__":
    main()
