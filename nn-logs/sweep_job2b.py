"""Job 2 sweep batch 2: confirm the batch-1 L2 lead across seeds and
test the bigger external set.

Batch 1 (same frozen 145-row holdout) found two leads at 0.9241
(+2 rows vs v2's 0.9103): l2-1e-3 and l2-3e-2. The seed noise floor
is 1 row (base seeds 42/43/44 scored 0.9103/0.9172/0.9103), so a
single-seed 0.9241 is NOT yet a confirmed beat. This batch:
  - replicates both L2 leads at seeds 43/44 (std 1,922 external rows)
  - replicates the AUC leader l2-1e-2 at seed 43
  - trains the base config and both L2 leads on the bigger external
    set (3,422 rows: xanoutas + audit-findings caps 1,200)

Same crash-proofing as batch 1: checkpoints every 20 epochs,
resumable via sweep-results-b2.jsonl + checkpoint files.

Run detached:
  nohup python3 nn-logs/sweep_job2b.py > nn-logs/job2-sweep-b2.log 2>&1 &
"""
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "backend")))
sys.path.insert(0, _HERE)

from app.nn.data import build_dataset, load_external_rows, stratified_split  # noqa: E402
from app.nn.mlp import MLP, load_checkpoint  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402
from sweep_job2 import _current_labels, _eval  # noqa: E402

NN_DIR = os.path.normpath(os.path.join(_HERE, "..", "backend", "app", "nn"))
FROZEN = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
STD_EXT = os.path.join(NN_DIR, "external_findings.jsonl")
BIG_EXT = os.path.join(_HERE, "job2", "external-3422.jsonl")
JOB2_DIR = os.path.join(_HERE, "job2")
RESULTS = os.path.join(JOB2_DIR, "sweep-results-b2.jsonl")

# name, layers, lr, l2, epochs, dropout, seed, ext_file
VARIANTS = [
    ("l2-1e-3-seed43", [255, 64, 32, 1], 0.05, 1e-3, 120, 0.0, 43, STD_EXT),
    ("l2-1e-3-seed44", [255, 64, 32, 1], 0.05, 1e-3, 120, 0.0, 44, STD_EXT),
    ("l2-3e-2-seed43", [255, 64, 32, 1], 0.05, 3e-2, 120, 0.0, 43, STD_EXT),
    ("l2-3e-2-seed44", [255, 64, 32, 1], 0.05, 3e-2, 120, 0.0, 44, STD_EXT),
    ("l2-1e-2-seed43", [255, 64, 32, 1], 0.05, 1e-2, 120, 0.0, 43, STD_EXT),
    ("ext3422-base", [255, 64, 32, 1], 0.05, 1e-4, 120, 0.0, 42, BIG_EXT),
    ("ext3422-l2-1e-3", [255, 64, 32, 1], 0.05, 1e-3, 120, 0.0, 42, BIG_EXT),
    ("ext3422-l2-3e-2", [255, 64, 32, 1], 0.05, 3e-2, 120, 0.0, 42, BIG_EXT),
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


def main():
    with open(os.path.join(NN_DIR, "weights.json"),
              encoding="utf-8") as fh:
        spec = json.load(fh)["features"]
    plugins, keys = spec["plugins"], spec["keys"]
    dataset = build_dataset(FROZEN, BATCHES)
    own_rows = dataset["rows"]
    own_train, own_test = stratified_split(own_rows, 0.2, 42)
    print(f"frozen own {len(own_rows)} train {len(own_train)} "
          f"test {len(own_test)}", flush=True)
    y_test_current = []
    cur = _current_labels()
    for r in own_test:
        k = ((r["chain"] or "").lower(), (r["address"] or "").lower(),
             r["plugin"] or "", r["key"] or "", r["function"] or "")
        y_test_current.append(cur.get(k, r["label"]))
    X_test = [extract_v2(r["finding"], plugins, keys) for r in own_test]
    y_test = [r["label"] for r in own_test]
    train_cache = {}

    def train_matrices(ext_path):
        if ext_path not in train_cache:
            ext_rows, _ = load_external_rows(ext_path)
            rows = own_train + ext_rows
            X = [extract_v2(r["finding"], plugins, keys) for r in rows]
            y = [r["label"] for r in rows]
            train_cache[ext_path] = (X, y, len(ext_rows))
            print(f"  external {os.path.basename(ext_path)}: "
                  f"{len(ext_rows)} rows -> train {len(rows)}", flush=True)
        return train_cache[ext_path]

    done = _done_variants()
    print(f"resuming; already done: {sorted(done)}", flush=True)
    for (name, layers, lr, l2, epochs, dropout, seed,
         ext_path) in VARIANTS:
        if name in done:
            print(f"SKIP {name} (already done)", flush=True)
            continue
        t0 = time.time()
        X_train, y_train, n_ext = train_matrices(ext_path)
        ckpt = os.path.join(JOB2_DIR, f"{name}-ckpt.json")
        print(f"START {name} layers={layers} lr={lr} l2={l2} "
              f"epochs={epochs} dropout={dropout} seed={seed} "
              f"ext={os.path.basename(ext_path)} train_n={len(X_train)}",
              flush=True)
        net = None
        start_epoch = 0
        resume_state = None
        if os.path.exists(ckpt):
            try:
                net, start_epoch, touch, ctr = load_checkpoint(ckpt)
                resume_state = ((list(touch), int(ctr))
                                if touch is not None else None)
                print(f"  resume {name} at epoch {start_epoch}", flush=True)
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
        ev = _eval(net, X_train, y_train, X_test, y_test, y_test_current)
        rec = {"kind": "final", "variant": name, "layers": layers,
               "lr": lr, "l2": l2, "epochs": epochs,
               "dropout": dropout, "seed": seed,
               "ext": os.path.basename(ext_path), "n_ext": n_ext,
               "train_n": len(X_train),
               "elapsed_s": round(time.time() - t0, 1), **ev}
        _record(rec)
        print(f"DONE {name}: test acc={ev['test']['acc']} "
              f"auc={ev['test']['auc']} cm={ev['test']['cm']} "
              f"fp_recall={ev['test']['fp_recall']} "
              f"train_acc={ev['train']['acc']} "
              f"({time.time() - t0:.0f}s)", flush=True)
    print("SWEEP-B2-DONE", flush=True)


if __name__ == "__main__":
    main()
