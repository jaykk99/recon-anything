"""Test the dropout change to MLP.

1. dropout=0 must be bit-identical to the pre-dropout code (train the
   same 5 epochs, compare final weights).
2. Numeric gradient check WITH dropout: freeze the masks by re-seeding
   the rng before every forward, perturb one weight, compare the
   analytic gradient from _backward against the finite difference.
3. predict_proba must be deterministic with dropout trained nets.
"""
import importlib.util
import math
import os
import random
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "backend")))

from app.nn.data import build_dataset, load_external_rows, stratified_split  # noqa: E402
from app.nn.mlp import MLP as NewMLP  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402

NN_DIR = os.path.normpath(os.path.join(_HERE, "..", "backend", "app", "nn"))
FROZEN = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(NN_DIR, "external_findings.jsonl")


def load_old_mlp():
    subprocess.run(["git", "show",
                    "origin/feat/nn-scorer:backend/app/nn/mlp.py"],
                   cwd=os.path.normpath(os.path.join(_HERE, "..")),
                   stdout=open("/tmp/old_mlp.py", "w"), check=True)
    spec = importlib.util.spec_from_file_location("old_mlp", "/tmp/old_mlp.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.MLP


def main():
    import json
    with open(os.path.join(NN_DIR, "weights.json"), encoding="utf-8") as fh:
        spec = json.load(fh)["features"]
    plugins, keys = spec["plugins"], spec["keys"]
    dataset = build_dataset(FROZEN, BATCHES)
    own_rows = dataset["rows"]
    ext_rows, _ = load_external_rows(EXTERNAL)
    own_train, _ = stratified_split(own_rows, 0.2, 42)
    train_rows = (own_train + ext_rows)[:200]
    X = [extract_v2(r["finding"], plugins, keys) for r in train_rows]
    y = [r["label"] for r in train_rows]

    # 1. dropout=0 vs old code, 5 epochs.
    OldMLP = load_old_mlp()
    old = OldMLP([255, 64, 32, 1], seed=42, lr=0.05)
    old.fit(X, y, epochs=5, batch_size=32, seed=42)
    new = NewMLP([255, 64, 32, 1], seed=42, lr=0.05)
    new.fit(X, y, epochs=5, batch_size=32, seed=42, dropout=0.0)
    same = old.weights == new.weights and old.biases == new.biases
    print(f"dropout=0 bit-identical to old code: {same}", flush=True)
    assert same, "dropout=0 changed training!"

    # 2. Numeric gradient check with dropout frozen masks.
    net = NewMLP([8, 4, 1], seed=1, lr=0.05)
    x = [0.3, -0.7, 0.0, 0.9, 0.0, 0.0, 0.5, -0.2]
    yv = 1.0

    def loss_with_mask():
        rng = random.Random(7)
        acts, _ = net._forward(x, dropout=0.5, training=True, rng=rng)
        p = min(max(acts[-1][0], 1e-12), 1 - 1e-12)
        return -(yv * math.log(p) + (1 - yv) * math.log(1 - p))

    def analytic():
        rng = random.Random(7)
        acts, pres = net._forward(x, dropout=0.5, training=True, rng=rng)
        return net._backward(acts, pres, yv)

    gw, gb = analytic()
    eps = 1e-6
    worst = 0.0
    for li in range(len(net.weights)):
        for r in range(len(net.weights[li])):
            for c in range(len(net.weights[li][r])):
                orig = net.weights[li][r][c]
                net.weights[li][r][c] = orig + eps
                lp = loss_with_mask()
                net.weights[li][r][c] = orig - eps
                lm = loss_with_mask()
                net.weights[li][r][c] = orig
                num = (lp - lm) / (2 * eps)
                ana = gw[li][r][c]
                denom = max(1e-9, abs(num) + abs(ana))
                worst = max(worst, abs(num - ana) / denom)
    print(f"dropout numeric-grad worst relative error: {worst:.2e}",
          flush=True)
    assert worst < 1e-4, f"dropout gradient wrong: {worst}"

    # 3. Deterministic prediction after dropout training.
    net2 = NewMLP([255, 64, 32, 1], seed=42, lr=0.05)
    net2.fit(X, y, epochs=3, batch_size=32, seed=42, dropout=0.5)
    p1 = net2.predict_proba(X[0])
    p2 = net2.predict_proba(X[0])
    print(f"dropout-trained predict deterministic: {p1 == p2} "
          f"(p={p1:.4f})", flush=True)
    assert p1 == p2
    print("DROPOUT-TEST-DONE", flush=True)


if __name__ == "__main__":
    main()
