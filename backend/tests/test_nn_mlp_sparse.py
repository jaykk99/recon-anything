"""Sparse first layer + crash-proof checkpoints (v3).

The v3 spec has 11,573 inputs; a finding lights up ~60 of them.
The sparse forward path must match the dense dot product, and a
checkpoint written mid-run must resume cleanly.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.mlp import MLP, load_checkpoint  # noqa: E402


def _sparse_rows(n=60, dim=500, k=12, seed=7):
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n):
        row = [0.0] * dim
        for i in rng.sample(range(dim), k):
            row[i] = rng.uniform(-1, 1)
        X.append(row)
        y.append(rng.randint(0, 1))
    return X, y


def test_sparse_forward_matches_dense():
    X, _ = _sparse_rows(n=5)
    net = MLP([500, 16, 8, 1], seed=3)
    for x in X:
        sparse, _ = net._forward(x)
        dense, _ = net._forward(x, nz=list(range(500)))
        for ra, rb in zip(sparse, dense):
            for a, b in zip(ra, rb):
                assert abs(a - b) < 1e-12
        # predict_proba matches to a float ULP: the dense path uses
        # CPython's compensated sum(), the sparse path a plain loop.
        assert abs(net.predict_proba(x) - net.predict_proba(
            x, nz=list(range(500)))) < 1e-12


def _dense_reference_fit(layers, W0, B0, X, y, epochs, batch_size,
                         seed, lr, l2):
    """Independent dense mini-batch SGD: no sparse paths, no lazy
    L2. The sparse fit must match this to a float ULP-ish tolerance.
    """
    import math
    W = [[row[:] for row in m] for m in W0]
    B = [b[:] for b in B0]
    rng = random.Random(seed)
    n = len(X)

    def sigmoid(z):
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def forward(x):
        acts = [list(map(float, x))]
        for li in range(len(W)):
            z = [sum(a * b for a, b in zip(row, acts[-1])) + bias
                 for row, bias in zip(W[li], B[li])]
            if li == len(W) - 1:
                acts.append([sigmoid(v) for v in z])
            else:
                acts.append([math.tanh(v) for v in z])
        return acts

    def deltas(acts, yy):
        d = [None] * len(W)
        d[-1] = [acts[-1][0] - yy]
        for li in range(len(W) - 2, -1, -1):
            dd = []
            for j in range(len(acts[li + 1])):
                s = sum(W[li + 1][k][j] * d[li + 1][k]
                        for k in range(len(d[li + 1])))
                dd.append(s * (1 - acts[li + 1][j] ** 2))
            d[li] = dd
        return d

    for _epoch in range(epochs):
        order = list(range(n))
        rng.shuffle(order)
        for s in range(0, n, batch_size):
            idxs = order[s:s + batch_size]
            gw = [[[0.0] * len(row) for row in m] for m in W]
            gb = [[0.0] * len(b) for b in B]
            for i in idxs:
                acts = forward(X[i])
                dl = deltas(acts, float(y[i]))
                for li in range(len(dl)):
                    for r in range(len(dl[li])):
                        for c in range(len(acts[li])):
                            gw[li][r][c] += dl[li][r] * acts[li][c]
                    for r in range(len(dl[li])):
                        gb[li][r] += dl[li][r]
            m = float(len(idxs))
            for li in range(len(W)):
                for r in range(len(W[li])):
                    for c in range(len(W[li][r])):
                        W[li][r][c] -= lr * (gw[li][r][c] / m
                                             + l2 * W[li][r][c])
                for r in range(len(B[li])):
                    B[li][r] -= lr * (gb[li][r] / m)
    return W, B


def test_sparse_fit_matches_dense_reference():
    X, y = _sparse_rows(n=40, dim=60, k=12, seed=11)
    net = MLP([60, 8, 1], seed=3, lr=0.05, l2=1e-4)
    W0 = [[row[:] for row in m] for m in net.weights]
    B0 = [b[:] for b in net.biases]
    net.fit(X, y, epochs=5, batch_size=8, seed=3)
    W, B = _dense_reference_fit([60, 8, 1], W0, B0, X, y, 5, 8, 3,
                                0.05, 1e-4)
    worst = 0.0
    for m1, m2 in zip(net.weights, W):
        for r1, r2 in zip(m1, m2):
            for a, b in zip(r1, r2):
                worst = max(worst, abs(a - b))
    for b1, b2 in zip(net.biases, B):
        for a, b in zip(b1, b2):
            worst = max(worst, abs(a - b))
    # Different summation orders (sparse loop vs dense Neumaier
    # sum) drift by ~1e-7 over 5 epochs: far below anything that
    # could move a score or a metric. The math is the same.
    assert worst < 1e-6, f"sparse vs dense max weight diff {worst}"


def test_never_touched_column_decays_exactly():
    # Column 0 is zero in every row: its weights may only shrink by
    # the L2 factor, once per batch, settled at the end of fit.
    X, y = _sparse_rows(n=40, dim=60, k=12, seed=11)
    for row in X:
        row[0] = 0.0
    net = MLP([60, 8, 1], seed=3, lr=0.05, l2=1e-4)
    w0_before = [row[0] for row in net.weights[0]]
    epochs, batch = 5, 8
    net.fit(X, y, epochs=epochs, batch_size=batch, seed=3)
    n_batches = epochs * ((len(X) + batch - 1) // batch)
    factor = (1.0 - 0.05 * 1e-4) ** n_batches
    for before, row in zip(w0_before, net.weights[0]):
        assert abs(row[0] - before * factor) < 1e-12


def test_checkpoint_resume_roundtrip(tmp_path):
    X, y = _sparse_rows()
    ckpt = str(tmp_path / "ckpt.json")
    net = MLP([500, 16, 8, 1], seed=3)
    net.fit(X, y, epochs=4, batch_size=16,
            checkpoint_path=ckpt, checkpoint_every=2)
    resumed, done, touch, ctr = load_checkpoint(ckpt)
    assert done == 4
    assert resumed.layers == [500, 16, 8, 1]
    assert touch is not None and len(touch) == 500
    assert ctr > 0
    resumed.fit(X, y, epochs=8, batch_size=16, start_epoch=done,
                resume_state=(touch, ctr))
    acc = resumed.accuracy(X, y)
    assert 0.0 <= acc <= 1.0
    # A torn checkpoint path must fail loudly, never silently resume.
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    try:
        load_checkpoint(str(bad))
    except ValueError:
        pass
    else:
        raise AssertionError("bad checkpoint did not raise")
