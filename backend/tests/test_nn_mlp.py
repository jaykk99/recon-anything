"""MLP math: forward on a hand-computed case, backprop learning on
XOR, JSON save/load round-trip. Pure stdlib, no network."""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.mlp import MLP, confusion_matrix, metrics_for, roc_auc  # noqa: E402


def test_forward_known_case():
    # layers [2, 1]: one sigmoid unit, no hidden layer.
    net = MLP([2, 1], seed=1)
    net.weights = [[[0.5, -0.25]]]
    net.biases = [[0.1]]
    x = [1.0, 2.0]
    z = 0.5 * 1.0 + (-0.25) * 2.0 + 0.1  # 0.1
    expected = 1.0 / (1.0 + math.exp(-z))
    assert net.predict_proba(x) == expected
    assert net.predict(x) == 1  # 0.525 > 0.5


def test_backprop_learns_xor():
    X = [[0.0, 0.0], [0.0, 1.0], [1.0, 0.0], [1.0, 1.0]]
    y = [0, 1, 1, 0]
    net = MLP([2, 4, 1], seed=7, lr=0.5)
    before = net._bce(X, y)
    net.fit(X, y, epochs=400, batch_size=4)
    after = net._bce(X, y)
    assert after < before
    assert after < 0.1
    assert net.accuracy(X, y) == 1.0


def test_save_load_roundtrip(tmp_path):
    net = MLP([3, 4, 1], seed=3)
    net.fit([[0.1, 0.2, 0.3], [0.9, 0.8, 0.7]], [0, 1], epochs=5)
    path = str(tmp_path / "net.json")
    net.save(path)
    net2 = MLP.load(path)
    assert net2.layers == net.layers
    for x in ([0.1, 0.2, 0.3], [0.9, 0.8, 0.7], [0.5, 0.5, 0.5]):
        assert net2.predict_proba(x) == net.predict_proba(x)


def test_roc_auc_and_metrics():
    assert roc_auc([0.1, 0.9, 0.2, 0.8], [0, 1, 0, 1]) == 1.0
    assert roc_auc([0.5, 0.5, 0.5, 0.5], [0, 1, 0, 1]) == 0.5
    m = metrics_for([1, 1, 0, 0], [0.9, 0.4, 0.6, 0.1])
    assert m["confusion"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert m["accuracy"] == 0.5
    assert m["majority_baseline_accuracy"] == 0.5
    assert confusion_matrix([1, 0], [0, 1]) == {
        "tn": 0, "fp": 1, "fn": 1, "tp": 0}
