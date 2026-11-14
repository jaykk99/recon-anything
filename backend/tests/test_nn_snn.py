"""Tests for the spiking triage network (app.nn.snn).

Pure stdlib, no network, no scanner data: synthetic rows only, so
these run anywhere. The real-data holdout numbers live in
snn_viewer_data.json (produced by `python -m app.nn.snn`), not here.
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.snn import LIF, SNN, encode_fixed, encode_rate  # noqa: E402
import random  # noqa: E402


def test_lif_strong_input_more_spikes_than_weak():
    """Constant strong current fires on (nearly) every step; weak
    current only once the leak lets the membrane build up."""
    lif = LIF(1, beta=0.9, threshold=1.0)
    strong = sum(lif.step([1.5])[0] for _ in range(20))
    lif.reset()
    weak = sum(lif.step([0.3])[0] for _ in range(20))
    assert strong == 20
    assert 0 < weak < strong


def test_lif_zero_input_no_spikes():
    lif = LIF(3, beta=0.9, threshold=1.0)
    total = 0
    for _ in range(20):
        total += sum(lif.step([0.0, 0.0, 0.0]))
    assert total == 0


def test_lif_leak_decays_membrane():
    # A sub-threshold pulse that stops must decay back toward 0.
    lif = LIF(1, beta=0.5, threshold=1.0)
    lif.step([0.9])
    assert lif.v[0] == 0.9
    lif.step([0.0])
    assert lif.v[0] == 0.45


def test_rate_encoding_monotonic():
    """A 0.9 feature fires on far more steps than a 0.1 feature."""
    rng = random.Random(7)
    hi = encode_rate([0.9], 100, rng)
    rng = random.Random(7)
    lo = encode_rate([0.1], 100, rng)
    n_hi = sum(len(t) for t in hi)
    n_lo = sum(len(t) for t in lo)
    assert n_hi > 80
    assert n_lo < 25
    assert n_hi > n_lo


def test_rate_encoding_zero_feature_never_fires():
    trains = encode_rate([0.0, 1.0, 0.0], 16, random.Random(3))
    assert all(0 not in t and 2 not in t for t in trains)
    assert all(1 in t for t in trains)


def test_rate_encoding_deterministic():
    a = encode_fixed([0.7, 0.2, 0.9], 16, seed=99)
    b = encode_fixed([0.7, 0.2, 0.9], 16, seed=99)
    assert a == b


def test_training_reduces_loss_no_explosion():
    """Two separable clusters: strong feature 0 -> label 0, strong
    feature 1 -> label 1. A few epochs must cut the loss and keep
    every weight finite."""
    rng = random.Random(0)
    X, y = [], []
    for _ in range(40):
        X.append([0.9 if rng.random() < 0.8 else 0.1, 0.05, 0.05, 0.05])
        y.append(0)
    for _ in range(40):
        X.append([0.05, 0.9 if rng.random() < 0.8 else 0.1, 0.05, 0.05])
        y.append(1)
    net = SNN(4, n_hidden=8, timesteps=16, seed=1, lr=0.2, scale=8.0)
    before = net._bce([encode_rate(x, 16, random.Random(42)) for x in X],
                      [float(v) for v in y], 1.0, 1.0)
    history = net.fit(X, y, epochs=20, batch_size=16, seed=1)
    after = history["loss"][-1]
    assert after < before
    assert after < before * 0.9
    assert net.accuracy_encoded(
        [encode_rate(x, 16, random.Random(42)) for x in X],
        [float(v) for v in y]) >= 0.6
    for row in net.w_in + net.w_out:
        for v in row:
            assert math.isfinite(v)
    for v in net.b_hidden + net.b_out:
        assert math.isfinite(v)


def test_save_load_roundtrip(tmp_path):
    net = SNN(6, n_hidden=4, timesteps=8, seed=3)
    net.fit([[0.9, 0.1, 0.0, 0.0, 0.0, 0.0],
             [0.1, 0.9, 0.0, 0.0, 0.0, 0.0]], [0, 1], epochs=3)
    path = str(tmp_path / "snn.json")
    net.save(path)
    net2 = SNN.load(path)
    assert net2.n_in == net.n_in
    assert net2.n_hidden == net.n_hidden
    assert net2.timesteps == net.timesteps
    for x in ([0.9, 0.1, 0.0, 0.0, 0.0, 0.0],
              [0.1, 0.9, 0.0, 0.0, 0.0, 0.0],
              [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]):
        assert net2.predict_proba(x) == net.predict_proba(x)


def test_predict_proba_range_and_labels_only():
    """Scores are probabilities in (0, 1); predictions are only the
    two triage labels (0/1). The model has no VERIFIED_REAL output:
    there is no third class anywhere in its readout."""
    net = SNN(4, n_hidden=4, timesteps=8, seed=5)
    for x in ([1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0],
              [0.0, 0.0, 0.0, 0.0], [1.0, 1.0, 1.0, 1.0]):
        p = net.predict_proba(x)
        assert 0.0 < p < 1.0
        assert net.predict(x) in (0, 1)


def test_spike_count_readout_direction():
    """With the class-1 output weights larger, a fully-firing hidden
    layer must count more spikes for class 1 than class 0."""
    net = SNN(2, n_hidden=2, timesteps=8, seed=1)
    net.w_out = [[0.1, 0.1], [2.0, 2.0]]
    net.b_out = [0.0, 0.0]
    net.b_hidden = [2.0, 2.0]  # hidden fires every step
    spikes = encode_fixed([1.0, 1.0], 8, seed=1)
    c0, c1 = net.spike_counts(spikes)
    assert c1 > c0
