"""Feature extraction: real finding shapes in, fixed vectors out.
No invented fields: absent evidence reads as absent, and label-side
data (validation verdicts, live probes) never changes a vector."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.features import FeatureSpec, build_vocab, extract, top_features  # noqa: E402
from app.nn.mlp import MLP  # noqa: E402
from nn_fixtures import ROWS  # noqa: E402


def _spec():
    return build_vocab([f for f, _ in ROWS])


def test_vector_length_matches_spec():
    spec = _spec()
    for f, _ in ROWS:
        v = extract(f, spec)
        assert len(v) == spec.dim == len(spec.feature_names())
        assert all(0.0 <= x <= 1.0 for x in v)


def test_unknown_plugin_and_key_land_in_other():
    spec = _spec()
    names = spec.feature_names()
    f = dict(ROWS[0][0])
    f["plugin"] = "never_seen_plugin_xyz"
    f["key"] = "never_seen_key_xyz"
    v = extract(f, spec)
    assert v[names.index("plugin:OTHER:fired")] == 1.0
    assert v[names.index("key:OTHER")] == 1.0


def test_known_signals_present():
    spec = _spec()
    names = spec.feature_names()
    # Row 2 (index 2) is an implementation contract with a gate note.
    # Its plugin block carries the gate/detector signals now.
    blk = "plugin:unchecked_math_user_input:"
    v = extract(ROWS[2][0], spec)
    assert v[names.index("role:implementation")] == 1.0
    assert v[names.index(blk + "gate_present")] == 1.0
    assert v[names.index(blk + "gate_no_caller")] == 1.0
    assert v[names.index("proxy_present")] == 1.0
    assert v[names.index(blk + "detector_present")] == 1.0
    assert v[names.index(blk + "fired")] == 1.0
    assert v[names.index(blk + "confidence")] == 0.8
    # Row 1 (index 1) has no detector outcome and no proxy.
    blk1 = "plugin:contract_logic:"
    v2 = extract(ROWS[1][0], spec)
    assert v2[names.index(blk1 + "detector_present")] == 0.0
    assert v2[names.index("proxy_present")] == 0.0


def test_plugin_blocks_only_fired_block_is_live():
    spec = _spec()
    names = spec.feature_names()
    v = extract(ROWS[2][0], spec)
    fired = [n for n in names
             if n.startswith("plugin:") and n.endswith(":fired")]
    live = [n for n in fired if v[names.index(n)] == 1.0]
    assert live == ["plugin:unchecked_math_user_input:fired"]
    # Count input: absent -> 1 finding -> 1/8; 8 findings -> 1.0.
    blk = "plugin:unchecked_math_user_input:"
    assert v[names.index(blk + "count")] == 1.0 / 8.0
    f = dict(ROWS[2][0])
    f["plugin_finding_count"] = 8
    v8 = extract(f, spec)
    assert v8[names.index(blk + "count")] == 1.0
    f["plugin_finding_count"] = 80
    assert extract(f, spec)[names.index(blk + "count")] == 1.0


def test_label_side_data_never_leaks_into_features():
    spec = _spec()
    f = dict(ROWS[0][0])
    base = extract(f, spec)
    f["validation"] = {"verdict": "FALSE_POSITIVE"}
    f["live_probe"] = {"status": "revert"}
    assert extract(f, spec) == base


def test_top_features_explain_a_score():
    spec = _spec()
    X = [extract(f, spec) for f, _ in ROWS]
    y = [label for _, label in ROWS]
    net = MLP([spec.dim, 8, 1], seed=5, lr=0.1)
    net.fit(X, y, epochs=30, batch_size=6)
    feats = top_features(ROWS[2][0], spec, net, k=3)
    assert 1 <= len(feats) <= 3
    for item in feats:
        assert set(item) == {"feature", "direction", "delta"}
        assert item["direction"] in ("up", "down")
        assert item["feature"] in spec.feature_names()
