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


def test_registry_vocab_gives_every_plugin_a_block():
    import json
    import os
    reg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "app", "nn", "registry-plugin-ids.json")
    with open(reg_path, encoding="utf-8") as fh:
        registry = json.load(fh)
    assert len(registry) == 1433
    spec = build_vocab([f for f, _ in ROWS], registry_plugins=registry)
    # (1433 plugins + OTHER) x 8 inputs, plus keys from the fixture
    # rows, 35 other v2 inputs, and the 41 v3 context inputs.
    names = spec.feature_names()
    assert spec.dim == len(names)
    assert sum(1 for n in names if n.startswith("plugin:")) == 1434 * 8
    assert spec.dim == 1434 * 8 + (len(spec.keys) + 1) + 35 + 41
    assert len(spec.keys) == 6  # fixtures only carry 6 distinct keys
    v = extract(ROWS[2][0], spec)
    assert len(v) == spec.dim
    assert all(0.0 <= x <= 1.0 for x in v)
    assert v[names.index("plugin:unchecked_math_user_input:fired")] == 1.0
    # A plugin never seen in training still has a block, all zero here.
    assert v[names.index("plugin:aave_v3_state:fired")] == 0.0
    assert spec.to_dict()["spec_version"] == 3


def test_context_features_from_real_joins_only():
    import json
    import os
    reg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "app", "nn", "registry-plugin-ids.json")
    with open(reg_path, encoding="utf-8") as fh:
        registry = json.load(fh)
    spec = build_vocab([f for f, _ in ROWS], registry_plugins=registry)
    names = spec.feature_names()
    f = dict(ROWS[2][0])
    f["context"] = {
        "n_findings": 99, "n_plugins": 16, "n_keys": 8, "n_functions": 4,
        "max_conf": 90.0, "mean_conf": 50.0, "plugin_share": 0.25,
        "has_source": True, "has_proxy": True, "has_impl": False,
        "function_count": 59, "code_len": 9999, "stake_usd": 1e6,
        "n_batches": 4, "first_seen": "2026-11-01T00:00:00+00:00",
        "span_days": 9.0, "callgraph_n": 2, "n_proxy_addrs": 1,
        "n_impl_addrs": 1, "deployer_present": True,
        "deployer_contracts": 32, "deployer_fresh_7d": True,
        "deployer_verified": True, "deployer_age_days": 99.0,
        "owner_events": 2, "owner_changed": True, "owner_now_null": True,
        "owner_stake_usd": 5e6, "creator_chains": 2,
    }
    v = extract(f, spec)
    assert v[names.index("ctx_contract_findings")] == 2.0 / 3.0
    assert v[names.index("ctx_contract_plugins")] == 0.5
    assert v[names.index("ctx_contract_function_count")] == 0.59
    assert v[names.index("ctx_contract_has_source")] == 1.0
    assert v[names.index("ctx_contract_has_impl")] == 0.0
    assert v[names.index("dep_age_days")] == 2.0 / 3.0
    assert v[names.index("dep_age_present")] == 1.0
    assert v[names.index("temp_span_days")] == 1.0 / 3.0
    assert v[names.index("x_owner_events")] == 0.5
    assert v[names.index("x_owner_now_null")] == 1.0
    # No context at all: every context input reads zero, never invented.
    f2 = dict(ROWS[2][0])
    v2 = extract(f2, spec)
    ctx_idx = [i for i, n in enumerate(names)
               if n.startswith(("ctx_", "dep_", "temp_", "x_"))]
    assert all(v2[i] == 0.0 for i in ctx_idx)
