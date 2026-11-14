"""TDA features: persistent-homology-style summaries over call graphs.

Every Betti number below is hand-computed for a toy graph whose
answer is known by construction: a triangle must give 1 cycle, a
tree must give 0, two triangles sharing a vertex must give 2. The
filtration tests pin merge weights and cycle births the same way.
No finding in this file carries a label; nothing here trains.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.data import _call_graph_record  # noqa: E402
from app.nn.features import FeatureSpec, build_vocab, extract  # noqa: E402
from app.nn.pipeline import load_model  # noqa: E402
from app.nn.tda import (  # noqa: E402
    TDA_FEATURE_NAMES,
    betti_numbers,
    build_graph,
    filtration,
    parse_depth_record,
    summarize,
    tda_features,
)


def _graph(edges, nodes=()):
    """CallGraph from (u, v) / (u, v, w) edge tuples."""
    from app.nn.tda import CallGraph
    g = CallGraph()
    for n in nodes:
        g.add_node(n)
    for e in edges:
        if len(e) == 2:
            g.add_edge(e[0], e[1])
        else:
            g.add_edge(e[0], e[1], e[2])
    return g


def _names():
    return [f"tda:{n}" for n in TDA_FEATURE_NAMES]


# ------------------------------------------------------------------ Betti-0

def test_empty_graph_is_all_zero():
    f = {"plugin": "contract_logic", "key": "x", "evidence": {}}
    assert build_graph(f).nodes == set()
    assert tda_features(f) == [0.0] * len(TDA_FEATURE_NAMES)


def test_measured_empty_graph_is_one_node():
    # A depth record with 0 callees: the graph was measured and it is
    # a single node. graph_present must read 1, not 0.
    f = {"plugin": "cross_contract_call_graph", "key": "deep_layer_coverage",
         "evidence": {"depth": '{"call_graph": "ran", "callees": 0, '
                                '"callee_layers": [], "storage": "absent"}'}}
    g = build_graph(f)
    assert len(g) == 1 and len(g.edges) == 0
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (1, 0)
    v = tda_features(f)
    assert v[_names().index("tda:graph_present")] == 1.0
    assert v[_names().index("tda:betti0")] == 1.0 / 8.0


def test_two_disconnected_edges_have_betti0_two():
    g = _graph([("a", "b"), ("c", "d")])
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (2, 0)
    assert sorted(len(c) for c in b["components"]) == [2, 2]


def test_star_from_callee_count():
    f = {"plugin": "x", "key": "y", "evidence": {},
         "call_graph": {"callees": 3, "callee_layers": ["source"] * 3}}
    g = build_graph(f)
    assert len(g) == 4 and len(g.edges) == 3
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (1, 0)
    s = summarize(g)
    assert s["n_merges"] == 3
    assert s["total_persistence_h0"] == 3.0  # three merges, all weight 1


# ------------------------------------------------------------------ Betti-1

def test_triangle_has_one_cycle_of_length_three():
    g = _graph([("a", "b"), ("b", "c"), ("a", "c")])
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (1, 1)
    assert b["cycle_lengths"] == [3]


def test_tree_has_no_cycles():
    # 5 nodes, 4 edges, connected: a tree, beta1 must be 0.
    g = _graph([("a", "b"), ("a", "c"), ("c", "d"), ("c", "e")])
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (1, 0)
    assert b["cycle_lengths"] == []


def test_square_has_one_cycle_of_length_four():
    g = _graph([("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")])
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (1, 1)
    assert b["cycle_lengths"] == [4]


def test_two_triangles_sharing_a_vertex_have_two_cycles():
    # Bowtie: triangles a-b-c and c-d-e share vertex c.
    g = _graph([("a", "b"), ("b", "c"), ("a", "c"),
                ("c", "d"), ("d", "e"), ("c", "e")])
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (1, 2)
    assert b["cycle_lengths"] == [3, 3]


def test_self_loop_is_a_cycle_of_length_one():
    g = _graph([("a", "a"), ("a", "b")])
    b = betti_numbers(g)
    assert (b["beta0"], b["beta1"]) == (1, 1)
    assert b["cycle_lengths"] == [1]


def test_square_with_diagonal_has_two_cycles():
    # 4 nodes, 5 edges: cycles of length 3 and 3 (two triangles).
    g = _graph([("a", "b"), ("b", "c"), ("c", "d"), ("d", "a"),
                ("a", "c")])
    b = betti_numbers(g)
    assert b["beta1"] == 2
    assert sorted(b["cycle_lengths"]) == [3, 3]


# -------------------------------------------------------------- filtration

def test_filtration_triangle_merges_then_cycle():
    # Edges weight 1, 2, 3. Merges at 1 and 2 (persistences 1, 2);
    # the third edge closes the cycle, born at 3.
    g = _graph([("a", "b", 1.0), ("b", "c", 2.0), ("a", "c", 3.0)])
    f = filtration(g)
    assert f["merge_persistences"] == [1.0, 2.0]
    assert f["cycle_births"] == [3.0]
    assert f["final_beta0"] == 1
    assert f["max_beta1"] == 1
    assert f["curve"][-1] == (3.0, 1, 1)


def test_filtration_late_bridge_merge():
    # Two components joined by a weight-5 edge: one merge at 5.
    g = _graph([("a", "b", 1.0), ("c", "d", 1.0), ("b", "c", 5.0)])
    f = filtration(g)
    assert f["merge_persistences"] == [1.0, 1.0, 5.0]
    assert f["final_beta0"] == 1
    assert f["cycle_births"] == []


def test_filtration_cycle_birth_uses_edge_weight():
    # A 4-cycle whose closing edge weighs 4: born at 4, not at 1.
    g = _graph([("a", "b", 1.0), ("b", "c", 1.0), ("c", "d", 1.0),
                ("d", "a", 4.0)])
    f = filtration(g)
    assert f["cycle_births"] == [4.0]


# ------------------------------------------------------- graph construction

def test_proxy_implementation_edge():
    f = {"plugin": "x", "key": "y", "evidence": {
        "proxy_address": "0xproxy", "implementation_address": "0ximpl"}}
    g = build_graph(f)
    assert len(g) == 2 and len(g.edges) == 1
    assert betti_numbers(g)["beta1"] == 0


def test_multihop_call_edges_shape():
    # The multihop plugin's extract_call_edges shape.
    f = {"plugin": "x", "key": "y", "evidence": {},
         "call_graph": {"call_edges": [
             {"from_fn": "a", "to_addr": "0xb"},
             {"from_fn": "a", "to_addr": "0xc"},
             {"from_fn": "b", "to_addr": "0xc"}]}}
    g = build_graph(f)
    # Nodes a, 0xb, 0xc, b; edges a-0xb, a-0xc, b-0xc. All four join
    # one component through 0xc, and 3 edges on 4 nodes is a tree.
    assert betti_numbers(g)["beta0"] == 1
    assert betti_numbers(g)["beta1"] == 0


def test_depth_record_parsing():
    assert parse_depth_record(
        '{"call_graph": "ran", "callees": 2, "callee_layers": ["source"]}'
    ) == {"callees": 2, "callee_layers": ["source"]}
    assert parse_depth_record({"callees": 1, "callee_layers": []}) == {
        "callees": 1, "callee_layers": []}
    assert parse_depth_record("not json") is None
    assert parse_depth_record(None) is None
    assert parse_depth_record({"callees": "3"}) == {
        "callees": 3, "callee_layers": []}


def test_call_graph_record_from_finding():
    rec = _call_graph_record({
        "plugin": "cross_contract_call_graph",
        "evidence": {"depth": '{"callees": 1, "callee_layers": ["source"]}'}})
    assert rec == {"callees": 1, "callee_layers": ["source"]}
    assert _call_graph_record({"plugin": "other", "evidence": {}}) is None


# ------------------------------------------------------- feature integration

def test_tda_feature_values_on_triangle():
    f = {"plugin": "x", "key": "y", "evidence": {},
         "call_graph": {"edges": [["a", "b"], ["b", "c"], ["a", "c"]]}}
    v = tda_features(f)
    names = _names()
    assert len(v) == 16
    assert all(0.0 <= x <= 1.0 for x in v)
    assert v[names.index("tda:graph_present")] == 1.0
    assert v[names.index("tda:n_nodes")] == 3.0 / 16.0
    assert v[names.index("tda:n_edges")] == 3.0 / 16.0
    assert v[names.index("tda:betti0")] == 1.0 / 8.0
    assert v[names.index("tda:betti1")] == 1.0 / 8.0
    assert v[names.index("tda:max_cycle_len")] == 3.0 / 16.0
    assert v[names.index("tda:mean_cycle_len")] == 3.0 / 16.0
    assert v[names.index("tda:triangles")] == 1.0 / 4.0
    assert v[names.index("tda:has_cycle")] == 1.0


def test_extract_appends_tda_block():
    spec = FeatureSpec(plugins=["a", "b"], keys=["k"], use_tda=True)
    spec_no_tda = FeatureSpec(plugins=["a", "b"], keys=["k"], use_tda=False)
    # 3 plugin blocks x 8 + 2 keys + 1 + 5 + 6 + 3 + 2 + 4 + 3 + 2 + 2
    # + 1 + 1 = 56 v2 features; +16 with the TDA block.
    assert spec_no_tda.dim == 56
    assert spec.dim == 72
    assert spec.feature_names()[-16:] == _names()
    assert "tda" in spec.groups()
    f = {"plugin": "a", "key": "k", "severity": "high",
         "bounty_value": "high", "confidence": 80, "value": "v",
         "recipient_class": "CALLER", "chain": "bsc",
         "function": "withdraw",
         "evidence": {"risk": "high"},
         "call_graph": {"edges": [["a", "b"], ["b", "c"], ["a", "c"]]}}
    v = extract(f, spec)
    assert len(v) == spec.dim == 72
    assert v[-16:] == tda_features(f)
    assert extract(f, spec_no_tda) == v[:56]


def test_spec_round_trip():
    spec = FeatureSpec(plugins=["a"], keys=["k"], use_tda=True)
    assert FeatureSpec.from_dict(spec.to_dict()).use_tda is True
    assert FeatureSpec.from_dict(spec.to_dict()).dim == spec.dim
    # A v2 weights file carries no use_tda key: it loads TDA-off,
    # so its 255-input layout is preserved, never silently extended.
    v2 = {"plugins": ["a"], "keys": ["k"], "spec_version": 2}
    assert FeatureSpec.from_dict(v2).use_tda is False


def test_v2_weights_still_load_tda_off():
    # The shipped v2 weights (nn-scorer worktree, read-only) load
    # under the new code with the v2 layout intact: 255 inputs, no
    # TDA block. The dim check in load_model must not reject them.
    model = load_model(
        os.path.expanduser("~/workspace/wt/nn-scorer/backend/app/nn/"
                           "weights.json"))
    assert model is not None
    net, spec, _meta = model
    assert spec.dim == 255 == net.layers[0]
    assert spec.use_tda is False
