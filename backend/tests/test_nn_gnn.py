"""Tests for the GNN + combined neuro-symbolic model.

Fixtures are the real-shaped rows in nn_fixtures.py (trimmed from
recon-continuous candidates + batches). No labels are invented:
fixture labels are the rows' own labels.
"""
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.nn.combined import CombinedModel  # noqa: E402
from app.nn.features import build_vocab  # noqa: E402
from app.nn.gnn import CombinedNet, GNN  # noqa: E402
from app.nn.graph import (  # noqa: E402
    NODE_DIM, adjacency, build_graph)
from app.nn.symbolic import validate_rules  # noqa: E402
from nn_fixtures import ROWS  # noqa: E402


def _rows():
    out = []
    for finding, label in ROWS:
        f = dict(finding)
        out.append({
            "finding": f, "label": label,
            "verdict": "UNVERIFIED" if label == 1 else "FALSE_POSITIVE",
            "chain": f.get("chain"),
            "address": "0x0000000000000000000000000000000000000001",
            "plugin": f.get("plugin"), "key": f.get("key"),
            "function": f.get("function"),
        })
    return out


def _proxy_row():
    for r in _rows():
        if r["plugin"] == "unchecked_math_user_input":
            return r
    raise AssertionError("proxy fixture missing")


def _standalone_row():
    for r in _rows():
        if r["plugin"] == "bridge_replay_unbound_digest":
            return r
    raise AssertionError("standalone fixture missing")


def test_graph_builds_from_real_row():
    row = _proxy_row()
    g = build_graph(row)
    assert g["meta"]["has_implementation"] is True
    assert "implementation" in g["meta"]["node_kinds"]
    assert "function" in g["meta"]["node_kinds"]
    assert "finding" in g["meta"]["node_kinds"]
    assert all(len(v) == NODE_DIM for v in g["nodes"])
    # Contract node links to every other node (star + impl edge).
    assert (0, 1) in g["edges"]  # contract-implementation
    assert 3 <= len(g["nodes"]) <= 9
    assert len(g["edges"]) >= 2


def test_graph_no_implementation_when_absent():
    row = _standalone_row()
    g = build_graph(row)
    assert g["meta"]["has_implementation"] is False
    assert "implementation" not in g["meta"]["node_kinds"]
    assert g["nodes"][0][0] == 1.0  # node 0 is the contract


def test_graph_never_invents_function_edges():
    row = _standalone_row()
    finding = dict(row["finding"])
    finding.pop("function", None)
    ev = dict(finding.get("evidence") or {})
    ev.pop("function", None)
    finding["evidence"] = ev
    row = dict(row, finding=finding, function=None)
    g = build_graph(row)
    # No function node at all when no function is named anywhere.
    assert "function" not in g["meta"]["node_kinds"]
    # Finding node still links to the contract.
    assert any(a == 0 for a, _ in g["edges"])


def test_adjacency_is_symmetric_no_self_loops():
    row = _proxy_row()
    g = build_graph(row)
    adj = adjacency(len(g["nodes"]), g["edges"])
    for i, nbrs in enumerate(adj):
        assert i not in nbrs
        for j in nbrs:
            assert i in adj[j]


def test_gnn_forward_deterministic_and_bounded():
    rows = _rows()
    spec = build_vocab(rows)
    net = CombinedNet(spec, seed=42)
    row = _proxy_row()
    g = build_graph(row)
    p1 = net.predict_proba(g, row["finding"])
    p2 = net.predict_proba(g, row["finding"])
    assert 0.0 < p1 < 1.0
    assert p1 == p2


def test_gnn_backward_gradients_finite():
    rows = _rows()
    spec = build_vocab(rows)
    net = CombinedNet(spec, seed=42)
    row = _proxy_row()
    g = build_graph(row)
    _, (ggw, ggb), (hgw, hgb) = net._example_grads(
        g, row["finding"], float(row["label"]))
    for grad in (ggw, ggb, hgw, hgb):
        flat = [v for mat in grad for v in
                (mat if isinstance(mat, list) and mat
                 and isinstance(mat[0], list) else [mat])
                for v in (v if isinstance(v, list) else [v])]
        assert all(math.isfinite(v) for v in flat)
    # Head gradients are non-zero: the loss reaches the head.
    assert any(abs(v) > 0 for mat in hgw for row_ in mat for v in row_)


def test_combined_fit_smoke_runs():
    rows = _rows()
    spec = build_vocab(rows)
    net = CombinedNet(spec, seed=42)
    graphs = [build_graph(r) for r in rows]
    hist = net.fit(graphs, [r["finding"] for r in rows],
                   [r["label"] for r in rows], epochs=2, batch_size=4)
    assert len(hist["loss"]) == 2
    assert all(math.isfinite(v) for v in hist["loss"])
    assert 0.0 <= hist["train_acc"][-1] <= 1.0


def test_combined_roundtrip_preserves_score():
    rows = _rows()
    spec = build_vocab(rows)
    net = CombinedNet(spec, seed=42)
    kept, _ = validate_rules(rows)
    model = CombinedModel(net, kept)
    row = _proxy_row()
    before = model.predict_row(row)
    data = model.to_dict()
    assert data["format"] == "recon-nn-gnn-weights/1"
    net2 = CombinedNet.from_dict(data)
    model2 = CombinedModel(net2, data["kept_rules"], data.get("meta") or {})
    after = model2.predict_row(row)
    assert before["combined_p"] == after["combined_p"]
    assert before["fired_rules"] == after["fired_rules"]


def test_evaluate_returns_all_three_models():
    rows = _rows()
    spec = build_vocab(rows)
    net = CombinedNet(spec, seed=42)
    kept, _ = validate_rules(rows)
    model = CombinedModel(net, kept)
    ev = model.evaluate(rows)
    for key in ("neural", "symbolic", "combined"):
        m = ev[key]
        assert "accuracy" in m and "roc_auc" in m
        assert "confusion" in m
        assert 0.0 <= m["accuracy"] <= 1.0
    assert "caught_by_symbolic" in ev
    assert "caught_by_neural" in ev


def test_gnn_weights_serialise():
    gnn = GNN(seed=42)
    data = gnn.to_dict()
    assert len(data["weights"]) == 4  # self/neigh x 2 layers
    assert len(data["weights"][0]) == 16  # hidden
    assert len(data["weights"][0][0]) == NODE_DIM
    assert len(data["weights"][2][0]) == 16
    gnn2 = GNN.from_dict(data)
    assert gnn2.weights[0] == gnn.weights[0]
