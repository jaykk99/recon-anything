"""Tests for the hypergraph triage network (backend/app/nn/).

Run from backend/:  python -m pytest tests/test_nn_hypergraph.py -q
(or python -m pytest tests/test_nn_hypergraph.py -q -k "not slow"
to skip the real-data training test).

Everything here is triage-only and offline: the tests use synthetic
rows or the real labeled rows on disk, never the network, never a
live probe, never a transaction.
"""
import json
import math
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.nn.hypergraph import (  # noqa: E402
    HypergraphNN,
    build_hypergraph,
    score_finding_dicts_hypergraph,
    score_rows,
)
from app.nn.mlp import metrics_for  # noqa: E402

NN_DIR = os.path.join(os.path.dirname(__file__), "..", "app", "nn")


def _row(plugin="contract_logic", key="k", chain="bsc", address="",
         impl="", project="", label=1):
    ev = {}
    if impl:
        ev["implementation_address"] = impl
    finding = {"plugin": plugin, "key": key, "severity": "high",
               "bounty_value": "high", "confidence": 80, "value": "v",
               "recipient_class": "CALLER", "chain": chain,
               "function": "withdraw", "evidence": ev,
               "plugin_finding_count": 1}
    row = {"finding": finding, "label": label, "verdict": "UNVERIFIED",
           "chain": chain, "address": address, "plugin": plugin,
           "key": key, "function": "withdraw"}
    if project:
        row["source"] = {"dataset": "test", "project_id": project}
    return row


# --- hyperedge construction -------------------------------------------

def test_build_hypergraph_target_edges():
    rows = [_row(address="0xaaa"), _row(address="0xaaa"),
            _row(address="0xbbb")]
    edges, stats = build_hypergraph(rows)
    assert stats["n_edges"] == 1
    assert edges[0]["type"] == "target"
    assert sorted(edges[0]["members"]) == [0, 1]
    assert stats["nodes_covered"] == 2


def test_build_hypergraph_implementation_links_targets():
    rows = [_row(address="0xaaa", impl="0ximpl"),
            _row(address="0xbbb", impl="0ximpl"),
            _row(address="0xccc", impl="0xother")]
    edges, stats = build_hypergraph(rows)
    impl_edges = [e for e in edges if e["type"] == "implementation"]
    assert len(impl_edges) == 1
    assert sorted(impl_edges[0]["members"]) == [0, 1]


def test_build_hypergraph_project_edges():
    rows = [_row(project="p1"), _row(project="p1"), _row(project="p2")]
    edges, stats = build_hypergraph(rows)
    assert [e["type"] for e in edges] == ["project"]
    assert stats["by_type"] == {"project": 1}


def test_build_hypergraph_drops_singletons_and_giants():
    rows = [_row(address="0xaaa")]  # singleton: no edge
    rows += [_row(address="0xgiant%02d" % i, impl="0xbig")
             for i in range(20)]  # 20-share impl: giant, dropped
    edges, stats = build_hypergraph(rows, max_edge_size=16)
    assert stats["n_edges"] == 0
    assert stats["dropped_giant_groups"] == 1
    assert stats["nodes_covered"] == 0


def test_build_hypergraph_dedupes_identical_member_sets():
    # Both findings on one proxy target share its impl address, so
    # the target group and the implementation group are the same set.
    rows = [_row(address="0xaaa", impl="0xonly"),
            _row(address="0xaaa", impl="0xonly")]
    edges, stats = build_hypergraph(rows)
    assert stats["n_edges"] == 1


def test_build_hypergraph_empty():
    edges, stats = build_hypergraph([])
    assert edges == [] and stats["n_edges"] == 0


# --- forward / training on synthetic data ------------------------------

def _tiny_net_and_data():
    rng = random.Random(0)
    net = HypergraphNN(6, hidden=4, seed=1, lr=0.5)
    X = [[rng.uniform(-1, 1) for _ in range(6)] for _ in range(8)]
    y = [1, 1, 0, 1, 0, 0, 1, 0]
    edges = [{"type": "target", "key": ["a"], "members": [0, 1, 2]},
             {"type": "target", "key": ["b"], "members": [2, 3]},
             {"type": "project", "key": ["p"], "members": [5, 6, 7]}]
    return net, X, y, edges


def test_forward_probs_in_range_and_shape():
    net, X, y, edges = _tiny_net_and_data()
    probs, cache = net.forward(X, edges)
    assert len(probs) == len(X)
    assert all(0.0 < p < 1.0 for p in probs)
    assert cache["h2"] and len(cache["h2"][0]) == 4


def test_forward_no_edges_matches_self_path():
    net, X, y, edges = _tiny_net_and_data()
    p_edges, _ = net.forward(X, edges)
    p_none, _ = net.forward(X, [])
    # Nodes 4 has no edge in either case; its score must be identical.
    assert p_edges[4] == pytest.approx(p_none[4])
    # Nodes in edges generally differ (context changes the score).
    assert any(abs(a - b) > 1e-9
               for a, b in zip(p_edges, p_none))


def test_predict_proba_single_matches_empty_batch():
    net, X, y, edges = _tiny_net_and_data()
    assert net.predict_proba(X[0]) == pytest.approx(
        net.predict_proba_nodes([X[0]], [])[0])


def test_sparse_forward_matches_dense():
    """Sparse input path is the same math: identical probs and
    (up to float noise) identical gradients."""
    net, X, y, edges = _tiny_net_and_data()
    Xs = [[(k, v) for k, v in enumerate(row) if v != 0.0] for row in X]
    p_dense, c_dense = net.forward(X, edges)
    p_sparse, c_sparse = net.forward(X, edges, Xs)
    assert p_dense == pytest.approx(p_sparse)
    g_dense = net._gradients(p_dense, c_dense, y)
    g_sparse = net._gradients(p_sparse, c_sparse, y)
    for ra, rb in zip(g_dense["W_in"], g_sparse["W_in"]):
        assert ra == pytest.approx(rb, abs=1e-12)
    assert g_dense["w_out"] == pytest.approx(g_sparse["w_out"],
                                             abs=1e-12)


def test_fit_reduces_loss_on_synthetic():
    net, X, y, edges = _tiny_net_and_data()
    before, _ = net.forward(X, edges)
    loss_before = net._bce(before, y)
    net.fit(X, y, edges, epochs=30, history_every=30)
    after, _ = net.forward(X, edges)
    assert net._bce(after, y) < loss_before


def test_gradients_match_numeric():
    """Hand-derived backprop vs central differences, tiny graph."""
    net, X, y, edges = _tiny_net_and_data()
    probs, cache = net.forward(X, edges)
    grads = net._gradients(probs, cache, y)
    eps = 1e-5
    checks = []
    for r in range(4):
        for k in range(6):
            checks.append(("W_in", lambda r=r, k=k: net.W_in[r][k],
                           lambda v, r=r, k=k: net.W_in[r].__setitem__(k, v),
                           grads["W_in"][r][k]))
    for li in range(2):
        for r in range(4):
            for k in range(4):
                checks.append((f"W_self{li}",
                               lambda li=li, r=r, k=k: net.W_self[li][r][k],
                               lambda v, li=li, r=r, k=k:
                               net.W_self[li][r].__setitem__(k, v),
                               grads["W_self"][li][r][k]))
                checks.append((f"W_edge{li}",
                               lambda li=li, r=r, k=k: net.W_edge[li][r][k],
                               lambda v, li=li, r=r, k=k:
                               net.W_edge[li][r].__setitem__(k, v),
                               grads["W_edge"][li][r][k]))
    for k in range(4):
        checks.append(("w_out", lambda k=k: net.w_out[k],
                       lambda v, k=k: net.w_out.__setitem__(k, v),
                       grads["w_out"][k]))
    for _name, get, set_, analytic in random.Random(3).sample(checks, 25):
        old = get()
        set_(old + eps)
        lp, _ = net.forward(X, edges)
        l_plus = net._bce(lp, y)
        set_(old - eps)
        lm, _ = net.forward(X, edges)
        l_minus = net._bce(lm, y)
        set_(old)
        numeric = (l_plus - l_minus) / (2 * eps)
        rel = abs(numeric - analytic) / max(1e-8, abs(numeric)
                                            + abs(analytic))
        assert rel < 1e-4, f"{_name}: analytic={analytic} numeric={numeric}"


def test_save_load_roundtrip(tmp_path):
    net, X, y, edges = _tiny_net_and_data()
    net.fit(X, y, edges, epochs=2, history_every=2)
    path = str(tmp_path / "hg.json")
    net.save(path)
    net2 = HypergraphNN.load(path)
    assert net2.predict_proba_nodes(X, edges) == pytest.approx(
        net.predict_proba_nodes(X, edges))
    with pytest.raises(ValueError):
        HypergraphNN.from_dict({"format": "recon-nn-weights/1"})


def test_score_rows_and_finding_dicts_use_spec(tmp_path):
    from app.nn.features import FeatureSpec
    spec = FeatureSpec(["contract_logic"], ["k"])
    net = HypergraphNN(spec.dim, hidden=4, seed=1, lr=0.5)
    rows = [_row(address="0xaaa"), _row(address="0xaaa", label=0)]
    probs = score_rows(rows, spec, net)
    assert len(probs) == 2 and all(0.0 < p < 1.0 for p in probs)
    findings = [dict(r["finding"]) for r in rows]
    scored = score_finding_dicts_hypergraph(findings, spec, net)
    assert scored[0]["nn_score"] >= scored[1]["nn_score"]
    assert all("nn_label" in f for f in scored)


# --- real-data smoke test (slow: reads the 451MB batches file) ---------

@pytest.mark.slow
def test_real_data_holdout_shape():
    """The fixed own-rows holdout is 144 rows, seed 42, and the
    hypergraph builds on it without leaking train rows in.
    Counts are the live data at train time: candidates.jsonl was
    re-adjudicated upstream on 2026-11-14 (723 own rows, was 725;
    144-row holdout, was 145)."""
    from app.nn.data import (build_dataset, load_external_rows,
                             stratified_split)
    from app.nn.features import build_vocab, extract
    ds = build_dataset(
        os.path.expanduser("~/workspace/recon-continuous/results/"
                           "candidates.jsonl"),
        os.path.expanduser("~/workspace/recon-continuous/results/"
                           "batches.jsonl"))
    own = ds["rows"]
    assert len(own) == 723
    ext, _ = load_external_rows(os.path.join(NN_DIR,
                                             "external_findings.jsonl"))
    assert len(ext) == 1922
    own_train, own_test = stratified_split(own, 0.2, 42)
    assert len(own_test) == 144 and len(own_train) == 579
    assert sum(r["label"] for r in own_test) == 123
    spec = build_vocab([r["finding"] for r in own_train + ext])
    assert spec.dim == 255
    X_test = [extract(r["finding"], spec) for r in own_test]
    te_edges, te_stats = build_hypergraph(own_test)
    assert te_stats["nodes_total"] == 144
    assert te_stats["nodes_covered"] >= 0
    # No test hyperedge may reference a train row index: edges are
    # built from the test list alone, so every member is < 144.
    assert all(m < 144 for e in te_edges for m in e["members"])
    net = HypergraphNN(spec.dim, hidden=4, seed=42, lr=0.1)
    probs = net.predict_proba_nodes(X_test, te_edges)
    m = metrics_for([r["label"] for r in own_test], probs)
    assert m["n"] == 144
    # An untrained net must not claim anything: it ranks at chance.
    assert 0.3 < m["roc_auc"] < 0.7
