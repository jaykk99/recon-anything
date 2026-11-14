"""Sheaf + hypergraph tests: hyperedge construction, restriction-map
consistency on a consistent toy example, and detection of an
injected contradiction (low score, correct culprit facts named).
Pure stdlib, no network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.hyperedges import (build_all, build_call_path_hyperedges,
                               build_symbol_cluster_hyperedges,
                               latest_owner_map)
from app.nn.sheaf import (check_cover, consistency, copy_hyperedge,
                          cover_obstructions, rank_inconsistencies,
                          restrict_all, to_hypergraph_nn)

A = "0x" + "aa" * 20
B = "0x" + "bb" * 20
C = "0x" + "cc" * 20
CONTRACT = "0x" + "11" * 20
CONTRACT2 = "0x" + "22" * 20


def toy_transitions():
    # One clean transfer A -> B, then B -> C. No nulls, blocks rise.
    return [
        {"chain": "ethereum", "address": CONTRACT, "symbol": "TOY",
         "changed": ["owner"],
         "before": {"owner": A}, "after": {"owner": B},
         "detected_at": "2026-11-10T00:00:00+00:00", "block": 100},
        {"chain": "ethereum", "address": CONTRACT, "symbol": "TOY",
         "changed": ["owner"],
         "before": {"owner": B}, "after": {"owner": C},
         "detected_at": "2026-11-11T00:00:00+00:00", "block": 110},
    ]


def toy_candidates():
    return [
        {"chain": "ethereum", "address": CONTRACT, "symbol": "TOY",
         "plugin": "contract_logic", "key": "access_control_flaw",
         "severity": "high", "function": "withdraw",
         "recipient_class": "CALLER",
         "validation": {"address": CONTRACT, "chain": "ethereum",
                        "function": "withdraw",
                        "kind": "access_control_flaw",
                        "verdict": "UNVERIFIED",
                        "recipient": "0x" + "dd" * 20,
                        "missing": [], "evidence": {"gate": True}},
         "live_probe": {"status": "revert"}},
    ]


def test_hyperedge_construction_from_transitions():
    edges = build_all(toy_candidates(), toy_transitions())
    trans = edges["owner_transition"]
    assert len(trans) == 2
    edge = trans[0]
    assert edge.kind == "owner_transition"
    kinds = sorted(e[0] for e in edge.entities)
    assert kinds == ["contract", "owner", "owner"]
    contract = next(e for e in edge.entities if e[0] == "contract")
    stalk = edge.stalk(contract)
    assert stalk.get("owner_before") == A
    assert stalk.get("owner_after") == B
    assert stalk.get("block") == 100
    # finding cluster: contract + 1 finding
    assert len(edges["finding_cluster"]) == 1
    cluster = edges["finding_cluster"][0]
    assert len(cluster.entities) == 2
    # symbol cluster: TOY on one contract only -> no hyperedge
    assert edges["symbol_cluster"] == []
    # owner map: latest known owner is C, no oscillation
    owner_map = latest_owner_map(toy_transitions())
    info = owner_map[("ethereum", CONTRACT)]
    assert info["latest_known"] == C
    assert info["oscillates"] is False


def test_consistent_toy_scores_high():
    edges = build_all(toy_candidates(), toy_transitions())
    for kind_edges in edges.values():
        for edge in kind_edges:
            score, results = consistency(edge)
            assert score == 1.0, (edge.id, score, results)
    # the cover glues: no obstructions on a clean timeline
    contract = ("contract", "ethereum:" + CONTRACT)
    assert check_cover(contract, edges["owner_transition"]) == []


def test_restriction_maps_agree_on_consistent_toy():
    edges = build_all(toy_candidates(), toy_transitions())
    edge = edges["owner_transition"][0]
    restricted = restrict_all(edge, "owner@after")
    # contract restricts to its after-owner; the after-owner entity
    # restricts to itself. Both name B.
    values = set(restricted.values())
    assert values == {B}


def test_injected_contradiction_detected_with_culprit_facts():
    edges = build_all(toy_candidates(), toy_transitions())
    edge = copy_hyperedge(edges["finding_cluster"][0])
    # Inject: validator binds a different address than the finding.
    finding = next(e for e in edge.entities if e[0] == "finding")
    stalk = edge.stalk(finding)
    fact = stalk.fact("validation_address")
    stalk.facts["validation_address"] = type(fact)(
        finding, "validation_address", "0x" + "99" * 20,
        fact.source + " [injected]")
    score, results = consistency(edge)
    assert score < 1.0
    failed = [r for r in results if not r.passed]
    assert len(failed) == 1
    assert failed[0].name == "validation_binds_same_target"
    # the culprit facts name the exact disagreeing values
    text = " ".join(f.describe() for f in failed[0].facts)
    assert "0x" + "99" * 20 in text
    assert CONTRACT in text


def test_injected_noop_transition_detected():
    edges = build_all(toy_candidates(), toy_transitions())
    edge = copy_hyperedge(edges["owner_transition"][0])
    contract = next(e for e in edge.entities if e[0] == "contract")
    stalk = edge.stalk(contract)
    fact = stalk.fact("owner_after")
    stalk.facts["owner_after"] = type(fact)(
        contract, "owner_after", A, fact.source + " [injected]")
    score, results = consistency(edge)
    assert score < 1.0
    assert any(r.name == "transition_changes_owner"
               and not r.passed for r in results)


def test_oscillation_detected_by_cover_not_by_single_edge():
    # A -> B, B -> null, null -> B: the same owner returns after a
    # null read. Each single transition is self-consistent; only the
    # cover sees the hole.
    rows = [
        {"chain": "ethereum", "address": CONTRACT, "symbol": "TOY",
         "changed": ["owner"], "before": {"owner": A},
         "after": {"owner": B},
         "detected_at": "2026-11-10T00:00:00+00:00", "block": 100},
        {"chain": "ethereum", "address": CONTRACT, "symbol": "TOY",
         "changed": ["owner"], "before": {"owner": B},
         "after": {"owner": None},
         "detected_at": "2026-11-10T12:00:00+00:00", "block": 110},
        {"chain": "ethereum", "address": CONTRACT, "symbol": "TOY",
         "changed": ["owner"], "before": {"owner": None},
         "after": {"owner": B},
         "detected_at": "2026-11-11T00:00:00+00:00", "block": 120},
    ]
    edges = build_all([], rows)
    for edge in edges["owner_transition"]:
        score, _ = consistency(edge)
        assert score == 1.0, edge.id  # pairwise-blind by design
    contract = ("contract", "ethereum:" + CONTRACT)
    obs = check_cover(contract, edges["owner_transition"])
    assert len(obs) == 1
    assert obs[0].kind == "owner_null_flip_oscillation"
    text = " ".join(f.describe() for f in obs[0].facts)
    assert B in text
    # and the pairwise baseline also misses it (cover is multi-edge)
    assert cover_obstructions(edges["owner_transition"]) != []


def test_pairwise_baseline_misses_multi_entity_checks():
    # Two contracts share one symbol but have different owners.
    # The symbol check needs all three entities; pairwise mode
    # skips it, full mode flags it.
    cands = [
        {"chain": "bsc", "address": CONTRACT, "symbol": "TOY"},
        {"chain": "bsc", "address": CONTRACT2, "symbol": "TOY"},
    ]
    owner_map = {
        ("bsc", CONTRACT): {"latest_known": A},
        ("bsc", CONTRACT2): {"latest_known": B},
    }
    edges = build_symbol_cluster_hyperedges(cands, owner_map)
    assert len(edges) == 1
    full, _ = consistency(edges[0], pairwise=False)
    pair, _ = consistency(edges[0], pairwise=True)
    assert full < 1.0
    assert pair == 1.0
    ranked = rank_inconsistencies(edges, pairwise=False)
    assert len(ranked) == 1
    assert A in ranked[0]["facts"][0] or B in " ".join(ranked[0]["facts"])


def test_call_path_paused_candidate_flagged():
    paths = build_call_path_hyperedges([
        {"id": "p1", "grade": "candidate",
         "finding_kinds": ["call_graph_gate_bypass_multihop"],
         "hops": [
             {"caller": CONTRACT, "callee": CONTRACT2, "chain": "bsc",
              "function": "execute", "gated": True, "paused": False,
              "source_available": True},
             {"caller": CONTRACT2, "callee": "0x" + "33" * 20,
              "chain": "bsc", "function": "relay", "gated": False,
              "paused": True, "source_available": True},
         ]},
    ])
    assert len(paths) == 1
    score, results = consistency(paths[0])
    assert score < 1.0
    assert any(r.name == "call_path_paused_not_candidate"
               and not r.passed for r in results)
    # same path graded trigger-only glues fine
    paths[0].meta["grade"] = "trigger-only"
    score2, _ = consistency(paths[0])
    assert score2 == 1.0


def test_hypergraph_nn_adapter_shape():
    edges = build_all(toy_candidates(), toy_transitions())
    out = to_hypergraph_nn(edges["finding_cluster"][0])
    assert set(out) == {"id", "kind", "nodes", "features", "score"}
    assert out["kind"] == "finding_cluster"
    assert out["score"] == 1.0
    assert out["features"]["n_entities"] == 2
    assert out["features"]["consistency"] == 1.0
