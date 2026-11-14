"""Structural Causal Models: graph, do-operator, identification,
intervention effects, and counterfactuals -- all on small hand-built
graphs with known ground truth. Pure stdlib, no network, no real
data files (so this runs in CI as well as locally).

The synthetic graphs here are tool self-tests (same status as the
Anvil fixtures): they verify the engine against known truth. They
are never presented as real recon findings.
"""
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.causal import (  # noqa: E402
    CausalGraph,
    CounterfactualEngine,
    StructuralModel,
    average_causal_effect,
    backdoor_paths,
    build_recon_graph,
    estimate_effect,
    find_backdoor_set,
    identify_effect,
    predict_backup_infra,
    raw_conditional,
)


# ---------------------------------------------------------------------------
# Hand-built ground-truth SCMs
# ---------------------------------------------------------------------------

def confounded_model():
    """Z -> X, Z -> Y, X -> Y. True ACE = 0.20, raw P(Y|X) is biased.

    Z ~ Bern(0.5); X|Z: 0.2 / 0.8; Y|X,Z: 0.1 + 0.2X + 0.3Z.
    P(Y=1|do(X=1)) = 0.45, P(Y=1|do(X=0)) = 0.25.
    P(Y=1|X=1) = 0.54 (confounded), P(Y=1|X=0) = 0.16.
    """
    g = CausalGraph()
    g.add_node("Z", [0, 1])
    g.add_node("X", [0, 1])
    g.add_node("Y", [0, 1])
    g.add_edge("Z", "X")
    g.add_edge("Z", "Y")
    g.add_edge("X", "Y")
    cpts = {
        "Z": {(): {0: 0.5, 1: 0.5}},
        "X": {(0,): {0: 0.8, 1: 0.2}, (1,): {0: 0.2, 1: 0.8}},
        "Y": {(0, 0): {0: 0.9, 1: 0.1},
              (0, 1): {0: 0.6, 1: 0.4},
              (1, 0): {0: 0.7, 1: 0.3},
              (1, 1): {0: 0.4, 1: 0.6}},
    }
    return StructuralModel(g, cpts)


def collider_model():
    """X, Y fair coins; M = X AND Y. do(X) leaves Y at 0.5, but
    conditioning on the collider M=1 makes Y certain given X=1."""
    g = CausalGraph()
    g.add_node("X", [0, 1])
    g.add_node("Y", [0, 1])
    g.add_node("M", [0, 1])
    g.add_edge("X", "M")
    g.add_edge("Y", "M")
    cpts = {
        "X": {(): {0: 0.5, 1: 0.5}},
        "Y": {(): {0: 0.5, 1: 0.5}},
        "M": {(0, 0): {0: 1.0, 1: 0.0},
              (0, 1): {0: 1.0, 1: 0.0},
              (1, 0): {0: 1.0, 1: 0.0},
              (1, 1): {0: 0.0, 1: 1.0}},
    }
    return StructuralModel(g, cpts)


def mediation_model():
    """X -> M -> Y plus X -> Y. True total P(Y=1|do(X=1)) = 0.54,
    P(Y=1|do(X=0)) = 0.16, ACE = 0.38."""
    g = CausalGraph()
    g.add_node("X", [0, 1])
    g.add_node("M", [0, 1])
    g.add_node("Y", [0, 1])
    g.add_edge("X", "M")
    g.add_edge("M", "Y")
    g.add_edge("X", "Y")
    cpts = {
        "X": {(): {0: 0.5, 1: 0.5}},
        "M": {(0,): {0: 0.8, 1: 0.2}, (1,): {0: 0.2, 1: 0.8}},
        # Keys are (M, X): parents are sorted, M before X.
        # P(Y=1) = 0.1 + 0.3*M + 0.2*X.
        "Y": {(0, 0): {0: 0.9, 1: 0.1},
              (0, 1): {0: 0.7, 1: 0.3},
              (1, 0): {0: 0.6, 1: 0.4},
              (1, 1): {0: 0.4, 1: 0.6}},
    }
    return StructuralModel(g, cpts)


def backup_infra_model():
    """Synthetic operator SCM: OFFLINE -> BACKUP.
    P(backup | offline=1): secondary .7 / new .2 / none .1.
    P(backup | offline=0): secondary .08 / new .02 / none .90."""
    g = CausalGraph()
    g.add_node("offline", [0, 1])
    g.add_node("backup", ["new", "none", "secondary"])
    g.add_edge("offline", "backup")
    cpts = {
        "offline": {(): {0: 0.7, 1: 0.3}},
        "backup": {(0,): {"new": 0.02, "none": 0.90, "secondary": 0.08},
                   (1,): {"new": 0.20, "none": 0.10, "secondary": 0.70}},
    }
    return StructuralModel(g, cpts)


def xor_model():
    """Y = X XOR U, U fair coin. Evidence X=0, Y=1 pins U=1, so
    the counterfactual do(X=1) gives Y=0 with probability 1."""
    g = CausalGraph()
    g.add_node("X", [0, 1])
    g.add_node("U", [0, 1], observed=False)
    g.add_node("Y", [0, 1])
    g.add_edge("X", "Y")
    g.add_edge("U", "Y")
    cpts = {
        "X": {(): {0: 0.5, 1: 0.5}},
        "U": {(): {0: 0.5, 1: 0.5}},
        "Y": {(0, 0): {0: 1.0, 1: 0.0},
              (0, 1): {0: 0.0, 1: 1.0},
              (1, 0): {0: 0.0, 1: 1.0},
              (1, 1): {0: 1.0, 1: 0.0}},
    }
    return StructuralModel(g, cpts)


# ---------------------------------------------------------------------------
# Graph build + d-separation
# ---------------------------------------------------------------------------

def test_graph_build_and_cycle_rejection():
    g = CausalGraph()
    g.add_node("A", [0, 1])
    g.add_node("B", [0, 1])
    g.add_node("C", [0, 1])
    g.add_edge("A", "B")
    g.add_edge("B", "C")
    assert g.topological_order() == ["A", "B", "C"]
    assert g.parents_of("C") == ("B",)
    assert g.children_of("A") == ("B",)
    assert g.ancestors_of(["C"]) == frozenset({"A", "B", "C"})
    try:
        g.add_edge("C", "A")
    except ValueError:
        pass
    else:
        raise AssertionError("cycle was not rejected")
    assert g.is_acyclic()
    assert g.parents_of("A") == ()


def test_d_separation_chain_fork_collider():
    # Chain X -> M -> Y: blocked by M, open without it.
    g = CausalGraph()
    for n in ("X", "M", "Y"):
        g.add_node(n, [0, 1])
    g.add_edge("X", "M")
    g.add_edge("M", "Y")
    assert not g.d_separated("X", "Y")
    assert g.d_separated("X", "Y", ["M"])
    # Fork X <- Z -> Y: blocked by Z, open without it.
    g2 = CausalGraph()
    for n in ("X", "Z", "Y"):
        g2.add_node(n, [0, 1])
    g2.add_edge("Z", "X")
    g2.add_edge("Z", "Y")
    assert not g2.d_separated("X", "Y")
    assert g2.d_separated("X", "Y", ["Z"])
    # Collider X -> M <- Y: blocked WITHOUT M, open given M.
    g3 = CausalGraph()
    for n in ("X", "M", "Y"):
        g3.add_node(n, [0, 1])
    g3.add_edge("X", "M")
    g3.add_edge("Y", "M")
    assert g3.d_separated("X", "Y")
    assert not g3.d_separated("X", "Y", ["M"])


def test_graph_serialization_roundtrip():
    g = confounded_model().graph
    g2 = CausalGraph.from_dict(g.to_dict())
    assert g2.to_dict() == g.to_dict()
    assert g2.topological_order() == g.topological_order()


# ---------------------------------------------------------------------------
# do-operator surgery
# ---------------------------------------------------------------------------

def test_do_operator_surgery():
    model = confounded_model()
    cut = model.intervene({"X": 1})
    # Incoming edges to X are gone; nothing else changed.
    assert cut.graph.parents_of("X") == ()
    assert cut.graph.parents_of("Y") == ("X", "Z")
    assert cut.graph.children_of("Z") == ("Y",)
    # The intervened CPT is a point mass; upstream Z is untouched.
    assert cut.cpts["X"] == {(): {0: 0.0, 1: 1.0}}
    assert cut.cpts["Z"] == model.cpts["Z"]
    # do(X=1) forces X=1 in every sample.
    rng = random.Random(0)
    assert all(s["X"] == 1 for s in cut.sample(rng, 50))
    # Surgery on an unknown node / out-of-domain value fails.
    try:
        model.intervene({"Q": 1})
    except ValueError:
        pass
    else:
        raise AssertionError("unknown intervention node accepted")
    try:
        model.intervene({"X": 2})
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-domain intervention accepted")


# ---------------------------------------------------------------------------
# Intervention effects vs correlation
# ---------------------------------------------------------------------------

def test_intervention_effect_confounded_known_truth():
    model = confounded_model()
    p1 = model.interventional_dist({"X": 1}, "Y")
    p0 = model.interventional_dist({"X": 0}, "Y")
    assert abs(p1[1] - 0.45) < 1e-9
    assert abs(p0[1] - 0.25) < 1e-9
    assert abs(average_causal_effect(model, "X", "Y") - 0.20) < 1e-9
    # The observational conditional is NOT the effect (confounding).
    obs = model.distribution("Y", {"X": 1})
    assert abs(obs[1] - 0.54) < 1e-9
    assert obs[1] != p1[1]


def test_collider_conditioning_biases_but_do_does_not():
    model = collider_model()
    assert model.interventional_dist({"X": 1}, "Y") == {0: 0.5, 1: 0.5}
    # Conditioning on the collider M=1 selects Y=1 whenever X=1.
    assert model.distribution("Y", {"X": 1, "M": 1}) == {0: 0.0, 1: 1.0}
    assert model.distribution("Y", {"X": 1}) == {0: 0.5, 1: 0.5}


def test_mediation_total_effect_known_truth():
    model = mediation_model()
    assert abs(model.interventional_dist({"X": 1}, "Y")[1] - 0.54) < 1e-9
    assert abs(model.interventional_dist({"X": 0}, "Y")[1] - 0.16) < 1e-9
    assert abs(average_causal_effect(model, "X", "Y") - 0.38) < 1e-9


def test_monte_carlo_matches_exact():
    model = confounded_model()
    mc = model.interventional_dist_mc({"X": 1}, "Y",
                                      n=20_000, seed=0)
    assert abs(mc[1] - 0.45) < 0.02
    assert abs(sum(mc.values()) - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------

def test_backdoor_paths_and_adjustment_set():
    model = confounded_model()
    g = model.graph
    paths = backdoor_paths(g, "X", "Y")
    assert paths == [["X", "Z", "Y"]]
    assert find_backdoor_set(g, "X", "Y") == frozenset({"Z"})
    ident = identify_effect(g, "X", "Y")
    assert ident["identifiable"] is True
    assert ident["adjustment_set"] == ["Z"]
    # No back-door path in the mediation graph once X is the
    # treatment: X -> M -> Y and X -> Y are front-door only.
    g2 = mediation_model().graph
    assert backdoor_paths(g2, "X", "Y") == []
    assert identify_effect(g2, "X", "Y")["adjustment_set"] == []


def test_unidentifiable_latent_confounder():
    g = CausalGraph()
    g.add_node("X", [0, 1])
    g.add_node("Y", [0, 1])
    g.add_node("U", [0, 1], observed=False)
    g.add_edge("U", "X")
    g.add_edge("U", "Y")
    g.add_edge("X", "Y")
    ident = identify_effect(g, "X", "Y")
    assert ident["identifiable"] is False
    assert ident["adjustment_set"] is None
    assert "unobserved" in ident["reason"]


def test_estimate_effect_recovers_truth_from_rows():
    rng = random.Random(42)
    rows = confounded_model().sample(rng, 20_000)
    est = estimate_effect(rows, "X", "Y", ["Z"])
    assert abs(est["estimate"][1][1] - 0.45) < 0.02
    assert abs(est["estimate"][0][1] - 0.25) < 0.02
    assert est["n"] == 20_000
    # The raw conditional on the same rows is biased away from
    # the truth: P(Y=1|X=1) ~= 0.54, not 0.45.
    raw = raw_conditional(rows, "X", "Y")
    assert abs(raw[(1,)][1] - 0.54) < 0.03
    assert abs(raw[(1,)][1] - est["estimate"][1][1]) > 0.05


def test_fit_recovers_cpts_and_keeps_latent_uniform():
    rng = random.Random(7)
    rows = confounded_model().sample(rng, 5_000)
    fitted = StructuralModel.fit(confounded_model().graph, rows)
    assert abs(fitted.cpts["X"][(1,)][1] - 0.8) < 0.03
    assert abs(fitted.cpts["Y"][(1, 1)][1] - 0.6) < 0.03
    # The latent node in the xor model is never learned from data.
    xor_rows = xor_model().sample(random.Random(7), 2_000)
    fitted_xor = StructuralModel.fit(xor_model().graph, xor_rows)
    assert fitted_xor.cpts["U"][()][0] == 0.5
    assert fitted_xor.fit_counts["U"] == 0


# ---------------------------------------------------------------------------
# Counterfactuals
# ---------------------------------------------------------------------------

def test_counterfactual_xor_known_answer():
    engine = CounterfactualEngine(xor_model(), seed=0)
    out = engine.query({"X": 0, "Y": 1}, {"X": 1}, "Y")
    assert out["distribution"] == {0: 1.0, 1: 0.0}
    assert out["confidence"] in ("high", "medium")
    assert any("twin-network" in a for a in out["assumptions"])


def test_counterfactual_backup_infra_known_answer():
    # Evidence: server online, backup none. Counterfactual:
    # had it gone offline, which backup? Exact answer from the
    # noise intervals: new 0.20, none ~0.111, secondary ~0.689.
    engine = CounterfactualEngine(backup_infra_model(), seed=1)
    out = engine.query({"offline": 0, "backup": "none"},
                       {"offline": 1}, "backup", n_samples=20_000)
    dist = out["distribution"]
    assert out["confidence"] in ("high", "medium")
    assert abs(dist["secondary"] - 0.689) < 0.03
    assert abs(dist["new"] - 0.20) < 0.03
    assert abs(dist["none"] - 0.111) < 0.03


def test_counterfactual_rare_evidence_is_unidentified():
    engine = CounterfactualEngine(xor_model(), seed=0)
    # Evidence with probability zero under the model (Y=1 while
    # X=0 and U is pinned by... use an impossible combination:
    # X=0, Y=0 is possible; instead force acceptance to collapse
    # with a tiny sample budget on rare evidence.
    out = engine.query({"X": 0, "Y": 1}, {"X": 1}, "Y",
                       n_samples=10, min_kept=100)
    assert out["distribution"] is None
    assert out["confidence"] == "unidentified"
    assert out["n_kept"] < 100


# ---------------------------------------------------------------------------
# Recon graph + backup-infra question
# ---------------------------------------------------------------------------

def test_recon_graph_build_and_identification():
    candidates = [
        {"chain": "bsc", "plugin": "unchecked_math_user_input",
         "function": "_transferShares",
         "recipient_class": "CALLER-SUPPLIED",
         "validation": {"verdict": "UNVERIFIED"},
         "live_probe": {"status": "transport_error"}},
        {"chain": "bsc", "plugin": "contract_logic",
         "function": "withdraw", "recipient_class": "CALLER",
         "validation": {"verdict": "FALSE_POSITIVE"},
         "live_probe": {"status": "revert"}},
        {"chain": "ethereum", "plugin": "contract_logic",
         "function": "mint", "recipient_class": "CALLER-SUPPLIED",
         "validation": {"verdict": "UNVERIFIED"},
         "live_probe": {"status": "success"}},
    ]
    transitions = [
        {"chain": "ethereum", "address": "0xabc",
         "changed": ["owner"],
         "before": {"owner": "0x1"}, "after": {"owner": None}},
    ]
    g, notes = build_recon_graph(candidates, transitions)
    assert set(g.nodes) == {
        "chain", "plugin", "function", "recipient_class",
        "latent_vuln", "worth_validating", "live_probe",
        "owner_change", "next_owner", "backup_infra"}
    assert g.parents_of("worth_validating") == (
        "latent_vuln", "plugin")
    assert g.observed["latent_vuln"] is False
    assert g.observed["backup_infra"] is False
    # PLUGIN -> WORTH_VALIDATING is confounded by the latent
    # vulnerability: not identifiable from candidate rows.
    ident = identify_effect(g, "plugin", "worth_validating")
    assert ident["identifiable"] is False
    # OWNER_CHANGE -> NEXT_OWNER is identified (adjust for chain).
    ident2 = identify_effect(g, "owner_change", "next_owner")
    assert ident2["identifiable"] is True
    assert "chain" in ident2["adjustment_set"]
    assert any("not identifiable" in n.lower()
               or "identifiable" in n.lower() for n in notes)


def test_predict_backup_infra_synthetic_and_unidentified():
    g = CausalGraph()
    g.add_node("chain", ["bsc", "ethereum"])
    g.add_node("owner_change", [0, 1])
    g.add_node("next_owner", ["renounced", "new_owner", "unchanged"])
    g.add_edge("chain", "owner_change")
    g.add_edge("chain", "next_owner")
    g.add_edge("owner_change", "next_owner")
    cpts = {
        "chain": {(): {"bsc": 0.5, "ethereum": 0.5}},
        "owner_change": {("bsc",): {0: 0.9, 1: 0.1},
                         ("ethereum",): {0: 0.9, 1: 0.1}},
        "next_owner": {
            ("bsc", 0): {"renounced": 0.0, "new_owner": 0.0,
                         "unchanged": 1.0},
            ("bsc", 1): {"renounced": 0.5, "new_owner": 0.5,
                         "unchanged": 0.0},
            ("ethereum", 0): {"renounced": 0.0, "new_owner": 0.0,
                              "unchanged": 1.0},
            ("ethereum", 1): {"renounced": 0.5, "new_owner": 0.5,
                              "unchanged": 0.0}},
    }
    model = StructuralModel(g, cpts, fit_counts={"next_owner": 100})
    out = predict_backup_infra(
        model, {"chain": "ethereum", "owner_change": 0},
        n_samples=10_000, seed=0)
    assert out["confidence"] in ("high", "medium")
    assert abs(out["prediction"]["renounced"] - 0.5) < 0.05
    assert abs(out["prediction"]["new_owner"] - 0.5) < 0.05
    assert any("do(" in a for a in out["assumptions"])
    # Same model, mechanism barely observed: no prediction.
    thin = StructuralModel(g, cpts, fit_counts={"next_owner": 5})
    out2 = predict_backup_infra(
        thin, {"chain": "ethereum", "owner_change": 0})
    assert out2["prediction"] is None
    assert out2["confidence"] == "unidentified"


def test_fit_coerces_rare_values_to_other():
    g = CausalGraph()
    g.add_node("plugin", ["a", "other"])
    g.add_node("function", ["f", "other"])
    g.add_edge("plugin", "function")
    rows = [{"plugin": "zzz", "function": "f"},
            {"plugin": "a", "function": "weird"},
            {"plugin": "a", "function": "f"}]
    fitted = StructuralModel.fit(g, rows)
    # Rare values collapse to "other" instead of dropping rows.
    assert fitted.fit_counts["plugin"] == 3
    assert fitted.fit_counts["function"] == 3
    assert fitted.cpts["function"][("other",)]["f"] > 0.5
    assert fitted.cpts["function"][("a",)]["other"] > 0.3


def test_model_save_load_roundtrip(tmp_path):
    model = confounded_model()
    path = str(tmp_path / "model.json")
    model.save(path)
    model2 = StructuralModel.load(path)
    assert model2.graph.to_dict() == model.graph.to_dict()
    assert (model2.interventional_dist({"X": 1}, "Y")
            == model.interventional_dist({"X": 1}, "Y"))


def test_model_dict_roundtrip_in_memory():
    model = confounded_model()
    model2 = StructuralModel.from_dict(model.to_dict())
    assert model2.graph.to_dict() == model.graph.to_dict()
    assert (model2.interventional_dist({"X": 1}, "Y")
            == model.interventional_dist({"X": 1}, "Y"))
    assert (model2.interventional_dist({"X": 0}, "Y")
            == model.interventional_dist({"X": 0}, "Y"))
