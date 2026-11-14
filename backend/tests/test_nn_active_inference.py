"""Tests for the Active Inference / Free Energy Principle triage loop.

Pure stdlib, no network, no live probes. Covers:
- entropy / EIG on known distributions,
- belief updates converging on repeated consistent observations,
- the loop picking the highest-EIG query over a decoy low-value one,
- variational free-energy bounds and the drop-in scanner function.

The synthetic distributions in these tests are unit self-tests of
the entropy/EIG math only (allowed by the Nov 14 no-simulation
rule for that purpose). They are never evaluation numbers: the
evaluation is the replay over real batches/candidates data in
app/nn/replay_active_inference.py.
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.active_inference import (  # noqa: E402
    DEFAULT_QUERIES,
    Belief,
    ActiveInferenceLoop,
    Query,
    beta_differential_entropy,
    binary_entropy,
    contract_id,
    expected_free_energy,
    expected_information_gain,
    pick_next_contract,
    prior_for_contract,
    score_query,
)


def test_binary_entropy_known_values():
    assert binary_entropy(0.5) == 1.0
    assert binary_entropy(0.0) == 0.0
    assert binary_entropy(1.0) == 0.0
    # H(0.25) = 0.811278... bits
    assert abs(binary_entropy(0.25) - 0.8112781244591328) < 1e-9
    # Symmetric, max at 0.5
    assert binary_entropy(0.2) == binary_entropy(0.8)
    assert binary_entropy(0.2) < binary_entropy(0.5)


def test_beta_differential_entropy_uniform_is_zero():
    assert abs(beta_differential_entropy(1.0, 1.0)) < 1e-9
    # A concentrated Beta has negative differential entropy (bits).
    assert beta_differential_entropy(10.0, 10.0) < 0.0
    # More concentrated -> lower entropy.
    assert (beta_differential_entropy(50.0, 50.0)
            < beta_differential_entropy(10.0, 10.0))


def test_belief_from_beta_mean_and_entropy():
    b = Belief.from_beta(2.0, 2.0)
    assert abs(b.mean - 0.5) < 0.01
    assert abs(b.theta_mean - 0.5) < 0.01
    assert abs(sum(b.weights) - 1.0) < 1e-9
    uniform = Belief.from_beta(1.0, 1.0)
    # Uniform over 101 grid points: log2(101) bits of theta entropy.
    assert abs(uniform.theta_entropy - math.log2(101)) < 1e-6
    concentrated = Belief.from_beta(50.0, 50.0)
    assert concentrated.theta_entropy < uniform.theta_entropy


def test_eig_perfect_observation_equals_prior_entropy():
    # A full probe (sens=1, fpr=0) reveals S exactly: from q=0.5
    # the outcome is a fair coin and the posterior is 0 or 1, so
    # EIG = 1 bit.
    thetas = [i / 100 for i in range(101)]
    w = [0.0] * 101
    w[50] = 1.0
    b = Belief(thetas, w, 0.5)
    full = Query("full_probe", "full_probe", 1.0, 1.0, 0.0)
    assert abs(expected_information_gain(b, full) - 1.0) < 1e-6
    # An uninformative query (sens == fpr) gains nothing.
    dead = Query("dead", "lane", 0.1, 0.4, 0.4)
    assert abs(expected_information_gain(b, dead)) < 1e-9


def test_eig_known_case_arithmetic():
    # q=0.5, lane sens=0.9 fpr=0.1: P(pos)=0.5, q|pos=0.9,
    # q|neg=0.1, H(0.9)=0.468996 bits, so EIG = 1 - 0.468996.
    thetas = [i / 100 for i in range(101)]
    w = [0.0] * 101
    w[50] = 1.0
    b = Belief(thetas, w, 0.5)
    lane = Query("lane", "lane", 0.1, 0.9, 0.1)
    assert abs(expected_information_gain(b, lane)
               - (1.0 - 0.4689955935892812)) < 1e-9
    # A weaker lane gains less.
    weak = Query("weak", "lane", 0.1, 0.6, 0.4)
    assert 0.0 < expected_information_gain(b, weak) < 1.0


def test_eig_never_negative_and_bounded_by_prior_entropy():
    b = Belief.from_beta(3.0, 7.0)
    for q in DEFAULT_QUERIES:
        eig = expected_information_gain(b, q)
        assert -1e-9 <= eig <= b.entropy + 1e-9


def test_belief_update_converges_on_repeated_positive_observations():
    # Repeated consistent positive observations from a good lane
    # (LR+ ~4) drive q up toward 1.
    b = Belief.from_mean(0.16)
    lane = Query("arithmetic_guards", "lane", 0.1, 0.929, 0.230)
    for _ in range(6):
        b.update(lane, "positive")
    assert b.mean > 0.9
    assert b.entropy < Belief.from_mean(0.16).entropy


def test_belief_update_converges_on_repeated_negative_observations():
    b = Belief.from_mean(0.16)
    lane = Query("arithmetic_guards", "lane", 0.1, 0.929, 0.230)
    for _ in range(3):
        b.update(lane, "negative")
    assert b.mean < 0.02


def test_belief_update_positive_then_negative_roughly_restores():
    # A symmetric lane (LR+ = 9, LR- = 1/9): a positive then a
    # negative observation returns q to its prior.
    b = Belief.from_mean(0.5)
    lane = Query("sym", "lane", 0.1, 0.9, 0.1)
    b.update(lane, "positive")
    assert b.mean > 0.5
    b.update(lane, "negative")
    assert abs(b.mean - 0.5) < 1e-9


def test_free_energy_is_negative_log_evidence_for_exact_posterior():
    # For the exact Bayes posterior over theta, F = -log p(obs).
    b = Belief.from_mean(0.3)
    lane = Query("gate_analysis", "lane", 0.1, 0.889, 0.237)
    lik = lane.theta_likelihoods(b.thetas, "positive")
    log_ev = b.update(lane, "positive")
    f = b.free_energy(lik)
    assert abs(f - (-log_ev / math.log(2.0))) < 1e-6
    # And F >= -log p(obs) always holds (KL >= 0).
    assert f >= -log_ev / math.log(2.0) - 1e-9


def test_expected_free_energy_prefers_cheap_informative_query():
    b = Belief.from_mean(0.5)
    cheap_good = Query("cheap", "lane", 0.1, 0.9, 0.1)
    dear_same = Query("dear", "lane", 1.0, 0.9, 0.1)
    assert (expected_free_energy(b, cheap_good)
            < expected_free_energy(b, dear_same))


def test_score_query_eig_per_cost_scales_with_cost():
    b = Belief.from_mean(0.5)
    q1 = Query("a", "lane", 0.1, 0.9, 0.1)
    q2 = Query("b", "lane", 0.2, 0.9, 0.1)
    s1 = score_query(b, q1)
    s2 = score_query(b, q2)
    assert s1["eig_bits"] == s2["eig_bits"]
    assert s1["eig_per_cost"] == 2.0 * s2["eig_per_cost"]


def test_loop_picks_highest_eig_query_over_decoy():
    # Two contracts, one query each scenario: the loop must fire
    # the informative lane before the near-useless recipient lane,
    # and must prefer the high-uncertainty contract.
    contracts = [
        {"chain": "bsc", "address": "0x" + "11" * 20,
         "queue": "bnb_tier3", "stake_usd": 100.0, "symbol": "AAA"},
        {"chain": "bsc", "address": "0x" + "22" * 20,
         "queue": "fresh", "stake_usd": 100.0, "symbol": "BBB"},
    ]
    loop = ActiveInferenceLoop(contracts)
    nxt = loop.pick_next()
    assert nxt is not None
    # The bnb contract (prior ~0.16, H ~0.63 bits) beats fresh
    # (prior ~0.01, H ~0.08 bits); the decoy recipient lane
    # (EIG ~ 0) must never be the first pick.
    assert nxt["contract"]["address"] == "0x" + "11" * 20
    assert nxt["query"] != "recipient_probe"
    assert nxt["eig_bits"] > 0.05


def test_loop_promotes_on_repeated_positive_and_drops_on_negative():
    good = {"chain": "bsc", "address": "0x" + "aa" * 20,
            "queue": "bnb_tier3", "stake_usd": 10.0, "symbol": "G"}
    bad = {"chain": "bsc", "address": "0x" + "bb" * 20,
           "queue": "bnb_tier3", "stake_usd": 10.0, "symbol": "B"}
    seen = {}

    def obs(contract, query_name):
        # The good contract fires every lane; the bad one none.
        return "positive" if contract["symbol"] == "G" else "negative"

    loop = ActiveInferenceLoop([good, bad])
    summary = loop.run(obs, budget=5.0)
    assert loop.states[contract_id(good)].status == "promoted"
    assert loop.states[contract_id(bad)].status == "dropped"
    assert summary["promoted"] == 1
    assert summary["dropped"] == 1
    assert summary["entropy_reduction_bits"] > 0


def test_loop_respects_budget():
    contracts = [{"chain": "bsc", "address": "0x%040x" % i,
                  "queue": "bnb_tier3", "stake_usd": 50.0,
                  "symbol": "T%d" % i} for i in range(20)]
    loop = ActiveInferenceLoop(contracts)
    loop.run(lambda c, q: "negative", budget=1.0)
    assert loop.spent <= 1.0 + 1e-9


def test_pick_next_contract_drop_in():
    contracts = [
        {"chain": "bsc", "address": "0x" + "33" * 20,
         "queue": "bnb_tier3", "stake_usd": 100.0, "symbol": "AAA"},
        {"chain": "bsc", "address": "0x" + "44" * 20,
         "queue": "fresh", "stake_usd": 100.0, "symbol": "BBB"},
    ]
    nxt = pick_next_contract(contracts)
    assert nxt is not None
    assert nxt["contract"]["queue"] == "bnb_tier3"
    assert nxt["query"] in {q.name for q in DEFAULT_QUERIES}
    assert nxt["eig_bits"] > 0
    assert "expected_free_energy" in nxt
    assert pick_next_contract([]) is None


def test_prior_stake_adjustment_direction():
    # Worth-validating contracts have lower stake (fit-half beta
    # -0.25): the same queue with low stake gets a higher prior.
    low = {"chain": "bsc", "address": "0x" + "55" * 20,
           "queue": "bnb_tier3", "stake_usd": 1.0, "symbol": "L"}
    high = {"chain": "bsc", "address": "0x" + "66" * 20,
            "queue": "bnb_tier3", "stake_usd": 100000.0, "symbol": "H"}
    assert prior_for_contract(low)[0] > prior_for_contract(high)[0]
    # Queue order is preserved in the prior: bnb >> fresh.
    fresh = {"chain": "bsc", "address": "0x" + "77" * 20,
             "queue": "fresh", "stake_usd": 1.0, "symbol": "F"}
    assert prior_for_contract(low)[0] > prior_for_contract(fresh)[0]


def test_missing_data_widens_prior():
    known = {"chain": "bsc", "address": "0x" + "88" * 20,
             "queue": "bnb_tier3", "stake_usd": 100.0, "symbol": "K",
             "source_verified": True, "owner_known": True,
             "probed_lanes": ["a", "b", "c", "d", "e", "f", "g"]}
    missing = {"chain": "bsc", "address": "0x" + "99" * 20,
               "queue": "bnb_tier3", "stake_usd": None, "symbol": None}
    _, a1, b1 = prior_for_contract(known)
    _, a2, b2 = prior_for_contract(missing)
    assert a1 + b1 > a2 + b2  # weaker prior strength when data missing
    assert abs(a1 / (a1 + b1) - a2 / (a2 + b2)) < 0.05  # same mean
