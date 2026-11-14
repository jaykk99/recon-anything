"""Tests for the MARL evasion game (backend/app/nn/).

Kuhn poker and rock-paper-scissors appear here ONLY as unit
self-tests proving CFR converges on small known games (the Nov 14
no-simulation rule: known games are a tool self-test, never an
evaluation result). All evaluation runs on real candidate rows
(see test_replay_* with the real file, and the eval CLI).

The tiny hand-built row lists in the replay-math tests are fixtures
for the replay arithmetic, not evaluation data: they check the
coverage/probe formulas, nothing more.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.cfr import CFR, KuhnPoker, rock_paper_scissors  # noqa: E402
from app.nn.marl import (  # noqa: E402
    CURATED_29,
    EMPIRICAL_LANES,
    LANES,
    STATIC29_LANE_ORDER,
    YIELD_LANE_ORDER,
    cfr_rank_order,
    lane_stats,
    load_candidate_rows,
    make_replay_policy,
    replay,
    solve_evasion,
)

CANDIDATES_PATH = os.path.join(
    os.path.expanduser("~"), "workspace", "recon-continuous", "results",
    "candidates.jsonl")


@pytest.fixture(scope="module")
def solution():
    return solve_evasion(500)


def test_kuhn_converges_to_known_value():
    """CFR on Kuhn poker: game value -1/18, low exploitability."""
    solver = CFR(KuhnPoker())
    solver.train(1500)
    assert solver.game_value() == pytest.approx(-1.0 / 18.0, abs=0.01)
    assert solver.exploitability() < 0.03


def test_kuhn_regret_decreases():
    """Exploitability falls with more CFR iterations (regret is
    actually being minimised, not just asserted)."""
    early = CFR(KuhnPoker())
    early.train(100)
    late = CFR(KuhnPoker())
    late.train(1500)
    assert late.exploitability() < early.exploitability()
    assert late.exploitability() < 0.03


def test_rps_uniform_equilibrium():
    """CFR on rock-paper-scissors: the unique equilibrium is uniform
    for both players, value 0."""
    solver = CFR(rock_paper_scissors())
    solver.train(2000)
    for infoset in (("P0",), ("P1",)):
        strat = solver.average_strategy_full(infoset, [0, 1, 2])
        for action in (0, 1, 2):
            assert strat[action] == pytest.approx(1.0 / 3.0, abs=0.07)
    assert solver.game_value() == pytest.approx(0.0, abs=0.01)
    assert solver.exploitability() < 0.05


def test_evasion_solve_matches_analytic_equilibrium(solution):
    """The evasion game has a known analytic equilibrium: the
    attacker probes math (prior 0.67 x rate 0.996 dominates every
    other lane) and the defender redeploys on math targets and plays
    none elsewhere; game value ~0.385. CFR must find it."""
    assert solution["game_value"] == pytest.approx(0.385, abs=0.02)
    assert solution["exploitability"] < 0.01
    assert solution["attacker_mix"]["math"] > 0.95
    assert solution["defender_mix"]["math"]["redeploy"] > 0.9
    for lane in ("logic", "other", "upgrade", "mint", "bridge"):
        assert solution["defender_mix"][lane]["none"] > 0.9


def test_static29_lane_order_and_size():
    assert len(CURATED_29) == 29
    assert STATIC29_LANE_ORDER == ["other", "logic", "bridge", "mint"]
    # The curated 29 never reaches the math or upgrade lanes.
    assert "math" not in STATIC29_LANE_ORDER
    assert "upgrade" not in STATIC29_LANE_ORDER
    assert YIELD_LANE_ORDER == ["math", "logic", "upgrade",
                                "other", "mint", "bridge"]


def test_cfr_rank_order(solution):
    order = cfr_rank_order(solution)
    assert order[0] == "math"
    assert sorted(order) == sorted(LANES)


def _fixture_rows():
    """Hand fixture for replay arithmetic only: 4 real rows (math,
    logic, upgrade, bridge) + 1 false-positive math row."""
    return [
        {"plugin": "unchecked_math_user_input", "lane": "math",
         "chain": "bsc", "address": "0x1", "real": True,
         "verdict": "UNVERIFIED"},
        {"plugin": "contract_logic", "lane": "logic",
         "chain": "bsc", "address": "0x2", "real": True,
         "verdict": "UNVERIFIED"},
        {"plugin": "uups_authorize_upgrade_missing", "lane": "upgrade",
         "chain": "ethereum", "address": "0x3", "real": True,
         "verdict": "UNVERIFIED"},
        {"plugin": "bridge_replay_unbound_digest", "lane": "bridge",
         "chain": "arbitrum", "address": "0x4", "real": True,
         "verdict": "UNVERIFIED"},
        {"plugin": "unchecked_math_user_input", "lane": "math",
         "chain": "bsc", "address": "0x5", "real": False,
         "verdict": "FALSE_POSITIVE"},
    ]


def test_replay_order_arithmetic():
    """Static29 reaches logic (pos 2) and bridge (pos 3) but never
    math or upgrade; the yield order reaches all four real lanes
    within budget 6. False positives cost probes, never count."""
    rows = _fixture_rows()
    static = replay(rows, {"name": "static29", "kind": "order",
                           "lanes": list(STATIC29_LANE_ORDER)}, budget=6)
    assert static["n_real_rows"] == 4
    assert static["coverage"] == pytest.approx(0.5)  # logic + bridge
    assert static["per_lane"]["math"]["coverage"] == 0.0
    assert static["per_lane"]["upgrade"]["coverage"] == 0.0
    assert static["per_lane"]["logic"]["coverage"] == 1.0
    # Probes: math FP row costs 6 (never reached), math real 6,
    # logic 2, upgrade 6, bridge 3 = 23.
    assert static["expected_probes"] == pytest.approx(23.0)
    yld = replay(rows, {"name": "yield", "kind": "order",
                        "lanes": list(YIELD_LANE_ORDER)}, budget=6)
    assert yld["coverage"] == pytest.approx(1.0)
    assert yld["expected_probes"] == pytest.approx(1 + 2 + 3 + 6 + 1)


def test_replay_mix_geometric_arithmetic():
    """Mix replay uses exact geometric expectations: q=0.5, budget 2
    reaches a lane with P=0.75 and spends E=1.5 probes."""
    rows = [{"plugin": "unchecked_math_user_input", "lane": "math",
             "chain": "bsc", "address": "0x1", "real": True,
             "verdict": "UNVERIFIED"}]
    mix = {"name": "half-math", "kind": "mix",
           "mix": {"math": 0.5, "logic": 0.5, "other": 0.0,
                   "upgrade": 0.0, "mint": 0.0, "bridge": 0.0}}
    result = replay(rows, mix, budget=2)
    assert result["coverage"] == pytest.approx(0.75)
    assert result["expected_probes"] == pytest.approx(1.5)
    # Deterministic: same rows and policy, same numbers.
    assert replay(rows, mix, budget=2) == result


def test_replay_evasion_adjustment_is_labelled(solution):
    """Evasion adjustment is a separate, labelled figure: with no
    evasion it equals the raw finds; under the CFR defender it is
    lower (redeploy halves math detection)."""
    rows = _fixture_rows()
    policy = make_replay_policy("cfr-rank", solution)
    result = replay(rows, policy, budget=6, solution=solution)
    adj = result["evasion_adjusted"]
    assert adj["none"]["expected_finds"] == pytest.approx(
        result["expected_finds"])
    assert (adj["cfr"]["expected_finds"]
            < result["expected_finds"])


@pytest.mark.skipif(not os.path.exists(CANDIDATES_PATH),
                    reason="real candidates file absent")
def test_lane_stats_match_embedded():
    rows = load_candidate_rows(CANDIDATES_PATH)
    assert len(rows) == 725
    for lane, stats in lane_stats(rows).items():
        embedded = EMPIRICAL_LANES[lane]
        assert stats["prior"] == pytest.approx(embedded["prior"],
                                                abs=0.001)
        assert stats["unverified_rate"] == pytest.approx(
            embedded["unverified_rate"], abs=0.001)


@pytest.mark.skipif(not os.path.exists(CANDIDATES_PATH),
                    reason="real candidates file absent")
def test_replay_on_real_rows(solution):
    """Replay over the real rows: the CFR-rank policy covers far more
    real UNVERIFIED rows than the static29 order or random, and
    static29 finds zero math-lane rows (its blind spot is real)."""
    rows = load_candidate_rows(CANDIDATES_PATH)
    budget = 6
    cfr = replay(rows, make_replay_policy("cfr-rank", solution),
                 budget=budget, solution=solution)
    static = replay(rows, make_replay_policy("static29", solution),
                    budget=budget, solution=solution)
    rnd = replay(rows, make_replay_policy("random", solution),
                 budget=budget, solution=solution)
    assert static["per_lane"]["math"]["reached"] == 0.0
    assert static["per_lane"]["upgrade"]["reached"] == 0.0
    assert cfr["coverage"] > static["coverage"]
    assert cfr["coverage"] > rnd["coverage"]
    assert cfr["finds_per_100_probes"] > rnd["finds_per_100_probes"]
    assert cfr["finds_per_100_probes"] > static["finds_per_100_probes"]
