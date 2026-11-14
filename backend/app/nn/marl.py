"""Multi-agent reinforcement learning + game theory for ReconAnything.

The recon/target interaction is modelled as a two-player zero-sum
imperfect-information game and solved with Counterfactual Regret
Minimization (CFR, see ``cfr.py``):

- Player 0, the attacker (recon): picks which plugin lane to probe.
  It does NOT know the target's hidden vulnerability lane and does
  NOT see the defender's opsec move. One infoset.
- Player 1, the defender (target/owner): knows its own lane and picks
  an opsec move (owner rotation, burner wallet, proxy hop, redeploy,
  timestamp jitter, or nothing). One infoset per lane.
- Chance deals the hidden lane from the empirical distribution over
  the 725 usable real candidates, and decides detection: a probe only pays
  off when it hits the right lane, the finding is worth validating
  (UNVERIFIED), and the defender's opsec did not hide it.

What is REAL here and what is ASSUMED:
- REAL (measured from ~/workspace/recon-continuous/results/
  candidates.jsonl, 727 lines / 725 usable rows): the lane prior, the per-lane
  UNVERIFIED rate, and the owner-flip behaviour (52 owner flips on
  11 watched addresses, Nov 5-14 2026). These numbers are embedded
  below as EMPIRICAL_LANES / EMPIRICAL_DEFENDER and recomputed from
  the file whenever it is present.
- ASSUMED (synthetic, labelled as such everywhere): the evasion
  multipliers EVASION_MULT, i.e. how much each opsec move hides each
  lane. No data measures these. They are explicit modelling choices,
  not measurements. Change them and the equilibrium moves; the CFR
  machinery does not care.
- The evaluation is a DETERMINISTIC REPLAY over the real candidate
  rows: what each probe policy would have picked, and how many
  probes it would have spent to reach each real finding's lane.
  No random draws, no invented targets, no invented findings. Its
  numbers are policy-study numbers (which probe order reaches more
  of the already-promoted candidates per probe spent), not scan
  results and not proof of anything live.

NO-SIMULATION RULE (restated Nov 14, Jay's order): no simulated
data anywhere in ReconAnything, real workflow only, real numbers,
nothing invented. This module complies: there is no Monte Carlo
simulator and no synthetic fallback data. The CFR game is a model
solved on real lane priors/rates plus explicitly assumed evasion
multipliers, and the evaluation replays over the real rows. Small
known games (Kuhn poker, rock-paper-scissors) appear only as unit
self-tests proving CFR converges; they are never evaluation
results. Where the real data cannot support a claim (the
defender's actual per-target move is unobserved), the docs say so
instead of substituting a simulated win.

Detection only. Read-only live probes only. No transactions, no
drains, no exploit execution, no auth bypass, no private-data access.
crypto.com is never a target.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .cfr import CFR, Game

# ----------------------------------------------------------------------
# Empirical data (recomputed from candidates.jsonl, 725 usable rows)
# ----------------------------------------------------------------------

# 22 plugins observed in the 725 usable candidates, collapsed to 6 lanes so
# the game stays small enough for exact CFR. "bridge" groups every
# bridge_* plugin plus recipient_bridge_release_unproven; "other" is
# the long tail (recipient_sig_value_to_self, cross_function_guard_
# sibling, recipient_unbacked_claim, eip712/ERC-2771, ...).
LANES: Tuple[str, ...] = ("math", "logic", "other", "upgrade", "mint",
                          "bridge")

PLUGIN_TO_LANE: Dict[str, str] = {
    "unchecked_math_user_input": "math",
    "contract_logic": "logic",
    "uups_authorize_upgrade_missing": "upgrade",
    "recipient_mint_to_caller": "mint",
    "bridge_replay_unbound_digest": "bridge",
    "bridge_withdrawer_identity_spoof": "bridge",
    "bridge_proof_length_unvalidated": "bridge",
    "bridge_proof_nullifier_missing": "bridge",
    "bridge_receiver_sender_unchecked": "bridge",
    "recipient_bridge_release_unproven": "bridge",
    # Long tail -> "other".
    "recipient_sig_value_to_self": "other",
    "cross_function_guard_sibling": "other",
    "recipient_overdraw_withdraw": "other",
    "recipient_unbacked_claim": "other",
    "eip712_separator_unbound": "other",
    "erc2771_msg_sender_unbound": "other",
    "crypto_drain_scanner": "other",
    "recipient_rescue_to_param": "other",
    "hardcoded_hash_constant_mismatch": "other",
    "fee_on_transfer_overcredit": "other",
    "weak_randomness_value_outcome": "other",
    "empty_signature_accepted": "other",
}

# n = candidates in lane, prior = n/725, unverified_rate = share of
# the lane's candidates whose validator verdict is UNVERIFIED
# (worth validating; the rest are FALSE_POSITIVE / TRIGGER_ONLY).
# The file holds 727 lines; 2 VERIFIED_REAL rows are dropped on load
# (already-adjudicated simulation-path false positives, 0 real
# verified rows to learn from), so the table is on the 725 usable
# rows. Recompute with: lane_stats(load_candidate_rows()).
EMPIRICAL_LANES: Dict[str, Dict[str, float]] = {
    "math":    {"n": 487, "prior": 0.6717, "unverified_rate": 0.9959},
    "logic":   {"n": 69,  "prior": 0.0952, "unverified_rate": 0.6812},
    "other":   {"n": 66,  "prior": 0.0910, "unverified_rate": 0.4394},
    "upgrade": {"n": 37,  "prior": 0.0510, "unverified_rate": 0.9730},
    "mint":    {"n": 35,  "prior": 0.0483, "unverified_rate": 0.3714},
    "bridge":  {"n": 31,  "prior": 0.0428, "unverified_rate": 0.3226},
}

# Curated contract plugin set: the same 29 ids the continuous scanner
# runs when no widened set is configured (recon-continuous/runner.py:
# CORE + DEEP + DEEP3 + RECIPIENT + LAYERS), copied from
# backend/app/nn/score.py (nn-scorer branch). The static baseline
# probes lanes in the order they FIRST appear in this list.
CURATED_29: List[str] = [
    "contract_recon", "crypto_drain_scanner", "contract_logic",
    "vault_share_inflation", "readonly_reentrancy_gap",
    "diamond_cut_ungated", "aa_validation_ungated",
    "ecrecover_zero_signer", "hook_cei_reentrancy",
    "bridge_replay_unbound_digest", "eip7702_unverified_delegate",
    "l2_sequencer_uptime_missing", "fee_on_transfer_overcredit",
    "create2_metamorphic_redeploy",
    "transient_latch_unconsumed", "v4_hook_shared_delta_take_pair",
    "inverted_division_zero_collapse", "share_transfer_cancel_desync",
    "eip712_digest_unbound_to_payload",
    "recipient_mint_to_caller", "recipient_unbacked_claim",
    "recipient_overdraw_withdraw", "recipient_rescue_to_param",
    "recipient_bridge_release_unproven", "recipient_sig_value_to_self",
    "cross_contract_call_graph", "storage_state_analysis",
    "bytecode_deep_analysis", "candidate_confirmation_queue",
]


def static29_lane_order() -> List[str]:
    """Lanes in first-appearance order in CURATED_29.

    Only 4 of the 6 lanes appear at all: the curated 29 never probes
    the math lane (unchecked_math_user_input, 67% of all candidates)
    or the upgrade lane (uups_*, 5%). That blind spot is a property
    of the plugin list, not of CFR, and the evaluation reports it.
    """
    order: List[str] = []
    for plugin in CURATED_29:
        lane = PLUGIN_TO_LANE.get(plugin, "other")
        if lane not in order:
            order.append(lane)
    return order


STATIC29_LANE_ORDER: List[str] = static29_lane_order()

# Lane order by expected value (prior * unverified_rate): the naive
# yield-ordered rotation used as a control, to show how much of the
# CFR gain is just "probe the productive lanes first" vs equilibrium.
YIELD_LANE_ORDER: List[str] = sorted(
    LANES,
    key=lambda lane: (EMPIRICAL_LANES[lane]["prior"]
                      * EMPIRICAL_LANES[lane]["unverified_rate"]),
    reverse=True)

# ----------------------------------------------------------------------
# Defender moves. Costs and multipliers are SYNTHETIC assumptions.
# ----------------------------------------------------------------------

DEFENDER_MOVES: Tuple[str, ...] = (
    "none", "owner_rotation", "burner_wallet", "proxy_hop", "redeploy",
    "timestamp_jitter",
)

# Cost the defender pays for the move (zero-sum: it is added to the
# attacker's payoff, i.e. the defender pays for its own opsec).
MOVE_COST: Dict[str, float] = {
    "none": 0.0,
    "owner_rotation": 0.05,
    "burner_wallet": 0.05,
    "proxy_hop": 0.08,
    "redeploy": 0.15,
    "timestamp_jitter": 0.02,
}

# SYNTHETIC ASSUMPTION. P(a worth-validating finding in this lane is
# still detectable after this opsec move). 1.0 = move does not hide
# this lane at all. Nothing here is measured: no data links opsec
# moves to detection rates. The table encodes the qualitative story:
# owner rotation hides owner-gated lanes (upgrade), burner wallets
# hide recipient lanes (mint), proxy hops hide bridge lanes, redeploy
# hides everything but costs the most (new address breaks linkage),
# timestamp jitter slightly hides math lanes.
EVASION_MULT: Dict[str, Dict[str, float]] = {
    "none":             {lane: 1.0 for lane in LANES},
    "owner_rotation":   {"math": 1.0, "logic": 0.8, "other": 1.0,
                         "upgrade": 0.3, "mint": 1.0, "bridge": 1.0},
    "burner_wallet":    {"math": 0.9, "logic": 1.0, "other": 0.9,
                         "upgrade": 1.0, "mint": 0.5, "bridge": 0.7},
    "proxy_hop":        {"math": 1.0, "logic": 0.9, "other": 1.0,
                         "upgrade": 1.0, "mint": 1.0, "bridge": 0.5},
    "redeploy":         {lane: 0.5 for lane in LANES},
    "timestamp_jitter": {"math": 0.85, "logic": 1.0, "other": 1.0,
                         "upgrade": 1.0, "mint": 1.0, "bridge": 1.0},
}

# Cost of one probe to the attacker (rate-limit / RPC budget).
PROBE_COST = 0.05

# Empirical defender behaviour, from transition_events.jsonl: the ONLY
# opsec move actually observed is the owner flip (52 flips on 11
# watched addresses, Nov 5-14 2026; roughly every watched address
# flipped at least once, in both directions, which is also consistent
# with unreadable owner slots rather than deliberate rotation).
# No redeploy, burner, proxy-hop or timestamp move is observed in the
# data. So the empirical defender mixes only owner_rotation / none,
# 50/50; every other move in the game is modelled, not observed.
EMPIRICAL_DEFENDER: Dict[str, float] = {"owner_rotation": 0.5, "none": 0.5}

DEFAULT_CANDIDATES_PATH = os.path.join(
    os.path.expanduser("~"), "workspace", "recon-continuous", "results",
    "candidates.jsonl")


# ----------------------------------------------------------------------
# Data loading
# ----------------------------------------------------------------------

def load_candidate_rows(path: Optional[str] = None) -> List[Dict]:
    """Load real candidate rows: {plugin, lane, chain, real, address}.

    ``real`` is True when the validator verdict is UNVERIFIED (worth
    validating). FALSE_POSITIVE / TRIGGER_ONLY rows are kept with
    real=False: probing them can never count as a find. The 2
    VERIFIED_REAL rows in the file are already-adjudicated
    simulation-path false positives, so they are dropped, exactly as
    the nn-scorer training data does: there are 0 real verified rows
    to learn from and this module must never predict VERIFIED_REAL.
    """
    path = path or os.environ.get("RECON_CANDIDATES") or DEFAULT_CANDIDATES_PATH
    rows: List[Dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                cand = json.loads(line)
            except ValueError:
                continue
            verdict = (cand.get("validation") or {}).get("verdict")
            if verdict == "VERIFIED_REAL":
                continue
            plugin = cand.get("plugin") or ""
            rows.append({
                "plugin": plugin,
                "lane": PLUGIN_TO_LANE.get(plugin, "other"),
                "chain": cand.get("chain") or "",
                "address": cand.get("address") or "",
                "real": verdict == "UNVERIFIED",
                "verdict": verdict,
            })
    return rows


def lane_stats(rows: Sequence[Dict]) -> Dict[str, Dict[str, float]]:
    """Recompute lane aggregates from rows (checks the embedded table)."""
    total = len(rows)
    out: Dict[str, Dict[str, float]] = {}
    for lane in LANES:
        lane_rows = [r for r in rows if r["lane"] == lane]
        n = len(lane_rows)
        out[lane] = {
            "n": n,
            "prior": (n / total) if total else 0.0,
            "unverified_rate": ((sum(1 for r in lane_rows if r["real"]) / n)
                                if n else 0.0),
        }
    return out


# ----------------------------------------------------------------------
# The evasion game (1 round, for CFR)
# ----------------------------------------------------------------------

class EvasionGame(Game):
    """One round of the evasion game.

    Chance deals a hidden lane L ~ empirical prior. The defender
    (player 1, knows L) picks an opsec move. The attacker (player 0,
    one infoset: knows neither L nor the move) picks a probe lane.
    Chance decides detection: P(detect) = unverified_rate[L] *
    EVASION_MULT[move][L] if the probe hits L, else 0. Payoff to the
    attacker is 1 for a detection, 0 otherwise, minus PROBE_COST,
    plus the defender's move cost (zero-sum pricing of opsec).

    States: ("deal",) -> ("def", lane) -> ("att", lane, move) ->
    ("chance", lane, move, probe) -> ("done", lane, move, probe, det).
    """

    def __init__(self, lanes: Sequence[str] = LANES,
                 lane_stats_: Optional[Dict[str, Dict[str, float]]] = None,
                 evasion_mult: Optional[Dict[str, Dict[str, float]]] = None,
                 move_cost: Optional[Dict[str, float]] = None,
                 probe_cost: float = PROBE_COST) -> None:
        self.lanes = list(lanes)
        self.stats = lane_stats_ or EMPIRICAL_LANES
        self.evasion_mult = evasion_mult or EVASION_MULT
        self.move_cost = move_cost or MOVE_COST
        self.probe_cost = probe_cost

    def detection_prob(self, lane: str, move: str, probe: str) -> float:
        if probe != lane:
            return 0.0
        return (self.stats[lane]["unverified_rate"]
                * self.evasion_mult[move][lane])

    def initial_state(self):
        return ("deal",)

    def is_terminal(self, state) -> bool:
        return state[0] == "done"

    def payoff(self, state) -> float:
        _, _, move, _, detected = state
        return ((1.0 if detected else 0.0)
                - self.probe_cost + self.move_cost[move])

    def player(self, state) -> int:
        kind = state[0]
        if kind in ("deal", "chance"):
            return -1
        if kind == "def":
            return 1
        if kind == "att":
            return 0
        raise ValueError(f"terminal state has no player: {state!r}")

    def actions(self, state) -> List:
        if state[0] == "def":
            return list(DEFENDER_MOVES)
        if state[0] == "att":
            return list(self.lanes)
        raise ValueError(f"no actions for state {state!r}")

    def infoset(self, state, player: int):
        if player == 1:
            return ("D", state[1])  # defender knows its lane
        return ("A",)  # attacker knows nothing: one infoset

    def chance_outcomes(self, state):
        if state[0] == "deal":
            return [(("def", lane), self.stats[lane]["prior"])
                    for lane in self.lanes
                    if self.stats[lane]["prior"] > 0]
        _, lane, move, probe = state
        p = self.detection_prob(lane, move, probe)
        outcomes = []
        if p > 0:
            outcomes.append((("done", lane, move, probe, True), p))
        if p < 1:
            outcomes.append((("done", lane, move, probe, False), 1.0 - p))
        return outcomes

    def apply(self, state, action):
        if state[0] == "def":
            return ("att", state[1], action)
        if state[0] == "att":
            return ("chance", state[1], state[2], action)
        raise ValueError(f"cannot apply an action to {state!r}")


def solve_evasion(iterations: int = 2000) -> Dict:
    """Solve the 1-round evasion game with CFR.

    Returns the attacker's equilibrium probe mix, the defender's
    equilibrium opsec mix per lane, the game value (expected attacker
    payoff per round) and the exploitability of the average profile.
    """
    game = EvasionGame()
    solver = CFR(game)
    solver.train(iterations)
    attacker_mix = solver.average_strategy_full(("A",), LANES)
    defender_mix = {
        lane: solver.average_strategy_full(("D", lane), DEFENDER_MOVES)
        for lane in LANES
    }
    return {
        "iterations": iterations,
        "attacker_mix": attacker_mix,
        "defender_mix": defender_mix,
        "game_value": solver.game_value(),
        "exploitability": solver.exploitability(),
    }


# ----------------------------------------------------------------------
# Replay: what each probe policy would have picked, over the real rows
# ----------------------------------------------------------------------
# NO SIMULATION. The replay is a deterministic counterfactual over
# real candidate rows. Each row is a real finding the scanner already
# produced, with its real verdict. A probe policy is either:
# - an ORDER: a fixed lane sequence (probe lane 1, then 2, ...). The
#   probes needed to reach a row's lane is its 1-based position in
#   the order, or never if the lane is absent. Exact, no sampling.
# - a MIX: a per-probe lane distribution (the CFR equilibrium mix, or
#   uniform for random). Exact geometric expectations are used:
#   P(reach lane L within B probes) = 1 - (1 - q_L)^B, and E[probes
#   spent, capped at B] = sum_{k=0}^{B-1} (1 - q_L)^k. Exact math,
#   no random draws.
# Coverage = share of the REAL worth-validating (UNVERIFIED) rows
# whose lane the policy reaches within the probe budget. Probes spent
# are counted over ALL rows (a false-positive row still costs probes
# to reach its lane; it just never counts as a find). Nothing is
# invented: the rows, lanes and verdicts are real. The only modelled
# quantity is the evasion multiplier, applied as an explicit
# expected-value factor under a named defender scenario and always
# labelled assumption-dependent, because the defender's actual
# per-target move is unobserved in the real data.

REPLAY_POLICIES = ("cfr-mix", "cfr-rank", "static29", "yield", "random")
DEFENDER_SCENARIOS = ("none", "empirical", "cfr")


def cfr_rank_order(solution: Dict) -> List[str]:
    """Lanes ranked by equilibrium mix weight, ties broken by
    expected value (prior * unverified_rate). This is the multi-probe
    reading of the 1-round equilibrium: probe the highest-weight
    lane first, then the next, and so on."""
    mix = solution["attacker_mix"]
    ev = {lane: (EMPIRICAL_LANES[lane]["prior"]
                 * EMPIRICAL_LANES[lane]["unverified_rate"])
          for lane in LANES}
    return sorted(LANES, key=lambda lane: (-mix.get(lane, 0.0),
                                           -ev[lane]))


def make_replay_policy(name: str, solution: Optional[Dict] = None) -> Dict:
    """One replay policy: {"name", "kind", "lanes" | "mix"}."""
    if name == "cfr-mix":
        if solution is None:
            raise ValueError("cfr-mix needs a CFR solution")
        return {"name": name, "kind": "mix",
                "mix": dict(solution["attacker_mix"])}
    if name == "cfr-rank":
        if solution is None:
            raise ValueError("cfr-rank needs a CFR solution")
        return {"name": name, "kind": "order",
                "lanes": cfr_rank_order(solution)}
    if name == "static29":
        return {"name": name, "kind": "order",
                "lanes": list(STATIC29_LANE_ORDER)}
    if name == "yield":
        return {"name": name, "kind": "order",
                "lanes": list(YIELD_LANE_ORDER)}
    if name == "random":
        return {"name": name, "kind": "mix",
                "mix": {lane: 1.0 / len(LANES) for lane in LANES}}
    raise ValueError(f"unknown replay policy {name!r}")


def defender_expected_mult(scenario: str, lane: str,
                           solution: Optional[Dict] = None) -> float:
    """Expected evasion multiplier for one lane under a defender
    scenario. ASSUMPTION-DEPENDENT: the multipliers are modelled,
    not measured, and the defender's actual per-target move is
    unobserved. "none" = no evasion (1.0). "empirical" = the only
    observed move, owner_rotation half the time. "cfr" = the
    equilibrium defender mix for that lane."""
    if scenario == "none":
        return 1.0
    if scenario == "empirical":
        return (EMPIRICAL_DEFENDER.get("owner_rotation", 0.0)
                * EVASION_MULT["owner_rotation"][lane]
                + EMPIRICAL_DEFENDER.get("none", 0.0) * 1.0)
    if scenario == "cfr":
        if solution is None:
            raise ValueError("cfr defender scenario needs a CFR solution")
        mix = solution["defender_mix"][lane]
        return sum(mix.get(move, 0.0) * EVASION_MULT[move][lane]
                   for move in DEFENDER_MOVES)
    raise ValueError(f"unknown defender scenario {scenario!r}")


def replay(rows: Sequence[Dict], policy: Dict, budget: int = 6,
           solution: Optional[Dict] = None) -> Dict:
    """Replay one probe policy over real candidate rows.

    ``rows`` are the real loaded rows (all verdicts). Only UNVERIFIED
    rows can count as finds; every row costs probes to reach its
    lane. Returns coverage of the UNVERIFIED rows, expected finds,
    expected probes, finds per 100 probes, and the same finds figure
    evasion-adjusted under each defender scenario (labelled
    assumption-dependent). Deterministic: the same rows and policy
    always give the same numbers.
    """
    rows = list(rows)
    real_rows = [r for r in rows if r["real"]]
    n_real = len(real_rows)
    found = 0.0
    probes = 0.0
    per_lane: Dict[str, Dict[str, float]] = {
        lane: {"targets": 0, "reached": 0.0} for lane in LANES}
    # Evasion-adjusted finds, one accumulator per defender scenario.
    # The cfr scenario needs a solution; without one it is omitted.
    scenarios = [s for s in DEFENDER_SCENARIOS
                 if s != "cfr" or solution is not None]
    adj_found = {scenario: 0.0 for scenario in scenarios}
    mults = {
        scenario: {
            lane: defender_expected_mult(scenario, lane, solution)
            for lane in LANES}
        for scenario in scenarios}

    def reach_and_spent(lane: str):
        """-> (P(reach lane within budget), E[probes spent])."""
        if policy["kind"] == "order":
            order = policy["lanes"]
            pos = order.index(lane) + 1 if lane in order else None
            if pos is not None and pos <= budget:
                return 1.0, float(pos)
            return 0.0, float(budget)
        q = policy["mix"].get(lane, 0.0)
        reached = 1.0 - (1.0 - q) ** budget
        spent = sum((1.0 - q) ** k for k in range(budget))
        return reached, spent

    for row in rows:
        lane = row["lane"]
        reached, spent = reach_and_spent(lane)
        probes += spent
        if row["real"]:
            per_lane[lane]["targets"] += 1
            per_lane[lane]["reached"] += reached
            found += reached
            for scenario in scenarios:
                adj_found[scenario] += reached * mults[scenario][lane]
    return {
        "policy": policy["name"],
        "budget": budget,
        "n_rows": len(rows),
        "n_real_rows": n_real,
        "coverage": (found / n_real) if n_real else 0.0,
        "expected_finds": found,
        "expected_probes": probes,
        "mean_probes_per_target": (probes / len(rows)) if rows else 0.0,
        "finds_per_100_probes": (100.0 * found / probes) if probes else 0.0,
        "evasion_adjusted": {
            scenario: {
                "expected_finds": adj_found[scenario],
                "finds_per_100_probes": (
                    100.0 * adj_found[scenario] / probes) if probes else 0.0,
            }
            for scenario in scenarios},
        "per_lane": {
            lane: {
                "targets": int(v["targets"]),
                "reached": v["reached"],
                "coverage": (v["reached"] / v["targets"]
                             if v["targets"] else 0.0),
            }
            for lane, v in per_lane.items()},
    }


def evaluate_replay(rows: Optional[Sequence[Dict]] = None,
                    iterations: int = 2000,
                    budgets: Sequence[int] = (1, 3, 6),
                    candidates_path: Optional[str] = None) -> Dict:
    """Headline evaluation: replay the CFR policy against the random
    baseline and the static curated-29 order over the real rows.

    Solves the 1-round evasion game with CFR, then replays every
    policy at each budget. No simulation, no synthetic data: the rows
    are real, the replay is exact. Prints a human-readable table.
    """
    if rows is None:
        rows = load_candidate_rows(candidates_path)
    rows = list(rows)
    n_real = sum(1 for r in rows if r["real"])
    print(f"replay pool: {len(rows)} real candidate rows, "
          f"{n_real} UNVERIFIED (worth validating)")
    print(f"CFR: solving 1-round evasion game ({iterations} iterations)...")
    solution = solve_evasion(iterations)
    print(f"  game value (attacker payoff/round): "
          f"{solution['game_value']:.4f}")
    print(f"  exploitability: {solution['exploitability']:.4f}")
    print("  attacker equilibrium mix: "
          + ", ".join(f"{lane}={p:.3f}"
                      for lane, p in solution["attacker_mix"].items()))
    print("  cfr-rank order: "
          + " > ".join(cfr_rank_order(solution)))
    print("  static29 order: " + " > ".join(STATIC29_LANE_ORDER)
          + " (never reaches math or upgrade)")
    results: Dict = {
        "n_pool_rows": len(rows),
        "n_real_rows": n_real,
        "iterations": iterations,
        "budgets": list(budgets),
        "solution": solution,
        "cells": {},
    }
    for budget in budgets:
        print(f"--- budget {budget} probe(s) per target ---")
        for name in REPLAY_POLICIES:
            policy = make_replay_policy(name, solution)
            cell = replay(rows, policy, budget=budget, solution=solution)
            results["cells"][f"budget{budget}/{name}"] = cell
            print(f"  {name:9s} coverage={cell['coverage']:.3f} "
                  f"finds/100 probes={cell['finds_per_100_probes']:5.2f} "
                  f"mean probes/target={cell['mean_probes_per_target']:.2f} "
                  f"(evasion-adj cfr-defender: "
                  f"{cell['evasion_adjusted']['cfr']['finds_per_100_probes']:.2f})")
    return results


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="MARL evasion game: solve with CFR and replay the "
                    "probe policies over the real candidate rows.")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--budgets", default="1,3,6",
                        help="comma-separated probe budgets")
    parser.add_argument("--candidates", default=None)
    parser.add_argument("--out", default=None,
                        help="write results JSON here")
    args = parser.parse_args(argv)
    budgets = [int(b) for b in args.budgets.split(",") if b.strip()]
    results = evaluate_replay(iterations=args.iterations,
                              budgets=budgets,
                              candidates_path=args.candidates)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
