"""Counterfactual Regret Minimization (CFR) for two-player zero-sum games.

Pure Python stdlib. No dependencies. The engine is game-agnostic: any
game that implements the small interface below (``Game``) can be solved
for an approximate Nash equilibrium, and its exploitability can be
measured exactly by best response.

Games implemented here:
- ``KuhnPoker``: 3-card Kuhn poker, the standard CFR sanity check.
  Known game value for player 0 is -1/18.
- ``MatrixGame``: a simultaneous-move matrix game (player 0 picks a
  row, player 1 picks a column without seeing the row). Rock-paper-
  scissors is the canonical test: the unique equilibrium is uniform.

The evasion game for ReconAnything lives in ``marl.py`` and uses the
same interface, so it is solved by the same code that is validated
against Kuhn poker and RPS here.

Vanilla CFR with regret matching. Average strategies are accumulated
with reach weighting, which is what the equilibrium guarantees are
about: the average strategy profile converges to Nash as iterations
grow, and exploitability (computed by exact best response) measures
how far away it is.
"""
from __future__ import annotations

import random
from typing import Dict, Hashable, List, Optional, Sequence, Tuple

Action = Hashable
Infoset = Hashable
State = Hashable


class Game:
    """Interface a game must implement for the CFR engine.

    ``player(state)`` returns 0 or 1 for a decision node, -1 for a
    chance node. ``payoff(state)`` is the zero-sum payoff to player 0
    at a terminal state. Chance nodes expose their outcomes with
    probabilities; decision nodes expose actions and the acting
    player's infoset key (states the player cannot distinguish share
    one key: that is what makes the game imperfect-information).
    """

    def initial_state(self) -> State:
        raise NotImplementedError

    def is_terminal(self, state: State) -> bool:
        raise NotImplementedError

    def payoff(self, state: State) -> float:
        raise NotImplementedError

    def player(self, state: State) -> int:
        raise NotImplementedError

    def actions(self, state: State) -> List[Action]:
        raise NotImplementedError

    def infoset(self, state: State, player: int) -> Infoset:
        raise NotImplementedError

    def chance_outcomes(self, state: State) -> List[Tuple[State, float]]:
        raise NotImplementedError

    def apply(self, state: State, action: Action) -> State:
        raise NotImplementedError


def _regret_matched(regrets: Dict[Action, float],
                    actions: Sequence[Action]) -> Dict[Action, float]:
    """Regret matching: play actions in proportion to positive regret.

    All regrets non-positive -> uniform (no reason to prefer any move).
    """
    pos = {a: max(0.0, regrets.get(a, 0.0)) for a in actions}
    total = sum(pos.values())
    if total <= 0.0:
        return {a: 1.0 / len(actions) for a in actions}
    return {a: pos[a] / total for a in actions}


class CFR:
    """Vanilla CFR solver for a two-player zero-sum game."""

    def __init__(self, game: Game) -> None:
        self.game = game
        self.regrets: Dict[Infoset, Dict[Action, float]] = {}
        self.avg_strategy: Dict[Infoset, Dict[Action, float]] = {}
        self.avg_weight: Dict[Infoset, float] = {}
        self.iterations = 0

    # -- strategy access -------------------------------------------------
    def _current_strategy(self, infoset: Infoset,
                          actions: Sequence[Action]) -> Dict[Action, float]:
        regrets = self.regrets.setdefault(infoset, {})
        return _regret_matched(regrets, actions)

    def average_strategy(self, infoset: Infoset) -> Dict[Action, float]:
        """Reach-weighted average strategy at an infoset (the equilibrium
        estimate). Empty dict if the infoset was never visited."""
        strat = self.avg_strategy.get(infoset)
        if not strat:
            return {}
        total = self.avg_weight.get(infoset, 0.0)
        if total <= 0.0:
            return dict(strat)
        return {a: w / total for a, w in strat.items()}

    def average_strategy_full(self, infoset: Infoset,
                              actions: Sequence[Action]) -> Dict[Action, float]:
        """Average strategy with every action present (zeros filled)."""
        strat = self.average_strategy(infoset)
        if not strat:
            return {a: 1.0 / len(actions) for a in actions}
        return {a: strat.get(a, 0.0) for a in actions}

    # -- training --------------------------------------------------------
    def train(self, iterations: int = 1000) -> None:
        for _ in range(iterations):
            self._cfr(self.game.initial_state(), 1.0, 1.0)
            self.iterations += 1

    def _cfr(self, state: State, reach0: float, reach1: float) -> float:
        """Counterfactual value of ``state`` (payoff to player 0)."""
        game = self.game
        if game.is_terminal(state):
            return game.payoff(state)
        player = game.player(state)
        if player == -1:  # chance node: expectation over outcomes.
            # The chance probability folds into BOTH players' reaches:
            # counterfactual regret weights a node by the opponent's
            # reach INCLUDING chance. Without this, a rare lane and a
            # common lane would count the same (this was a real bug:
            # the evasion game stalled at value 0.227 with the
            # attacker over-probing the logic lane, while pure math
            # guarantees 0.385). The returned value is still the plain
            # expectation; reaches only feed the regret weights.
            value = 0.0
            for next_state, prob in game.chance_outcomes(state):
                value += prob * self._cfr(next_state, reach0 * prob,
                                          reach1 * prob)
            return value
        actions = game.actions(state)
        infoset = game.infoset(state, player)
        strategy = self._current_strategy(infoset, actions)
        # Counterfactual utilities of each action (player-0 payoff).
        utils: Dict[Action, float] = {}
        node_value = 0.0
        for action in actions:
            if player == 0:
                child_reach0 = reach0 * strategy[action]
                child_reach1 = reach1
            else:
                child_reach0 = reach0
                child_reach1 = reach1 * strategy[action]
            utils[action] = self._cfr(game.apply(state, action),
                                      child_reach0, child_reach1)
            node_value += strategy[action] * utils[action]
        # Regret update. Player 1 maximises -payoff, so its regret has
        # the opposite sign. Reach of the opponent is the counterfactual
        # weight: how likely the opponent is to let this infoset happen.
        sign = 1.0 if player == 0 else -1.0
        opp_reach = reach1 if player == 0 else reach0
        regrets = self.regrets.setdefault(infoset, {})
        for action in actions:
            regrets[action] = (regrets.get(action, 0.0)
                               + opp_reach * sign * (utils[action] - node_value))
        # Average-strategy accumulation, weighted by the player's own
        # reach (how likely the player is to reach this infoset).
        own_reach = reach0 if player == 0 else reach1
        avg = self.avg_strategy.setdefault(infoset, {})
        for action in actions:
            avg[action] = avg.get(action, 0.0) + own_reach * strategy[action]
        self.avg_weight[infoset] = (self.avg_weight.get(infoset, 0.0)
                                    + own_reach)
        return node_value

    # -- evaluation ------------------------------------------------------
    def game_value(self) -> float:
        """Expected payoff to player 0 when both play their average
        strategies (exact, by full tree traversal)."""
        return _expected_value(self.game, self.game.initial_state(),
                               self._avg_lookup)

    def _avg_lookup(self, infoset: Infoset, player: int,
                    actions: Sequence[Action]) -> Dict[Action, float]:
        return self.average_strategy_full(infoset, actions)

    def exploitability(self) -> float:
        """How much the two players could gain by deviating to a best
        response against the opponent's average strategy. Zero at an
        exact Nash equilibrium. Computed exactly by best response."""
        avg0 = self._avg_lookup
        br0 = _best_response_value(self.game, avg0, 0)
        br1 = _best_response_value(self.game, avg0, 1)
        value = self.game_value()
        # Player 0 gains br0 - value by deviating; player 1 gains
        # value - br1 (its payoff is -payoff, so its best response
        # minimises the player-0 payoff).
        return (br0 - value) + (value - br1)


def _expected_value(game: Game, state: State, lookup) -> float:
    """Expected player-0 payoff under fixed per-infoset strategies."""
    if game.is_terminal(state):
        return game.payoff(state)
    player = game.player(state)
    if player == -1:
        return sum(prob * _expected_value(game, s2, lookup)
                   for s2, prob in game.chance_outcomes(state))
    actions = game.actions(state)
    strategy = lookup(game.infoset(state, player), player, actions)
    return sum(strategy.get(a, 0.0)
               * _expected_value(game, game.apply(state, a), lookup)
               for a in actions)


def _best_response_value(game: Game, opp_lookup, player: int) -> float:
    """Player-0 payoff when ``player`` best-responds and the opponent
    plays the fixed strategies from ``opp_lookup``.

    A best response must pick ONE action per infoset, not one per
    node: the responder cannot condition on things it cannot observe
    (e.g. in rock-paper-scissors player 1 cannot pick a different
    column per row). So this works with counterfactual values: for
    each responder infoset, sum over its nodes the opponent+chance
    reach times the subtree value of each action, with deeper
    infosets already fixed to their best actions (perfect recall
    means deeper infosets are decided first). The best action is the
    argmax (player 0) or argmin (player 1) of that sum, since the
    responder's own reach to the infoset is a common factor across
    its actions. The final value is the expected payoff with both
    sides fixed.
    """
    # Pass 1: collect responder infosets, their nodes, and the
    # opponent+chance reach of each node. Branch all responder
    # actions with weight 1 (the responder's own reach is factored
    # out of counterfactual values).
    infoset_nodes: Dict[Infoset, List[Tuple[State, float, int]]] = {}
    infoset_actions: Dict[Infoset, List[Action]] = {}

    def collect(state: State, reach: float, depth: int) -> None:
        if game.is_terminal(state):
            return
        acting = game.player(state)
        if acting == -1:
            for next_state, prob in game.chance_outcomes(state):
                collect(next_state, reach * prob, depth)
            return
        actions = game.actions(state)
        if acting == player:
            infoset = game.infoset(state, player)
            infoset_nodes.setdefault(infoset, []).append(
                (state, reach, depth))
            infoset_actions[infoset] = list(actions)
            for action in actions:
                collect(game.apply(state, action), reach, depth + 1)
        else:
            strategy = opp_lookup(game.infoset(state, acting), acting,
                                  actions)
            for action in actions:
                prob = strategy.get(action, 0.0)
                if prob > 0:
                    collect(game.apply(state, action), reach * prob,
                            depth)

    collect(game.initial_state(), 1.0, 0)

    # Pass 2: decide infosets deepest-first.
    best_action: Dict[Infoset, Action] = {}

    def subtree_value(state: State) -> float:
        """Expected player-0 payoff from ``state`` with the opponent
        fixed and the responder playing already-decided best actions
        at deeper infosets."""
        if game.is_terminal(state):
            return game.payoff(state)
        acting = game.player(state)
        if acting == -1:
            return sum(prob * subtree_value(s2)
                       for s2, prob in game.chance_outcomes(state))
        actions = game.actions(state)
        if acting == player:
            infoset = game.infoset(state, player)
            action = best_action[infoset]
            return subtree_value(game.apply(state, action))
        strategy = opp_lookup(game.infoset(state, acting), acting,
                              actions)
        return sum(strategy.get(a, 0.0)
                   * subtree_value(game.apply(state, a))
                   for a in actions)

    ordered = sorted(infoset_nodes.items(),
                     key=lambda kv: -max(depth for _, _, depth in kv[1]))
    for infoset, nodes in ordered:
        actions = infoset_actions[infoset]
        scored = {}
        for action in actions:
            total = 0.0
            for node_state, reach, _ in nodes:
                total += reach * subtree_value(
                    game.apply(node_state, action))
            scored[action] = total
        if player == 0:
            best_action[infoset] = max(actions, key=lambda a: scored[a])
        else:
            best_action[infoset] = min(actions, key=lambda a: scored[a])

    # Pass 3: expected value with the responder fixed to its best
    # actions and the opponent fixed.
    def fixed_lookup(infoset: Infoset, acting: int,
                     actions: Sequence[Action]) -> Dict[Action, float]:
        if acting == player:
            return {a: (1.0 if a == best_action[infoset] else 0.0)
                    for a in actions}
        return opp_lookup(infoset, acting, actions)

    return _expected_value(game, game.initial_state(), fixed_lookup)


# ----------------------------------------------------------------------
# Reference games
# ----------------------------------------------------------------------

class KuhnPoker(Game):
    """3-card Kuhn poker. Cards J=0, Q=1, K=2. Each antes 1.

    Player 0 moves first (check/bet). If player 0 bets, player 1 may
    call or fold. If player 0 checks, player 1 may check or bet; if
    player 1 bets, player 0 may call or fold. Showdown: high card
    wins the pot. Known game value for player 0 is -1/18.
    """

    CARDS = (0, 1, 2)

    def initial_state(self) -> State:
        return ("deal",)

    def is_terminal(self, state: State) -> bool:
        if state[0] != "play":
            return False
        history = state[3]
        return history in (("check", "check"), ("bet", "call"),
                           ("bet", "fold"), ("check", "bet", "call"),
                           ("check", "bet", "fold"))

    def payoff(self, state: State) -> float:
        cards, history = state[1], state[3]
        # Contributions: ante 1 each, plus 1 per bet/call made.
        bets = {"check": 0, "bet": 1, "call": 1, "fold": 0}
        contrib = [1, 1]
        for i, action in enumerate(history):
            contrib[i % 2] += bets[action]
        if history[-1] == "fold":
            # Folder is the player who made the last move; the other
            # player takes the pot.
            folder = (len(history) - 1) % 2
            winner = 1 - folder
        else:
            winner = 0 if cards[0] > cards[1] else 1
        pot = sum(contrib)
        return float(pot - contrib[0]) if winner == 0 else float(-contrib[0])

    def player(self, state: State) -> int:
        if state[0] == "deal":
            return -1
        if self.is_terminal(state):
            raise ValueError("terminal state has no player")
        return len(state[3]) % 2

    def actions(self, state: State) -> List[Action]:
        history = state[3]
        if not history:
            return ["check", "bet"]
        if history == ("bet",):
            return ["call", "fold"]
        if history == ("check",):
            return ["check", "bet"]
        if history == ("check", "bet"):
            return ["call", "fold"]
        raise ValueError(f"no actions for history {history!r}")

    def infoset(self, state: State, player: int) -> Infoset:
        return (player, state[1][player], state[3])

    def chance_outcomes(self, state: State) -> List[Tuple[State, float]]:
        outcomes = []
        for c0 in self.CARDS:
            for c1 in self.CARDS:
                if c0 != c1:
                    outcomes.append((("play", (c0, c1), 0, ()), 1.0 / 6.0))
        return outcomes

    def apply(self, state: State, action: Action) -> State:
        kind, cards, turn, history = state
        return ("play", cards, turn + 1, history + (action,))


class MatrixGame(Game):
    """Simultaneous-move matrix game. Player 0 picks a row, player 1
    picks a column without seeing the row. Payoff is the matrix entry
    (player-0 payoff)."""

    def __init__(self, matrix: Sequence[Sequence[float]]) -> None:
        self.matrix = [[float(v) for v in row] for row in matrix]
        self.n_rows = len(self.matrix)
        self.n_cols = len(self.matrix[0]) if self.matrix else 0

    def initial_state(self) -> State:
        return ("row", None, None)

    def is_terminal(self, state: State) -> bool:
        return state[0] == "done"

    def payoff(self, state: State) -> float:
        return self.matrix[state[1]][state[2]]

    def player(self, state: State) -> int:
        if state[0] == "row":
            return 0
        if state[0] == "col":
            return 1
        raise ValueError("terminal state has no player")

    def actions(self, state: State) -> List[Action]:
        if state[0] == "row":
            return list(range(self.n_rows))
        return list(range(self.n_cols))

    def infoset(self, state: State, player: int) -> Infoset:
        # Player 1's infoset does NOT include player 0's row: that is
        # what makes the moves simultaneous.
        return ("P0",) if player == 0 else ("P1",)

    def chance_outcomes(self, state: State) -> List[Tuple[State, float]]:
        raise ValueError("matrix game has no chance nodes")

    def apply(self, state: State, action: Action) -> State:
        if state[0] == "row":
            return ("col", action, None)
        return ("done", state[1], action)


def rock_paper_scissors() -> MatrixGame:
    """RPS payoff matrix (player-0 payoff). Unique equilibrium: uniform."""
    return MatrixGame([
        [0.0, -1.0, 1.0],
        [1.0, 0.0, -1.0],
        [-1.0, 1.0, 0.0],
    ])


def solve(game: Game, iterations: int = 1000,
          seed: Optional[int] = None) -> CFR:
    """Solve a game with CFR and return the trained solver.

    CFR itself is deterministic (no sampling); ``seed`` is accepted
    for API symmetry with the simulator and ignored.
    """
    del seed
    solver = CFR(game)
    solver.train(iterations)
    return solver
