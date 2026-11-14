"""Active Inference & the Free Energy Principle for ReconAnything triage.

Replaces the scanner's static queue order (runner.py QUEUE_PRIORITY:
fresh first, then transitions, legacy, zeroday_tail, bytecode,
market_deep, bnb_tier3, keyword_search) with an information-gain loop.

Generative model
---------------
Each contract has a hidden binary state S in {worth-validating, FP}:
"worth-validating" means a live probe would promote it to an
UNVERIFIED candidate (the only label the triage model ever predicts;
this module never predicts VERIFIED_REAL). The agent holds two
linked beliefs:

- q = P(S = worth), the decision probability. It starts at the
  prior mean and updates by exact binary Bayes on every
  observation, using the query's likelihood ratio. Promote/drop
  thresholds apply to q.
- a Beta distribution over theta, the population parameter behind
  q, on a fixed grid (default 101 points). It starts at the prior
  Beta and updates with the mixture likelihood
  P(obs | theta) = theta * P(obs | S=worth)
  + (1 - theta) * P(obs | S=FP). It carries the parameter
  uncertainty used for the variational free-energy accounting.

The prior mean comes from the contract's queue base rate plus a
stake adjustment (both fit on the fit-half of history, see
backend/docs/nn-active-inference.md); the prior strength is shrunk
when data is missing (unknown symbol/stake, no verified source,
unknown owner, unprobed lanes), so missing data widens the belief
and raises its entropy.

Queries
-------
A query is one recon observation with a cost (probe-units) and a
binary likelihood model P(fire | S): sensitivity P(fire | worth)
and false-positive rate P(fire | FP), fit on the fit-half. Six lane
queries (cheap, partial information) plus one full-contract probe
(cost 1.0, reveals S exactly). Every candidate query gets:

- Expected Information Gain (EIG): expected reduction of the
  decision entropy H(q), E[H(q)] - E_obs[H(q | obs)].
- Expected free energy G = -EIG + lambda * cost - reward *
  P(promote after the query). The loop fires the query with the
  highest EIG per unit cost (equivalently the lowest G per cost at
  lambda = 1); a pure-EIG ranking would always fire the full probe,
  so cost enters through G. See docs for the derivation.

After each observation the belief updates by exact Bayes, and the
variational free energy F[q] = KL(q || prior) - E_q[log p(obs |
theta)] over the theta-posterior is available for inspection. A
contract is promoted when q crosses PROMOTE_Q (0.85) and dropped
when it falls below DROP_Q (0.05); both are parameters.

Drop-in for the scanner (branch module only, live scanner untouched):

    from app.nn.active_inference import pick_next_contract
    nxt = pick_next_contract(contracts)   # contracts: list of dicts
    # nxt = {"contract": {...}, "query": "arithmetic_guards",
    #        "eig_bits": ..., "eig_per_cost": ...,
    #        "expected_free_energy": ...}

The live scanner must persist beliefs between runs (a belief is
state, not a pure function of the contract row); that persistence
is NOT built here.

Pure Python stdlib. Detection only: queries are read-only
observations (plugin reads / eth_calls). No transactions, no
drains, no exploit execution, no auth bypass, no private data.
crypto.com is never a target (enforced by the caller's target
filter, as everywhere else in the scanner).
"""
from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# ------------------------------------------------------------------
# Constants fit on the fit-half of history (see docs).
# Split: md5(chain:address) % 2 == 0, 2,344 addresses, 274 worth.
# ------------------------------------------------------------------

# Static order this loop replaces (runner.py QUEUE_PRIORITY).
STATIC_QUEUE_ORDER = ["fresh", "transitions", "legacy", "zeroday_tail",
                      "bytecode", "market_deep", "bnb_tier3",
                      "keyword_search"]

# Queue base rates, shrinkage k=20 toward the global fit-half rate
# 0.117: (worth + 20*0.117) / (n + 20).
QUEUE_PRIOR = {
    "fresh": 0.0101,
    "transitions": 0.1170,
    "legacy": 0.0856,
    "zeroday_tail": 0.0814,
    "bytecode": 0.0355,
    "market_deep": 0.0101,
    "bnb_tier3": 0.1598,
    "keyword_search": 0.1271,
}
GLOBAL_PRIOR = 0.117
PRIOR_STRENGTH = 20.0  # Beta pseudo-count; also the shrinkage k above.

# Stake effect, 1-D grid search on the fit-half (loglik -730.6 vs
# -767.1 queue-only): worth-validating contracts have LOWER stake.
STAKE_BETA = -0.25
STAKE_MEAN_LOG = 2.12  # mean log10(stake_usd + 1) on the fit-half.

# Decision thresholds on q = P(worth-validating).
PROMOTE_Q = 0.85
DROP_Q = 0.05

# Query costs in probe-units: a full contract probe is 1.0 (the unit
# the static/random baselines spend per contract); one lane read is
# 0.1 (one plugin-group read vs the ~29-plugin curated set).
LANE_COST = 0.1
FULL_PROBE_COST = 1.0

GRID_N = 101  # theta grid points in [0, 1]


# ------------------------------------------------------------------
# Small numeric helpers
# ------------------------------------------------------------------

def clip_prob(p: float) -> float:
    """Clip into (1e-9, 1-1e-9) so logs stay finite."""
    return min(max(float(p), 1e-9), 1.0 - 1e-9)


def logit(p: float) -> float:
    p = clip_prob(p)
    return math.log(p / (1.0 - p))


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


def binary_entropy(p: float) -> float:
    """Shannon entropy of a Bernoulli(p) in bits."""
    p = float(p)
    if p <= 0.0 or p >= 1.0:
        return 0.0
    p = clip_prob(p)
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))


def _digamma(x: float) -> float:
    """Digamma psi(x) for x > 0: recurrence down to x >= 6, then the
    asymptotic expansion. Accurate to ~1e-9, stdlib only."""
    if x <= 0:
        raise ValueError("digamma needs x > 0")
    result = 0.0
    while x < 6.0:
        result -= 1.0 / x
        x += 1.0
    inv = 1.0 / x
    inv2 = inv * inv
    result += (math.log(x) - 0.5 * inv
               - inv2 * (1.0 / 12.0 - inv2 * (1.0 / 120.0
                                              - inv2 * (1.0 / 252.0))))
    return result


def beta_differential_entropy(alpha: float, beta: float) -> float:
    """Differential entropy of Beta(alpha, beta) in bits.

    H = ln B(a,b) - (a-1) psi(a) - (b-1) psi(b) + (a+b-2) psi(a+b),
    in nats; converted to bits. Beta(1, 1) (uniform) is 0 bits.
    """
    if alpha <= 0 or beta <= 0:
        raise ValueError("Beta params must be positive")
    lbeta = (math.lgamma(alpha) + math.lgamma(beta)
             - math.lgamma(alpha + beta))
    h_nats = (lbeta - (alpha - 1.0) * _digamma(alpha)
              - (beta - 1.0) * _digamma(beta)
              + (alpha + beta - 2.0) * _digamma(alpha + beta))
    return h_nats / math.log(2.0)


def beta_grid(alpha: float, beta: float,
              n: int = GRID_N) -> Tuple[List[float], List[float]]:
    """Beta(alpha, beta) evaluated on a uniform theta grid in [0, 1],
    normalised to weights summing to 1. Endpoints use the limit of
    the density (0 unless the exponent is 0)."""
    thetas = [i / (n - 1) for i in range(n)]
    log_norm = (math.lgamma(alpha) + math.lgamma(beta)
                - math.lgamma(alpha + beta))
    weights: List[float] = []
    for t in thetas:
        if t == 0.0:
            w = 0.0 if alpha > 1.0 else (1.0 if alpha == 1.0 else float("inf"))
        elif t == 1.0:
            w = 0.0 if beta > 1.0 else (1.0 if beta == 1.0 else float("inf"))
        else:
            w = math.exp((alpha - 1.0) * math.log(t)
                         + (beta - 1.0) * math.log(1.0 - t) - log_norm)
        weights.append(w)
    total = sum(weights)
    if total <= 0.0 or not math.isfinite(total):
        # Degenerate prior (e.g. alpha or beta huge at an endpoint):
        # fall back to a point mass at the mean.
        mean = alpha / (alpha + beta)
        idx = min(range(n), key=lambda i: abs(thetas[i] - mean))
        weights = [0.0] * n
        weights[idx] = 1.0
        return thetas, weights
    return thetas, [w / total for w in weights]


# ------------------------------------------------------------------
# Queries
# ------------------------------------------------------------------

@dataclass(frozen=True)
class Query:
    """One recon observation.

    ``sens`` = P(fire | worth), ``fpr`` = P(fire | FP). ``kind``
    is "lane" (cheap partial read) or "full_probe" (reveals S).
    A full probe is modelled as sens=1, fpr=0: a positive outcome
    means the validator promoted the contract, a negative one that
    it did not.
    """
    name: str
    kind: str  # "lane" | "full_probe"
    cost: float
    sens: float
    fpr: float

    def outcome_likelihoods(self, outcome: str) -> Tuple[float, float]:
        """(P(outcome | S=worth), P(outcome | S=FP))."""
        if outcome == "positive":
            return self.sens, self.fpr
        return 1.0 - self.sens, 1.0 - self.fpr

    def theta_likelihoods(self, thetas: Sequence[float],
                          outcome: str) -> List[float]:
        """P(outcome | theta) per grid point: theta*sens +
        (1-theta)*fpr for a positive outcome, and the complement
        for a negative one."""
        l1, l0 = self.outcome_likelihoods(outcome)
        return [t * l1 + (1.0 - t) * l0 for t in thetas]


# Lane likelihoods fit on the fit-half (sens/fpr, see docs). A lane
# "fires" when any plugin in its group fired on the contract in the
# historical batch. recipient_probe is near-useless (sens 0.035):
# it is kept with its honest numbers so the loop learns to skip it.
DEFAULT_QUERIES: Tuple[Query, ...] = (
    Query("source_verification", "lane", LANE_COST, 0.987, 0.823),
    Query("recipient_probe", "lane", LANE_COST, 0.035, 0.042),
    Query("gate_analysis", "lane", LANE_COST, 0.889, 0.237),
    Query("bytecode_deep", "lane", LANE_COST, 0.995, 0.820),
    Query("proxy_impl", "lane", LANE_COST, 0.998, 0.822),
    Query("arithmetic_guards", "lane", LANE_COST, 0.929, 0.230),
    Query("full_probe", "full_probe", FULL_PROBE_COST, 1.0, 0.0),
)

QUERY_BY_NAME: Dict[str, Query] = {q.name: q for q in DEFAULT_QUERIES}


# ------------------------------------------------------------------
# Belief: decision probability q plus a Beta grid over theta
# ------------------------------------------------------------------

class Belief:
    """Belief about one contract.

    ``q`` is the decision probability P(S = worth). ``thetas`` /
    ``weights`` is the Beta grid posterior over the parameter theta.
    ``prior_weights`` is the theta-grid before the latest
    observation (for the variational free-energy computation).
    """

    def __init__(self, thetas: Sequence[float],
                 weights: Sequence[float], q: float,
                 prior_weights: Optional[Sequence[float]] = None) -> None:
        self.thetas = list(thetas)
        self.weights = list(weights)
        self.q = clip_prob(q)
        self.prior_weights = (list(prior_weights) if prior_weights
                              is not None else list(weights))

    @classmethod
    def from_beta(cls, alpha: float, beta: float,
                  n: int = GRID_N) -> "Belief":
        thetas, weights = beta_grid(alpha, beta, n)
        return cls(thetas, weights, alpha / (alpha + beta))

    @classmethod
    def from_mean(cls, mean: float, strength: float = PRIOR_STRENGTH,
                  n: int = GRID_N) -> "Belief":
        mean = clip_prob(mean)
        return cls.from_beta(strength * mean, strength * (1.0 - mean), n)

    @property
    def mean(self) -> float:
        """Decision probability q = P(worth-validating)."""
        return self.q

    @property
    def theta_mean(self) -> float:
        """Posterior mean of the parameter theta."""
        return sum(w * t for w, t in zip(self.weights, self.thetas))

    @property
    def entropy(self) -> float:
        """Decision entropy H(q) in bits: the uncertainty the loop
        is trying to reduce."""
        return binary_entropy(self.q)

    @property
    def theta_entropy(self) -> float:
        """Shannon entropy of the discretised theta posterior, bits."""
        h = 0.0
        for w in self.weights:
            if w > 0.0:
                h -= w * math.log2(w)
        return h

    def copy(self) -> "Belief":
        return Belief(self.thetas, self.weights, self.q,
                      self.prior_weights)

    def _theta_update(self, likelihoods: Sequence[float]) -> float:
        """Bayes update of the theta grid. Returns log-evidence."""
        self.prior_weights = list(self.weights)
        unnorm = [w * l for w, l in zip(self.weights, likelihoods)]
        evidence = sum(unnorm)
        if evidence <= 0.0 or not math.isfinite(evidence):
            return float("-inf")
        self.weights = [u / evidence for u in unnorm]
        return math.log(evidence)

    def update(self, query: Query, outcome: str) -> float:
        """Apply one observation. Updates q by binary Bayes with
        the query's likelihood ratio and the theta grid with the
        mixture likelihood. Returns the theta log-evidence."""
        l1, l0 = query.outcome_likelihoods(outcome)
        p_obs = self.q * l1 + (1.0 - self.q) * l0
        if p_obs > 0.0:
            self.q = clip_prob(self.q * l1 / p_obs)
        log_ev = self._theta_update(
            query.theta_likelihoods(self.thetas, outcome))
        return log_ev

    def posterior_after(self, query: Query, outcome: str) -> "Belief":
        """What update() would produce, without mutating this belief."""
        nxt = self.copy()
        nxt.update(query, outcome)
        return nxt

    def free_energy(self, likelihoods: Sequence[float]) -> float:
        """Variational free energy F over the theta posterior after
        an observation with per-grid-point likelihoods, against the
        stored prior:

            F = KL(q || prior) - E_q[log p(obs | theta)]

        F >= -log p(obs), with equality when q is the exact posterior
        (then F is the negative log-evidence / surprise), in bits.
        """
        kl = 0.0
        exp_loglik = 0.0
        for q, p, l in zip(self.weights, self.prior_weights, likelihoods):
            if q > 0.0:
                if p <= 0.0:
                    return float("inf")
                kl += q * math.log(q / p)
                exp_loglik += q * math.log(max(l, 1e-300))
        return (kl - exp_loglik) / math.log(2.0)  # nats -> bits


# ------------------------------------------------------------------
# EIG and expected free energy
# ------------------------------------------------------------------

def expected_information_gain(belief: Belief, query: Query) -> float:
    """EIG in bits: H(q) - E_obs[H(q | obs)], where q is the decision
    probability and the outcome probabilities come from q and the
    query's (sens, fpr)."""
    h0 = belief.entropy
    expected_h = 0.0
    for outcome in ("positive", "negative"):
        l1, l0 = query.outcome_likelihoods(outcome)
        p_obs = belief.q * l1 + (1.0 - belief.q) * l0
        if p_obs <= 0.0:
            continue
        q_post = belief.q * l1 / p_obs
        expected_h += p_obs * binary_entropy(q_post)
    return h0 - expected_h


def expected_free_energy(belief: Belief, query: Query,
                         cost_weight: float = 1.0,
                         reward: float = 0.0,
                         promote_q: float = PROMOTE_Q) -> float:
    """Expected free energy G in bits:

        G = -EIG + lambda * cost - reward * P(promote after query)

    The first term is the epistemic value (information gain), the
    second the expected free-energy cost of acting, the third an
    optional pragmatic term (expected log-preference for resolving
    the contract as worth-validating). With reward=0 the loop
    minimises -EIG + lambda*cost, i.e. maximises information per
    unit of free-energy cost.
    """
    eig = expected_information_gain(belief, query)
    p_promote = 0.0
    if reward:
        for outcome in ("positive", "negative"):
            l1, l0 = query.outcome_likelihoods(outcome)
            p_obs = belief.q * l1 + (1.0 - belief.q) * l0
            if p_obs <= 0.0:
                continue
            if belief.q * l1 / p_obs >= promote_q:
                p_promote += p_obs
    return -eig + cost_weight * query.cost - reward * p_promote


def score_query(belief: Belief, query: Query,
                cost_weight: float = 1.0,
                reward: float = 0.0) -> Dict[str, float]:
    """All ranking numbers for one (belief, query) pair."""
    eig = expected_information_gain(belief, query)
    return {
        "eig_bits": eig,
        "cost": query.cost,
        "eig_per_cost": eig / query.cost if query.cost > 0 else float("inf"),
        "expected_free_energy": expected_free_energy(
            belief, query, cost_weight=cost_weight, reward=reward),
    }


# ------------------------------------------------------------------
# Priors from contract rows, and the scorer hook
# ------------------------------------------------------------------

def missing_data_score(contract: Dict) -> float:
    """Fraction of the belief-relevant data that is missing, 0..1.

    Counts: symbol unknown, stake unknown, source unverified /
    unknown, owner unknown, and the share of the six lanes still
    unprobed. Missing data widens the prior (lower strength), which
    raises entropy and therefore EIG: the loop is drawn to the
    contracts it knows least about, all else equal.
    """
    checks = [
        not contract.get("symbol"),
        contract.get("stake_usd") is None,
        not contract.get("source_verified"),
        not contract.get("owner_known"),
    ]
    probed = contract.get("probed_lanes") or []
    checks.append(1.0 - len(set(probed)) / (len(DEFAULT_QUERIES) - 1))
    return sum(1.0 if c else 0.0 for c in checks) / len(checks)


def prior_for_contract(contract: Dict) -> Tuple[float, float, float]:
    """(pi, alpha, beta) prior for a contract row.

    pi = sigmoid(logit(queue rate) + STAKE_BETA *
    (log10(stake+1) - STAKE_MEAN_LOG)); strength shrinks with
    missing data: kappa = PRIOR_STRENGTH * (1 - 0.5*missing).
    Unknown queue falls back to GLOBAL_PRIOR.
    """
    queue = (contract.get("queue") or "").strip()
    base = QUEUE_PRIOR.get(queue, GLOBAL_PRIOR)
    stake = contract.get("stake_usd")
    try:
        log_stake = math.log10(1.0 + float(stake)) if stake is not None else STAKE_MEAN_LOG
    except (TypeError, ValueError):
        log_stake = STAKE_MEAN_LOG
    pi = sigmoid(logit(base) + STAKE_BETA * (log_stake - STAKE_MEAN_LOG))
    missing = missing_data_score(contract)
    strength = PRIOR_STRENGTH * (1.0 - 0.5 * missing)
    return pi, strength * pi, strength * (1.0 - pi)


def belief_from_scorer(pi: float, p_score: float,
                       strength: float = PRIOR_STRENGTH) -> Belief:
    """Combine a prior mean pi with a scorer output p_score (the v1/v2
    network's P(worth-validating) for the contract's best finding).

    Log-odds pooling: posterior odds = prior odds * scorer odds,
    i.e. the scorer is treated as one calibrated observation that is
    independent of the prior given S. This is an approximation: the
    scorer was trained on the same plugin outputs the lanes read,
    so its errors correlate with the lanes'. The replay does not use
    this path (findings only exist after a probe); unit tests cover
    the pooling arithmetic.
    """
    q = sigmoid(logit(pi) + logit(p_score))
    return Belief.from_mean(q, strength)


# ------------------------------------------------------------------
# Contract state + the loop
# ------------------------------------------------------------------

@dataclass
class ContractState:
    """One queued contract under active inference."""
    contract_id: str
    contract: Dict
    belief: Belief
    probed: List[str] = field(default_factory=list)
    status: str = "open"  # open | promoted | dropped
    cost_spent: float = 0.0
    log_evidence: float = 0.0
    free_energy: Optional[float] = None

    @property
    def q(self) -> float:
        return self.belief.mean

    @property
    def uncertainty(self) -> float:
        """Decision entropy (bits) plus the missing-data bonus, in
        bits. The bonus is 0.5 bits at fully-missing, 0 at
        fully-known."""
        return (self.belief.entropy
                + 0.5 * missing_data_score(self.contract))


class ActiveInferenceLoop:
    """The information-gain loop over a queue of contracts.

    At each step it fires the (contract, query) pair with the
    highest EIG per unit cost among open contracts, updates that
    contract's belief with the observation, and promotes/drops the
    contract when q crosses a threshold. EIG values are cached per
    contract and recomputed only when that contract's belief changes
    (heap + version stamps).
    """

    def __init__(self, contracts: Sequence[Dict],
                 queries: Sequence[Query] = DEFAULT_QUERIES,
                 promote_q: float = PROMOTE_Q, drop_q: float = DROP_Q,
                 cost_weight: float = 1.0, reward: float = 0.0,
                 score_fn: Optional[Callable[[Dict], Optional[float]]] = None
                 ) -> None:
        self.queries = {q.name: q for q in queries}
        self.promote_q = promote_q
        self.drop_q = drop_q
        self.cost_weight = cost_weight
        self.reward = reward
        self.states: Dict[str, ContractState] = {}
        self._versions: Dict[str, int] = {}
        self._heap: List[Tuple[float, int, str, str]] = []
        self.spent = 0.0
        self.trace: List[Dict] = []
        for c in contracts:
            cid = contract_id(c)
            pi, alpha, beta = prior_for_contract(c)
            p_score = score_fn(c) if score_fn else None
            if p_score is not None:
                belief = belief_from_scorer(pi, p_score)
            else:
                belief = Belief.from_beta(alpha, beta)
            self.states[cid] = ContractState(cid, dict(c), belief)
            self._versions[cid] = 0
            self._push_candidates(cid)

    # -- candidate ranking -----------------------------------------
    def _push_candidates(self, cid: str) -> None:
        st = self.states[cid]
        if st.status != "open":
            return
        for name, query in self.queries.items():
            if name in st.probed:
                continue
            s = score_query(st.belief, query,
                            cost_weight=self.cost_weight,
                            reward=self.reward)
            heapq.heappush(self._heap,
                           (-s["eig_per_cost"], self._versions[cid],
                            cid, name))

    def pick_next(self, max_cost: Optional[float] = None) -> Optional[Dict]:
        """Highest-EIG-per-cost (contract, query) among open contracts,
        or None when nothing is left to probe. With ``max_cost``,
        pairs dearer than the remaining budget are held aside and
        re-queued, so a cheap lane query can still fire when a full
        probe no longer fits."""
        held: List[Tuple[float, int, str, str]] = []
        found = None
        while self._heap:
            neg_eig, version, cid, qname = heapq.heappop(self._heap)
            st = self.states.get(cid)
            if st is None or st.status != "open":
                continue
            if version != self._versions[cid]:
                continue  # stale: belief changed since this was scored
            query = self.queries[qname]
            if max_cost is not None and query.cost > max_cost:
                held.append((neg_eig, version, cid, qname))
                continue
            s = score_query(st.belief, query,
                            cost_weight=self.cost_weight,
                            reward=self.reward)
            found = {"contract_id": cid, "contract": st.contract,
                     "query": qname, "query_kind": query.kind,
                     "eig_bits": s["eig_bits"], "cost": query.cost,
                     "eig_per_cost": s["eig_per_cost"],
                     "expected_free_energy": s["expected_free_energy"],
                     "q_before": st.q,
                     "uncertainty_bits": st.uncertainty}
            break
        for entry in held:
            heapq.heappush(self._heap, entry)
        return found

    # -- observation + belief update -------------------------------
    def observe(self, contract_id: str, query_name: str,
                outcome: str) -> ContractState:
        """Apply one observation ("positive"/"negative") to a
        contract's belief. Returns the updated state."""
        st = self.states[contract_id]
        query = self.queries[query_name]
        log_ev = st.belief.update(query, outcome)
        st.free_energy = st.belief.free_energy(
            query.theta_likelihoods(st.belief.thetas, outcome))
        if log_ev != float("-inf"):
            st.log_evidence += log_ev
        st.cost_spent += query.cost
        self.spent += query.cost
        if query_name not in st.probed:
            st.probed.append(query_name)
        if st.q >= self.promote_q:
            st.status = "promoted"
        elif st.q <= self.drop_q:
            st.status = "dropped"
        self._versions[contract_id] += 1
        self._push_candidates(contract_id)
        return st

    def run(self, observation_fn: Callable[[Dict, str], Optional[str]],
            budget: float) -> Dict:
        """Drive the loop until the probe budget is spent or every
        contract is promoted/dropped. ``observation_fn(contract,
        query_name)`` returns "positive"/"negative" (or None to skip
        that pair without spending). Returns a summary dict."""
        while self.spent < budget:
            nxt = self.pick_next(max_cost=budget - self.spent)
            if nxt is None:
                break
            outcome = observation_fn(nxt["contract"], nxt["query"])
            if outcome is None:
                break
            before = nxt["q_before"]
            st = self.observe(nxt["contract_id"], nxt["query"], outcome)
            self.trace.append({
                "contract_id": nxt["contract_id"], "query": nxt["query"],
                "outcome": outcome, "cost": nxt["cost"],
                "q_before": before, "q_after": st.q,
                "status": st.status,
                "eig_bits": nxt["eig_bits"],
                "free_energy_bits": st.free_energy,
            })
        return self.summary()

    def summary(self) -> Dict:
        states = list(self.states.values())
        promoted = [s for s in states if s.status == "promoted"]
        dropped = [s for s in states if s.status == "dropped"]
        open_states = [s for s in states if s.status == "open"]
        h0 = sum(binary_entropy(prior_for_contract(s.contract)[0])
                 for s in states)
        h1 = sum(s.belief.entropy for s in states)
        return {
            "contracts": len(states),
            "promoted": len(promoted),
            "dropped": len(dropped),
            "open": len(open_states),
            "probe_units_spent": round(self.spent, 2),
            "queries_fired": len(self.trace),
            "entropy_before_bits": round(h0, 2),
            "entropy_after_bits": round(h1, 2),
            "entropy_reduction_bits": round(h0 - h1, 2),
            "entropy_reduction_per_probe_unit":
                round((h0 - h1) / self.spent, 4) if self.spent else 0.0,
            "promoted_ids": [s.contract_id for s in promoted],
            "dropped_ids": [s.contract_id for s in dropped],
        }


def contract_id(contract: Dict) -> str:
    """Stable id for a contract row: chain:address (lowercased)."""
    chain = (contract.get("chain") or "").strip().lower()
    addr = (contract.get("address") or "").strip().lower()
    return f"{chain}:{addr}"


def pick_next_contract(contracts: Sequence[Dict],
                       queries: Sequence[Query] = DEFAULT_QUERIES,
                       promote_q: float = PROMOTE_Q,
                       drop_q: float = DROP_Q,
                       cost_weight: float = 1.0,
                       reward: float = 0.0,
                       score_fn: Optional[Callable[[Dict], Optional[float]]] = None,
                       beliefs: Optional[Dict[str, Belief]] = None
                       ) -> Optional[Dict]:
    """Drop-in for the scanner: given the current queue (list of
    contract dicts with chain/address/queue/stake_usd/symbol, plus
    optional source_verified / owner_known / probed_lanes), return
    the single next (contract, query) the loop would fire, with its
    EIG and expected free energy. Returns None when the queue is
    empty or every contract is already promoted/dropped.

    ``beliefs`` optionally carries persisted Belief objects keyed by
    contract_id from a previous run; without it every contract
    starts from its prior. The caller owns persistence.
    """
    loop = ActiveInferenceLoop(contracts, queries=queries,
                               promote_q=promote_q, drop_q=drop_q,
                               cost_weight=cost_weight, reward=reward,
                               score_fn=score_fn)
    if beliefs:
        for cid, belief in beliefs.items():
            if cid in loop.states:
                loop.states[cid].belief = belief
                loop._versions[cid] += 1
                loop._push_candidates(cid)
    return loop.pick_next()


def pick_next_contracts(contracts: Sequence[Dict], k: int = 1,
                        **kwargs) -> List[Dict]:
    """Batch form of pick_next_contract: the top-k (contract, query)
    pairs by EIG per cost, without firing any of them. The pairs are
    distinct contracts (a contract appears at most once)."""
    loop = ActiveInferenceLoop(contracts, **kwargs)
    out: List[Dict] = []
    seen: set = set()
    while len(out) < k:
        nxt = loop.pick_next()
        if nxt is None:
            break
        if nxt["contract_id"] in seen:
            continue
        seen.add(nxt["contract_id"])
        out.append(nxt)
    return out
