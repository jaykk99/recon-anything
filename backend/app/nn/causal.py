"""Structural Causal Models (SCMs) and do-calculus for ReconAnything.

Pure Python stdlib, zero new dependencies. This is the causal
counterpart to the correlation-only NN scorers (v1 81-32-16-1,
v2 255-64-32-1): those learn P(label | features); this module learns
and queries P(label | do(X = x)) -- what happens when we *intervene*.

What it implements (Pearl, "Causality", 2nd ed.):
- ``CausalGraph``: a DAG over discrete variables, with d-separation
  (ancestral-graph + moralization algorithm) and graph surgery.
- ``StructuralModel``: a DAG plus a conditional probability table
  (CPT) per node, i.e. one structural equation per variable. CPTs
  are fitted from rows by counting (Laplace smoothing) or set by
  hand for ground-truth / synthetic graphs.
- The do-operator: ``model.intervene({X: x})`` cuts all incoming
  edges to X and clamps X to x (graph surgery), then
  ``interventional_dist`` enumerates the mutilated joint exactly.
- Identification: the back-door criterion. ``identify_effect``
  reports whether P(Y | do(X)) is identified from the graph, and
  the smallest adjustment set when it is. ``estimate_effect``
  applies the adjustment formula to rows.
- Counterfactuals: ``CounterfactualEngine`` does the three steps
  abduction / action / prediction on the twin-network idea, using
  noise-variable (inverse-CDF) structural functions and rejection
  sampling against the observed evidence, with a fixed seed.
- ``build_recon_graph``: the recon-specific graph over findings,
  contracts, owners and implementations, with every assumption
  written down and every unidentifiable effect labelled as such.
- ``predict_backup_infra``: the operator question -- "if this
  owner/server went offline, which backup infra would the operator
  spin up next?" -- answered from the learned mechanism, with an
  explicit confidence and an explicit list of the assumptions the
  answer rests on. When the mechanism is not observed in the data
  it says so (``unidentified``) instead of inventing an answer.

Scope and honesty rules (enforced by the API, not just the docs):
- Detection / triage only. Nothing here predicts VERIFIED_REAL,
  executes an exploit, drains funds, or bypasses auth.
- An effect is only ever reported with its identification status.
  A confounded effect (e.g. plugin -> verdict, confounded by the
  unobserved true vulnerability) is reported as NOT identifiable,
  never silently adjusted away.
- Counterfactual answers always carry their assumptions and a
  confidence; a low-acceptance abduction is reported, not hidden.
"""
from __future__ import annotations

import json
import math
import random
from itertools import combinations, product
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Causal graph (DAG) + d-separation
# ---------------------------------------------------------------------------

# A value is any JSON-able discrete label (str / int / bool / None).
Value = object  # nominal only; concrete values are str/int/bool/None


class CausalGraph:
    """A directed acyclic graph over discrete named variables.

    ``values`` maps each node to its (finite) domain. ``observed``
    marks whether the variable is measured in the data: unobserved
    nodes (e.g. the latent true vulnerability) can still confound
    an effect, and the identification code treats them as
    unadjustable.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, Tuple] = {}
        self.observed: Dict[str, bool] = {}
        self.parents: Dict[str, FrozenSet[str]] = {}
        self.children: Dict[str, FrozenSet[str]] = {}

    # -- construction ---------------------------------------------------
    def add_node(self, name: str, values: Sequence,
                 observed: bool = True) -> "CausalGraph":
        values = tuple(values)
        if not values:
            raise ValueError(f"node {name!r} needs a non-empty domain")
        if len(set(values)) != len(values):
            raise ValueError(f"node {name!r} has duplicate values")
        self.nodes[name] = values
        self.observed[name] = bool(observed)
        self.parents.setdefault(name, frozenset())
        self.children.setdefault(name, frozenset())
        return self

    def add_edge(self, parent: str, child: str) -> "CausalGraph":
        for n in (parent, child):
            if n not in self.nodes:
                raise ValueError(f"unknown node {n!r}")
        if parent == child:
            raise ValueError("self-loops are not allowed")
        self.parents[child] = self.parents[child] | {parent}
        self.children[parent] = self.children[parent] | {child}
        if not self.is_acyclic():
            self.parents[child] = self.parents[child] - {parent}
            self.children[parent] = self.children[parent] - {child}
            raise ValueError(f"edge {parent!r} -> {child!r} would cycle")
        return self

    # -- structure ------------------------------------------------------
    def parents_of(self, node: str) -> Tuple[str, ...]:
        return tuple(sorted(self.parents[node]))

    def children_of(self, node: str) -> Tuple[str, ...]:
        return tuple(sorted(self.children[node]))

    def ancestors_of(self, nodes: Iterable[str]) -> FrozenSet[str]:
        seen = set(nodes)
        stack = list(nodes)
        while stack:
            n = stack.pop()
            for p in self.parents.get(n, ()):
                if p not in seen:
                    seen.add(p)
                    stack.append(p)
        return frozenset(seen)

    def descendants_of(self, nodes: Iterable[str]) -> FrozenSet[str]:
        seen = set(nodes)
        stack = list(nodes)
        while stack:
            n = stack.pop()
            for c in self.children.get(n, ()):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return frozenset(seen)

    def topological_order(self) -> List[str]:
        indeg = {n: len(self.parents[n]) for n in self.nodes}
        ready = sorted(n for n, d in indeg.items() if d == 0)
        order: List[str] = []
        while ready:
            n = ready.pop(0)
            order.append(n)
            for c in self.children[n]:
                indeg[c] -= 1
                if indeg[c] == 0:
                    ready.append(c)
            ready.sort()
        if len(order) != len(self.nodes):
            raise ValueError("graph has a cycle")
        return order

    def is_acyclic(self) -> bool:
        try:
            self.topological_order()
            return True
        except ValueError:
            return False

    # -- d-separation ---------------------------------------------------
    def d_separated(self, x: str, y: str,
                    z: Iterable[str] = ()) -> bool:
        """True iff X and Y are d-separated given Z.

        Ancestral-graph + moralization (Lauritzen et al.): restrict
        to the ancestors of {X, Y} U Z, moralize (marry parents,
        drop directions), delete Z, and test undirected reachability.
        """
        for n in [x, y, *z]:
            if n not in self.nodes:
                raise ValueError(f"unknown node {n!r}")
        zset = frozenset(z)
        anc = self.ancestors_of([x, y, *zset])
        # Undirected adjacency on the ancestral subgraph, moralized.
        adj: Dict[str, set] = {n: set() for n in anc}
        for child in anc:
            ps = [p for p in self.parents[child] if p in anc]
            for p in ps:
                adj[child].add(p)
                adj[p].add(child)
            for a, b in combinations(ps, 2):
                adj[a].add(b)
                adj[b].add(a)
        # Delete the conditioning set, then BFS from X.
        alive = set(anc) - set(zset)
        if x not in alive or y not in alive:
            return True
        seen = {x}
        stack = [x]
        while stack:
            n = stack.pop()
            for m in adj[n]:
                if m in alive and m not in seen:
                    seen.add(m)
                    stack.append(m)
        return y not in seen

    # -- surgery ----------------------------------------------------------
    def mutilate(self, intervention: Dict[str, object]) -> "CausalGraph":
        """Graph surgery for do(X = x): cut every edge into each
        intervened node. Values/domains are unchanged; the
        intervened node's parents are gone, so its distribution
        becomes the point mass set by the intervention."""
        g = CausalGraph()
        for name, values in self.nodes.items():
            g.add_node(name, values, observed=self.observed[name])
        for child, ps in self.parents.items():
            for p in ps:
                if child not in intervention:
                    g.add_edge(p, child)
        return g

    # -- serialization ----------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "nodes": {n: list(v) for n, v in self.nodes.items()},
            "observed": dict(self.observed),
            "edges": sorted(
                (p, c) for c, ps in self.parents.items() for p in ps),
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "CausalGraph":
        g = cls()
        for name, values in d["nodes"].items():
            g.add_node(name, values,
                       observed=d.get("observed", {}).get(name, True))
        for p, c in d["edges"]:
            g.add_edge(p, c)
        return g


# ---------------------------------------------------------------------------
# Structural model: graph + one CPT (structural equation) per node
# ---------------------------------------------------------------------------

# cpts[node] = {parent-value tuple: {value: prob}}; the parent tuple
# follows graph.parents_of(node) order. A node with no parents has
# the single key ().
CPT = Dict[Tuple, Dict[object, float]]


def _coerce_to_domain(value: object, domain: Tuple) -> Optional[object]:
    """Map a raw row value into a node's domain: in-domain values
    pass through, anything else collapses to "other" when the
    domain has one, else None (row skipped for that node)."""
    if value in domain:
        return value
    if "other" in domain:
        return "other"
    return None


def _norm(dist: Dict[object, float]) -> Dict[object, float]:
    total = sum(dist.values())
    if total <= 0:
        raise ValueError("distribution sums to zero")
    return {k: v / total for k, v in dist.items()}


class StructuralModel:
    """A DAG plus a CPT per node.

    Each CPT is the node's structural equation in probabilistic
    form: P(node | parents). Together they define the joint
    distribution by the Markov factorization.
    """

    def __init__(self, graph: CausalGraph,
                 cpts: Dict[str, CPT],
                 fit_counts: Optional[Dict[str, int]] = None) -> None:
        self.graph = graph
        self.cpts = cpts
        # fit_counts[node] = rows the node's CPT was fitted from
        # (absent / None = hand-set structural equation, not data).
        self.fit_counts = dict(fit_counts or {})
        for node in graph.nodes:
            if node not in cpts:
                raise ValueError(f"no CPT for node {node!r}")
            for parent_vals, dist in cpts[node].items():
                if set(dist) != set(graph.nodes[node]):
                    raise ValueError(
                        f"CPT for {node!r} at {parent_vals!r} does not "
                        f"cover its domain {graph.nodes[node]!r}")

    # -- fitting ----------------------------------------------------------
    @classmethod
    def fit(cls, graph: CausalGraph,
            rows: Sequence[Dict[str, object]],
            alpha: float = 1.0) -> "StructuralModel":
        """Fit every observed node's CPT by counting, with Laplace
        smoothing ``alpha``. Rows are dicts node -> value; rows
        missing a node (or its parents) are skipped for that node.
        A value outside the node's domain is coerced to "other"
        when "other" is in the domain (rare plugins/functions
        collapse there); otherwise that row is skipped for the
        node. Unobserved nodes get a uniform CPT (their mechanism
        is not learned from data) and fit count 0."""
        cpts: Dict[str, CPT] = {}
        counts: Dict[str, int] = {}
        for node in graph.topological_order():
            parents = graph.parents_of(node)
            domain = graph.nodes[node]
            table: Dict[Tuple, Dict[object, float]] = {}
            for pv in product(*[graph.nodes[p] for p in parents]) or [()]:
                table[pv] = {v: alpha for v in domain}
            n = 0
            for row in rows:
                value = _coerce_to_domain(row.get(node), domain)
                if value is None:
                    continue
                pv_list = []
                ok = True
                for p in parents:
                    cv = _coerce_to_domain(row.get(p), graph.nodes[p])
                    if cv is None:
                        ok = False
                        break
                    pv_list.append(cv)
                if not ok:
                    continue
                table[tuple(pv_list)][value] += 1.0
                n += 1
            if not graph.observed[node]:
                # Never pretend to have learned an unobserved
                # mechanism from data: uniform, count 0.
                table = {pv: {v: 1.0 / len(domain) for v in domain}
                         for pv in table}
                n = 0
            cpts[node] = {pv: _norm(d) for pv, d in table.items()}
            counts[node] = n
        return cls(graph, cpts, fit_counts=counts)

    # -- joint / sampling ---------------------------------------------------
    def prob(self, assignment: Dict[str, object]) -> float:
        p = 1.0
        for node in self.graph.topological_order():
            pv = tuple(assignment[par] for par in self.graph.parents_of(node))
            p *= self.cpts[node][pv][assignment[node]]
            if p == 0.0:
                return 0.0
        return p

    def sample_one(self, rng: random.Random) -> Dict[str, object]:
        out: Dict[str, object] = {}
        for node in self.graph.topological_order():
            pv = tuple(out[par] for par in self.graph.parents_of(node))
            out[node] = _sample_from(self.cpts[node][pv], rng)
        return out

    def sample(self, rng: random.Random,
               n: int) -> List[Dict[str, object]]:
        return [self.sample_one(rng) for _ in range(n)]

    # -- the do-operator ------------------------------------------------------
    def intervene(self, intervention: Dict[str, object]
                  ) -> "StructuralModel":
        """do(X = x): graph surgery + point-mass CPTs for the
        intervened nodes. Everything downstream is recomputed
        from the mutilated model; nothing upstream changes."""
        for node, value in intervention.items():
            if node not in self.graph.nodes:
                raise ValueError(f"unknown node {node!r}")
            if value not in self.graph.nodes[node]:
                raise ValueError(
                    f"value {value!r} not in domain of {node!r}")
        g2 = self.graph.mutilate(intervention)
        cpts2: Dict[str, CPT] = {}
        for node in g2.nodes:
            if node in intervention:
                v = intervention[node]
                cpts2[node] = {(): {u: 1.0 if u == v else 0.0
                                    for u in g2.nodes[node]}}
            else:
                cpts2[node] = self.cpts[node]
        counts2 = {n: c for n, c in self.fit_counts.items()
                   if n not in intervention}
        return StructuralModel(g2, cpts2, fit_counts=counts2)

    # -- exact distributions by enumeration ------------------------------------
    def _all_assignments(self, max_states: int) -> List[Dict[str, object]]:
        nodes = self.graph.topological_order()
        total = 1
        for n in nodes:
            total *= len(self.graph.nodes[n])
        if total > max_states:
            raise ValueError(
                f"state space {total} exceeds cap {max_states}; "
                f"use the Monte Carlo estimators instead")
        return [dict(zip(nodes, combo))
                for combo in product(*[self.graph.nodes[n] for n in nodes])]

    def distribution(self, target: str,
                     evidence: Optional[Dict[str, object]] = None,
                     max_states: int = 250_000) -> Dict[object, float]:
        """Exact P(target | evidence) by enumeration."""
        evidence = evidence or {}
        out = {v: 0.0 for v in self.graph.nodes[target]}
        total = 0.0
        for a in self._all_assignments(max_states):
            if any(a[k] != v for k, v in evidence.items()):
                continue
            p = self.prob(a)
            out[a[target]] += p
            total += p
        if total <= 0:
            raise ValueError("evidence has probability zero")
        return {k: v / total for k, v in out.items()}

    def interventional_dist(
            self, intervention: Dict[str, object], target: str,
            max_states: int = 250_000) -> Dict[object, float]:
        """Exact P(target | do(intervention)) by enumeration on the
        mutilated model. This is the causal effect, not the
        observational conditional P(target | intervention)."""
        return self.intervene(intervention).distribution(
            target, max_states=max_states)

    def interventional_dist_mc(
            self, intervention: Dict[str, object], target: str,
            n: int = 20_000, seed: int = 0) -> Dict[object, float]:
        """Monte Carlo P(target | do(intervention)) for state spaces
        too big to enumerate. Fixed seed: reproducible."""
        rng = random.Random(seed)
        model = self.intervene(intervention)
        out = {v: 0 for v in self.graph.nodes[target]}
        for _ in range(n):
            out[model.sample_one(rng)[target]] += 1
        return {k: v / n for k, v in out.items()}

    # -- serialization ---------------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "graph": self.graph.to_dict(),
            "cpts": {node: {"|".join(map(repr, pv)): dist
                            for pv, dist in table.items()}
                     for node, table in self.cpts.items()},
            "fit_counts": self.fit_counts,
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> "StructuralModel":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def from_dict(cls, d: Dict) -> "StructuralModel":
        graph = CausalGraph.from_dict(d["graph"])
        cpts: Dict[str, CPT] = {}
        for node, table in d["cpts"].items():
            parents = graph.parents_of(node)
            decoded: CPT = {}
            for key, dist in table.items():
                pv = tuple() if key == "" else tuple(
                    _parse_repr(part)
                    for part in key.split("|"))
                if len(pv) != len(parents):
                    raise ValueError(f"bad CPT key {key!r} for {node!r}")
                decoded[pv] = { _parse_repr(k) if isinstance(k, str) else k: v
                                for k, v in dist.items() }
            cpts[node] = decoded
        return cls(graph, cpts, fit_counts=d.get("fit_counts") or {})


def _parse_repr(text: str) -> object:
    """Inverse of repr() for the small scalar domains we use
    (str / int / bool / None). Falls back to the raw string."""
    if text == "None":
        return None
    if text in ("True", "False"):
        return text == "True"
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        return text[1:-1]
    return text


def _sample_from(dist: Dict[object, float],
                 rng: random.Random) -> object:
    r = rng.random()
    acc = 0.0
    items = sorted(dist.items(), key=lambda kv: str(kv[0]))
    for value, p in items:
        acc += p
        if r < acc:
            return value
    return items[-1][0]


# ---------------------------------------------------------------------------
# Identification: back-door criterion + the adjustment formula
# ---------------------------------------------------------------------------

def _all_simple_paths(graph: CausalGraph, start: str, end: str,
                      max_len: int = 6) -> List[List[str]]:
    """All simple (acyclic) undirected paths start..end."""
    paths: List[List[str]] = []
    stack: List[Tuple[str, List[str]]] = [(start, [start])]
    while stack:
        node, path = stack.pop()
        if node == end and len(path) > 1:
            paths.append(path)
            continue
        if len(path) >= max_len:
            continue
        neighbours = set(graph.parents.get(node, ())) | set(
            graph.children.get(node, ()))
        for m in sorted(neighbours):
            if m not in path:
                stack.append((m, path + [m]))
    return paths


def backdoor_paths(graph: CausalGraph, x: str,
                   y: str) -> List[List[str]]:
    """Paths between X and Y that start with an arrow INTO X --
    the back-door paths, the ones that carry confounding."""
    return [p for p in _all_simple_paths(graph, x, y)
            if len(p) >= 2 and p[1] in graph.parents.get(x, ())]


def _blocks_backdoor(graph: CausalGraph, x: str, y: str,
                     z: FrozenSet[str]) -> bool:
    """Z blocks every back-door path iff Z d-separates X and Y in
    the graph with X's outgoing edges removed (Pearl's
    back-door criterion, graphical form)."""
    g2 = CausalGraph()
    for name, values in graph.nodes.items():
        g2.add_node(name, values, observed=graph.observed[name])
    for child, ps in graph.parents.items():
        for p in ps:
            if p != x:  # drop edges OUT of X
                g2.add_edge(p, child)
    return g2.d_separated(x, y, z)


def find_backdoor_set(graph: CausalGraph, x: str, y: str,
                      max_size: int = 4) -> Optional[FrozenSet[str]]:
    """Smallest set of *observed* non-descendants of X that
    satisfies the back-door criterion, or None. Searched by
    increasing size; the search is exact up to ``max_size``."""
    if x not in graph.nodes or y not in graph.nodes:
        raise ValueError("unknown node")
    forbidden = graph.descendants_of([x]) | {x, y}
    eligible = sorted(n for n in graph.nodes
                      if n not in forbidden and graph.observed[n])
    for size in range(0, max_size + 1):
        for combo in combinations(eligible, size):
            if _blocks_backdoor(graph, x, y, frozenset(combo)):
                return frozenset(combo)
    return None


def identify_effect(graph: CausalGraph, x: str,
                    y: str) -> Dict:
    """Is P(Y | do(X)) identified from this graph?

    Returns {"identifiable": bool, "adjustment_set": [...]|None,
    "reason": str}. Unidentifiable cases name the blocker:
    an unobserved confounder (a back-door path through an
    unobserved node, or a direct unblocked path no observed set
    can close), or a direct X->Y edge with unobserved confounding.
    """
    if x == y:
        return {"identifiable": False, "adjustment_set": None,
                "reason": "X and Y are the same node"}
    z = find_backdoor_set(graph, x, y)
    if z is not None:
        return {"identifiable": True,
                "adjustment_set": sorted(z),
                "reason": ("back-door criterion satisfied by "
                           f"adjusting for {sorted(z) or 'nothing'}")}
    # Diagnose why: is there a back-door path through an unobserved
    # node (latent confounding no adjustment can fix)?
    paths = backdoor_paths(graph, x, y)
    latent = sorted({n for p in paths for n in p
                     if not graph.observed[n]})
    if latent:
        return {"identifiable": False, "adjustment_set": None,
                "reason": ("back-door path(s) run through unobserved "
                           f"node(s) {latent}; no observed adjustment "
                           "set can block them")}
    return {"identifiable": False, "adjustment_set": None,
            "reason": ("no observed set of <=4 non-descendants of "
                       f"{x!r} blocks every back-door path to {y!r}")}


def _cond_table(rows: Sequence[Dict[str, object]],
                target: str, given: Sequence[str],
                alpha: float = 1.0) -> Dict[Tuple, Dict[object, float]]:
    """Empirical P(target | given) with Laplace smoothing."""
    domains: Dict[str, List[object]] = {}
    for col in list(given) + [target]:
        domains[col] = sorted({r[col] for r in rows if col in r
                               and r[col] is not None}, key=str)
    table: Dict[Tuple, Dict[object, float]] = {}
    for key in product(*[domains[c] for c in given]) or [()]:
        table[key] = {v: alpha for v in domains[target]}
    for r in rows:
        if target not in r or r[target] is None:
            continue
        key = tuple(r.get(c) for c in given)
        if any(v not in domains[c]
               for c, v in zip(given, key)):
            continue
        table[key][r[target]] += 1.0
    return {k: _norm(v) for k, v in table.items()}


def raw_conditional(rows: Sequence[Dict[str, object]], x: str,
                    y: str, alpha: float = 1.0) -> Dict[Tuple, Dict]:
    """The correlation-only quantity P(Y | X): what the scorers
    (and any associational model) can see. Kept so the eval can
    show exactly where it diverges from the causal effect."""
    table = _cond_table(rows, y, [x], alpha=alpha)
    return {k: v for k, v in table.items()}


def estimate_effect(rows: Sequence[Dict[str, object]], x: str,
                    y: str, z: Sequence[str],
                    alpha: float = 1.0) -> Dict:
    """Back-door adjustment: P(Y | do(X=x)) =
    sum_z P(Y | X=x, Z=z) P(Z=z), estimated from rows.

    Returns {"estimate": {x_value: {y_value: prob}},
    "n": rows used, "strata": {z-tuple: count}}.
    Only valid when Z satisfies the back-door criterion -- check
    with identify_effect first; this function does the arithmetic,
    not the identification."""
    z = list(z)
    p_y_xz = _cond_table(rows, y, [x, *z], alpha=alpha)
    p_z: Dict[Tuple, float] = {}
    n = 0
    for r in rows:
        key = tuple(r.get(c) for c in z)
        if any(v is None for v in key):
            continue
        p_z[key] = p_z.get(key, 0.0) + 1.0
        n += 1
    if n == 0:
        raise ValueError("no rows with complete Z values")
    p_z = {k: v / n for k, v in p_z.items()}
    x_values = sorted({r[x] for r in rows if x in r
                       and r[x] is not None}, key=str)
    y_values = sorted({r[y] for r in rows if y in r
                       and r[y] is not None}, key=str)
    estimate: Dict[object, Dict[object, float]] = {}
    for xv in x_values:
        acc = {yv: 0.0 for yv in y_values}
        for zt, pz in p_z.items():
            cond = p_y_xz.get((xv, *zt))
            if cond is None:
                continue
            for yv in y_values:
                acc[yv] += pz * cond.get(yv, 0.0)
        estimate[xv] = _norm(acc)
    return {"estimate": estimate, "n": n,
            "strata": {str(k): v for k, v in p_z.items()}}


def average_causal_effect(model: StructuralModel, x: str, y: str,
                          x1: object = 1, x0: object = 0,
                          y1: object = 1) -> float:
    """E[Y=1 | do(X=1)] - E[Y=1 | do(X=0)] on the fitted model."""
    p1 = model.interventional_dist({x: x1}, y)[y1]
    p0 = model.interventional_dist({x: x0}, y)[y1]
    return p1 - p0


# ---------------------------------------------------------------------------
# Counterfactuals: abduction / action / prediction
# ---------------------------------------------------------------------------

class CounterfactualEngine:
    """Twin-network counterfactuals via noise variables.

    Each structural equation is written as a deterministic
    function of its parents plus one exogenous uniform noise
    variable u in [0, 1), using the CPT as an inverse CDF.
    Abduction: rejection-sample noise vectors until the factual
    assignment matches the observed evidence. Action: apply
    do(intervention) to the kept noise vectors (same u, new
    equations downstream). Prediction: read off the target.

    The answer is only as good as the SCM: same noise, same
    mechanism, different intervention. When the evidence is rare
    under the model the acceptance rate collapses and the query
    reports low confidence instead of a confident-looking number.
    """

    def __init__(self, model: StructuralModel, seed: int = 0) -> None:
        self.model = model
        self.seed = seed

    def _structural_value(self, node: str,
                          parent_values: Dict[str, object],
                          u: float) -> object:
        pv = tuple(parent_values[p]
                   for p in self.model.graph.parents_of(node))
        dist = self.model.cpts[node][pv]
        acc = 0.0
        for value in sorted(dist, key=str):
            acc += dist[value]
            if u < acc:
                return value
        return sorted(dist, key=str)[-1]

    def _run_with_noise(self, noise: Dict[str, float],
                        intervention: Optional[Dict[str, object]] = None
                        ) -> Dict[str, object]:
        intervention = intervention or {}
        out: Dict[str, object] = {}
        graph = self.model.graph
        if intervention:
            graph = graph.mutilate(intervention)
        for node in graph.topological_order():
            if node in intervention:
                out[node] = intervention[node]
                continue
            pv = {p: out[p] for p in graph.parents_of(node)}
            out[node] = self._structural_value(node, pv, noise[node])
        return out

    def query(self, evidence: Dict[str, object],
              intervention: Dict[str, object],
              target: str,
              n_samples: int = 20_000,
              min_kept: int = 100) -> Dict:
        """P(target_counterfactual | evidence, do(intervention)).

        Returns {"distribution": {value: prob}, "n_kept": int,
        "n_samples": int, "acceptance": float, "confidence": str,
        "assumptions": [str, ...]}. ``confidence`` is "high" /
        "medium" / "low" from the acceptance count; it is about
        the computation, not about whether the SCM itself is right
        -- that is listed under "assumptions" instead.
        """
        if target not in self.model.graph.nodes:
            raise ValueError(f"unknown target {target!r}")
        for node in evidence:
            if node not in self.model.graph.nodes:
                raise ValueError(f"unknown evidence node {node!r}")
        rng = random.Random(self.seed)
        nodes = self.model.graph.topological_order()
        dist = {v: 0 for v in self.model.graph.nodes[target]}
        kept = 0
        for _ in range(n_samples):
            noise = {n: rng.random() for n in nodes}
            factual = self._run_with_noise(noise)
            if any(factual[k] != v for k, v in evidence.items()):
                continue
            kept += 1
            counter = self._run_with_noise(noise, intervention)
            dist[counter[target]] += 1
        if kept < min_kept:
            return {
                "distribution": None,
                "n_kept": kept,
                "n_samples": n_samples,
                "acceptance": kept / n_samples,
                "confidence": "unidentified",
                "assumptions": [
                    "Abduction failed: only "
                    f"{kept} of {n_samples} noise draws matched the "
                    "evidence, below the minimum "
                    f"{min_kept}. The counterfactual is not "
                    "computable from this model + evidence; "
                    "collect more evidence or loosen it.",
                ],
            }
        probs = {k: v / kept for k, v in dist.items()}
        if kept >= 500:
            confidence = "high"
        elif kept >= 200:
            confidence = "medium"
        else:
            confidence = "low"
        return {
            "distribution": probs,
            "n_kept": kept,
            "n_samples": n_samples,
            "acceptance": kept / n_samples,
            "confidence": confidence,
            "assumptions": [
                "The SCM's graph and CPTs are correct (causal "
                "sufficiency: no unobserved confounder between "
                "the intervened node and the target).",
                "The noise variables are exogenous and invariant: "
                "the same unit, same noise, under the "
                "intervention (the twin-network assumption).",
                "The intervention is surgical: do() changes only "
                "the intervened node; every other mechanism "
                "stays as fitted.",
                f"Monte Carlo error at n_kept={kept} is about "
                f"+/-{1.96 * math.sqrt(0.25 / kept):.3f} on a "
                "probability (95% interval, worst case).",
            ],
        }


# ---------------------------------------------------------------------------
# The recon graph: findings, contracts, owners, implementations
# ---------------------------------------------------------------------------

# Verdict -> triage label, copied from the NN scorer's data.py
# (same rule, so causal and NN numbers are comparable).
# 1 = worth-validating (UNVERIFIED), 0 = likely false positive
# (FALSE_POSITIVE / TRIGGER_ONLY). VERIFIED_REAL rows are excluded:
# the two in the data are already-adjudicated simulation-path
# false positives, so the real verified count is 0.
VERDICT_LABELS = {
    "UNVERIFIED": 1,
    "FALSE_POSITIVE": 0,
    "TRIGGER_ONLY": 0,
    "VERIFIED_REAL": None,
}

RECON_ASSUMPTIONS = [
    "CHAIN shapes which plugins fire: scanner coverage and the "
    "target mix differ by chain (bsc dominates the candidate set), "
    "so CHAIN confounds PLUGIN -> WORTH_VALIDATING.",
    "PLUGIN determines which FUNCTION it flags and which "
    "RECIPIENT_CLASS it reports; those are read-outs of the same "
    "finding, not independent causes.",
    "LATENT_VULN is the unobserved true vulnerability. It causes "
    "both the plugin firing and the validator's verdict, so the "
    "PLUGIN -> WORTH_VALIDATING effect is NOT identifiable from "
    "candidate rows alone: no adjustment set can block a path "
    "through an unobserved node.",
    "LIVE_PROBE outcome depends on the latent vulnerability and "
    "on transport (most probes fail with transport_error), not "
    "directly on the plugin label.",
    "OWNER_CHANGE is an observed intervention on the contract: "
    "the owner actually changed. NEXT_OWNER is what it changed "
    "to (renounced/null vs a new address). No implementation "
    "change was observed in the transition data (0 rows), "
    "so the OWNER_CHANGE -> IMPLEMENTATION edge has no fitted "
    "mechanism and is left out rather than invented.",
    "BACKUP_INFRA is the infra the operator would spin up next "
    "if the owner/server went offline. It is unobserved in this "
    "data (no follow-on deployment is recorded after any flip), "
    "so its mechanism is unidentified: the counterfactual query "
    "for it must return 'unidentified', never a made-up answer.",
    "crypto.com is never a target and never appears in this data.",
    "This graph is triage-only: it never predicts VERIFIED_REAL.",
]


def build_recon_graph(candidates: Optional[Sequence[Dict]] = None,
                      transitions: Optional[Sequence[Dict]] = None
                      ) -> Tuple[CausalGraph, List[str]]:
    """The recon SCM's graph. ``candidates`` / ``transitions``
    (when given) only set the observed value domains -- e.g. the
    plugin list actually seen -- never the edges. Edges are the
    domain assumptions listed in RECON_ASSUMPTIONS."""
    candidates = list(candidates or [])
    transitions = list(transitions or [])
    chains = sorted({(c.get("chain") or "other") for c in candidates}
                    or {"bsc", "ethereum", "base", "arbitrum",
                        "polygon", "other"})
    plugins = sorted({(c.get("plugin") or "other") for c in candidates}
                     or {"other"})
    if len(plugins) > 12:
        top = [p for p, _ in _top_counts(candidates, "plugin", 11)]
        plugins = sorted(top + ["other"])
    functions = sorted({(c.get("function") or "other")
                        for c in candidates} or {"other"})
    if len(functions) > 12:
        top = [f for f, _ in _top_counts(candidates, "function", 11)]
        functions = sorted(top + ["other"])
    recipients = sorted({(c.get("recipient_class") or "other")
                         for c in candidates}
                        or ["CALLER", "CALLER-SUPPLIED", "OTHER"])

    g = CausalGraph()
    g.add_node("chain", chains)
    g.add_node("plugin", plugins)
    g.add_node("function", functions)
    g.add_node("recipient_class", recipients)
    g.add_node("latent_vuln", [0, 1], observed=False)
    g.add_node("worth_validating", [0, 1])
    g.add_node("live_probe",
               ["success", "revert", "transport_error", "other"])
    g.add_node("owner_change", [0, 1])
    g.add_node("next_owner", ["renounced", "new_owner", "unchanged"])
    g.add_node("backup_infra", ["none", "secondary", "new", "unknown"],
               observed=False)
    # Structure (see RECON_ASSUMPTIONS for why each edge exists).
    g.add_edge("chain", "plugin")
    g.add_edge("chain", "owner_change")
    g.add_edge("plugin", "function")
    g.add_edge("plugin", "recipient_class")
    g.add_edge("latent_vuln", "plugin")
    g.add_edge("latent_vuln", "worth_validating")
    g.add_edge("latent_vuln", "live_probe")
    g.add_edge("plugin", "worth_validating")
    g.add_edge("owner_change", "next_owner")
    g.add_edge("chain", "next_owner")
    g.add_edge("owner_change", "backup_infra")
    notes = list(RECON_ASSUMPTIONS)
    ident = identify_effect(g, "plugin", "worth_validating")
    notes.append(
        "Identification check, PLUGIN -> WORTH_VALIDATING: "
        f"identifiable={ident['identifiable']}. {ident['reason']}")
    ident2 = identify_effect(g, "owner_change", "next_owner")
    notes.append(
        "Identification check, OWNER_CHANGE -> NEXT_OWNER: "
        f"identifiable={ident2['identifiable']}. {ident2['reason']}")
    return g, notes


def _top_counts(rows: Sequence[Dict], key: str,
                k: int) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for r in rows:
        v = r.get(key) or "other"
        counts[v] = counts.get(v, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:k]


def predict_backup_infra(model: StructuralModel,
                         evidence: Dict[str, object],
                         offline_node: str = "owner_change",
                         offline_value: object = 1,
                         target: str = "next_owner",
                         n_samples: int = 20_000,
                         seed: int = 0,
                         min_mechanism_rows: int = 30) -> Dict:
    """"If this owner/server went offline, which backup infra
    would the operator spin up next?"

    A counterfactual query on the learned mechanism:
    do(offline_node = offline_value), read off ``target``. The
    answer is only returned when the mechanism is actually
    observed in the data: the target's CPT must have been fitted
    from at least ``min_mechanism_rows`` rows. Otherwise the
    result is ``prediction: None`` with confidence
    "unidentified" and the reason spelled out -- an invented
    backup-infra prediction would be worse than none.

    On the real transition data (52 owner flips, 0 implementation
    changes) the backup-infra mechanism is unobserved, so this
    returns unidentified. On a graph whose mechanism is known
    (e.g. the synthetic operator SCM in the tests / eval) it
    returns the real distribution.
    """
    fit_n = model.fit_counts.get(target)
    if fit_n is None or fit_n < min_mechanism_rows:
        return {
            "prediction": None,
            "confidence": "unidentified",
            "n_samples": 0,
            "n_kept": 0,
            "assumptions": [
                f"The {target!r} mechanism was fitted from "
                f"{fit_n} rows (need >= {min_mechanism_rows}). "
                "No backup-infra behaviour is observed in the "
                "data, so no prediction is made.",
                "What would identify it: observed follow-on "
                "events after an owner/server goes offline "
                "(new implementation deployed, new owner set, "
                "or renouncement), recorded per contract.",
            ],
        }
    engine = CounterfactualEngine(model, seed=seed)
    out = engine.query(evidence, {offline_node: offline_value},
                       target, n_samples=n_samples)
    return {
        "prediction": out["distribution"],
        "confidence": out["confidence"],
        "n_samples": out["n_samples"],
        "n_kept": out["n_kept"],
        "assumptions": out["assumptions"] + [
            "Intervention is do("
            f"{offline_node}={offline_value!r}): the operator's "
            "offline event is set, everything else follows "
            "the fitted mechanism.",
        ],
    }
