"""Topological Data Analysis (TDA) features over contract call graphs.

Pure Python stdlib, no new dependencies. Persistent-homology-style
summaries of the call graph a finding's target was measured with:

- Betti-0 style: connected components and their size distribution,
  via union-find over the graph's edges.
- Betti-1 style: cycle counts and cycle-length distribution, via a
  spanning forest: every non-tree edge closes exactly one cycle, and
  its length is the tree path between its endpoints plus one.
- Filtration: grow the graph by edge weight (call depth: 1 = direct
  callee, 2 = second hop, ...) and track when components merge and
  cycles are born. Each component merge is a persistence pair
  (born 0, dies at the merge weight); each cycle birth is recorded
  with death = infinity. The summary is a small set of persistence
  statistics, not the full diagram.

Homology here is over the UNDERLYING UNDIRECTED graph: call graphs
are directed (caller -> callee), but Betti numbers are a property of
the undirected shape. Direction is preserved only in the edge weight
(call depth), which the filtration reads.

Where the graph comes from (in priority order):
1. finding["call_graph"]: a dict attached by the caller. Shapes:
   - {"edges": [[u, v], [u, v, w], {"from": u, "to": v, "weight": w}]}
   - {"call_edges": [{"from_fn": fn, "to_addr": addr, ...}]} (the
     multihop call-graph plugin's extract_call_edges shape; an edge
     runs from the target's function to the callee address, weight 1
     unless the record carries a hop/depth number)
   - {"callees": N, "callee_layers": [...]} (the deep-layer coverage
     record: a star, target -> N callee nodes, weight 1)
   - {"nodes": [...], "edges": [...]} (explicit node list + edges)
2. finding["evidence"]["depth"]: the same deep-layer record as a
   JSON string (how the batch rows store it) or a dict.
3. Proxy / implementation: evidence proxy_address ->
   implementation_address is one edge (weight 1), merged into
   whatever graph the above produced.
4. Nothing: the empty graph. All features read 0 and
   tda:graph_present reads 0, so the network can tell "no graph was
   measured" apart from "a graph was measured and it is trivial".
   A depth record with callees == 0 is NOT empty: it is one node
   (the target) with no edges, graph_present = 1.

Triage only: these features describe the SHAPE of a target's call
graph. They never verify anything and never predict VERIFIED_REAL.
"""
from __future__ import annotations

import json
import math
from collections import deque
from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- graphs

Node = str
Edge = Tuple[Node, Node, float]


class CallGraph:
    """Undirected weighted graph. Nodes are strings (addresses,
    function names, or synthetic "callee:i" labels). Edge weight is
    call depth (1.0 = direct callee)."""

    def __init__(self) -> None:
        self.nodes: set = set()
        self._edges: Dict[Tuple[Node, Node], float] = {}

    def add_node(self, node: Node) -> None:
        self.nodes.add(str(node))

    def add_edge(self, u: Node, v: Node, weight: float = 1.0) -> None:
        u, v = str(u), str(v)
        self.nodes.add(u)
        self.nodes.add(v)
        try:
            w = float(weight)
        except (TypeError, ValueError):
            w = 1.0
        if not (math.isfinite(w) and w > 0):
            w = 1.0
        key = (u, v) if u <= v else (v, u)
        # Duplicate edge: keep the smallest weight (earliest hop).
        if key not in self._edges or w < self._edges[key]:
            self._edges[key] = w

    @property
    def edges(self) -> List[Edge]:
        return [(u, v, w) for (u, v), w in sorted(self._edges.items())]

    def adjacency(self) -> Dict[Node, List[Tuple[Node, float]]]:
        adj: Dict[Node, List[Tuple[Node, float]]] = {n: [] for n in self.nodes}
        for (u, v), w in self._edges.items():
            adj[u].append((v, w))
            if u != v:
                adj[v].append((u, w))
        return adj

    def __len__(self) -> int:
        return len(self.nodes)


def _as_float(value, default: float = 1.0) -> float:
    try:
        w = float(value)
    except (TypeError, ValueError):
        return default
    return w if (math.isfinite(w) and w > 0) else default


def _parse_json_maybe(value):
    """A dict passes through; a JSON string is parsed; anything else
    yields None. Never raises."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def parse_depth_record(value) -> Optional[Dict]:
    """The deep-layer coverage record: {"call_graph": "ran",
    "callees": N, "callee_layers": [...], "storage": ...}. Returns
    {"callees": int, "callee_layers": [...]} or None."""
    rec = _parse_json_maybe(value)
    if rec is None:
        return None
    callees = rec.get("callees")
    if not isinstance(callees, int) or isinstance(callees, bool):
        try:
            callees = int(callees)
        except (TypeError, ValueError):
            return None
    layers = rec.get("callee_layers") or []
    if not isinstance(layers, list):
        layers = []
    return {"callees": max(0, callees),
            "callee_layers": [str(x) for x in layers]}


def _add_edge_record(graph: CallGraph, edge, target: str) -> None:
    """One edge in any accepted shape. `target` is the node used
    when the record names only one endpoint (a bare callee)."""
    if isinstance(edge, (list, tuple)):
        if len(edge) == 2:
            graph.add_edge(edge[0], edge[1], 1.0)
        elif len(edge) >= 3:
            graph.add_edge(edge[0], edge[1], _as_float(edge[2]))
        return
    if isinstance(edge, dict):
        u = (edge.get("from") or edge.get("from_fn") or edge.get("src")
             or edge.get("caller"))
        v = (edge.get("to") or edge.get("to_addr") or edge.get("dst")
             or edge.get("callee") or edge.get("to_address"))
        w = _as_float(edge.get("weight", edge.get("hop",
                      edge.get("depth", 1.0))))
        if u is None and v is not None:
            u = target
        if v is None and u is not None:
            v = target
        if u is not None and v is not None:
            graph.add_edge(u, v, w)
        return
    if isinstance(edge, str):
        graph.add_edge(target, edge, 1.0)


def build_graph(finding: Dict, target: Optional[str] = None) -> CallGraph:
    """Build the call graph for one finding dict. See the module
    docstring for the sources, in priority order."""
    graph = CallGraph()
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    target = target or str(
        finding.get("address") or ev.get("address") or "target")
    present = False

    # 1. An attached call_graph record (train path: data.py stamps
    # the target's deep-layer / multihop record; live path: score.py
    # stamps the record from the run's own call-graph finding).
    record = finding.get("call_graph")
    if isinstance(record, dict):
        present = True
        nodes = record.get("nodes")
        if isinstance(nodes, list):
            for n in nodes:
                graph.add_node(n)
        edges = record.get("edges") or record.get("call_edges") or []
        if isinstance(edges, list):
            for e in edges:
                _add_edge_record(graph, e, target)
        callees = record.get("callees")
        if isinstance(callees, int) and not isinstance(callees, bool):
            graph.add_node(target)
            for i in range(max(0, callees)):
                graph.add_edge(target, f"callee:{i}", 1.0)
        # A record with no edges and no callees still counts as a
        # measured graph: the target alone.
        if not graph.nodes:
            graph.add_node(target)

    # 2. The depth record in the finding's own evidence (the
    # cross_contract_call_graph finding itself carries it).
    if not present:
        depth = parse_depth_record(ev.get("depth"))
        if depth is not None:
            present = True
            graph.add_node(target)
            for i in range(depth["callees"]):
                graph.add_edge(target, f"callee:{i}", 1.0)

    # 3. Proxy -> implementation is one real edge; merge it in.
    proxy = ev.get("proxy_address")
    impl = ev.get("implementation_address")
    if proxy and impl:
        present = True
        graph.add_edge(str(proxy), str(impl), 1.0)
    if present and not graph.nodes:
        graph.add_node(target)
    return graph


# ------------------------------------------------------- union-find (H0)

class _UnionFind:
    def __init__(self, nodes: Sequence[Node]) -> None:
        self.parent = {n: n for n in nodes}
        self.size = {n: 1 for n in nodes}

    def find(self, x: Node) -> Node:
        parent = self.parent
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(self, a: Node, b: Node) -> Optional[Node]:
        """Merge the sets of a and b. Returns the surviving root, or
        None when they were already one set."""
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return None
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]
        return ra

    def components(self) -> List[List[Node]]:
        groups: Dict[Node, List[Node]] = {}
        for n in self.parent:
            groups.setdefault(self.find(n), []).append(n)
        return list(groups.values())


# ------------------------------------------------------------- Betti numbers

def betti_numbers(graph: CallGraph) -> Dict:
    """beta0 = # connected components (union-find).
    beta1 = cyclomatic number E - V + beta0, realised as explicit
    cycles: build a spanning forest (BFS), and for every non-tree
    edge the cycle length is the tree distance between its endpoints
    plus one. A self-loop is a cycle of length 1."""
    nodes = list(graph.nodes)
    edges = graph.edges
    uf = _UnionFind(nodes)
    tree_adj: Dict[Node, List[Node]] = {n: [] for n in nodes}
    non_tree: List[Edge] = []
    self_loops = 0
    for u, v, _w in edges:
        if u == v:
            self_loops += 1
            continue
        if uf.union(u, v) is not None:
            tree_adj[u].append(v)
            tree_adj[v].append(u)
        else:
            non_tree.append((u, v, _w))
    components = uf.components()
    beta0 = len(components)
    cycle_lengths: List[int] = [1] * self_loops
    for u, v, _w in non_tree:
        cycle_lengths.append(_tree_distance(tree_adj, u, v) + 1)
    beta1 = len(cycle_lengths)
    # E - V + beta0 must agree with the explicit count (self-loops
    # included: each contributes 1 to E and 1 to beta1).
    assert beta1 == len(edges) - len(nodes) + beta0, (
        f"cycle count {beta1} != E-V+b0 "
        f"{len(edges)}-{len(nodes)}+{beta0}")
    return {
        "beta0": beta0,
        "beta1": beta1,
        "components": components,
        "cycle_lengths": sorted(cycle_lengths),
    }


def _tree_distance(adj: Dict[Node, List[Node]], src: Node,
                   dst: Node) -> int:
    """BFS distance in the spanning forest (src and dst are in the
    same tree by construction)."""
    if src == dst:
        return 0
    seen = {src}
    queue = deque([(src, 0)])
    while queue:
        node, dist = queue.popleft()
        for nb in adj[node]:
            if nb == dst:
                return dist + 1
            if nb not in seen:
                seen.add(nb)
                queue.append((nb, dist + 1))
    raise ValueError(f"{src!r} and {dst!r} are not connected in the tree")


# --------------------------------------------------------------- filtration

def filtration(graph: CallGraph) -> Dict:
    """Sweep edges in ascending weight order (call depth). At each
    step record beta0 / beta1, and collect persistence pairs:
    - H0: every component is born at weight 0. When an edge merges
      two components, the smaller one dies at that edge's weight;
      its persistence is (death - 0). Survivors live forever.
    - H1: when an edge joins two nodes already in one component it
      closes a cycle, born at that edge's weight, death = infinity.
    Returns the merge persistences, cycle births, and the
    (weight, beta0, beta1) curve."""
    nodes = list(graph.nodes)
    edges = sorted(graph.edges, key=lambda e: e[2])
    uf = _UnionFind(nodes)
    # Birth of each component's root: all 0. Deaths recorded on merge.
    merge_persistences: List[float] = []
    cycle_births: List[float] = []
    curve: List[Tuple[float, int, int]] = []
    n_comp = len(nodes)
    n_cycles = 0
    # Components alive at weight 0 (before any edge).
    curve.append((0.0, n_comp, 0))
    for u, v, w in edges:
        if u == v:
            n_cycles += 1
            cycle_births.append(w)
            curve.append((w, n_comp, n_cycles))
            continue
        if uf.union(u, v) is not None:
            n_comp -= 1
            merge_persistences.append(w)  # born 0, dies at w
        else:
            n_cycles += 1
            cycle_births.append(w)
        curve.append((w, n_comp, n_cycles))
    return {
        "merge_persistences": sorted(merge_persistences),
        "cycle_births": sorted(cycle_births),
        "curve": curve,
        "max_beta1": n_cycles,
        "final_beta0": n_comp,
    }


# ------------------------------------------------------- feature extraction

TDA_FEATURE_NAMES = (
    "graph_present",
    "n_nodes",
    "n_edges",
    "betti0",
    "betti1",
    "largest_component_frac",
    "mean_component_size",
    "components_gt1",
    "max_cycle_len",
    "mean_cycle_len",
    "triangles",
    "has_cycle",
    "n_merges",
    "total_persistence_h0",
    "max_persistence_h0",
    "earliest_cycle_birth",
)

# Caps for the /N scalings below. Chosen so a realistic call graph
# (tens of nodes, a handful of cycles, depths 1-3) lands mid-range
# instead of saturating: contract call graphs are small.
_NODES_CAP = 16.0
_EDGES_CAP = 16.0
_BETTI_CAP = 8.0
_COMP_CAP = 8.0
_CYCLE_CAP = 16.0


def _cap(x: float, cap: float) -> float:
    return max(0.0, min(1.0, x / cap))


def summarize(graph: CallGraph) -> Dict:
    """All TDA numbers for one graph, unscaled, plus the raw counts
    the feature vector is built from."""
    n = len(graph.nodes)
    e = len(graph.edges)
    betti = betti_numbers(graph)
    filt = filtration(graph)
    comps = betti["components"]
    sizes = sorted((len(c) for c in comps), reverse=True)
    cycles = betti["cycle_lengths"]
    merges = filt["merge_persistences"]
    births = filt["cycle_births"]
    return {
        # build_graph only returns a non-empty graph when a record,
        # depth evidence, or a proxy edge was present, so any
        # non-empty graph counts as measured.
        "graph_present": 1.0 if n > 0 else 0.0,
        "n_nodes": n,
        "n_edges": e,
        "betti0": betti["beta0"],
        "betti1": betti["beta1"],
        "largest_component_frac": (sizes[0] / n) if n else 0.0,
        "mean_component_size": (sum(sizes) / len(sizes)) if sizes else 0.0,
        "components_gt1": sum(1 for s in sizes if s > 1),
        "max_cycle_len": max(cycles) if cycles else 0,
        "mean_cycle_len": (sum(cycles) / len(cycles)) if cycles else 0.0,
        "triangles": sum(1 for c in cycles if c == 3),
        "has_cycle": 1.0 if cycles else 0.0,
        "n_merges": len(merges),
        "total_persistence_h0": sum(merges),
        "max_persistence_h0": max(merges) if merges else 0.0,
        "earliest_cycle_birth": min(births) if births else 0.0,
        "cycle_lengths": cycles,
        "merge_persistences": merges,
        "cycle_births": births,
    }


def tda_features(finding: Dict, target: Optional[str] = None) -> List[float]:
    """One finding dict -> the 16 TDA features, each in [0, 1].
    A finding with no graph evidence yields all zeros."""
    graph = build_graph(finding, target=target)
    if len(graph) == 0:
        return [0.0] * len(TDA_FEATURE_NAMES)
    s = summarize(graph)
    return [
        s["graph_present"],
        _cap(s["n_nodes"], _NODES_CAP),
        _cap(s["n_edges"], _EDGES_CAP),
        _cap(s["betti0"], _BETTI_CAP),
        _cap(s["betti1"], _BETTI_CAP),
        s["largest_component_frac"],
        _cap(s["mean_component_size"], _COMP_CAP),
        _cap(s["components_gt1"], 4.0),
        _cap(s["max_cycle_len"], _CYCLE_CAP),
        _cap(s["mean_cycle_len"], _CYCLE_CAP),
        _cap(s["triangles"], 4.0),
        s["has_cycle"],
        _cap(s["n_merges"], _BETTI_CAP),
        _cap(s["total_persistence_h0"], _BETTI_CAP),
        _cap(s["max_persistence_h0"], 4.0),
        _cap(s["earliest_cycle_birth"], 4.0),
    ]


def tda_feature_names() -> List[str]:
    return [f"tda:{name}" for name in TDA_FEATURE_NAMES]
