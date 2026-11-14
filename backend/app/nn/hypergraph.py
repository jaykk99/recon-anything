"""Hypergraph neural network for ReconAnything triage.

A finding that spans several contracts at once (a proxy + its
implementation + the router that calls it, or several plugins firing
on the same target) is a *hyperedge*: one interaction connecting
many nodes, where a plain graph edge can only connect two. This
module builds those hyperedges from the findings data and runs
hypergraph message passing over them:

    node -> hyperedge aggregation -> node update, 2 layers,
    then a readout for the triage score.

Nodes are findings, featurised with the existing v2 spec
(features.py, 255 inputs). Hyperedges come from links already in
the findings data, never invented:

- ``target``: all findings on the same (chain, address). Several
  plugins firing on one target is one multi-plugin interaction.
- ``implementation``: all findings sharing one implementation
  address (evidence ``implementation_address``). Different proxy
  targets sharing an implementation are one system.
- ``project``: external (audit) findings from the same project
  (``source.project_id``). Findings from one audit are related.

Limits of the data, measured on the real rows (see docs):
- most targets have exactly one finding, so most nodes sit in no
  hyperedge at all and fall back to the self path (the model then
  behaves like a small MLP). Coverage is ~11% of train nodes.
- the two biggest shared implementations (384 and 68 targets) are
  dropped: a hyperedge that big is a global average, not a signal.
  ``max_edge_size`` (default 16) caps every hyperedge.
- there are ZERO cross_contract_call_graph rows in the own data, so
  no call-graph hyperedges exist yet. When that plugin's findings
  carry related-contract addresses, add a ``call_graph`` edge type
  here; the message passing already handles any edge list.

Triage only, same as the MLP scorer: the network ranks findings by
how much they look like past candidates that survived triage. It
never predicts VERIFIED_REAL (zero verified-real positives exist
in the data) and must never be used to claim one. Detection only:
no transactions, no drains, no live probes from this module.

Pure Python stdlib only, same as mlp.py: lists of floats, tanh
hidden units, sigmoid output, binary cross-entropy, full-batch
gradient descent. The input projection and its gradient run on the
sparse form of the feature vectors (16 nonzero entries of 255 on
average): same math, zeros skipped, ~4x faster per epoch. Backprop
through the hyperedge aggregation is hand-derived and
gradient-checked (see tests/test_nn_hypergraph.py: worst relative
error ~1e-8 on a tiny graph).
"""
from __future__ import annotations

import json
import math
import random
from collections import Counter, defaultdict
from operator import mul
from typing import Dict, List, Optional, Sequence, Tuple

from .features import FeatureSpec, extract
from .mlp import metrics_for


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def build_hypergraph(rows: Sequence[Dict], max_edge_size: int = 16,
                     min_edge_size: int = 2) -> Tuple[List[Dict], Dict]:
    """Build hyperedges from a list of NN row dicts.

    Returns (edges, stats). Each edge is {"type", "key", "members"}
    with members = row indices into ``rows``. Only groups of size
    ``min_edge_size``..``max_edge_size`` become edges; singleton
    groups carry no message-passing signal and giant groups are
    global averages, so both are dropped (and counted).

    IMPORTANT: build the hypergraph separately on the train rows and
    on the test rows. An edge joining a train node to a test node
    would leak test information into training.
    """
    groups: Dict[Tuple, List[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        chain = (r.get("chain") or "").lower()
        addr = (r.get("address") or "").lower()
        if addr:
            groups[("target", chain, addr)].append(i)
        ev = (r.get("finding") or {}).get("evidence") or {}
        ia = (ev.get("implementation_address") or "").lower()
        if ia and ia.strip("0x") != "":
            groups[("implementation", ia)].append(i)
        pid = ((r.get("source") or {}).get("project_id") or "")
        if pid:
            groups[("project", pid)].append(i)
    edges: List[Dict] = []
    seen = set()
    dropped_giant = 0
    for key, members in groups.items():
        if len(members) > max_edge_size:
            dropped_giant += 1
            continue
        if len(members) < min_edge_size:
            continue
        fs = frozenset(members)
        if fs in seen:  # same member set under two keys: keep one
            continue
        seen.add(fs)
        edges.append({"type": key[0], "key": list(key[1:]),
                      "members": list(members)})
    covered = set()
    for e in edges:
        covered.update(e["members"])
    stats = {
        "n_edges": len(edges),
        "by_type": dict(Counter(e["type"] for e in edges)),
        "nodes_covered": len(covered),
        "nodes_total": len(rows),
        "edge_size": {str(k): v for k, v in
                      sorted(Counter(len(e["members"])
                                   for e in edges).items())},
        "dropped_giant_groups": dropped_giant,
        "max_edge_size": max_edge_size,
        "min_edge_size": min_edge_size,
    }
    return edges, stats


class HypergraphNN:
    """2-layer hypergraph network: 255 -> hidden -> hidden -> 1.

    Per layer: hyperedge embedding = mean of member node
    embeddings; node update = tanh(W_self h + W_edge * mean of
    incident hyperedge embeddings + b). Nodes in no hyperedge get
    a zero edge term and update from themselves only. Readout is a
    sigmoid over the final node embedding: the estimated probability
    the finding is worth validating.
    """

    def __init__(self, n_in: int, hidden: int = 16, seed: int = 42,
                 lr: float = 0.1, l2: float = 1e-4) -> None:
        rng = random.Random(seed)
        self.n_in = int(n_in)
        self.hidden = int(hidden)
        self.lr = float(lr)
        self.l2 = float(l2)
        self.seed = int(seed)

        def xavier(fan_in: int, fan_out: int):
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            return [[rng.uniform(-limit, limit) for _ in range(fan_in)]
                    for _ in range(fan_out)]

        self.W_in = xavier(n_in, hidden)
        self.b_in = [0.0] * hidden
        self.W_self = [xavier(hidden, hidden) for _ in range(2)]
        self.W_edge = [xavier(hidden, hidden) for _ in range(2)]
        self.b = [[0.0] * hidden for _ in range(2)]
        limit = math.sqrt(6.0 / (hidden + 1))
        self.w_out = [rng.uniform(-limit, limit) for _ in range(hidden)]
        self.b_out = 0.0

    # -- forward ---------------------------------------------------------
    @staticmethod
    def _prep(edges: Sequence[Dict], n: int) -> List[List[int]]:
        """node -> list of incident hyperedge indices."""
        node_edges: List[List[int]] = [[] for _ in range(n)]
        for j, e in enumerate(edges):
            for m in e["members"]:
                if 0 <= m < n:
                    node_edges[m].append(j)
        return node_edges

    def forward(self, X: Sequence[Sequence[float]],
                edges: Sequence[Dict],
                X_sparse: Optional[Sequence[Sequence[Tuple[int, float]]]] = None):
        """Return (probs, cache); cache holds every intermediate
        the backward pass needs.

        X_sparse (optional) is the sparse form of X: per row, the
        (index, value) pairs of the nonzero entries. The v2 feature
        vectors are ~8% nonzero (one live plugin block + a few
        one-hots), so the input projection and its gradient skip
        the zeros: same math, ~14x less work. fit() builds it once.
        """
        n = len(X)
        h = self.hidden
        if n == 0:
            return [], {}
        node_edges = self._prep(edges, n)
        if X_sparse is not None:
            h0 = [[math.tanh(
                sum(self.W_in[r][k] * v for k, v in X_sparse[i])
                + self.b_in[r]) for r in range(h)]
                for i in range(n)]
        else:
            h0 = [[math.tanh(sum(map(mul, self.W_in[r], x)) + self.b_in[r])
                   for r in range(h)] for x in X]

        def layer(h_in, W_self, W_edge, b):
            e_emb = [[sum(h_in[m][k] for m in e["members"])
                      / len(e["members"]) for k in range(h)]
                     for e in edges]
            agg = []
            for i in range(n):
                js = node_edges[i]
                if js:
                    agg.append([sum(e_emb[j][k] for j in js) / len(js)
                                for k in range(h)])
                else:
                    agg.append([0.0] * h)
            h_out = [[math.tanh(sum(map(mul, W_self[r], h_in[i]))
                                + sum(map(mul, W_edge[r], agg[i]))
                                + b[r]) for r in range(h)]
                     for i in range(n)]
            return h_out, e_emb, agg

        h1, e1, agg1 = layer(h0, self.W_self[0], self.W_edge[0], self.b[0])
        h2, e2, agg2 = layer(h1, self.W_self[1], self.W_edge[1], self.b[1])
        probs = [_sigmoid(sum(map(mul, self.w_out, h2[i])) + self.b_out)
                 for i in range(n)]
        cache = {"X": X, "X_sparse": X_sparse, "edges": edges,
                 "node_edges": node_edges,
                 "h0": h0, "h1": h1, "h2": h2,
                 "e1": e1, "agg1": agg1, "e2": e2, "agg2": agg2}
        return probs, cache

    def predict_proba(self, x: Sequence[float]) -> float:
        """Score one feature vector with no hyperedge context
        (self path only). The batch path in predict_proba_nodes is
        what carries the multi-contract context."""
        probs, _ = self.forward([list(map(float, x))], [])
        return probs[0]

    def predict_proba_nodes(self, X: Sequence[Sequence[float]],
                            edges: Sequence[Dict],
                            X_sparse=None) -> List[float]:
        probs, _ = self.forward(X, edges, X_sparse)
        return probs

    def predict(self, x: Sequence[float], threshold: float = 0.5) -> int:
        return 1 if self.predict_proba(x) >= threshold else 0

    # -- training --------------------------------------------------------
    def _bce(self, probs, y) -> float:
        n = len(y)
        eps = 1e-12
        return -sum(yi * math.log(min(max(p, eps), 1 - eps))
                    + (1 - yi) * math.log(min(max(1 - p, eps), 1 - eps))
                    for p, yi in zip(probs, y)) / max(1, n)

    def _gradients(self, probs, cache, y) -> Dict:
        """Gradients of the mean-BCE loss for one full batch.

        Readout: sigmoid + BCE gives delta (p - y) / n. Each tanh
        layer: dz = dh * (1 - h_out^2). Hyperedge aggregation is a
        mean, so its backward distributes evenly: dL/de_j collects
        dL/dagg_i / deg(i) over the edge's members, and dL/dh_m
        collects dL/de_j / |j| over the node's incident edges.
        """
        n = len(y)
        h = self.hidden
        edges = cache["edges"]
        node_edges = cache["node_edges"]
        d_out = [(p - yi) / n for p, yi in zip(probs, y)]
        gw_out = [sum(d_out[i] * cache["h2"][i][k] for i in range(n))
                  for k in range(h)]
        gb_out = sum(d_out)
        dh2 = [[d_out[i] * self.w_out[k] for k in range(h)]
               for i in range(n)]

        def layer_bwd(dh_next, h_in, h_out, agg, W_self, W_edge):
            dz = [[dh_next[i][r] * (1.0 - h_out[i][r] ** 2)
                   for r in range(h)] for i in range(n)]
            gW_self = [[sum(dz[i][r] * h_in[i][k] for i in range(n))
                        for k in range(h)] for r in range(h)]
            gW_edge = [[sum(dz[i][r] * agg[i][k] for i in range(n))
                        for k in range(h)] for r in range(h)]
            gb = [sum(dz[i][r] for i in range(n)) for r in range(h)]
            dh_self = [[sum(W_self[r][k] * dz[i][r] for r in range(h))
                        for k in range(h)] for i in range(n)]
            dagg = [[sum(W_edge[r][k] * dz[i][r] for r in range(h))
                     for k in range(h)] for i in range(n)]
            de = [[0.0] * h for _ in edges]
            for j, e in enumerate(edges):
                for m in e["members"]:
                    deg = len(node_edges[m]) or 1
                    for k in range(h):
                        de[j][k] += dagg[m][k] / deg
            dh_edge = [[0.0] * h for _ in range(n)]
            for j, e in enumerate(edges):
                s = len(e["members"])
                for m in e["members"]:
                    for k in range(h):
                        dh_edge[m][k] += de[j][k] / s
            dh_in = [[dh_self[i][k] + dh_edge[i][k] for k in range(h)]
                     for i in range(n)]
            return dh_in, gW_self, gW_edge, gb

        dh1, gWs1, gWe1, gb1 = layer_bwd(
            dh2, cache["h1"], cache["h2"], cache["agg2"],
            self.W_self[1], self.W_edge[1])
        dh0, gWs0, gWe0, gb0 = layer_bwd(
            dh1, cache["h0"], cache["h1"], cache["agg1"],
            self.W_self[0], self.W_edge[0])
        dz0 = [[dh0[i][r] * (1.0 - cache["h0"][i][r] ** 2)
                for r in range(h)] for i in range(n)]
        if cache.get("X_sparse") is not None:
            gW_in = [[0.0] * self.n_in for _ in range(h)]
            for i in range(n):
                for k, v in cache["X_sparse"][i]:
                    for r in range(h):
                        gW_in[r][k] += dz0[i][r] * v
        else:
            gW_in = [[sum(dz0[i][r] * cache["X"][i][k] for i in range(n))
                      for k in range(self.n_in)] for r in range(h)]
        gb_in = [sum(dz0[i][r] for i in range(n)) for r in range(h)]
        return {"W_in": gW_in, "b_in": gb_in,
                "W_self": [gWs0, gWs1], "W_edge": [gWe0, gWe1],
                "b": [gb0, gb1], "w_out": gw_out, "b_out": gb_out}

    def _step(self, g: Dict) -> None:
        lr = self.lr
        for r in range(self.hidden):
            for k in range(self.n_in):
                self.W_in[r][k] -= lr * (g["W_in"][r][k]
                                         + self.l2 * self.W_in[r][k])
            self.b_in[r] -= lr * g["b_in"][r]
        for li in range(2):
            for r in range(self.hidden):
                for k in range(self.hidden):
                    self.W_self[li][r][k] -= lr * (
                        g["W_self"][li][r][k]
                        + self.l2 * self.W_self[li][r][k])
                    self.W_edge[li][r][k] -= lr * (
                        g["W_edge"][li][r][k]
                        + self.l2 * self.W_edge[li][r][k])
                self.b[li][r] -= lr * g["b"][li][r]
        for k in range(self.hidden):
            self.w_out[k] -= lr * (g["w_out"][k] + self.l2 * self.w_out[k])
        self.b_out -= lr * g["b_out"]

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int],
            edges: Sequence[Dict], epochs: int = 60,
            history_every: int = 5, verbose: bool = False) -> Dict[str, List[float]]:
        """Full-batch gradient descent. History records post-update
        loss / train accuracy (same convention as mlp.MLP.fit)."""
        X = [list(map(float, row)) for row in X]
        y = [float(v) for v in y]
        if not X:
            raise ValueError("empty training set")
        if len(X[0]) != self.n_in:
            raise ValueError(
                f"feature dim {len(X[0])} != network input {self.n_in}")
        n = len(X)
        # Sparse form of X, built once: the v2 vectors are ~8%
        # nonzero, and the input projection + its gradient are the
        # two expensive steps. Same math, zeros skipped.
        X_sparse = [[(k, v) for k, v in enumerate(row) if v != 0.0]
                    for row in X]
        history: Dict[str, List[float]] = {"loss": [], "train_acc": []}
        for ep in range(int(epochs)):
            probs, cache = self.forward(X, edges, X_sparse)
            self._step(self._gradients(probs, cache, y))
            if ep % max(1, int(history_every)) == 0 or ep == epochs - 1:
                p2, _ = self.forward(X, edges, X_sparse)
                history["loss"].append(self._bce(p2, y))
                history["train_acc"].append(
                    sum(1 for p, yi in zip(p2, y)
                        if (1 if p >= 0.5 else 0) == yi) / n)
                if verbose:
                    print(f"hypergraph epoch {ep}: loss "
                          f"{history['loss'][-1]:.4f} acc "
                          f"{history['train_acc'][-1]:.4f}", flush=True)
        return history

    def accuracy(self, X, y, edges, threshold: float = 0.5) -> float:
        if not X:
            return 0.0
        probs = self.predict_proba_nodes(X, edges)
        return sum(1 for p, yi in zip(probs, y)
                   if (1 if p >= threshold else 0) == yi) / len(y)

    # -- persistence -----------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "format": "recon-nn-hypergraph/1",
            "n_in": self.n_in,
            "hidden": self.hidden,
            "layers": [self.n_in, self.hidden, self.hidden, 1],
            "lr": self.lr,
            "l2": self.l2,
            "seed": self.seed,
            "W_in": self.W_in,
            "b_in": self.b_in,
            "W_self": self.W_self,
            "W_edge": self.W_edge,
            "b": self.b,
            "w_out": self.w_out,
            "b_out": self.b_out,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "HypergraphNN":
        if data.get("format") != "recon-nn-hypergraph/1":
            raise ValueError("not a recon-nn-hypergraph/1 weights file")
        net = cls(int(data["n_in"]), hidden=int(data.get("hidden", 16)),
                  seed=int(data.get("seed", 42)),
                  lr=float(data.get("lr", 0.1)),
                  l2=float(data.get("l2", 1e-4)))
        net.W_in = [[float(v) for v in row] for row in data["W_in"]]
        net.b_in = [float(v) for v in data["b_in"]]
        net.W_self = [[[float(v) for v in row] for row in mat]
                      for mat in data["W_self"]]
        net.W_edge = [[[float(v) for v in row] for row in mat]
                      for mat in data["W_edge"]]
        net.b = [[float(v) for v in b] for b in data["b"]]
        net.w_out = [float(v) for v in data["w_out"]]
        net.b_out = float(data["b_out"])
        return net

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)

    @classmethod
    def load(cls, path: str) -> "HypergraphNN":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def score_rows(rows: Sequence[Dict], spec: FeatureSpec,
               net: HypergraphNN,
               max_edge_size: int = 16) -> List[float]:
    """Score NN row dicts with the hypergraph: features from the
    shared v2 spec, hyperedges built from exactly these rows."""
    X = [extract(r["finding"], spec) for r in rows]
    edges, _stats = build_hypergraph(rows, max_edge_size=max_edge_size)
    return net.predict_proba_nodes(X, edges)


def score_finding_dicts_hypergraph(findings: Sequence[Dict],
                                   spec: FeatureSpec,
                                   net: HypergraphNN,
                                   threshold: float = 0.5) -> List[Dict]:
    """Score plain finding dicts (live-scan shape) with the
    hypergraph. Each finding gains nn_score / nn_label. Findings
    from one run form the hypergraph together, so a lone finding
    scores on its self path and a run's findings share context.
    Returns the findings ranked by nn_score, highest first."""
    rows = [{"finding": f} for f in findings]
    probs = score_rows(rows, spec, net)
    scored = []
    for f, p in zip(findings, probs):
        f["nn_score"] = round(p, 4)
        f["nn_label"] = ("worth-validating" if p >= threshold
                         else "likely-false-positive")
        scored.append(f)
    scored.sort(key=lambda d: (d.get("nn_score") is None,
                               -(d.get("nn_score") or 0.0)))
    return scored


def metrics_for_rows(rows: Sequence[Dict], spec: FeatureSpec,
                    net: HypergraphNN,
                    max_edge_size: int = 16) -> Dict:
    """Full honest metric set for a scored row list."""
    y = [r["label"] for r in rows]
    probs = score_rows(rows, spec, net, max_edge_size=max_edge_size)
    return metrics_for(y, probs)
