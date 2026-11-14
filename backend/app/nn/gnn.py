"""Graph neural network + head, trained jointly with the flat scorer.

Architecture (pure Python stdlib, same rule as the scorer):

    graph nodes (32-dim) --[2 message-passing layers, hidden 16]-->
    node embeddings --[mean readout, 16-dim]--> concat with the
    flat 255-dim finding vector --> MLP head [271, 32, 1] (sigmoid)
    --> triage probability (worth-validating vs likely-false-positive).

Message passing, one layer: h' = tanh(W_self . h + W_neigh .
mean(neighbours) + b). Self and neighbour terms are separate
weights, so a node keeps its own signal while absorbing its
neighbourhood. Readout is the mean of the final node embeddings.

Training is joint mini-batch SGD on binary cross-entropy with L2,
the same optimiser shape as mlp.MLP.fit: the head's gradients come
from MLP._deltas/_backward, the gradient w.r.t. the readout is
pushed back through the readout and both message-passing layers by
hand (tanh derivatives, mean-aggregation redistribution).

Triage only: the output is a rank, never VERIFIED_REAL.
"""
from __future__ import annotations

import math
import random
from typing import Dict, List, Optional, Sequence, Tuple

from .features import FeatureSpec, extract
from .graph import GNN_HIDDEN, NODE_DIM, adjacency, build_graph
from .mlp import MLP

HEAD_HIDDEN = 32


def _tanh(v: float) -> float:
    return math.tanh(v)


def _tanh_deriv(a: float) -> float:
    return 1.0 - a * a


def _matvec(w: Sequence[Sequence[float]], x: Sequence[float],
            b: Sequence[float]) -> List[float]:
    return [sum(a * b_ for a, b_ in zip(row, x)) + bias
            for row, bias in zip(w, b)]


def _zeros_like(w):
    if isinstance(w, list) and w and isinstance(w[0], list):
        return [[0.0] * len(row) for row in w]
    return [0.0] * len(w)


class GNN:
    """Two message-passing layers over 32-dim node features."""

    def __init__(self, node_dim: int = NODE_DIM,
                 hidden: int = GNN_HIDDEN, seed: int = 42,
                 lr: float = 0.05, l2: float = 1e-4) -> None:
        self.node_dim = int(node_dim)
        self.hidden = int(hidden)
        self.lr = float(lr)
        self.l2 = float(l2)
        self.seed = int(seed)
        rng = random.Random(seed)
        self.weights: List[List[List[float]]] = []
        self.biases: List[List[float]] = []
        # Four matrices: layer-1 self, layer-1 neighbour, layer-2
        # self, layer-2 neighbour. Neighbour matrices are independent
        # draws, never aliases of the self matrices.
        for fan_in, fan_out in ((node_dim, hidden), (node_dim, hidden),
                                (hidden, hidden), (hidden, hidden)):
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            self.weights.append(
                [[rng.uniform(-limit, limit) for _ in range(fan_in)]
                 for _ in range(fan_out)])
        for _ in range(2):
            self.biases.append([0.0 for _ in range(hidden)])

    def _layer(self, h: List[List[float]], adj: List[List[int]],
               w_self, w_neigh, b) -> Tuple[List[List[float]],
                                            List[List[float]]]:
        """One message-passing layer. Returns (out, agg) where agg is
        the per-node mean neighbour embedding (cached for backward)."""
        n = len(h)
        agg: List[List[float]] = []
        for i in range(n):
            nbrs = adj[i]
            if nbrs:
                agg.append([sum(h[j][k] for j in nbrs) / len(nbrs)
                            for k in range(len(h[0]))])
            else:
                agg.append([0.0] * len(h[0]))
        out = []
        for i in range(n):
            z = _matvec(w_self, h[i], b)
            zn = _matvec(w_neigh, agg[i], [0.0] * len(b))
            out.append([_tanh(a + c) for a, c in zip(z, zn)])
        return out, agg

    def forward(self, graph: Dict):
        """Return a cache dict with everything backward needs."""
        nodes = graph["nodes"]
        adj = adjacency(len(nodes), graph["edges"])
        h1, agg0 = self._layer(nodes, adj, self.weights[0],
                               self.weights[1], self.biases[0])
        h2, agg1 = self._layer(h1, adj, self.weights[2],
                               self.weights[3], self.biases[1])
        n = len(nodes)
        readout = [sum(h2[i][k] for i in range(n)) / n
                   for k in range(self.hidden)]
        return {"nodes": nodes, "adj": adj, "h1": h1, "agg0": agg0,
                "h2": h2, "agg1": agg1, "readout": readout}

    def backward(self, cache: Dict, d_readout: Sequence[float]):
        """Gradients of the loss w.r.t. the four weight matrices and
        two bias vectors, given dL/dreadout. Returns (grad_w, grad_b)
        in the same shapes as self.weights / self.biases."""
        nodes, adj = cache["nodes"], cache["adj"]
        h1, agg0, h2, agg1 = (cache["h1"], cache["agg0"],
                              cache["h2"], cache["agg1"])
        n = len(nodes)
        hidden = self.hidden
        gw = [_zeros_like(w) for w in self.weights]
        gb = [_zeros_like(b) for b in self.biases]
        # Readout is a mean: every node gets d_readout / n.
        d_h2 = [[d_readout[k] / n for k in range(hidden)]
                for _ in range(n)]
        # Layer 2 backward.
        d_h1 = [[0.0] * hidden for _ in range(n)]
        d_agg1 = [[0.0] * hidden for _ in range(n)]
        for i in range(n):
            delta = [d_h2[i][k] * _tanh_deriv(h2[i][k])
                     for k in range(hidden)]
            for r in range(hidden):
                dr = delta[r]
                gb[1][r] += dr
                ws_row, wn_row = self.weights[2][r], self.weights[3][r]
                for c in range(hidden):
                    gw[2][r][c] += dr * h1[i][c]
                    gw[3][r][c] += dr * agg1[i][c]
                    d_h1[i][c] += ws_row[c] * dr
                    d_agg1[i][c] += wn_row[c] * dr
        for i in range(n):
            nbrs = adj[i]
            if not nbrs:
                continue
            share = 1.0 / len(nbrs)
            for j in nbrs:
                for k in range(hidden):
                    d_h1[j][k] += d_agg1[i][k] * share
        # Layer 1 backward.
        for i in range(n):
            delta = [d_h1[i][k] * _tanh_deriv(h1[i][k])
                     for k in range(hidden)]
            for r in range(hidden):
                dr = delta[r]
                gb[0][r] += dr
                ws_row, wn_row = self.weights[0][r], self.weights[1][r]
                for c in range(self.node_dim):
                    gw[0][r][c] += dr * nodes[i][c]
                    gw[1][r][c] += dr * agg0[i][c]
        return gw, gb

    def to_dict(self) -> Dict:
        return {"node_dim": self.node_dim, "hidden": self.hidden,
                "weights": self.weights, "biases": self.biases}

    @classmethod
    def from_dict(cls, data: Dict) -> "GNN":
        obj = cls.__new__(cls)
        obj.node_dim = int(data["node_dim"])
        obj.hidden = int(data["hidden"])
        obj.weights = data["weights"]
        obj.biases = data["biases"]
        obj.lr = 0.05
        obj.l2 = 1e-4
        obj.seed = 42
        return obj


class CombinedNet:
    """GNN readout + flat finding vector -> MLP head -> triage score."""

    def __init__(self, spec: FeatureSpec, seed: int = 42,
                 lr: float = 0.05, l2: float = 1e-4,
                 head_hidden: int = HEAD_HIDDEN) -> None:
        self.spec = spec
        self.gnn = GNN(seed=seed, lr=lr, l2=l2)
        self.head = MLP([GNN_HIDDEN + spec.dim, head_hidden, 1],
                        seed=seed, lr=lr, l2=l2)
        self.lr = float(lr)
        self.l2 = float(l2)
        self.seed = int(seed)

    def predict_proba(self, graph: Dict, finding: Dict) -> float:
        cache = self.gnn.forward(graph)
        z = list(cache["readout"]) + extract(finding, self.spec)
        return self.head.predict_proba(z)

    def _example_grads(self, graph: Dict, finding: Dict, y: float):
        """Forward + backward for one example. Returns
        (p, gnn_grads, head_grads)."""
        cache = self.gnn.forward(graph)
        x = extract(finding, self.spec)
        z = list(cache["readout"]) + x
        acts, pres = self.head._forward(z)
        p = acts[-1][0]
        deltas = self.head._deltas(acts, y)
        head_gw, head_gb = self.head._backward(acts, pres, y)
        # Gradient w.r.t. the head input: W1^T . delta1.
        w1 = self.head.weights[0]
        d0 = deltas[0]
        dz = [sum(w1[i][j] * d0[i] for i in range(len(d0)))
              for j in range(len(z))]
        d_readout = dz[:GNN_HIDDEN]
        gnn_gw, gnn_gb = self.gnn.backward(cache, d_readout)
        return p, (gnn_gw, gnn_gb), (head_gw, head_gb)

    def fit(self, graphs: Sequence[Dict], findings: Sequence[Dict],
            y: Sequence[int], epochs: int = 30, batch_size: int = 32,
            seed: int = 42, history_every: int = 1) -> Dict:
        """Joint mini-batch SGD over GNN + head. Returns history
        {"loss": [...], "train_acc": [...]} (loss/acc recorded every
        history_every epochs, first epoch always)."""
        y = [float(v) for v in y]
        n = len(y)
        if n == 0:
            raise ValueError("empty training set")
        rng = random.Random(seed)
        history: Dict[str, List[float]] = {"loss": [], "train_acc": []}
        for epoch in range(int(epochs)):
            order = list(range(n))
            rng.shuffle(order)
            for start in range(0, n, max(1, int(batch_size))):
                idxs = order[start:start + int(batch_size)]
                gw_acc = [_zeros_like(w) for w in self.gnn.weights]
                gb_acc = [_zeros_like(b) for b in self.gnn.biases]
                hw_acc = [_zeros_like(w) for w in self.head.weights]
                hb_acc = [_zeros_like(b) for b in self.head.biases]
                for i in idxs:
                    _, (ggw, ggb), (hgw, hgb) = self._example_grads(
                        graphs[i], findings[i], y[i])
                    for li in range(len(gw_acc)):
                        for r in range(len(gw_acc[li])):
                            for c in range(len(gw_acc[li][r])):
                                gw_acc[li][r][c] += ggw[li][r][c]
                    for li in range(len(gb_acc)):
                        for r in range(len(gb_acc[li])):
                            gb_acc[li][r] += ggb[li][r]
                    for li in range(len(hw_acc)):
                        for r in range(len(hw_acc[li])):
                            for c in range(len(hw_acc[li][r])):
                                hw_acc[li][r][c] += hgw[li][r][c]
                    for li in range(len(hb_acc)):
                        for r in range(len(hb_acc[li])):
                            hb_acc[li][r] += hgb[li][r]
                m = float(len(idxs))
                # Four weight matrices (self/neighbour x 2 layers) but
                # only two bias vectors (one per layer): matrices 0-1
                # share bias 0, matrices 2-3 share bias 1.
                for li in range(len(self.gnn.weights)):
                    for r in range(len(self.gnn.weights[li])):
                        for c in range(len(self.gnn.weights[li][r])):
                            g = gw_acc[li][r][c] / m
                            g += self.l2 * self.gnn.weights[li][r][c]
                            self.gnn.weights[li][r][c] -= self.lr * g
                for layer in range(len(self.gnn.biases)):
                    for r in range(len(self.gnn.biases[layer])):
                        self.gnn.biases[layer][r] -= self.lr * (
                            gb_acc[layer][r] / m)
                for li in range(len(self.head.weights)):
                    for r in range(len(self.head.weights[li])):
                        for c in range(len(self.head.weights[li][r])):
                            g = hw_acc[li][r][c] / m
                            g += self.l2 * self.head.weights[li][r][c]
                            self.head.weights[li][r][c] -= self.lr * g
                    for r in range(len(self.head.biases[li])):
                        self.head.biases[li][r] -= self.lr * (
                            hb_acc[li][r] / m)
            if epoch % max(1, int(history_every)) == 0:
                loss = 0.0
                correct = 0
                eps = 1e-12
                for i in range(n):
                    p = self.predict_proba(graphs[i], findings[i])
                    p = min(max(p, eps), 1.0 - eps)
                    loss += -(y[i] * math.log(p)
                              + (1.0 - y[i]) * math.log(1.0 - p))
                    if (1 if p >= 0.5 else 0) == int(y[i]):
                        correct += 1
                history["loss"].append(loss / n)
                history["train_acc"].append(correct / n)
        return history

    def to_dict(self) -> Dict:
        return {"format": "recon-nn-gnn-weights/1",
                "gnn": self.gnn.to_dict(),
                "head": self.head.to_dict(),
                "features": self.spec.to_dict()}

    @classmethod
    def from_dict(cls, data: Dict) -> "CombinedNet":
        if data.get("format") != "recon-nn-gnn-weights/1":
            raise ValueError("not a recon-nn-gnn-weights/1 file")
        spec = FeatureSpec.from_dict(data["features"])
        obj = cls.__new__(cls)
        obj.spec = spec
        obj.gnn = GNN.from_dict(data["gnn"])
        obj.head = MLP.from_dict(data["head"])
        obj.lr = 0.05
        obj.l2 = 1e-4
        obj.seed = 42
        return obj
