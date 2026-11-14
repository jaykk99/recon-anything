"""Federated learning (FedAvg) for the ReconAnything triage scorer.

    python -m app.nn.federated demo [--rounds N] [--local-epochs E]
    python -m app.nn.federated serve [--host 127.0.0.1] [--port 8766]
    python -m app.nn.federated client --server URL --client-id vm
        [--rounds N] [--local-epochs E]

What this is: the same 255-64-32-1 triage MLP as the centrally trained
v2 model, trained across Jay's own machines WITHOUT moving raw
findings off any device. Each client trains locally on its own
partition and sends only weight updates; the server aggregates them
with a sample-weighted average (FedAvg, McMahan et al. 2017) and
sends back the global model.

What moves over the wire, per client per round:
- the client's weight matrices + biases (floats), its row count n,
  its client id, the round number, and a plugin/key frequency
  sketch (counts only, used to agree the feature vocabulary).
What NEVER moves: finding dicts, labels, verdicts, addresses,
contract code, values, evidence. A client update payload contains
no raw finding rows by construction (see validate_update_payload
and the test that scans a serialised payload for row material).

Rules (non-negotiable, same as the central scorer):
- Triage / prediction only. The model ranks findings by how much
  they look like past candidates that survived triage. It never
  predicts VERIFIED_REAL: there are zero verified-real positives
  in the data, and nothing here changes that.
- Detection only, read-only live probes, no transactions, no
  drains. crypto.com is never a target.
- Raw findings never leave a device; only weight updates move.

Demo honesty: the demo runs 3 local partitions on THIS VM only
(clients "vm", "linux-box", "phone" are partitions of the local
training pool, not live devices). No second live device took part
in the demo run. The HTTP transport is real and a remote device
can join it (see backend/docs/nn-federated.md), but the numbers
in federated-viewer-data.json are local-partition numbers until a
real remote client actually trains a round.

Partitions (non-IID, deterministic, every training row used once):
- vm:        own-train rows from chain bsc + external scabench +
             external xanoutas (positive-heavy, BSC-dominated).
- linux-box: own-train rows from chains other than bsc +
             external defihack + external audit-findings.
- phone:     external sherlock-invalid only. Those rows are ALL
             likely-false-positive, so this client is label-skewed
             on purpose: it is the honest stress case, and its
             local-only model is expected to be degenerate.

The fixed holdout (145 own rows, stratified, seed 42) is never
trained on by any client, by the server, or by the central
baseline. All models below are scored on that same holdout.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import math
import multiprocessing
import os
import sys
import threading
import urllib.request
import urllib.error
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .data import build_dataset, load_external_rows, stratified_split
from .features import FeatureSpec, build_vocab, extract
from .mlp import MLP, metrics_for

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CANDIDATES = ("~/workspace/recon-continuous/results/"
                      "candidates.jsonl")
DEFAULT_BATCHES = "~/workspace/recon-continuous/results/batches.jsonl"

#: Architecture shared by the federated global model, the per-client
#: local-only models and the central baseline, so the comparison is
#: apples-to-apples. Same as the v2 centrally trained model.
LAYERS = [255, 64, 32, 1]
LR = 0.05
SEED = 42

#: Fixed holdout: 20% of Jay's own 725 rows, stratified, seed 42.
TEST_FRAC = 0.2
HOLDOUT_SEED = 42

CLIENT_IDS = ("vm", "linux-box", "phone")

#: Payload keys allowed in a client update. Anything else is rejected.
UPDATE_KEYS = frozenset({
    "protocol", "client_id", "round", "n", "layers",
    "weights", "biases", "vocab_sketch",
})
UPDATE_PROTOCOL = "recon-nn-fedavg/1"

# ---------------------------------------------------------------------------
# Partitions
# ---------------------------------------------------------------------------


def _row_source(row: Dict) -> str:
    """External source dataset for an external row ('' for own rows)."""
    return ((row.get("source") or {}).get("dataset") or "")


def partition_training_pool(own_train_rows: Sequence[Dict],
                            external_rows: Sequence[Dict]
                            ) -> Dict[str, List[Dict]]:
    """Split the training pool into non-IID client partitions.

    Deterministic, no row used twice, no row dropped. The holdout is
    not part of either input, so it cannot leak into a partition.
    """
    parts: Dict[str, List[Dict]] = {cid: [] for cid in CLIENT_IDS}
    for r in own_train_rows:
        if (r.get("chain") or "").lower() == "bsc":
            parts["vm"].append(r)
        else:
            parts["linux-box"].append(r)
    for r in external_rows:
        src = _row_source(r)
        if src in ("scabench", "xanoutas"):
            parts["vm"].append(r)
        elif src in ("defihack", "audit-findings"):
            parts["linux-box"].append(r)
        elif src == "sherlock-invalid":
            parts["phone"].append(r)
        else:
            # Unknown external source: keep it in the pool on the VM
            # rather than silently dropping training data.
            parts["vm"].append(r)
    return parts


def partition_stats(parts: Dict[str, List[Dict]]) -> Dict[str, Dict]:
    """Per-client row counts, label split and chain/source mix."""
    out = {}
    for cid, rows in parts.items():
        pos = sum(1 for r in rows if r["label"] == 1)
        out[cid] = {
            "n": len(rows),
            "n_positive": pos,
            "n_negative": len(rows) - pos,
            "chains": dict(Counter((r.get("chain") or "other")
                                   for r in rows)),
            "sources": dict(Counter(_row_source(r) or "own"
                                    for r in rows)),
            "plugins_top": dict(Counter(
                str((r.get("finding") or {}).get("plugin") or "OTHER")
                for r in rows).most_common(5)),
        }
    return out


# ---------------------------------------------------------------------------
# Feature vocabulary from count sketches (no rows leave a device)
# ---------------------------------------------------------------------------


def client_vocab_sketch(rows: Sequence[Dict]) -> Dict[str, Dict[str, int]]:
    """Count-only sketch of a client's rows: plugin and key frequencies.

    This is the ONLY row-derived information a client shares before
    training besides its weight updates: bare counts, no finding
    dicts, no labels, no addresses, no values.
    """
    plugins: Counter = Counter()
    keys: Counter = Counter()
    for r in rows:
        f = r.get("finding") or {}
        if f.get("plugin"):
            plugins[str(f["plugin"])] += 1
        key = (f.get("key") or (f.get("evidence") or {}).get("check")
               or "")
        if key:
            keys[str(key)] += 1
    return {"plugins": dict(plugins), "keys": dict(keys)}


def merge_sketches(sketches: Sequence[Dict[str, Dict[str, int]]],
                   top_k: int = 24) -> FeatureSpec:
    """Merge client count sketches into one shared feature vocabulary.

    Same top-K rule as features.build_vocab, applied to merged
    counts. The server never sees a row; it sees counts.
    """
    plugins: Counter = Counter()
    keys: Counter = Counter()
    for s in sketches:
        plugins.update(s.get("plugins") or {})
        keys.update(s.get("keys") or {})
    return FeatureSpec(
        [p for p, _ in plugins.most_common(top_k)],
        [k for k, _ in keys.most_common(top_k)])


# ---------------------------------------------------------------------------
# Model state: serialise / average (FedAvg)
# ---------------------------------------------------------------------------


def state_dict(net: MLP) -> Dict:
    """Deep-copied weights + biases (the only thing that ever moves)."""
    return {"weights": copy.deepcopy(net.weights),
            "biases": copy.deepcopy(net.biases)}


def load_state(net: MLP, state: Dict) -> None:
    """Load weights + biases into a net of the same layer sizes."""
    if [len(w) for w in state["weights"]] != [len(w) for w in net.weights]:
        raise ValueError("state layer sizes do not match this network")
    net.weights = copy.deepcopy(state["weights"])
    net.biases = copy.deepcopy(state["biases"])


def average_states(states: Sequence[Dict],
                   counts: Sequence[int]) -> Dict:
    """FedAvg: sample-weighted average of client states.

    states[i] is client i's weights after local training, counts[i]
    is how many rows client i trained on. A client with more rows
    pulls the global model further, exactly as if its rows had
    been in one central batch.
    """
    if not states:
        raise ValueError("no client states to average")
    if len(states) != len(counts):
        raise ValueError("states and counts length mismatch")
    total = float(sum(counts))
    if total <= 0:
        raise ValueError("total client row count must be > 0")
    avg_w = copy.deepcopy(states[0]["weights"])
    avg_b = copy.deepcopy(states[0]["biases"])
    for li in range(len(avg_w)):
        for r in range(len(avg_w[li])):
            for c in range(len(avg_w[li][r])):
                s = 0.0
                for st, n in zip(states, counts):
                    s += n * st["weights"][li][r][c]
                avg_w[li][r][c] = s / total
        for r in range(len(avg_b[li])):
            s = 0.0
            for st, n in zip(states, counts):
                s += n * st["biases"][li][r]
            avg_b[li][r] = s / total
    return {"weights": avg_w, "biases": avg_b}


def _all_finite(state: Dict) -> bool:
    for mat in state["weights"]:
        for row in mat:
            for v in row:
                if not math.isfinite(v):
                    return False
    for b in state["biases"]:
        for v in b:
            if not math.isfinite(v):
                return False
    return True


def package_update(client_id: str, net: MLP, n: int, round_no: int,
                   vocab_sketch: Optional[Dict] = None) -> Dict:
    """Build a client update payload. Contains weights only.

    Deliberately no "rows", "findings", "labels", "addresses" or
    "evidence" keys: a payload cannot carry a raw finding row
    because the packaging function never puts one in.
    """
    st = state_dict(net)
    return {
        "protocol": UPDATE_PROTOCOL,
        "client_id": client_id,
        "round": int(round_no),
        "n": int(n),
        "layers": list(net.layers),
        "weights": st["weights"],
        "biases": st["biases"],
        "vocab_sketch": vocab_sketch or {"plugins": {}, "keys": {}},
    }


def validate_update_payload(payload: Dict, layers: Sequence[int]) -> None:
    """Reject any update that is malformed, off-architecture, or
    tries to smuggle non-weight content. Raises ValueError."""
    if not isinstance(payload, dict):
        raise ValueError("update payload is not an object")
    extra = set(payload) - UPDATE_KEYS
    if extra:
        raise ValueError(f"update carries forbidden keys: {sorted(extra)}")
    if payload.get("protocol") != UPDATE_PROTOCOL:
        raise ValueError("unknown federated protocol")
    if list(payload.get("layers") or []) != list(layers):
        raise ValueError("update layer sizes do not match the global model")
    n = payload.get("n")
    if not isinstance(n, int) or n < 1:
        raise ValueError("update row count n must be a positive int")
    if not isinstance(payload.get("client_id"), str) or not payload["client_id"]:
        raise ValueError("update needs a non-empty client_id")
    if not isinstance(payload.get("round"), int) or payload["round"] < 0:
        raise ValueError("update needs a non-negative round number")
    state = {"weights": payload.get("weights"),
             "biases": payload.get("biases")}
    if not isinstance(state["weights"], list) or not isinstance(
            state["biases"], list):
        raise ValueError("update weights/biases must be lists")
    try:
        if not _all_finite(state):
            raise ValueError("update contains non-finite weights")
    except (TypeError, KeyError) as e:
        raise ValueError(f"update weights malformed: {e}") from e
    sketch = payload.get("vocab_sketch") or {}
    if not isinstance(sketch, dict):
        raise ValueError("vocab_sketch must be an object")
    for k in ("plugins", "keys"):
        counts = sketch.get(k) or {}
        if not isinstance(counts, dict) or any(
                not isinstance(v, int) or v < 0
                for v in counts.values()):
            raise ValueError(f"vocab_sketch.{k} must map names to counts")


def payload_contains_row_material(payload: Dict,
                                  forbidden: Sequence[str]) -> List[str]:
    """Leak check: serialise the payload and look for raw-row
    material (addresses, finding values, verdict strings). Returns
    the forbidden strings that appear (empty = clean)."""
    blob = json.dumps(payload, default=str)
    return [s for s in forbidden if s and s in blob]


# ---------------------------------------------------------------------------
# Client + server (in-process)
# ---------------------------------------------------------------------------


class FederatedClient:
    """One device's local trainer. Holds its own rows in memory and
    never exposes them; only package_update() output leaves."""

    def __init__(self, client_id: str, rows: Sequence[Dict],
                 spec: FeatureSpec, layers: Sequence[int] = LAYERS,
                 lr: float = LR, seed: int = SEED) -> None:
        self.client_id = client_id
        self.rows = list(rows)
        self.spec = spec
        self.layers = list(layers)
        self.lr = lr
        self.seed = seed
        self.X = [extract(r["finding"], spec) for r in self.rows]
        self.y = [int(r["label"]) for r in self.rows]
        self.sketch = client_vocab_sketch(self.rows)

    @property
    def n(self) -> int:
        return len(self.rows)

    def local_train(self, global_state: Dict, epochs: int,
                    round_no: int) -> Dict:
        """Train from the global weights on local rows only; return
        the update payload (weights + n, nothing else)."""
        net = MLP(self.layers, seed=self.seed, lr=self.lr)
        load_state(net, global_state)
        # Deterministic per-round shuffle seed: same inputs always
        # give the same update, so a run is reproducible.
        net.fit(self.X, self.y, epochs=int(epochs), batch_size=32,
                seed=self.seed + 1000 * int(round_no))
        return package_update(self.client_id, net, self.n, round_no,
                              vocab_sketch=self.sketch)

    def evaluate(self, state: Dict, X_test, y_test) -> Dict:
        """Score a model state on the shared holdout (read-only)."""
        net = MLP(self.layers, seed=self.seed, lr=self.lr)
        load_state(net, state)
        scores = [net.predict_proba(x) for x in X_test]
        return metrics_for(list(y_test), scores)


class FederatedServer:
    """Holds the global model, validates updates, averages them."""

    def __init__(self, spec: FeatureSpec, layers: Sequence[int] = LAYERS,
                 lr: float = LR, seed: int = SEED) -> None:
        self.spec = spec
        self.layers = list(layers)
        self.lr = lr
        self.seed = seed
        self.net = MLP(self.layers, seed=seed, lr=lr)
        self.round = 0
        self.history: List[Dict] = []

    @property
    def global_state(self) -> Dict:
        return state_dict(self.net)

    def aggregate(self, updates: Sequence[Dict]) -> Dict:
        """Validate every update, then FedAvg. Returns the new
        global state. Rejects the whole round on any bad update
        rather than averaging a poisoned one in."""
        if not updates:
            raise ValueError("no client updates to aggregate")
        for u in updates:
            validate_update_payload(u, self.layers)
        states = [{"weights": u["weights"], "biases": u["biases"]}
                  for u in updates]
        counts = [int(u["n"]) for u in updates]
        new_state = average_states(states, counts)
        load_state(self.net, new_state)
        self.round += 1
        return self.global_state

    def evaluate(self, X_test, y_test) -> Dict:
        scores = [self.net.predict_proba(x) for x in X_test]
        return metrics_for(list(y_test), scores)


# ---------------------------------------------------------------------------
# Data loading: fixed holdout + training pool
# ---------------------------------------------------------------------------


def load_federated_data(candidates_path: str = DEFAULT_CANDIDATES,
                        batches_path: str = DEFAULT_BATCHES,
                        external_path: Optional[str] = None,
                        cache_path: Optional[str] = None) -> Dict:
    """Load own rows + external rows, split off the FIXED holdout.

    The holdout is stratified_split(own rows, 0.2, seed 42): 145
    rows (124 worth-validating / 21 likely-false-positive). The
    training pool is the remaining 580 own rows + all 1,922
    external rows. External rows never enter the holdout: the
    holdout measures the model on Jay's own candidates only.

    cache_path (a /tmp file, never committed): the own-row build
    re-reads a 431M batches.jsonl, ~1 CPU-minute. When a cache
    file exists it is loaded instead; otherwise the build runs
    once and the cache is written for the next run.
    """
    if cache_path and os.path.exists(cache_path):
        with open(cache_path, encoding="utf-8") as fh:
            cached = json.load(fh)
        return cached
    ext_default = Path(__file__).resolve().parent / "external_findings.jsonl"
    dataset = build_dataset(os.path.expanduser(candidates_path),
                            os.path.expanduser(batches_path))
    own_rows = dataset["rows"]
    own_train, holdout = stratified_split(own_rows, TEST_FRAC,
                                          HOLDOUT_SEED)
    ext_path = external_path or str(ext_default)
    ext_rows, ext_stats = load_external_rows(ext_path)
    stats = dict(dataset["stats"])
    stats.update(ext_stats)
    out = {
        "own_rows": own_rows,
        "own_train": own_train,
        "holdout": holdout,
        "external": ext_rows,
        "train_pool_n": len(own_train) + len(ext_rows),
        "stats": stats,
    }
    if cache_path:
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh)
    return out


# ---------------------------------------------------------------------------
# Central + local-only baselines (same holdout, same spec, same arch)
# ---------------------------------------------------------------------------


def train_central(X_train, y_train, X_test, y_test,
                  layers: Sequence[int] = LAYERS, epochs: int = 60,
                  lr: float = LR, seed: int = SEED) -> Tuple[MLP, Dict]:
    """Centrally trained baseline: one model, whole training pool,
    same hyper-parameters as train.py defaults. This is the number
    federated learning has to be judged against (privacy cost)."""
    net = MLP(list(layers), seed=seed, lr=lr)
    net.fit(X_train, y_train, epochs=int(epochs), batch_size=32,
            X_val=X_test, y_val=y_test, seed=seed)
    scores = [net.predict_proba(x) for x in X_test]
    return net, metrics_for(list(y_test), scores)


def train_local_only(client: FederatedClient, X_test, y_test,
                     epochs: int) -> Tuple[MLP, Dict]:
    """What one client could do alone, without federating: train
    from scratch on its own partition only."""
    net = MLP(client.layers, seed=client.seed, lr=client.lr)
    net.fit(client.X, client.y, epochs=int(epochs), batch_size=32,
            seed=client.seed)
    scores = [net.predict_proba(x) for x in X_test]
    return net, metrics_for(list(y_test), scores)


def _local_train_job(arg) -> Dict:
    """Top-level pool worker: one client's local training for a
    round. (Top-level so a fork pool can run it; with fork the
    client object is inherited, no pickling of rows needed.)"""
    client, global_state, epochs, round_no = arg
    return client.local_train(global_state, epochs, round_no)


def _local_only_job(arg) -> Tuple[str, Dict]:
    """Top-level pool worker: one client's local-only model."""
    client, X_test, y_test, epochs = arg
    _net, metrics = train_local_only(client, X_test, y_test, epochs)
    return client.client_id, metrics


def _train_clients(clients: Dict[str, FederatedClient],
                   global_state: Dict, epochs: int, round_no: int,
                   jobs: int) -> List[Dict]:
    """Train all clients from the same global state. In parallel
    (fork pool, one worker per client) when jobs > 1: the clients
    are independent within a round, so this is ~3x faster on a
    multi-core box and changes nothing about the math — each
    worker runs the same local_train on the same inputs. Falls
    back to sequential on any pool failure."""
    args = [(clients[cid], global_state, int(epochs), int(round_no))
            for cid in CLIENT_IDS]
    if int(jobs) > 1:
        try:
            ctx = multiprocessing.get_context("fork")
            with ctx.Pool(processes=min(int(jobs), len(args))) as pool:
                return pool.map(_local_train_job, args)
        except Exception:
            pass  # fall through to sequential
    return [_local_train_job(a) for a in args]


# ---------------------------------------------------------------------------
# Demo: full federated run + baselines, all on the fixed holdout
# ---------------------------------------------------------------------------


def run_demo(rounds: int = 6, local_epochs: int = 2,
             central_epochs: int = 60,
             candidates_path: str = DEFAULT_CANDIDATES,
             batches_path: str = DEFAULT_BATCHES,
             external_path: Optional[str] = None,
             out_dir: Optional[str] = None,
             jobs: int = 3,
             cache_path: Optional[str] = "/tmp/fed-pool-cache.json",
             log=print) -> Dict:
    """Run the honest local demo: 3 partitions on this VM, FedAvg,
    local-only models, and the central baseline. Writes the
    federated weights + viewer data when out_dir is given."""
    data = load_federated_data(candidates_path, batches_path,
                               external_path, cache_path=cache_path)
    parts = partition_training_pool(data["own_train"], data["external"])
    stats = partition_stats(parts)
    log(f"holdout: {len(data['holdout'])} rows "
        f"(pos {sum(r['label'] for r in data['holdout'])} / "
        f"neg {sum(1 - r['label'] for r in data['holdout'])})")
    for cid in CLIENT_IDS:
        s = stats[cid]
        log(f"client {cid}: n={s['n']} pos={s['n_positive']} "
            f"neg={s['n_negative']} sources={s['sources']}")

    # Shared vocabulary from merged count sketches only.
    spec = merge_sketches([client_vocab_sketch(parts[c])
                           for c in CLIENT_IDS])
    log(f"feature dim (sketch-merged vocab): {spec.dim}")
    X_test = [extract(r["finding"], spec) for r in data["holdout"]]
    y_test = [r["label"] for r in data["holdout"]]

    clients = {cid: FederatedClient(cid, parts[cid], spec)
               for cid in CLIENT_IDS}
    server = FederatedServer(spec)
    total_local_epochs = int(rounds) * int(local_epochs)

    # Round 0: the untrained global model, for the record.
    m0 = server.evaluate(X_test, y_test)
    log(f"round 0 (init): acc {m0['accuracy']:.4f} "
        f"auc {m0['roc_auc']:.4f}")
    history = [{"round": 0, "metrics": m0}]
    for rnd in range(1, int(rounds) + 1):
        updates = _train_clients(clients, server.global_state,
                                 int(local_epochs), rnd, jobs)
        # Leak check on every update before it is accepted.
        forbidden = []
        for cid in CLIENT_IDS:
            for r in parts[cid][:50]:
                f = r.get("finding") or {}
                for v in (r.get("address") or "",
                          str(f.get("value") or "")[:40]):
                    if v:
                        forbidden.append(v)
        leaks = []
        for u in updates:
            leaks += payload_contains_row_material(
                u, forbidden[:200])
        if leaks:
            raise ValueError(f"update payload leaked row material: "
                             f"{leaks[:3]}")
        server.aggregate(updates)
        m = server.evaluate(X_test, y_test)
        history.append({"round": rnd, "metrics": m})
        log(f"round {rnd}: acc {m['accuracy']:.4f} "
            f"auc {m['roc_auc']:.4f} "
            f"fp-recall {m['recall_likely_fp']:.4f} "
            f"wv-recall {m['recall_worth_validating']:.4f} "
            f"cm={m['confusion']}")

    fed_metrics = server.evaluate(X_test, y_test)

    # Local-only models: same total local epochs as the federated
    # clients did across all rounds. Trained in parallel like the
    # rounds above (independent models, same math either way).
    local_only = {}
    lo_args = [(clients[cid], X_test, y_test, total_local_epochs)
               for cid in CLIENT_IDS]
    lo_results = None
    if int(jobs) > 1:
        try:
            ctx = multiprocessing.get_context("fork")
            with ctx.Pool(processes=min(int(jobs), len(lo_args))) as pool:
                lo_results = pool.map(_local_only_job, lo_args)
        except Exception:
            lo_results = None
    if lo_results is None:
        lo_results = [_local_only_job(a) for a in lo_args]
    for cid, m in lo_results:
        local_only[cid] = m
        log(f"local-only {cid} ({total_local_epochs} epochs): "
            f"acc {m['accuracy']:.4f} auc {m['roc_auc']:.4f} "
            f"cm={m['confusion']}")

    # Central baseline: whole pool, same spec + arch. Skipped when
    # central_epochs=0 (run it separately; it is the slow part).
    central_metrics = None
    if int(central_epochs) > 0:
        X_pool, y_pool = [], []
        for cid in CLIENT_IDS:
            X_pool += clients[cid].X
            y_pool += clients[cid].y
        _net, central_metrics = train_central(
            X_pool, y_pool, X_test, y_test, epochs=int(central_epochs))
        log(f"central v2 ({central_epochs} epochs, whole pool): "
            f"acc {central_metrics['accuracy']:.4f} "
            f"auc {central_metrics['roc_auc']:.4f} "
            f"cm={central_metrics['confusion']}")

    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "protocol": UPDATE_PROTOCOL,
        "architecture": LAYERS,
        "layers": LAYERS,
        "n_features": spec.dim,
        "feature_names": spec.feature_names(),
        "seed": SEED,
        "rounds": int(rounds),
        "local_epochs_per_round": int(local_epochs),
        "central_epochs": int(central_epochs),
        "devices_live": ["vm"],
        "devices_simulated_partitions": list(CLIENT_IDS),
        "honest_note": ("Demo ran on this VM only, with 3 local "
                        "partitions. No second live device took part; "
                        "the linux-box and phone clients are local "
                        "partitions standing in for those devices."),
        "holdout": {"n": len(data["holdout"]),
                    "n_positive": sum(y_test),
                    "n_negative": len(y_test) - sum(y_test),
                    "seed": HOLDOUT_SEED, "test_frac": TEST_FRAC},
        "partitions": stats,
        "dataset": data["stats"],
        "history": history,
        "federated_metrics": fed_metrics,
        "local_only_metrics": local_only,
        "central_metrics": central_metrics,
        "limits": [
            "Triage only. The federated model ranks findings by how "
            "much they look like past candidates that survived "
            "triage. It does not verify anything.",
            "Zero verified-real positives exist in the training "
            "data, so the model never predicts VERIFIED_REAL and "
            "must never be used to claim one.",
            "Federated training trades accuracy for privacy: raw "
            "findings never leave a device, so the global model "
            "sees no centralised data. If it scores below the "
            "central baseline, that gap is the privacy cost, not a "
            "bug to hide.",
            "Findings from plugins or chains unseen in training "
            "fall into the OTHER bucket.",
        ],
    }

    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        weights = {
            "format": "recon-nn-weights/1",
            "trained_at": result["trained_at"],
            "mlp": {"format": "recon-nn-mlp/1",
                    "layers": server.net.layers,
                    "lr": server.net.lr, "l2": server.net.l2,
                    "seed": server.net.seed,
                    "weights": server.net.weights,
                    "biases": server.net.biases},
            "features": spec.to_dict(),
            "metrics": {"train": None, "test": fed_metrics},
            "dataset": data["stats"],
            "federated": {
                "protocol": UPDATE_PROTOCOL,
                "rounds": int(rounds),
                "local_epochs_per_round": int(local_epochs),
                "partitions": stats,
                "devices_live": ["vm"],
                "honest_note": result["honest_note"],
            },
            "limits": result["limits"],
        }
        (out / "federated-weights.json").write_text(
            json.dumps(weights, indent=2), encoding="utf-8")
        (out / "federated-viewer-data.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8")
        log(f"wrote {out / 'federated-weights.json'}")
        log(f"wrote {out / 'federated-viewer-data.json'}")
    return result


def load_federated_model(path: Optional[str] = None):
    """Load a federated weights file with the normal pipeline
    loader: federated weights are the same recon-nn-weights/1
    format, so scoring needs no new code path."""
    from .pipeline import load_model
    default = Path(__file__).resolve().parent / "federated-weights.json"
    return load_model(str(path) if path else str(default))


# ---------------------------------------------------------------------------
# HTTP transport: a real second device can join this
# ---------------------------------------------------------------------------


def _auth_ok(handler: BaseHTTPRequestHandler, token: Optional[str]
             ) -> bool:
    if not token:
        return True
    return (handler.headers.get("Authorization") or "") == f"Bearer {token}"


def make_http_handler(server_state: Dict, token: Optional[str]):
    """Build a request handler bound to one FederatedServer.

    GET  /model  -> {round, layers, weights, biases, spec}
    POST /update -> accepts one client update payload, stores it
    POST /aggregate -> averages all stored updates for the round
    GET  /status -> {round, updates_received, client_ids}
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep the demo quiet
            pass

        def _send_json(self, code: int, obj: Dict) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> Dict:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def do_GET(self):
            if not _auth_ok(self, token):
                self._send_json(401, {"error": "unauthorized"})
                return
            srv: FederatedServer = server_state["server"]
            if self.path == "/model":
                st = srv.global_state
                self._send_json(200, {
                    "protocol": UPDATE_PROTOCOL, "round": srv.round,
                    "layers": srv.layers, "weights": st["weights"],
                    "biases": st["biases"],
                    "spec": srv.spec.to_dict()})
            elif self.path == "/status":
                self._send_json(200, {
                    "round": srv.round,
                    "updates_received": sorted(
                        server_state["pending"]),
                    "expected_clients": sorted(
                        server_state["expected"])})
            else:
                self._send_json(404, {"error": "unknown path"})

        def do_POST(self):
            if not _auth_ok(self, token):
                self._send_json(401, {"error": "unauthorized"})
                return
            srv: FederatedServer = server_state["server"]
            try:
                body = self._read_json()
            except Exception as e:  # noqa: BLE001 - bad client JSON
                self._send_json(400, {"error": f"bad json: {e}"})
                return
            if self.path == "/update":
                try:
                    validate_update_payload(body, srv.layers)
                except ValueError as e:
                    self._send_json(400, {"error": str(e)})
                    return
                server_state["pending"][body["client_id"]] = body
                self._send_json(200, {"ok": True,
                                      "round": srv.round,
                                      "received": body["client_id"]})
            elif self.path == "/aggregate":
                pending = server_state["pending"]
                if not pending:
                    self._send_json(400, {"error": "no updates yet"})
                    return
                try:
                    srv.aggregate(list(pending.values()))
                except ValueError as e:
                    self._send_json(400, {"error": str(e)})
                    return
                server_state["pending"] = {}
                self._send_json(200, {"ok": True, "round": srv.round})
            else:
                self._send_json(404, {"error": "unknown path"})

    return Handler


class FederatedHTTPServer:
    """Stdlib HTTP server wrapping a FederatedServer, so a remote
    device (Jay's Linux box, his phone via the linuxtomux bridge)
    can train a round against it. Bind 127.0.0.1 by default; pass
    host=0.0.0.0 only on a trusted LAN, and set a token via the
    FEDERATED_TOKEN env var."""

    def __init__(self, spec: FeatureSpec, host: str = "127.0.0.1",
                 port: int = 8766, expected_clients: Sequence[str] = (),
                 token: Optional[str] = None,
                 layers: Sequence[int] = LAYERS) -> None:
        self.server = FederatedServer(spec, layers=list(layers))
        self.state: Dict = {"server": self.server, "pending": {},
                            "expected": list(expected_clients)}
        self.token = token if token is not None else os.environ.get(
            "FEDERATED_TOKEN")
        handler = make_http_handler(self.state, self.token)
        self.httpd = ThreadingHTTPServer((host, int(port)), handler)
        self.host = host
        self.port = int(port)
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        kwargs={"poll_interval": 0.1},
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class RemoteClient:
    """A federated client that talks to a FederatedHTTPServer over
    HTTP instead of in-process calls. Same local_train, same
    payload: only weight updates leave the device."""

    def __init__(self, client_id: str, rows: Sequence[Dict],
                 server_url: str, token: Optional[str] = None) -> None:
        self.client_id = client_id
        self.rows = list(rows)
        self.server_url = server_url.rstrip("/")
        self.token = token if token is not None else os.environ.get(
            "FEDERATED_TOKEN")
        self.spec: Optional[FeatureSpec] = None
        self.layers: List[int] = list(LAYERS)
        self.sketch = client_vocab_sketch(self.rows)

    def _req(self, method: str, path: str,
             body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.server_url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise ValueError(
                f"server {method} {path} -> {e.code}: "
                f"{e.read().decode('utf-8', 'replace')[:200]}") from e

    def fetch_model(self) -> Dict:
        """GET /model: global state + shared spec. No rows involved."""
        model = self._req("GET", "/model")
        if model.get("protocol") != UPDATE_PROTOCOL:
            raise ValueError("server speaks an unknown protocol")
        self.layers = list(model["layers"])
        self.spec = FeatureSpec.from_dict(model["spec"])
        return {"weights": model["weights"], "biases": model["biases"]}

    def train_round(self, epochs: int, round_no: int) -> Dict:
        """Fetch the global model, train locally, POST the update."""
        state = self.fetch_model()
        client = FederatedClient(self.client_id, self.rows,
                                 self.spec, self.layers)
        update = client.local_train(state, epochs, round_no)
        return self._req("POST", "/update", update)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_report(result: Dict) -> None:
    fm = result["federated_metrics"]
    cm = result["central_metrics"]
    print(f"holdout: n={result['holdout']['n']} "
          f"(pos {result['holdout']['n_positive']} / "
          f"neg {result['holdout']['n_negative']})")
    print(f"federated ({result['rounds']} rounds x "
          f"{result['local_epochs_per_round']} local epochs): "
          f"acc {fm['accuracy']:.4f} auc {fm['roc_auc']:.4f} "
          f"cm={fm['confusion']}")
    for cid, m in result["local_only_metrics"].items():
        print(f"local-only {cid}: acc {m['accuracy']:.4f} "
              f"auc {m['roc_auc']:.4f} cm={m['confusion']}")
    if cm is not None:
        print(f"central v2 ({result['central_epochs']} epochs): "
              f"acc {cm['accuracy']:.4f} auc {cm['roc_auc']:.4f} "
              f"cm={cm['confusion']}")
    else:
        print("central v2: skipped (central_epochs=0)")
    print("LIMITS: triage only; never predicts VERIFIED_REAL; "
          "demo ran on this VM only (local partitions).")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Federated learning for the triage scorer.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run the local-partition demo")
    d.add_argument("--rounds", type=int, default=6)
    d.add_argument("--local-epochs", type=int, default=2)
    d.add_argument("--central-epochs", type=int, default=60)
    d.add_argument("--jobs", type=int, default=3,
                   help="parallel workers for client training "
                        "(1 = sequential)")
    d.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    d.add_argument("--batches", default=DEFAULT_BATCHES)
    d.add_argument("--external", default=None)
    d.add_argument("--out", default=os.path.dirname(
        os.path.abspath(__file__)))

    s = sub.add_parser("serve", help="serve the HTTP aggregator")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8766)
    s.add_argument("--clients", default="vm,linux-box,phone",
                   help="comma-separated expected client ids")
    s.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    s.add_argument("--batches", default=DEFAULT_BATCHES)
    s.add_argument("--external", default=None)

    c = sub.add_parser("client", help="train one round vs a server")
    c.add_argument("--server", required=True)
    c.add_argument("--client-id", required=True)
    c.add_argument("--rounds", type=int, default=1)
    c.add_argument("--local-epochs", type=int, default=2)
    c.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    c.add_argument("--batches", default=DEFAULT_BATCHES)
    c.add_argument("--external", default=None)
    c.add_argument("--data-mode", default="partition",
                   choices=("partition", "own-only"),
                   help="partition: take this client-id's slice of the "
                        "local pool (demo). own-only: train on ALL of "
                        "this device's own rows (real deployment: a "
                        "remote device trains on its own scanner "
                        "results, never on rows from another device).")

    args = ap.parse_args(argv)
    if args.cmd == "demo":
        result = run_demo(
            rounds=args.rounds, local_epochs=args.local_epochs,
            central_epochs=args.central_epochs,
            candidates_path=os.path.expanduser(args.candidates),
            batches_path=os.path.expanduser(args.batches),
            external_path=(os.path.expanduser(args.external)
                           if args.external else None),
            out_dir=args.out, jobs=args.jobs)
        _print_report(result)
        return 0
    if args.cmd == "serve":
        data = load_federated_data(
            os.path.expanduser(args.candidates),
            os.path.expanduser(args.batches),
            os.path.expanduser(args.external) if args.external else None,
            cache_path="/tmp/fed-pool-cache.json")
        parts = partition_training_pool(data["own_train"],
                                        data["external"])
        spec = merge_sketches([client_vocab_sketch(parts[c])
                               for c in CLIENT_IDS])
        expected = [x for x in args.clients.split(",") if x]
        srv = FederatedHTTPServer(spec, host=args.host, port=args.port,
                                  expected_clients=expected)
        srv.start()
        print(f"federated aggregator on {srv.url} "
              f"(expecting: {', '.join(expected)})")
        print("round flow: each client trains and POSTs /update, "
              "then POST /aggregate (or wait for all clients).")
        print("Ctrl-C to stop. Triage only; never VERIFIED_REAL.")
        try:
            while True:
                import time
                time.sleep(3600)
        except KeyboardInterrupt:
            srv.stop()
        return 0
    if args.cmd == "client":
        if args.data_mode == "own-only":
            dataset = build_dataset(
                os.path.expanduser(args.candidates),
                os.path.expanduser(args.batches))
            rows = list(dataset["rows"])
            if args.external:
                ext_rows, _ = load_external_rows(
                    os.path.expanduser(args.external))
                rows = rows + ext_rows
            print(f"client {args.client_id}: training on this device's "
                  f"own rows only (n={len(rows)})")
            remote = RemoteClient(args.client_id, rows, args.server)
        else:
            data = load_federated_data(
                os.path.expanduser(args.candidates),
                os.path.expanduser(args.batches),
                os.path.expanduser(args.external) if args.external else None,
                cache_path="/tmp/fed-pool-cache.json")
            parts = partition_training_pool(data["own_train"],
                                            data["external"])
            if args.client_id not in parts:
                print(f"unknown client {args.client_id!r}; "
                      f"known: {', '.join(CLIENT_IDS)}", file=sys.stderr)
                return 2
            remote = RemoteClient(args.client_id, parts[args.client_id],
                                  args.server)
        for rnd in range(1, args.rounds + 1):
            res = remote.train_round(args.local_epochs, rnd)
            print(f"round {rnd}: update accepted: {res}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
