"""Contract graphs for the GNN triage scorer.

One graph per finding row, built ONLY from real data — never invented:

- nodes: the target contract, its implementation contract when the
  evidence names one (proxy -> implementation), the functions named on
  that contract, and the findings produced on that contract.
- edges: contract-implementation (proxy link), contract-function
  (contains), contract-finding (produces), function-finding (the
  finding is about that function, matched on the real function name).

No edge is synthesised: every node and edge traces to a field in the
row's own evidence or in batches.jsonl (the same scan output the
scorer would see live). A contract with no implementation address
gets no implementation node; a finding with no function gets no
function-finding edge. Graphs are small (3-9 nodes) by design so the
whole thing trains on CPU in pure Python.

Node features (32 dims) reuse the v2 feature vocabulary where it
exists (severity/bounty ordinals, chains, sources, roles) so the
graph and the flat scorer speak the same language.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple

from .features import (
    BOUNTY_ORDER,
    CHAINS,
    CONTRACT_ROLES,
    COUNT_CAP,
    SEVERITY_ORDER,
    SOURCE_ORIGINS,
)

NODE_DIM = 32
GNN_HIDDEN = 16

# Node types (one-hot slots 0-3).
TYPE_CONTRACT = 0
TYPE_IMPLEMENTATION = 1
TYPE_FUNCTION = 2
TYPE_FINDING = 3
NODE_TYPES = ("contract", "implementation", "function", "finding")

MAX_FUNCTION_NODES = 3
MAX_FINDING_NODES = 4  # own finding + up to 3 others on the contract


def _ordinal(value, order) -> float:
    v = (value or "").strip().lower()
    if v not in order:
        return 0.0
    return order.index(v) / max(1, len(order) - 1)


def _one_hot(value, choices) -> List[float]:
    v = (value or "").strip()
    return [1.0 if v == c else 0.0 for c in choices]


def _source_bucket(ev: Dict) -> str:
    src = str(ev.get("source_origin") or "")
    if "sourcify" in src.lower():
        return "Sourcify v2"
    if "blockscout" in src.lower():
        return "Blockscout"
    return "other"


def _chain_bucket(finding: Dict) -> str:
    chain = str(finding.get("chain") or "").lower()
    return chain if chain in CHAINS else "other"


def _node_features(kind: int, finding: Optional[Dict] = None,
                   is_own_finding: bool = False,
                   is_own_function: bool = False,
                   n_nodes: int = 1) -> List[float]:
    """32-dim feature vector for one graph node.

    Finding-specific slots are zero for contract / implementation /
    function nodes: those nodes carry structural facts only, the
    finding node carries the finding's own profile.
    """
    finding = finding or {}
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    vec = [0.0] * NODE_DIM
    vec[kind] = 1.0  # node type one-hot (0-3)
    vec[4:10] = _one_hot(_chain_bucket(finding), CHAINS)
    vec[10:13] = _one_hot(_source_bucket(ev), SOURCE_ORIGINS)
    role = str(ev.get("contract_role") or "other")
    vec[13:17] = _one_hot(
        role if role in CONTRACT_ROLES else "other", CONTRACT_ROLES)
    vec[17] = 1.0 if ev.get("implementation_address") else 0.0
    # Bytecode-only (graph definition): no source and no implementation
    # to read, so only bytecode was available for this node.
    vec[18] = 1.0 if (not ev.get("source_origin")
                      and not ev.get("implementation_address")) else 0.0
    fn = str(finding.get("function") or ev.get("function") or "")
    vec[19] = 1.0 if fn else 0.0
    if kind == TYPE_FINDING:
        try:
            conf = float(finding.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0.0
        vec[20] = _ordinal(str(finding.get("severity")
                               or ev.get("severity") or ""),
                           SEVERITY_ORDER)
        vec[21] = max(0.0, min(1.0, conf / 100.0))
        vec[22] = _ordinal(str(ev.get("risk") or ""), SEVERITY_ORDER)
        vec[23] = _ordinal(str(finding.get("bounty_value") or ""),
                           BOUNTY_ORDER)
        try:
            count = float(finding.get("plugin_finding_count") or 1)
        except (TypeError, ValueError):
            count = 1.0
        vec[24] = max(0.0, min(1.0, count / COUNT_CAP))
        vec[25] = 1.0 if ev.get("gated") else 0.0
        gate = str(ev.get("gate_analysis") or "").lower()
        vec[26] = 1.0 if "no caller gate" in gate else 0.0
        vec[27] = 1.0 if ev.get("detector_outcome") not in (None, "") else 0.0
        vec[28] = min(1.0, len(ev) / 20.0)
        vec[29] = 1.0 if is_own_finding else 0.0
    if kind == TYPE_FUNCTION:
        vec[30] = 1.0 if is_own_function else 0.0
    vec[31] = min(1.0, n_nodes / 8.0)
    return vec


def build_graph(row: Dict,
                contract_findings: Optional[Sequence[Dict]] = None) -> Dict:
    """Build the graph for one training/scoring row.

    row: a data.py row (finding/label/verdict/chain/address/plugin/
    key/function). contract_findings: other findings on the same
    (chain, address) from batches.jsonl (or the live run being
    scored); the row's own finding is always node 0 of the finding
    set. Returns {"nodes": [32-dim vecs], "edges": [(i, j), ...]
    (undirected, i < j), "meta": {...}}.
    """
    finding = dict(row.get("finding") or {})
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    own_function = str(row.get("function")
                        or finding.get("function")
                        or ev.get("function") or "")

    # Finding nodes: own finding first, then up to 3 others on the
    # same contract, distinct plugins, first-seen order. Never the
    # row's own finding twice (same plugin + key).
    finding_nodes: List[Dict] = [finding]
    seen_plugins = {str(finding.get("plugin") or "")}
    for other in (contract_findings or []):
        if len(finding_nodes) >= MAX_FINDING_NODES:
            break
        other = dict(other)
        oev = other.get("evidence") or {}
        if not isinstance(oev, dict):
            oev = {}
        if (str(other.get("plugin") or "") == str(finding.get("plugin") or "")
                and str(other.get("key") or "") == str(finding.get("key") or "")):
            continue
        if str(other.get("plugin") or "") in seen_plugins:
            continue
        seen_plugins.add(str(other.get("plugin") or ""))
        # Stamp the chain so the node reads the real chain.
        other.setdefault("chain", row.get("chain"))
        finding_nodes.append(other)

    # Function nodes: own function first, then the most frequent
    # functions among this contract's findings (real names only).
    func_counts: Counter = Counter()
    for f in finding_nodes:
        fev = f.get("evidence") or {}
        fname = str(f.get("function") or fev.get("function") or "")
        if fname:
            func_counts[fname] += 1
    func_names: List[str] = []
    if own_function:
        func_names.append(own_function)
    for fname, _ in func_counts.most_common():
        if fname not in func_names:
            func_names.append(fname)
        if len(func_names) >= MAX_FUNCTION_NODES:
            break

    impl_address = ev.get("implementation_address") or ""
    has_impl = bool(impl_address)

    # Node order: 0 contract, 1 implementation (if any), then
    # functions, then findings.
    nodes: List[List[float]] = []
    meta: Dict = {"node_kinds": [], "functions": [], "plugins": [],
                  "has_implementation": has_impl,
                  "address": row.get("address") or ev.get("address") or "",
                  "chain": row.get("chain") or ""}
    n_nodes = 1 + (1 if has_impl else 0) + len(func_names) + len(finding_nodes)

    nodes.append(_node_features(TYPE_CONTRACT, finding, n_nodes=n_nodes))
    meta["node_kinds"].append("contract")
    if has_impl:
        impl_finding = dict(finding)
        impl_ev = dict(ev)
        impl_ev["contract_role"] = "implementation"
        impl_finding["evidence"] = impl_ev
        nodes.append(_node_features(TYPE_IMPLEMENTATION, impl_finding,
                                    n_nodes=n_nodes))
        meta["node_kinds"].append("implementation")
    func_idx: Dict[str, int] = {}
    for fname in func_names:
        func_idx[fname] = len(nodes)
        ff = {"function": fname, "chain": row.get("chain"),
              "evidence": {"function": fname}}
        nodes.append(_node_features(
            TYPE_FUNCTION, ff, is_own_function=(fname == own_function),
            n_nodes=n_nodes))
        meta["node_kinds"].append("function")
        meta["functions"].append(fname)
    finding_idx: List[int] = []
    for i, f in enumerate(finding_nodes):
        finding_idx.append(len(nodes))
        fev = f.get("evidence") or {}
        nodes.append(_node_features(
            TYPE_FINDING, f, is_own_finding=(i == 0), n_nodes=n_nodes))
        meta["node_kinds"].append("finding")
        meta["plugins"].append(str(f.get("plugin") or ""))

    edges = set()

    def link(a: int, b: int) -> None:
        if a != b:
            edges.add((min(a, b), max(a, b)))

    contract_i = 0
    impl_i = 1 if has_impl else None
    if impl_i is not None:
        link(contract_i, impl_i)
    for fname, fi in func_idx.items():
        link(contract_i, fi)
    for fi in finding_idx:
        link(contract_i, fi)
    # Function-finding edges: real function-name match only.
    for f, fi in zip(finding_nodes, finding_idx):
        fev = f.get("evidence") or {}
        fname = str(f.get("function") or fev.get("function") or "")
        if fname and fname in func_idx:
            link(func_idx[fname], fi)

    return {"nodes": nodes, "edges": sorted(edges), "meta": meta}


def adjacency(n_nodes: int, edges: Sequence[Tuple[int, int]]) -> List[List[int]]:
    """Undirected neighbour lists (no self-loops; the GNN adds the
    self term separately)."""
    adj: List[List[int]] = [[] for _ in range(n_nodes)]
    for a, b in edges:
        adj[a].append(b)
        adj[b].append(a)
    return adj


def build_contract_index(batches_path: str) -> Dict[Tuple[str, str], List[Dict]]:
    """Index batch findings by (chain, address) for graph context.

    Returns {(chain, address): [finding dicts]}. Findings carry the
    chain stamped on them (batch rows hold it at row level). Torn
    batch lines are skipped and counted in the returned stats under
    the "_torn" key entry.
    """
    index: Dict[Tuple[str, str], List[Dict]] = {}
    torn = 0
    rows = 0
    findings = 0
    with open(batches_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                torn += 1
                continue
            rows += 1
            chain = (row.get("chain") or "").lower()
            address = (row.get("address") or "").lower()
            if not address:
                continue
            key = (chain, address)
            bucket = index.setdefault(key, [])
            for f in row.get("findings") or []:
                if not isinstance(f, dict):
                    continue
                f = dict(f)
                f.setdefault("chain", chain)
                bucket.append(f)
                findings += 1
    # Per-plugin counts, for the finding nodes' count input (same
    # definition as data.py: findings per (chain, address, plugin)).
    counts: Dict[Tuple[str, str, str], int] = {}
    for (chain, address), fs in index.items():
        for f in fs:
            ckey = (chain, address, str(f.get("plugin") or ""))
            counts[ckey] = counts.get(ckey, 0) + 1
    for (chain, address), fs in index.items():
        for f in fs:
            ckey = (chain, address, str(f.get("plugin") or ""))
            f["plugin_finding_count"] = counts.get(ckey, 1)
    return {"index": index, "stats": {"batch_rows": rows,
                                      "batch_findings": findings,
                                      "batch_torn_lines": torn,
                                      "contracts": len(index)}}


def contract_findings_for(index: Dict, chain: str,
                          address: str) -> List[Dict]:
    """Findings on one contract from the index (empty when unknown)."""
    if not index:
        return []
    inner = index.get("index", index) if isinstance(index, dict) else {}
    return list(inner.get(((chain or "").lower(),
                           (address or "").lower()), []))
