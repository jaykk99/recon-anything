"""Build sheaf hyperedges from ReconAnything's real data.

Sources (all read-only; nothing here writes to them):
- ~/workspace/recon-continuous/results/candidates.jsonl (727 rows)
- ~/workspace/recon-continuous/state/transition_events.jsonl (52 rows)
- multi-hop call-graph paths, PR #178 shape (no real paths exist on
  disk for these contracts yet, so call_path hyperedges are built
  only when paths are supplied).

A hyperedge is built from the rows that belong to ONE event. Rows
are never flattened into a single vector and never invented: a
missing field stays missing (the stalk simply lacks that fact) and
a null owner stays the explicit key "null" so two unknowns never
merge with a real address.

Pure Python stdlib.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from .sheaf import (NULL_KEY, Fact, Hyperedge, Stalk, entity_contract,
                    entity_finding, entity_owner, entity_symbol)


def load_jsonl(path: str):
    """Yield parsed rows, skipping torn lines (counted by caller)."""
    rows = []
    torn = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                torn += 1
    return rows, torn


def _fact(entity, field_name, value, source):
    return Fact(entity, field_name, value, source)


def _stalk(entity, items):
    return Stalk(entity, {name: fact for name, fact in items})


def build_owner_transition_hyperedges(transitions):
    """One hyperedge per owner-transition row.

    Entities: the contract, the before-owner, the after-owner.
    The contract's stalk carries both owners plus block and time,
    so the hyperedge is the whole event, not three loose facts.
    """
    edges = []
    for i, row in enumerate(transitions):
        source = "transition_events.jsonl#%d" % i
        chain = row.get("chain") or ""
        address = row.get("address") or ""
        contract = entity_contract(chain, address)
        before = entity_owner((row.get("before") or {}).get("owner"))
        after = entity_owner((row.get("after") or {}).get("owner"))
        entities = frozenset([contract, before, after])
        stalks = {
            contract: _stalk(contract, [
                ("chain", _fact(contract, "chain", chain, source)),
                ("address", _fact(contract, "address", address, source)),
                ("symbol", _fact(contract, "symbol", row.get("symbol"),
                                 source)),
                ("owner_before", _fact(
                    contract, "owner_before",
                    (row.get("before") or {}).get("owner"), source)),
                ("owner_after", _fact(
                    contract, "owner_after",
                    (row.get("after") or {}).get("owner"), source)),
                ("block", _fact(contract, "block", row.get("block"),
                                source)),
                ("detected_at", _fact(contract, "detected_at",
                                      row.get("detected_at"), source)),
            ]),
            before: _stalk(before, [
                ("role", _fact(before, "role", "previous_owner", source)),
            ]),
            after: _stalk(after, [
                ("role", _fact(after, "role", "current_owner", source)),
            ]),
        }
        edges.append(Hyperedge(
            id="owner_transition:%s:%s#%d" % (chain, address, i),
            kind="owner_transition",
            entities=entities,
            stalks=stalks,
            meta={"chain": chain, "address": address,
                  "detected_at": row.get("detected_at"),
                  "block": row.get("block"), "row": i}))
    return edges


def build_finding_cluster_hyperedges(candidates):
    """One hyperedge per contract: the contract + all its findings.

    Entities: the contract plus one finding entity per candidate row
    on it. Each finding's stalk carries the plugin, verdict,
    recipient, function, live-probe outcome and the validator's own
    binding -- the local facts the consistency checks compare.
    """
    grouped = defaultdict(list)
    for i, row in enumerate(candidates):
        grouped[(row.get("chain") or "",
                 row.get("address") or "")].append((i, row))
    edges = []
    for (chain, address), items in sorted(grouped.items()):
        contract = entity_contract(chain, address)
        entities = {contract}
        stalks = {
            contract: _stalk(contract, [
                ("chain", _fact(contract, "chain", chain,
                                "candidates.jsonl")),
                ("address", _fact(contract, "address", address,
                                  "candidates.jsonl")),
                ("symbol", _fact(contract, "symbol",
                                 items[0][1].get("symbol"),
                                 "candidates.jsonl")),
                ("n_findings", _fact(contract, "n_findings", len(items),
                                     "candidates.jsonl")),
            ]),
        }
        for i, row in items:
            source = "candidates.jsonl#%d" % i
            finding = entity_finding(chain, address,
                                     row.get("plugin") or "",
                                     row.get("key") or "")
            entities.add(finding)
            validation = row.get("validation") or {}
            live = row.get("live_probe") or {}
            evidence = validation.get("evidence") or {}
            stalks[finding] = _stalk(finding, [
                ("chain", _fact(finding, "chain", chain, source)),
                ("address", _fact(finding, "address", address, source)),
                ("plugin", _fact(finding, "plugin", row.get("plugin"),
                                 source)),
                ("key", _fact(finding, "key", row.get("key"), source)),
                ("severity", _fact(finding, "severity",
                                   row.get("severity"), source)),
                ("function", _fact(finding, "function",
                                   row.get("function"), source)),
                ("recipient_class", _fact(finding, "recipient_class",
                                         row.get("recipient_class"),
                                         source)),
                ("bytecode_only", _fact(finding, "bytecode_only",
                                        row.get("bytecode_only"), source)),
                ("verdict", _fact(finding, "verdict",
                                  validation.get("verdict"), source)),
                ("validation_chain", _fact(finding, "validation_chain",
                                          validation.get("chain"), source)),
                ("validation_address", _fact(
                    finding, "validation_address",
                    validation.get("address"), source)),
                ("validation_kind", _fact(finding, "validation_kind",
                                         validation.get("kind"), source)),
                ("validation_function", _fact(
                    finding, "validation_function",
                    validation.get("function"), source)),
                ("live_status", _fact(finding, "live_status",
                                      live.get("status"), source)),
                ("evidence_keys", _fact(finding, "evidence_keys",
                                        sorted(evidence.keys()), source)),
                ("source_missing", _fact(
                    finding, "source_missing",
                    "verified source" in (validation.get("missing") or []),
                    source)),
            ])
        edges.append(Hyperedge(
            id="finding_cluster:%s:%s" % (chain, address),
            kind="finding_cluster",
            entities=frozenset(entities),
            stalks=stalks,
            meta={"chain": chain, "address": address,
                  "symbol": items[0][1].get("symbol"),
                  "n_findings": len(items)}))
    return edges


def latest_owner_map(transitions):
    """Per-contract owner timeline summary from transition rows.

    latest_raw: the last after-owner in time order (may be null).
    latest_known: the last non-null owner in time order, or None.
    oscillates: the timeline contains A -> null -> A.
    """
    grouped = defaultdict(list)
    for i, row in enumerate(transitions):
        grouped[(row.get("chain") or "",
                 row.get("address") or "")].append((i, row))
    out = {}
    for key, items in grouped.items():
        items.sort(key=lambda t: str(t[1].get("detected_at") or ""))
        timeline = [((r.get("before") or {}).get("owner"),
                     (r.get("after") or {}).get("owner"),
                     r.get("block"), r.get("detected_at"), i)
                    for i, r in items]
        owners_after = [t[1] for t in timeline]
        known = [o for o in owners_after if o]
        oscillates = any(
            owners_after[i] is None and owners_after[i - 1] is not None
            and owners_after[i - 1] == owners_after[i + 1]
            for i in range(1, len(owners_after) - 1))
        out[key] = {
            "latest_raw": owners_after[-1] if owners_after else None,
            "latest_known": known[-1] if known else None,
            "n_transitions": len(items),
            "oscillates": oscillates,
            "timeline": timeline,
        }
    return out


def build_symbol_cluster_hyperedges(candidates, owner_map):
    """One hyperedge per non-null symbol: the symbol + its contracts.

    Each contract restricts to (symbol, latest known owner). Two
    contracts that name the same symbol but different owners do not
    glue: the token-identity story contradicts itself. Null-symbol
    rows (82 candidates) carry no identity claim and form no
    hyperedge -- grouping 40 unrelated contracts under "no symbol"
    would be an invented relation.
    """
    grouped = defaultdict(list)
    for row in candidates:
        symbol = row.get("symbol")
        if not symbol:
            continue
        grouped[symbol].append(row)
    edges = []
    for symbol, rows in sorted(grouped.items()):
        contracts = {(r.get("chain") or "", r.get("address") or "")
                     for r in rows}
        if len(contracts) < 2:
            continue
        symbol_e = entity_symbol(symbol)
        entities = {symbol_e}
        stalks = {symbol_e: _stalk(symbol_e, [
            ("symbol", _fact(symbol_e, "symbol", symbol,
                             "candidates.jsonl")),
        ])}
        for chain, address in sorted(contracts):
            contract = entity_contract(chain, address)
            entities.add(contract)
            owner = (owner_map.get((chain, address)) or {}).get(
                "latest_known")
            stalks[contract] = _stalk(contract, [
                ("chain", _fact(contract, "chain", chain,
                                "candidates.jsonl")),
                ("address", _fact(contract, "address", address,
                                  "candidates.jsonl")),
                ("symbol", _fact(contract, "symbol", symbol,
                                 "candidates.jsonl")),
                ("owner", _fact(contract, "owner", owner,
                                "transition_events.jsonl")),
            ])
        edges.append(Hyperedge(
            id="symbol_cluster:%s" % symbol,
            kind="symbol_cluster",
            entities=frozenset(entities),
            stalks=stalks,
            meta={"symbol": symbol, "n_contracts": len(contracts)}))
    return edges


def build_owner_cluster_hyperedges(owner_map, candidates):
    """One hyperedge per known owner: the owner + its contracts.

    The contract set comes only from the transition rows (candidates
    carry no owner field), so on real data this is small: only the
    ~10 contracts the watcher tracked. The owner-agreement check is
    vacuous on one source and says so in the docs; it bites only
    when a second owner feed is supplied per contract stalk.
    """
    by_owner = defaultdict(set)
    symbols = {}
    for (chain, address), info in owner_map.items():
        owner = info.get("latest_known")
        if not owner:
            continue
        by_owner[owner].add((chain, address))
    for row in candidates:
        key = (row.get("chain") or "", row.get("address") or "")
        symbols[key] = row.get("symbol")
    edges = []
    for owner, contracts in sorted(by_owner.items()):
        owner_e = entity_owner(owner)
        entities = {owner_e}
        stalks = {owner_e: _stalk(owner_e, [
            ("n_contracts", _fact(owner_e, "n_contracts", len(contracts),
                                  "transition_events.jsonl")),
        ])}
        for chain, address in sorted(contracts):
            contract = entity_contract(chain, address)
            entities.add(contract)
            stalks[contract] = _stalk(contract, [
                ("chain", _fact(contract, "chain", chain,
                                "transition_events.jsonl")),
                ("address", _fact(contract, "address", address,
                                  "transition_events.jsonl")),
                ("owner", _fact(contract, "owner", owner,
                                "transition_events.jsonl")),
                ("symbol", _fact(contract, "symbol",
                                 symbols.get((chain, address)),
                                 "candidates.jsonl")),
            ])
        edges.append(Hyperedge(
            id="owner_cluster:%s" % owner.lower(),
            kind="owner_cluster",
            entities=frozenset(entities),
            stalks=stalks,
            meta={"owner": owner, "n_contracts": len(contracts)}))
    return edges


def build_call_path_hyperedges(paths):
    """One hyperedge per multi-hop call path (PR #178 shape).

    paths: list of dicts with keys:
        id (str), hops (list, in call order, each with caller,
        callee, function, gated, paused, source_available),
        finding_kinds (list of finding-kind strings on the path),
        grade ("candidate" or "trigger-only").
    Each hop's callee becomes a contract entity carrying that hop's
    gate/paused/source facts. With no real paths on disk this builds
    zero hyperedges on real data; it is exercised on toy paths in
    tests and documented as the PR #178 integration point.
    """
    edges = []
    for path in paths or []:
        hops = path.get("hops") or []
        if not hops:
            continue
        entities = set()
        stalks = {}
        for j, hop in enumerate(hops):
            callee = hop.get("callee") or ""
            chain = hop.get("chain") or ""
            contract = entity_contract(chain, callee)
            entities.add(contract)
            source = "call_graph:%s#hop%d" % (path.get("id"), j)
            stalks[contract] = _stalk(contract, [
                ("chain", _fact(contract, "chain", chain, source)),
                ("address", _fact(contract, "address", callee, source)),
                ("function", _fact(contract, "function",
                                   hop.get("function"), source)),
                ("gated", _fact(contract, "gated",
                                bool(hop.get("gated")), source)),
                ("paused", _fact(contract, "paused",
                                 bool(hop.get("paused")), source)),
                ("source_available", _fact(
                    contract, "source_available",
                    bool(hop.get("source_available")), source)),
            ])
        degraded = [j for j, h in enumerate(hops)
                    if not h.get("source_available")]
        edges.append(Hyperedge(
            id="call_path:%s" % path.get("id"),
            kind="call_path",
            entities=frozenset(entities),
            stalks=stalks,
            meta={"hops": hops,
                  "finding_kinds": path.get("finding_kinds") or [],
                  "grade": path.get("grade"),
                  "degraded_hops": degraded,
                  "depth": len(hops)}))
    return edges


def build_all(candidates, transitions, paths=None):
    """Build every hyperedge kind. Returns {kind: [Hyperedge]}."""
    owner_map = latest_owner_map(transitions)
    return {
        "owner_transition": build_owner_transition_hyperedges(transitions),
        "finding_cluster": build_finding_cluster_hyperedges(candidates),
        "symbol_cluster": build_symbol_cluster_hyperedges(candidates,
                                                          owner_map),
        "owner_cluster": build_owner_cluster_hyperedges(owner_map,
                                                        candidates),
        "call_path": build_call_path_hyperedges(paths),
    }
