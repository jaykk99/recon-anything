"""Deployment-lineage clustering: on-chain addresses -> operator clusters.

A fund-flow trace answers "where did this address's money go". It does not
answer the question that decides whether an audited contract is a business
risk: *who else is behind this deployer, and what have they shipped?*
This module adds that layer.

It is a deterministic, offline clustering pass over an already-fetched
fund-flow graph (``fundflow.build_graph`` / the ``agent_trace`` tool), a
contract list, and optional labels (``cryptolabels``). No network, no
numpy, no graph library: union-find over a handful of explicit rules, so
the same input always yields the same clusters and every link is
explainable.

WHAT LINKS ADDRESSES (and what deliberately does not)
-----------------------------------------------------
* shared deployer - a contract and its creator are the same operator
  (strongest signal: creation is not a payment).
* private funding - an *unlabelled* wallet that funded two addresses is
  treated as their common operator, but only while it fans out to at most
  ``max_funder_fanout`` recipients. Exchange hot wallets, bridges, mixers,
  sanctioned and burn addresses are never used to link: they terminate a
  trace, they do not identify one.
* identical init code + same CREATE2 salt - the same deployment recipe
  (repeated infrastructure, not shared standard library code).
* Identical bytecode *without* the same salt is recorded as a signal but
  does NOT merge clusters: thousands of unrelated tokens share a standard
  ERC-20 implementation.

Output is a hypothesis with its evidence, never attribution: shared
funding is not proof of common control, and the funnel lead says so. This
is analysis only - nothing here signs, sends or deanonymizes.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# A label in one of these categories means "many unrelated addresses touch
# this one": using it to link would merge the world.
TERMINUS_CATEGORIES = {"exchange", "bridge", "mixer", "sanctioned", "burn"}

DEFAULT_MAX_FUNDER_FANOUT = 25

_W_DEPLOYER = 55
_W_FUNDING_NATIVE = 30
_W_FUNDING_TOKEN = 20
_W_INIT_CODE = 25
_W_CODE_CLONE = 8      # signal only, never merges
_W_MULTI_CONTRACT = 10
_LABEL_BONUS = {"sanctioned": 20, "mixer": 15, "bridge": 5,
                "exchange": 0, "burn": 0}

MAX_EVIDENCE = 12


def _addr(value: Any) -> str:
    """Lowercased 0x address, or \"\" when the value is not one."""
    if not isinstance(value, str):
        return ""
    v = value.strip().lower()
    return v if ADDRESS_RE.match(v) else ""


def _short(addr: str) -> str:
    return f"{addr[:6]}…{addr[-4:]}" if len(addr) > 12 else addr


def _label_dicts(labels: Any, address: str) -> List[Dict[str, Any]]:
    """Labels for one address from the caller's map (dict or list form)."""
    if not isinstance(labels, dict):
        return []
    raw = labels.get(address) or labels.get(address.lower())
    if raw is None:
        return []
    if isinstance(raw, str):
        return [{"label": raw, "category": raw.strip().lower()[:20]}]
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class _UnionFind:
    """Union-find whose component root is always the smallest address.

    Deterministic by construction: clusters do not depend on input order.
    """

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def add(self, addr: str) -> None:
        self.parent.setdefault(addr, addr)

    def find(self, addr: str) -> str:
        self.add(addr)
        root = addr
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[addr] != root:
            self.parent[addr], addr = root, self.parent[addr]
        return root

    def union(self, a: str, b: str) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if ra < rb:
            self.parent[rb] = ra
        else:
            self.parent[ra] = rb
        return True


def _contract_dicts(contracts: Any, deployers: Any) -> List[Dict[str, Any]]:
    """Normalise contracts input (strings, dicts) + a deployer map."""
    out: List[Dict[str, Any]] = []
    seen = set()
    items: Iterable[Any] = contracts or []
    if isinstance(contracts, dict):
        items = [dict(v, address=k) if isinstance(v, dict) else
                 {"address": k, "deployer": v}
                 for k, v in contracts.items()]
    for item in items:
        if isinstance(item, str):
            addr = _addr(item)
            if addr:
                out.append({"address": addr})
                seen.add(addr)
            continue
        if not isinstance(item, dict):
            continue
        addr = _addr(item.get("address") or item.get("contract")
                     or item.get("contract_address"))
        if not addr or addr in seen:
            continue
        seen.add(addr)
        out.append({
            "address": addr,
            "deployer": _addr(item.get("deployer") or item.get("creator")),
            "funder": _addr(item.get("funder")),
            "bytecode_hash": str(item.get("bytecode_hash")
                                 or item.get("code_hash") or "").lower(),
            "salt": str(item.get("salt") or "").lower(),
            "chain": str(item.get("chain") or ""),
        })
    if isinstance(deployers, dict):
        by_addr = {c["address"]: c for c in out}
        for contract, deployer in deployers.items():
            c_addr, d_addr = _addr(contract), _addr(deployer)
            if not c_addr or not d_addr:
                continue
            if c_addr in by_addr:
                by_addr[c_addr]["deployer"] = by_addr[c_addr]["deployer"] or d_addr
            else:
                out.append({"address": c_addr, "deployer": d_addr,
                            "funder": "", "bytecode_hash": "", "salt": "",
                            "chain": ""})
    return out


def _normalise_edges(edges: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for e in edges or []:
        if not isinstance(e, dict):
            continue
        frm, to = _addr(e.get("from")), _addr(e.get("to"))
        if not frm or not to or frm == to:
            continue
        out.append({"from": frm, "to": to,
                    "asset": str(e.get("asset") or "").lower(),
                    "amount_raw": _int(e.get("amount_raw")),
                    "tx_hash": str(e.get("tx_hash") or ""),
                    "block": _int(e.get("block"))})
    out.sort(key=lambda e: (e["block"], e["tx_hash"], e["from"], e["to"],
                            e["asset"]))
    return out


def _is_native(edge: Dict[str, Any]) -> bool:
    return not ADDRESS_RE.match(edge.get("asset") or "")


def cluster(edges: Any = None, contracts: Any = None, deployers: Any = None,
            labels: Any = None,
            max_funder_fanout: int = DEFAULT_MAX_FUNDER_FANOUT) -> Dict[str, Any]:
    """Cluster addresses into deployment lineages.

    Returns ``{clusters, cluster_count, counts, linked_contracts,
    unlinked_contracts, input, note}``. Pure, deterministic, never raises.
    """
    try:
        return _cluster(edges, contracts, deployers, labels,
                        max_funder_fanout)
    except Exception as exc:  # noqa: BLE001 - never break a scan
        return {"clusters": [], "cluster_count": 0, "counts": {},
                "linked_contracts": 0, "unlinked_contracts": [],
                "input": {}, "error": str(exc)[:160],
                "note": "lineage clustering unavailable"}


def _cluster(edges: Any, contracts: Any, deployers: Any, labels: Any,
             max_funder_fanout: int) -> Dict[str, Any]:
    edge_list = _normalise_edges(edges)
    contract_list = _contract_dicts(contracts, deployers)
    max_fanout = max(2, _int(max_funder_fanout, DEFAULT_MAX_FUNDER_FANOUT))

    uf = _UnionFind()
    for c in contract_list:
        uf.add(c["address"])
        if c["deployer"]:
            uf.add(c["deployer"])
    for e in edge_list:
        uf.add(e["from"])
        uf.add(e["to"])

    signals: Dict[str, Dict[str, Any]] = {}
    for c in contract_list:
        signals[c["address"]] = {
            "deployer": c["deployer"], "funder": c["funder"],
            "bytecode_hash": c["bytecode_hash"], "salt": c["salt"],
            "chain": c["chain"]}

    rule_hits: Dict[frozenset, List[Dict[str, Any]]] = {}
    deployer_links: List[Dict[str, Any]] = []
    funding_links: List[Dict[str, Any]] = []
    init_code: List[Dict[str, Any]] = []
    code_clones: List[Dict[str, Any]] = []
    terminus: List[Dict[str, Any]] = []

    def _record(kind: str, a: str, b: str, weight: int,
                detail: str, **extra: Any) -> None:
        uf.union(a, b)
        pair = frozenset((a, b))
        rec = {"kind": kind, "addresses": sorted((a, b)), "weight": weight,
               "detail": detail, **extra}
        rule_hits.setdefault(pair, []).append(rec)

    # 1. contract -> deployer (strongest: creation is not a payment)
    for c in contract_list:
        if not c["deployer"]:
            continue
        _record("shared_deployer", c["address"], c["deployer"], _W_DEPLOYER,
                f"{_short(c['address'])} was deployed by "
                f"{_short(c['deployer'])}", contract=c["address"],
                deployer=c["deployer"])
        deployer_links.append({"deployer": c["deployer"],
                               "contracts": [c["address"]]})

    # 2. funding relationships, minus hubs and labelled terminus addresses
    recipients: Dict[str, List[str]] = {}
    for e in edge_list:
        recipients.setdefault(e["from"], [])
        if e["to"] not in recipients[e["from"]]:
            recipients[e["from"]].append(e["to"])

    for e in edge_list:
        frm, to = e["from"], e["to"]
        labs = _label_dicts(labels, frm)
        cats = {str(l.get("category") or "").lower() for l in labs}
        if cats & TERMINUS_CATEGORIES:
            terminus.append({"address": frm, "funded": to,
                             "label": (labs[0].get("label") if labs else ""),
                             "categories": sorted(cats)})
            continue
        if len(recipients.get(frm, [])) > max_fanout:
            continue  # hub-like funder: treats unrelated users alike
        weight = _W_FUNDING_NATIVE if _is_native(e) else _W_FUNDING_TOKEN
        _record("funded", frm, to, weight,
                f"{_short(frm)} funded {_short(to)}"
                + (f" ({e['tx_hash'][:12]}…)" if e["tx_hash"] else ""),
                tx_hash=e["tx_hash"], asset=e["asset"], block=e["block"])
        funding_links.append({"funder": frm, "funded": to,
                              "asset": e["asset"], "tx_hash": e["tx_hash"]})

    # 3. identical init code + same CREATE2 salt (same deployment recipe)
    by_recipe: Dict[Tuple[str, str], List[str]] = {}
    by_code: Dict[str, List[str]] = {}
    for c in contract_list:
        if c["bytecode_hash"] and c["salt"]:
            by_recipe.setdefault((c["bytecode_hash"], c["salt"]), []).append(
                c["address"])
        if c["bytecode_hash"]:
            by_code.setdefault(c["bytecode_hash"], []).append(c["address"])
    for (code_hash, salt), addrs in by_recipe.items():
        addrs = sorted(set(addrs))
        for other in addrs[1:]:
            _record("init_code", addrs[0], other, _W_INIT_CODE,
                    f"same init code and CREATE2 salt ({salt[:12]}) as "
                    f"{_short(addrs[0])}", bytecode_hash=code_hash, salt=salt)
        init_code.append({"contracts": addrs, "bytecode_hash": code_hash,
                          "salt": salt})
    for code_hash, addrs in by_code.items():
        addrs = sorted(set(addrs))
        if len(addrs) >= 2:
            code_clones.append({"contracts": addrs,
                                "bytecode_hash": code_hash})

    # 4. group components
    groups: Dict[str, List[str]] = {}
    for addr in sorted(uf.parent):
        groups.setdefault(uf.find(addr), []).append(addr)

    contract_addrs = {c["address"] for c in contract_list}
    clusters: List[Dict[str, Any]] = []
    unlinked: List[Dict[str, Any]] = []
    for root, members in groups.items():
        members = sorted(set(members))
        if len(members) < 2:
            continue
        contracts_in = [a for a in members if a in contract_addrs]
        pair_hits: List[Dict[str, Any]] = []
        for a in members:
            for b in members:
                if a < b:
                    pair_hits.extend(rule_hits.get(frozenset((a, b)), []))
        kinds = sorted({h["kind"] for h in pair_hits})

        cluster_labels: List[Dict[str, Any]] = []
        seen_labels = set()
        for addr in members:
            for lab in _label_dicts(labels, addr):
                key = (addr, str(lab.get("label") or ""))
                if key in seen_labels:
                    continue
                seen_labels.add(key)
                cluster_labels.append({"address": addr,
                                       "label": lab.get("label"),
                                       "category": str(lab.get("category")
                                                       or "").lower(),
                                       "severity": lab.get("severity")})
        cluster_labels.sort(key=lambda l: (l["address"], str(l["label"])))

        confidence = 0
        if "shared_deployer" in kinds:
            confidence += _W_DEPLOYER
        if "funded" in kinds:
            confidence += _W_FUNDING_NATIVE
        if "init_code" in kinds:
            confidence += _W_INIT_CODE
        if len(contracts_in) >= 2:
            confidence += _W_MULTI_CONTRACT
        label_cats = {l["category"] for l in cluster_labels}
        for cat, bonus in _LABEL_BONUS.items():
            if cat in label_cats:
                confidence += bonus
        clone_hit = any(set(c["contracts"]) & set(members)
                        for c in code_clones)
        if clone_hit:
            confidence += _W_CODE_CLONE
        confidence = max(0, min(100, confidence))
        risk = ("high" if confidence >= 70 or "sanctioned" in label_cats
                else "medium" if confidence >= 40 else "low")

        evidence = sorted(
            ({"kind": h["kind"], "detail": h["detail"],
              "addresses": h["addresses"]} for h in pair_hits),
            key=lambda e: (e["kind"], e["addresses"], e["detail"]))[:MAX_EVIDENCE]
        funding_for_members = [f for f in funding_links
                               if f["funder"] in members]
        clusters.append({
            # sha1 of the anchor: stable across inputs, unique per cluster
            # (a truncated address collides when prefixes repeat).
            "id": "lin-" + hashlib.sha1(
                root.encode("utf-8")).hexdigest()[:8],
            "anchor": root,
            "size": len(members),
            "members": members,
            "contracts": contracts_in,
            "chains": sorted({signals[a].get("chain", "") for a in contracts_in
                              if signals.get(a, {}).get("chain")}),
            "signals": kinds,
            "confidence": confidence,
            "risk": risk,
            "labels": cluster_labels,
            "evidence": evidence,
            "funding": sorted(funding_for_members,
                              key=lambda f: (f["funder"], f["funded"]))[:12],
            "note": ("Hypothesis from shared signals, not attribution: "
                     "shared funding does not prove common control."),
        })

    for c in contract_list:
        if c["address"] not in [a for cl in clusters for a in cl["members"]]:
            unlinked.append({"contract": c["address"],
                             "deployer": c["deployer"]})
    clusters.sort(key=lambda cl: (-cl["confidence"], cl["anchor"]))
    linked = sum(len(cl["contracts"]) for cl in clusters)
    counts: Dict[str, int] = {}
    for cl in clusters:
        counts[cl["risk"]] = counts.get(cl["risk"], 0) + 1

    return {
        "clusters": clusters,
        "cluster_count": len(clusters),
        "counts": counts,
        "linked_contracts": linked,
        "unlinked_contracts": sorted(unlinked, key=lambda u: u["contract"]),
        "input": {"edges": len(edge_list), "contracts": len(contract_list),
                  "max_funder_fanout": max_fanout,
                  "terminus_funders": sorted(
                      {t["address"] for t in terminus})[:12]},
        "note": ("Deterministic clustering over supplied fund-flow edges, "
                 "contract deployers and labels. Exchange/bridge/mixer/"
                 "sanctioned/burn addresses and hub funders are never used "
                 "to link addresses. Clusters are hypotheses, not "
                 "attribution."),
    }


def from_findings(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract contracts, deployers and funder edges from run findings.

    Reads the provenance shape plugins already emit
    (``evidence.hit = {contract, creator, funder}``) plus any
    contract/deployer/funder keys, so a completed run can be clustered
    without re-tracing the chain.
    """
    contracts: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    labels: Dict[str, Any] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        ev = row.get("evidence")
        ev = ev if isinstance(ev, dict) else {}
        candidates = [ev.get("hit"), ev, row]
        for src in candidates:
            if not isinstance(src, dict):
                continue
            contract = _addr(src.get("contract") or src.get("contract_address"))
            deployer = _addr(src.get("deployer") or src.get("creator")
                             or src.get("creator_address"))
            funder = _addr(src.get("funder") or src.get("funder_address"))
            if contract:
                rec = contracts.setdefault(contract, {"address": contract})
                if deployer:
                    rec["deployer"] = deployer
                if funder:
                    rec["funder"] = funder
            label = src.get("funder_label") or src.get("label")
            if funder and isinstance(label, str) and label.strip():
                labels[funder] = label.strip()
            if deployer and funder:
                edges.append({"from": funder, "to": deployer,
                              "asset": "native", "amount_raw": 1,
                              "tx_hash": ""})
        value = row.get("value")
        if isinstance(value, str):
            for token in value.split():
                addr = _addr(token.strip(".,;()[]"))
                if addr and row.get("category") in ("web3", "chain", "crypto"):
                    contracts.setdefault(addr, {"address": addr})
    return {"edges": edges, "contracts": sorted(contracts.values(),
                                                key=lambda c: c["address"]),
            "labels": labels}


def to_findings(report: Dict[str, Any], max_per_cluster: int = 5) -> List[Dict[str, Any]]:
    """Funnel-shaped finding rows, one per (cluster, audited contract)."""
    out: List[Dict[str, Any]] = []
    if not isinstance(report, dict):
        return out
    for cl in report.get("clusters") or []:
        if not isinstance(cl, dict):
            continue
        contracts = [c for c in (cl.get("contracts") or []) if isinstance(c, str)]
        contract_previous = contracts[:max(1, max_per_cluster)]
        signals = ", ".join(cl.get("signals") or []) or "shared signals"
        members = [m for m in (cl.get("members") or []) if isinstance(m, str)]
        for contract in contract_previous or [""]:
            value = (f"Cluster {cl.get('id')}: {cl.get('size')} addresses "
                     f"linked by {signals}"
                     + (f" around contract {contract}" if contract else
                        f" around {_short(members[0]) if members else 'target'}"))
            out.append({
                "plugin": "lineage", "category": "web3",
                "key": "deployment_cluster", "value": value,
                "confidence": int(cl.get("confidence") or 0),
                "evidence": {
                    "severity": cl.get("risk") or "low",
                    "exploitability": "unknown",
                    "cluster_id": cl.get("id"),
                    "contract": contract or None,
                    "signals": list(cl.get("signals") or []),
                    "members": members[:8],
                    "labels": [l.get("label") for l in
                               (cl.get("labels") or [])][:5],
                },
            })
    return out


def augment(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Append lineage findings derived from an existing finding list."""
    base = [r for r in (rows or []) if isinstance(r, dict)]
    try:
        report = cluster(**from_findings(base))
        return base + to_findings(report)
    except Exception:  # noqa: BLE001
        return base


def render_markdown(report: Dict[str, Any], limit: int = 5) -> str:
    """Markdown section for the exports (empty when there is no lineage)."""
    clusters = [c for c in (report or {}).get("clusters") or []
                if isinstance(c, dict)]
    if not clusters:
        return ""
    out = ["## Deployment lineage",
           "_Clusters of addresses that share a deployer, a private funder "
           "or the same CREATE2 recipe. Each is a hypothesis with its "
           "evidence attached - shared funding is not proof of common "
           "control._", ""]
    for i, cl in enumerate(clusters[:limit], 1):
        contracts = ", ".join(f"`{c}`" for c in (cl.get("contracts") or [])[:5])
        out.append(f"### {i}. [{cl.get('confidence')}/100] cluster "
                   f"`{cl.get('id')}` - {cl.get('risk')} risk")
        out.append(f"- **Audited contracts:** {contracts or '(none linked)'}")
        out.append(f"- **Members:** {cl.get('size')} addresses "
                   f"(signals: {', '.join(cl.get('signals') or []) or 'none'})")
        for ev in (cl.get("evidence") or [])[:3]:
            out.append(f"- **Link:** {ev.get('detail')}")
        labels = [l for l in (cl.get("labels") or []) if l.get("label")]
        if labels:
            out.append("- **Public labels:** "
                       + "; ".join(str(l.get("label")) for l in labels[:3]))
        out.append("")
    return "\n".join(out)


__all__ = ["ADDRESS_RE", "augment", "cluster", "from_findings",
           "render_markdown", "to_findings"]
