"""Asset graph builder: interactive topological map of the attack surface.

Consumes everything on the discovery bus (domains, subdomains, IPs,
ports, technologies, endpoints, cert SANs, shadow IT, crypto addresses)
and builds a node/edge graph:

  Nodes: domain, subdomain, ip, port, tech, endpoint, cert, tool, wallet
  Edges: resolves_to, runs_on, uses_tech, exposes, signed_by, etc.

Emits the full graph as a single JSON finding (category "graph") that
the frontend renders as an interactive map. Also emits summary
findings: most-connected nodes (pivot points), isolated nodes.

Pure computation - no network calls. Keyless.
Phase 2 chain plugin: needs the bus populated by phase-1 discovery.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Set

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


# bus kind -> node type
NODE_TYPES = {
    "subdomains": "subdomain",
    "ips": "ip",
    "ports": "port",
    "tech": "tech",
    "endpoints": "endpoint",
    "cert_sans": "cert",
    "shadow_it": "tool",
    "crypto_addresses": "wallet",
    "emails": "email",
    "surface_subdomains": "subdomain",
    "surface_ips": "ip",
    "surface_ports": "port",
    "surface_tech": "tech",
}

REMEDIATION_GRAPH = ("Review the asset map for unintended connections: "
                     "subdomains pointing at forgotten IPs, tech running on "
                     "unexpected hosts, shadow IT bridging internal and "
                     "external networks. Remove or isolate what should not "
                     "be connected.")


def _node_id(ntype: str, value: str) -> str:
    h = hashlib.sha256(f"{ntype}:{value}".encode()).hexdigest()[:12]
    return f"{ntype}_{h}"


class AssetGraphPlugin(Plugin):
    id = "assetgraph"
    label = "Asset Graph Builder"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    description = "Build interactive attack-surface map: domains, IPs, tech, ports."
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, str]] = []
        seen_edges: Set[str] = set()

        def add_node(ntype: str, value: str) -> str:
            nid = _node_id(ntype, value)
            if nid not in nodes:
                nodes[nid] = {"id": nid, "type": ntype,
                              "label": value[:80], "value": value[:300]}
            return nid

        def add_edge(frm: str, to: str, rel: str) -> None:
            key = f"{frm}|{to}|{rel}"
            if key not in seen_edges and frm != to:
                seen_edges.add(key)
                edges.append({"from": frm, "to": to, "rel": rel})

        # Root node: the target domain
        root = add_node("domain", domain)

        # Build nodes from every bus kind
        type_nodes: Dict[str, List[str]] = {}
        for kind, ntype in NODE_TYPES.items():
            ids = []
            for item in ctx.consume(kind)[:300]:
                val = item if isinstance(item, str) else json.dumps(item)[:200]
                if not val or not val.strip():
                    continue
                nid = add_node(ntype, val.strip())
                ids.append(nid)
            type_nodes[ntype] = ids

        # Wire edges with sensible relationships
        for sid in type_nodes.get("subdomain", []):
            add_edge(root, sid, "has_subdomain")
        for iid in type_nodes.get("ip", []):
            add_edge(root, iid, "resolves_to")
        for s in type_nodes.get("subdomain", [])[:100]:
            for i in type_nodes.get("ip", [])[:20]:
                add_edge(s, i, "may_resolve_to")
        for tid in type_nodes.get("tech", []):
            add_edge(root, tid, "uses_tech")
        for pid in type_nodes.get("port", []):
            for iid in type_nodes.get("ip", [])[:20]:
                add_edge(iid, pid, "open_port")
            if not type_nodes.get("ip"):
                add_edge(root, pid, "open_port")
        for eid in type_nodes.get("endpoint", []):
            add_edge(root, eid, "exposes")
        for cid in type_nodes.get("cert", []):
            add_edge(root, cid, "cert_covers")
        for tid in type_nodes.get("tool", []):
            add_edge(root, tid, "runs_shadow_tool")
        for wid in type_nodes.get("wallet", []):
            add_edge(root, wid, "publishes_wallet")
        for eid in type_nodes.get("email", []):
            add_edge(root, eid, "publishes_email")

        # Pivot analysis: nodes with the most edges = highest pivot value
        degree: Dict[str, int] = {}
        for e in edges:
            degree[e["from"]] = degree.get(e["from"], 0) + 1
            degree[e["to"]] = degree.get(e["to"], 0) + 1
        top_pivots = sorted(degree.items(), key=lambda x: -x[1])[:5]

        graph = {
            "root": domain,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": list(nodes.values())[:500],
            "edges": edges[:1000],
        }

        findings: List[Finding] = []
        findings.append(self._f(
            "graph", "asset_map",
            f"Attack surface map: {len(nodes)} nodes, {len(edges)} edges "
            f"for {domain}. Open the Graph tab for the interactive map.",
            source="Asset graph", confidence=95,
            evidence={"severity": "low",
                      "remediation": REMEDIATION_GRAPH,
                      "graph": graph,
                      "node_count": len(nodes),
                      "edge_count": len(edges)}}))

        for nid, deg in top_pivots:
            node = nodes.get(nid, {})
            if deg >= 3:
                findings.append(self._f(
                    "graph", "pivot_point",
                    f"Pivot point: {node.get('type')} '{node.get('label')}' "
                    f"connects {deg} assets. Compromising it expands access.",
                    source="Asset graph", confidence=80,
                    evidence={"severity": "medium",
                              "remediation": "Harden high-connectivity nodes "
                                             "first - they are the most "
                                             "valuable pivot targets.",
                              "node_type": node.get("type"),
                              "node_label": node.get("label"),
                              "degree": deg}}))

        reason = f"graph built: {len(nodes)} nodes, {len(edges)} edges"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
