"""Correlation graph builder (Milestone 7).

Every entity is a node (domain, subdomain, ip, cert, endpoint, tech,
email, tracking id, favicon hash, app, org). Every relation is an edge
with provenance + confidence. Auto-clusters shared indicators and flags
interesting nodes (admin panels, staging, exposed docs, leaked keys,
expired certs, dangling DNS).
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Tuple

from .models import Edge, Finding, Node

INTERESTING_KEYS = {
    "artifact_exposed", "jwt_weak", "spf_weak", "dmarc_weak",
    "cors_misconfig", "graphql_introspection", "apk_aws_access_key",
    "apk_private_key", "aws_access_key", "private_key", "slack_token",
    "github_token", "stripe_sk_hint", "source_map",
}

NODE_KIND = {
    "subdomain": "subdomain", "tls_san": "subdomain",
    "a": "ip", "aaaa": "ip", "ptr": "ip",
    "api_endpoint": "endpoint", "endpoint": "endpoint",
    "graphql_path": "endpoint", "apk_url": "endpoint", "mobile_url": "endpoint",
    "tech": "tech", "server_header": "tech", "tech_deep": "tech",
    "ga_id": "tracking_id", "gtm_id": "tracking_id", "adsense_id": "tracking_id",
    "favicon_mmh3": "favicon_hash",
    "registrant_org": "org",
    "app_title": "app", "bundle_id": "app",
    # connection mapper node types
    "connected_device": "device",
    "connected_service": "service",
    "connected_account": "account",
    "connected_financial": "financial",
    # financial plugin node types
    "payment_processor": "financial",
    "billing_endpoint": "financial",
    "bank_bank_account": "financial", "bank_routing_number": "financial",
    "bank_iban": "financial", "bank_swift_code": "financial",
    "bank_credit_card": "financial", "bank_billing_endpoint": "financial",
    "crypto_btc_address": "financial", "crypto_eth_address": "financial",
    "crypto_exchange_api": "financial", "crypto_web3_provider": "financial",
    "crypto_smart_contract": "financial",
}


def _nid(kind: str, label: str) -> str:
    h = hashlib.sha256(f"{kind}:{label}".encode()).hexdigest()[:16]
    return f"{kind}:{h}"


def build_graph(session, run_id: str) -> Tuple[int, int]:
    findings: List[Finding] = session.query(Finding).filter_by(run_id=run_id).all()
    nodes: Dict[str, Node] = {}
    edges: List[Edge] = []
    # target roots
    targets = {}
    for f in findings:
        targets.setdefault(f.target_id, set()).add(f.target_id)

    def add_node(kind: str, label: str, interesting: bool = False,
                 meta: dict | None = None) -> str:
        nid = _nid(kind, label)
        if nid not in nodes:
            nodes[nid] = Node(id=nid, run_id=run_id, kind=kind,
                              label=label[:300], interesting=interesting,
                              meta=meta or {})
        elif interesting:
            nodes[nid].interesting = True
        return nid

    def add_edge(a: str, b: str, relation: str, conf: int, prov: str):
        if a == b:
            return
        edges.append(Edge(run_id=run_id, src=a, dst=b, relation=relation,
                          confidence=conf, provenance=prov))

    # one root node per target
    roots: Dict[str, str] = {}
    seen_targets = session.query(Finding.target_id).filter_by(run_id=run_id).distinct()
    for (tid,) in seen_targets:
        roots[tid] = add_node("target", tid, meta={})

    for f in findings:
        kind = NODE_KIND.get(f.key)
        if not kind:
            continue
        interesting = f.key in INTERESTING_KEYS or "admin" in f.value.lower() \
            or "staging" in f.value.lower()
        nid = add_node(kind, f.value, interesting=interesting,
                       meta={"plugin": f.plugin_id, "source": f.source})
        root = roots.get(f.target_id)
        if root:
            add_edge(root, nid, f.key, f.confidence, f.plugin_id)

    # auto-cluster: shared tracking ids / favicon hashes / IPs link targets
    by_label: Dict[str, List[str]] = {}
    for nid, node in nodes.items():
        if node.kind in ("tracking_id", "favicon_hash", "ip", "tech"):
            by_label.setdefault(node.label, []).append(nid)
    for label, nids in by_label.items():
        uniq_targets = set()
        for nid in nids:
            for e in edges:
                if e.dst == nid:
                    uniq_targets.add(e.src)
        if len(uniq_targets) > 1:
            for nid in nids:
                node = nodes[nid]
                node.interesting = True
                node.meta = {**(node.meta or {}), "shared_across_targets": True}

    for n in nodes.values():
        session.merge(n)
    session.add_all(edges)
    return len(nodes), len(edges)


def graph_payload(session, run_id: str) -> Dict:
    nodes = session.query(Node).filter_by(run_id=run_id).all()
    edges = session.query(Edge).filter_by(run_id=run_id).all()
    return {
        "nodes": [{"id": n.id, "kind": n.kind, "label": n.label,
                   "interesting": n.interesting, "meta": n.meta} for n in nodes],
        "edges": [{"src": e.src, "dst": e.dst, "relation": e.relation,
                   "confidence": e.confidence, "provenance": e.provenance}
                  for e in edges],
    }
