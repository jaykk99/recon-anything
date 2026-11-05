"""Interactive attack-surface graph (anti-Maltego).

Maltego's strength is visual link analysis; its weakness is that it
is manual. ReconAnything already COLLECTS the graph three ways:

- ``app/graph.py`` builds Node/Edge rows at run finalize from
  findings (domains, subdomains, IPs, tech, endpoints, orgs).
- the ``assetgraph`` plugin builds a bus-driven asset map (ports,
  certs, emails, wallets) stored as one ``asset_map`` finding.
- ``app/correlate.py`` synthesizes multi-stage attack paths whose
  evidence cites the component findings they chain.

None of that was explorable: the old graph view was a static circle
of dots. This module fuses all three sources at READ time into one
payload built for interaction:

- nodes carry the findings that produced them, each with its
  read-only verification commands (``app/commands.py``), so clicking
  a node answers "what do we know about this asset and how do I
  confirm it myself?"
- HUMINT nodes (kind in HUMINT_KINDS) come ONLY from public data
  the scanners already collect: WHOIS/RDAP registrant orgs, emails
  the target itself published, and public platform accounts the
  username checker confirmed. No new collection, no private data.
- ``attack_paths`` lists each correlation path as an ordered set of
  node ids, so the UI can highlight the exact multi-stage chain
  through the graph instead of leaving the analyst to trace it.

Read-time and pure: no network calls, works on old runs, never
raises (worst case the payload degrades to whatever sources exist).
Secrets stay masked: findings come from findings_dump with
show_secrets=False, so node labels and commands never carry a raw
secret value.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .graph import NODE_KIND, _nid

HUMINT_KINDS = {"org", "email", "username", "account"}

MAX_NODES = 400
MAX_EDGES = 1500
MAX_FINDINGS_PER_NODE = 25

_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
_USERNAME_RE = re.compile(r"@([A-Za-z0-9_.\-]{2,30})\s+exists on\s+(\S+)", re.I)
_HOSTPORT_RE = re.compile(r"([a-z0-9.\-]+):(\d{1,5})\b", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Semantic edge names for the relations analysts actually read.
_RELATION_LABEL = {
    "a": "resolves to", "aaaa": "resolves to", "ptr": "resolves to",
    "subdomain": "has subdomain", "tls_san": "cert covers",
    "open_port": "hosts port", "port_open": "hosts port",
    "tls_issuer": "issued by", "tls_subject": "cert for",
    "cert_san": "cert covers",
    "tech": "runs", "server_header": "runs", "tech_deep": "runs",
    "registrant_org": "registered by", "whois_registrant_org": "registered by",
    "email_found": "publishes email",
    "username_found": "has public account",
}


def _relation_for(key: str) -> str:
    return _RELATION_LABEL.get(key, key.replace("_", " "))


class _Graph:
    """Canonical node/edge accumulator keyed by (kind, label)."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self._canon: Dict[Any, str] = {}
        self.edges: List[Dict[str, Any]] = []
        self._edge_keys = set()

    def add_node(self, kind: str, label: str, interesting: bool = False,
                 meta: Optional[dict] = None) -> str:
        label = str(label or "").strip()[:300]
        canon = (kind, label.lower())
        nid = self._canon.get(canon)
        if nid is None:
            nid = _nid(kind, label)
            self._canon[canon] = nid
            self.nodes[nid] = {
                "id": nid, "kind": kind, "label": label,
                "interesting": bool(interesting),
                "humint": kind in HUMINT_KINDS,
                "meta": dict(meta or {}), "findings": [],
            }
        node = self.nodes[nid]
        if interesting:
            node["interesting"] = True
        if meta:
            node["meta"].update(meta)
        return nid

    def add_edge(self, src: str, dst: str, relation: str,
                 confidence: int = 80, provenance: str = "") -> None:
        if src == dst or src not in self.nodes or dst not in self.nodes:
            return
        key = (src, dst, relation)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append({"src": src, "dst": dst, "relation": relation,
                           "confidence": confidence,
                           "provenance": provenance})

    def attach(self, nid: str, finding: Dict[str, Any]) -> None:
        node = self.nodes.get(nid)
        if node is None:
            return
        if len(node["findings"]) < MAX_FINDINGS_PER_NODE:
            node["findings"].append(finding)


def _finding_brief(row: Dict[str, Any], host_hint: Optional[str]) -> Dict:
    """The per-finding shape a node click shows: facts + commands."""
    from .commands import commands_for
    brief = {
        "id": row.get("id"), "plugin": row.get("plugin"),
        "key": row.get("key"), "value": row.get("value"),
        "confidence": row.get("confidence_score", row.get("confidence")),
        "confidence_tier": row.get("confidence_tier"),
        "source_url": row.get("source_url"),
    }
    try:
        brief["commands"] = commands_for(row, host_hint)
    except Exception:
        brief["commands"] = []
    return brief


def _extract_node(g: _Graph, row: Dict[str, Any], root: str) -> Optional[str]:
    """Map one finding row to its graph node (+ edges). None = root only."""
    key = str(row.get("key") or "")
    value = str(row.get("value") or "").strip()
    if not value:
        return None
    interesting = bool(row.get("confidence_tier") == "confirmed"
                       and (row.get("bounty_value") in ("critical", "high")))

    if key in ("email_found", "email"):
        m = _EMAIL_RE.search(value)
        if not m:
            return None
        nid = g.add_node("email", m.group(0).lower(), interesting,
                         {"plugin": row.get("plugin")})
        g.add_edge(root, nid, _relation_for(key), 80, row.get("plugin") or "")
        return nid

    if key == "username_found":
        m = _USERNAME_RE.search(value)
        if not m:
            return None
        nid = g.add_node("username", f"@{m.group(1)}", interesting,
                         {"platform": m.group(2),
                          "plugin": row.get("plugin")})
        g.add_edge(root, nid, _relation_for(key), 80, row.get("plugin") or "")
        return nid

    if key in ("open_port", "port_open"):
        m = _HOSTPORT_RE.search(value)
        if not m:
            return None
        host, port = m.group(1), m.group(2)
        host_kind = "ip" if _IP_RE.match(host) else "subdomain"
        host_id = g.add_node(host_kind, host)
        g.add_edge(root, host_id, "has subdomain" if host_kind == "subdomain"
                   else "resolves to", 80, row.get("plugin") or "")
        nid = g.add_node("port", f"{host}:{port}", interesting,
                         {"plugin": row.get("plugin")})
        g.add_edge(host_id, nid, _relation_for(key), 90,
                   row.get("plugin") or "")
        return nid

    kind = NODE_KIND.get(key)
    if not kind:
        return None
    # Email-shaped values under generic keys still become HUMINT nodes
    # only via the dedicated extractors above; everything else uses
    # the shared graph.py mapping verbatim.
    nid = g.add_node(kind, value, interesting,
                     {"plugin": row.get("plugin")})
    g.add_edge(root, nid, _relation_for(key),
               int(row.get("confidence") or 80), row.get("plugin") or "")
    return nid


def surface_graph_payload(session, run_id: str) -> Dict:
    """Full interactive payload for one run. See module docstring."""
    from .models import Target
    from .reporting import findings_dump
    from .graph import graph_payload

    g = _Graph()
    rows = findings_dump(session, run_id, show_secrets=False)
    targets = session.query(Target).filter_by(run_id=run_id).all()
    host_hint = targets[0].normalized if targets else None

    # One root per target; findings attach to their own target's root.
    roots: Dict[str, str] = {}
    for t in targets:
        roots[t.id] = g.add_node("target", t.normalized or t.raw or t.id,
                                 meta={"raw": t.raw, "type": t.type})

    finding_node: Dict[Any, str] = {}
    path_rows: List[Dict[str, Any]] = []
    asset_maps: List[Dict[str, Any]] = []
    for row in rows:
        root = roots.get(row.get("target_id")) or (
            next(iter(roots.values())) if roots else None)
        if root is None:
            root = g.add_node("target", host_hint or run_id)
            roots[row.get("target_id")] = root
        if row.get("key") == "attack_path":
            path_rows.append(row)
            continue
        if row.get("key") == "asset_map":
            ev = row.get("evidence") or {}
            if isinstance(ev, dict) and isinstance(ev.get("graph"), dict):
                asset_maps.append(ev["graph"])
            continue
        nid = _extract_node(g, row, root)
        attach_to = nid or root
        finding_node[row.get("id")] = attach_to
        g.attach(attach_to, _finding_brief(row, host_hint))

    # Merge the assetgraph plugin's bus graphs - one per target -
    # (ports/certs/wallets the finding-key mapping does not cover).
    # Its ids are translated through the canonical (kind, label)
    # index, so the same asset from two targets lands on one node.
    kind_map = {"tool": "tool", "wallet": "financial"}
    for asset_map in asset_maps:
        id_map: Dict[str, str] = {}
        for n in asset_map.get("nodes", []):
            kind = kind_map.get(n.get("type"), n.get("type") or "endpoint")
            label = n.get("label") or n.get("value") or ""
            if not label:
                continue
            if kind == "domain":
                kind = "target"
            id_map[n.get("id")] = g.add_node(kind, label)
        for e in asset_map.get("edges", []):
            src, dst = id_map.get(e.get("from")), id_map.get(e.get("to"))
            if src and dst:
                g.add_edge(src, dst, str(e.get("rel") or "linked").replace(
                    "_", " "), 70, "assetgraph")

    # Merge the finalize-time Node/Edge rows (shared-indicator links
    # between targets live only there).
    try:
        stored = graph_payload(session, run_id)
    except Exception:
        stored = {"nodes": [], "edges": []}
    stored_id: Dict[str, str] = {}
    for n in stored.get("nodes", []):
        stored_id[n["id"]] = g.add_node(n.get("kind") or "endpoint",
                                        n.get("label") or "",
                                        bool(n.get("interesting")),
                                        n.get("meta") or {})
    for e in stored.get("edges", []):
        src, dst = stored_id.get(e.get("src")), stored_id.get(e.get("dst"))
        if src and dst:
            g.add_edge(src, dst, _relation_for(str(e.get("relation") or "")),
                       int(e.get("confidence") or 80),
                       e.get("provenance") or "")

    # Attack paths: resolve each correlation cite to a graph node so
    # the UI can light the chain up in order.
    by_id = {r.get("id"): r for r in rows}
    by_key_value: Dict[Any, str] = {}
    for row in rows:
        nid = finding_node.get(row.get("id"))
        if nid:
            by_key_value.setdefault(
                (row.get("key"), normalize_label(row.get("value"))), nid)
    paths: List[Dict[str, Any]] = []
    for row in path_rows:
        ev = row.get("evidence") or {}
        node_ids: List[str] = []
        root = roots.get(row.get("target_id"))
        if root:
            node_ids.append(root)
        for comp in ev.get("components") or []:
            nid = None
            fid = comp.get("finding_id")
            if fid is not None and fid in finding_node:
                nid = finding_node[fid]
            if nid is None:
                nid = by_key_value.get(
                    (comp.get("key"), normalize_label(comp.get("value"))))
            if nid and (not node_ids or node_ids[-1] != nid):
                node_ids.append(nid)
        if len(node_ids) >= 2:
            paths.append({
                "id": ev.get("path_id") or f"path-{row.get('id')}",
                "name": ev.get("path_name") or row.get("value"),
                "severity": ev.get("severity"),
                "finding_id": row.get("id"),
                "steps": ev.get("chain_steps") or [],
                "node_ids": node_ids,
            })

    nodes = list(g.nodes.values())
    truncated = False
    if len(nodes) > MAX_NODES:
        # Keep targets, interesting and HUMINT nodes, then highest
        # degree; drop the long tail of leaf observations.
        degree: Dict[str, int] = {}
        for e in g.edges:
            degree[e["src"]] = degree.get(e["src"], 0) + 1
            degree[e["dst"]] = degree.get(e["dst"], 0) + 1

        def _rank(n: Dict[str, Any]) -> Any:
            return (n["kind"] == "target", n["interesting"], n["humint"],
                    degree.get(n["id"], 0))
        nodes.sort(key=_rank, reverse=True)
        keep = {n["id"] for n in nodes[:MAX_NODES]}
        nodes = [n for n in nodes if n["id"] in keep]
        g.edges = [e for e in g.edges
                   if e["src"] in keep and e["dst"] in keep]
        truncated = True

    kinds: Dict[str, int] = {}
    for n in nodes:
        kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
    return {
        "nodes": nodes,
        "edges": g.edges[:MAX_EDGES],
        "attack_paths": paths,
        "counts": {"nodes": len(nodes), "edges": len(g.edges[:MAX_EDGES]),
                   "kinds": kinds,
                   "humint": sum(1 for n in nodes if n["humint"]),
                   "attack_paths": len(paths)},
        "truncated": truncated,
    }


def normalize_label(value: Any) -> str:
    return str(value or "").strip().lower()
