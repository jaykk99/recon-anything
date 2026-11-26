"""Dual graph: what exists, and what has been tried.

The asset graph is shared knowledge: hosts, URLs, endpoints, parameters,
services, findings. The exploration graph is process knowledge: every
intent that was attempted, what it produced, and why it was planned.
Attempt nodes anchor into asset nodes, so "this finding came from that
request, which was planned because of that fact" is answerable from the
snapshot alone.

Deterministic ids and dict-based edges make the graph idempotent: a
replan, a resume after restart, or a second worker writing the same fact
merges instead of duplicating.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from .models import STAGES, Attempt, canon_target, finding as make_finding, nid

_ASSET_TYPES = {
    "host", "url", "http_service", "endpoint", "param", "service",
    "tech", "cookie", "secret", "container", "namespace", "index",
    "job", "dashboard", "bucket", "api", "note",
}


def canon_asset(asset_type: str, value: str) -> str:
    v = (value or "").strip()
    if asset_type in ("host", "service", "tech", "cookie"):
        return v.lower().rstrip(".")
    if asset_type in ("url", "endpoint"):
        return canon_target(v)
    return v


class Graph:
    def __init__(self) -> None:
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self.attempts: Dict[str, Dict[str, Any]] = {}
        self.findings: Dict[str, Dict[str, Any]] = {}

    # -- assets ---------------------------------------------------------
    def add_asset(self, asset_type: str, value: str, *,
                  source: str = "", stage: str = "recon",
                  meta: Optional[Dict[str, Any]] = None) -> str:
        value = canon_asset(asset_type, value)
        if not value:
            return ""
        if asset_type not in _ASSET_TYPES:
            asset_type = "note"
        aid = nid("asset", asset_type, value)
        node = self.assets.get(aid)
        if node is None:
            node = {
                "id": aid, "type": asset_type, "value": value,
                "stage": stage if stage in STAGES else "recon",
                "sources": [], "meta": {},
            }
            self.assets[aid] = node
        if source and source not in node["sources"]:
            node["sources"].append(source)
        if meta:
            for k, v in meta.items():
                if k not in node["meta"] or node["meta"][k] in (None, "", [], {}):
                    node["meta"][k] = v
        return aid

    def asset_for_target(self, target: str) -> str:
        """The asset node that stands for a URL/host target."""
        host = (urlparse(target if "://" in target else f"https://{target}")
                .hostname or target).lower()
        for node in self.assets.values():
            if node["type"] == "url" and canon_target(node["value"]) == canon_target(target):
                return node["id"]
            if node["type"] == "host" and node["value"] == host:
                return node["id"]
        if "://" in (target or ""):
            return self.add_asset("url", target)
        return self.add_asset("host", target)

    # -- findings -------------------------------------------------------
    def add_finding(self, f: Dict[str, Any], *, attempt_key: str = "") -> str:
        fid = f.get("id") or nid("finding", f.get("action"), f.get("title"),
                                canon_target(f.get("target", "")))
        f["id"] = fid
        existing = self.findings.get(fid)
        if existing is None:
            self.findings[fid] = f
        else:
            # Same fact observed twice: keep the strongest evidence, count it.
            existing.setdefault("meta", {})["observations"] = \
                int(existing.get("meta", {}).get("observations") or 1) + 1
            if f.get("confidence", 0) > existing.get("confidence", 0):
                existing["confidence"] = f["confidence"]
            if f.get("evidence") and not existing.get("evidence"):
                existing["evidence"] = f["evidence"]
        src = attempt_key or self.asset_for_target(f.get("target", ""))
        if src:
            self.link(src, fid, "produced" if attempt_key else "about")
        return fid

    # -- exploration ----------------------------------------------------
    def record_attempt(self, attempt: Attempt) -> str:
        aid = nid("attempt", attempt.key)
        row = attempt.to_dict()
        row["id"] = aid
        self.attempts[attempt.key] = row
        target_id = self.asset_for_target(attempt.target)
        if target_id:
            self.link(aid, target_id, "tried_on")
        for a in attempt.assets:
            node_id = self.add_asset(a.get("type", "note"), a.get("value", ""),
                                     source=attempt.action,
                                     stage=a.get("stage", "recon"),
                                     meta=a.get("meta"))
            if node_id:
                self.link(aid, node_id, "discovered")
        for f in attempt.findings:
            self.add_finding(f, attempt_key=aid)
        return aid

    def link(self, src: str, dst: str, kind: str,
             meta: Optional[Dict[str, Any]] = None) -> str:
        if not src or not dst:
            return ""
        eid = nid("edge", src, dst, kind)
        if eid not in self.edges:
            self.edges[eid] = {"id": eid, "src": src, "dst": dst,
                               "kind": kind, "meta": meta or {}}
        elif meta:
            self.edges[eid]["meta"].update(meta)
        return eid

    # -- read model -----------------------------------------------------
    def attempted_keys(self) -> Set[str]:
        return set(self.attempts.keys())

    def assets_of(self, asset_type: str) -> List[Dict[str, Any]]:
        return [a for a in self.assets.values() if a["type"] == asset_type]

    def confirmed_findings(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings.values() if f.get("confirmed")]

    # -- reporting ------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for a in self.assets.values():
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        by_sev: Dict[str, int] = {}
        for f in self.confirmed_findings():
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        statuses: Dict[str, int] = {}
        for a in self.attempts.values():
            statuses[a["status"]] = statuses.get(a["status"], 0) + 1
        receipts = sum(len(a.get("evidence") or [])
                       for a in self.attempts.values())
        return {
            "assets": len(self.assets),
            "assets_by_type": by_type,
            "edges": len(self.edges),
            "attempts": len(self.attempts),
            "attempts_by_status": statuses,
            "findings": len(self.findings),
            "confirmed_findings": len(self.confirmed_findings()),
            "confirmed_by_severity": by_sev,
            "evidence_receipts": receipts,
        }

    def kill_chain(self) -> List[Dict[str, Any]]:
        """Order what was found into the sequence an attacker walks."""
        stages: List[Dict[str, Any]] = []
        for stage in STAGES:
            fs = [f for f in self.confirmed_findings() if f.get("stage") == stage]
            fs.sort(key=lambda f: (-int(f.get("confidence") or 0),
                                   _sev_rank(f.get("severity")),
                                   f.get("title", "")))
            assets = [a["value"] for a in self.assets.values()
                      if a.get("stage") == stage]
            stages.append({
                "stage": stage,
                "reached": bool(fs or assets),
                "findings": [
                    {"id": f["id"], "title": f["title"],
                     "severity": f["severity"], "tags": f.get("tags", [])}
                    for f in fs[:5]
                ],
                "assets": sorted(set(assets))[:8],
            })
        return stages

    def to_snapshot(self) -> Dict[str, Any]:
        return {
            "assets": self.assets,
            "edges": self.edges,
            "attempts": self.attempts,
            "findings": self.findings,
        }

    @classmethod
    def from_snapshot(cls, snap: Optional[Dict[str, Any]]) -> "Graph":
        g = cls()
        snap = snap or {}
        g.assets = dict(snap.get("assets") or {})
        g.edges = dict(snap.get("edges") or {})
        g.attempts = dict(snap.get("attempts") or {})
        g.findings = dict(snap.get("findings") or {})
        return g


def _sev_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get((sev or "").lower(), 5)


def import_findings(graph: Graph, rows: Iterable[Dict[str, Any]]) -> int:
    """Seed the graph from an existing scan run's findings.

    Detection output is data, not instructions: a row only contributes
    its target/value/tags, and a row is never treated as a confirmed
    exploit - it enters as an unconfirmed lead unless the row itself
    carries a verification verdict.
    """
    added = 0
    for row in rows or []:
        target = (row.get("source_url") or row.get("target")
                  or row.get("value") or "")
        if not target:
            continue
        tags: List[str] = []
        key = str(row.get("key") or "")
        if key in ("exposed_jwt", "jwt_token") or "jwt" in key:
            tags.append("auth")
        if "secret" in key or "credential" in key or "api_key" in key:
            tags.append("secret")
        if "s3" in key or "bucket" in key:
            tags.append("object_storage")
        verdict = str((row.get("evidence") or {}).get("verdict") or "")
        confirmed = verdict.upper() == "VERIFIED_REAL"
        graph.add_finding(make_finding(
            action=str(row.get("plugin") or "scan"),
            title=str(row.get("key") or "scan finding"),
            target=target,
            severity=str((row.get("evidence") or {}).get("severity")
                         or row.get("severity") or "low"),
            confidence=int(row.get("confidence") or 50),
            tags=tags,
            detail=str(row.get("value") or "")[:500],
            stage="recon",
            confirmed=confirmed,
            meta={"imported": True, "source_key": key},
        ))
        added += 1
    return added
