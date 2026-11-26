"""Data shapes for the autonomous campaign engine.

Everything here is a plain dataclass or dict, stdlib only and
JSON-serialisable, so a campaign survives a restart and can be diffed
without a database. Network access is never imported
at module load: the workers take a ``fetch`` callable, which is what
makes the engine testable with a fake target.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# The kill-chain stages a campaign is ordered into. "recon" is what
# exists, "foothold" is a confirmed way in, "access" is a broken
# boundary, "impact" is what an attacker could actually do with it.
STAGES = ("recon", "foothold", "access", "impact")

SEVERITIES = ("info", "low", "medium", "high", "critical")


def digest(text: str) -> str:
    """sha256 of captured bytes/text; the receipt's tamper-evident part."""
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def nid(*parts: Any) -> str:
    """Deterministic node id: the same fact always gets the same id, so
    replanning after a restart does not duplicate the graph."""
    raw = "|".join(str(p) for p in parts)
    return "n_" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


def canon_target(target: str) -> str:
    """Stable target identity: lowercase scheme/host, no fragment, no
    trailing slash. Path case is preserved (it is significant)."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        return t.lower().rstrip("/")
    try:
        p = urlparse(t)
    except ValueError:
        return t.lower().rstrip("/")
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    netloc = host
    if p.port and not ((scheme == "http" and p.port == 80)
                       or (scheme == "https" and p.port == 443)):
        netloc = f"{host}:{p.port}"
    path = (p.path or "").rstrip("/")
    query = f"?{p.query}" if p.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def finding(action: str, title: str, target: str, *,
            severity: str = "medium", confidence: int = 70,
            tags: Optional[List[str]] = None,
            evidence: Optional[Dict[str, Any]] = None,
            detail: str = "", stage: str = "foothold",
            confirmed: bool = True,
            meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One campaign finding. ``confirmed`` means the worker actually
    observed the condition (it captured a receipt); it is not a claim
    about exploitability - the stage and tags carry that."""
    return {
        "id": nid("finding", action, title, canon_target(target)),
        "action": action,
        "title": title,
        "target": target,
        "severity": severity if severity in SEVERITIES else "medium",
        "confidence": max(0, min(100, int(confidence))),
        "tags": sorted(set(tags or [])),
        "evidence": evidence or {},
        "detail": detail[:1200],
        "stage": stage if stage in STAGES else "foothold",
        "confirmed": bool(confirmed),
        "meta": meta or {},
    }


@dataclass
class Intent:
    """One planned unit of work: what to try, on what, and why.

    ``why`` holds graph node ids for the facts that motivated it, so a
    planned action is always traceable to evidence instead of being a
    black-box guess.
    """
    kind: str                 # recon | probe | impact | verify
    action: str               # surface | probe id | enumerate:<console> | jwt-forge
    target: str
    goal: str = ""
    why: List[str] = field(default_factory=list)
    requires_approval: bool = False
    cost: int = 1
    priority: int = 50        # lower runs first
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.action}:{canon_target(self.target)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key, "kind": self.kind, "action": self.action,
            "target": self.target, "goal": self.goal,
            "why": list(self.why),
            "requires_approval": self.requires_approval,
            "cost": self.cost, "priority": self.priority,
            "meta": dict(self.meta),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Intent":
        return cls(
            kind=d.get("kind", ""), action=d.get("action", ""),
            target=d.get("target", ""), goal=d.get("goal", ""),
            why=list(d.get("why") or []),
            requires_approval=bool(d.get("requires_approval")),
            cost=int(d.get("cost") or 1),
            priority=int(d.get("priority") or 50),
            meta=dict(d.get("meta") or {}),
        )


@dataclass
class Attempt:
    """The result of executing (or refusing) one intent.

    ``status`` is explicit: ok, failed, blocked (scope), denied,
    pending_approval, skipped. Exactly one status per intent, so a
    campaign can be audited without re-reading the logs.
    """
    key: str
    kind: str
    action: str
    target: str
    status: str = "ok"
    seconds: float = 0.0
    detail: str = ""
    error: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    assets: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key, "kind": self.kind, "action": self.action,
            "target": self.target, "status": self.status,
            "seconds": round(self.seconds, 3), "detail": self.detail,
            "error": self.error, "findings": self.findings,
            "assets": self.assets, "evidence": self.evidence,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Attempt":
        return cls(
            key=d.get("key", ""), kind=d.get("kind", ""),
            action=d.get("action", ""), target=d.get("target", ""),
            status=d.get("status", "ok"), seconds=float(d.get("seconds") or 0),
            detail=d.get("detail", ""), error=d.get("error", ""),
            findings=list(d.get("findings") or []),
            assets=list(d.get("assets") or []),
            evidence=list(d.get("evidence") or []),
            meta=dict(d.get("meta") or {}),
        )


@dataclass
class Budget:
    """Hard caps for one campaign. The engine checks these before every
    intent; a worker can never outspend the operator's budget."""
    max_requests: int = 80
    max_intents: int = 30
    max_seconds: float = 90.0
    requests_used: int = 0
    intents_used: int = 0
    started: float = field(default_factory=time.time)
    stop_reason: str = ""

    def elapsed(self, now: Optional[float] = None) -> float:
        return max(0.0, (now if now is not None else time.time()) - self.started)

    def spend(self, requests: int = 1, now: Optional[float] = None) -> None:
        self.requests_used += max(0, int(requests))
        self.intents_used += 1
        if self.requests_used >= self.max_requests:
            self.stop_reason = self.stop_reason or "request budget exhausted"
        if self.intents_used >= self.max_intents:
            self.stop_reason = self.stop_reason or "intent budget exhausted"
        if self.elapsed(now) >= self.max_seconds:
            self.stop_reason = self.stop_reason or "time budget exhausted"

    def exhausted(self, now: Optional[float] = None) -> bool:
        if self.requests_used >= self.max_requests:
            self.stop_reason = self.stop_reason or "request budget exhausted"
            return True
        if self.intents_used >= self.max_intents:
            self.stop_reason = self.stop_reason or "intent budget exhausted"
            return True
        if self.elapsed(now) >= self.max_seconds:
            self.stop_reason = self.stop_reason or "time budget exhausted"
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "max_intents": self.max_intents,
            "max_seconds": self.max_seconds,
            "requests_used": self.requests_used,
            "intents_used": self.intents_used,
            "elapsed_s": round(self.elapsed(), 2),
            "exhausted": self.exhausted(),
            "stop_reason": self.stop_reason,
        }
