"""Plugin interface for ReconAnything.

Every capability is an isolated, hot-loadable plugin. A plugin never throws
fatally: it returns partial findings plus a per-plugin status.
"""
from __future__ import annotations

import abc
import datetime as dt
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PluginStatus(str, Enum):
    OK = "ok"
    SKIPPED = "skipped"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class Cost(str, Enum):
    FREE = "free"
    FREEMIUM = "freemium"
    PAID = "paid"


@dataclass
class Finding:
    plugin_id: str
    category: str  # dns | web | api | mobile | identity | infra | leak | graph
    key: str       # e.g. "subdomain", "endpoint", "tech"
    value: str
    source: str
    source_url: Optional[str] = None
    confidence: int = 80  # 0-100
    evidence: Optional[Dict[str, Any]] = None
    first_seen: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat())
    raw: Optional[Any] = None
    passive: bool = True  # badge: which mode produced it


@dataclass
class PluginResult:
    plugin_id: str
    status: PluginStatus
    reason: str = ""
    findings: List[Finding] = field(default_factory=list)
    duration_ms: int = 0


@dataclass
class Target:
    raw: str
    type: str  # domain, url, ip, ...
    normalized: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        if not self.normalized:
            self.normalized = self.raw.strip()


@dataclass
class Ctx:
    """Run context handed to every plugin."""
    run_id: str
    mode: str  # "passive" | "active"
    http: Any  # shared httpx.AsyncClient
    cache: Any  # cache layer with get/set
    keys: Dict[str, str]  # decrypted API keys by name
    limiter: Any = None  # rate limiter
    emit: Any = None  # optional async callback(event dict)
    module_overrides: Dict[str, str] = field(default_factory=dict)
    evidence_dir: str = "./evidence"
    # Discovery bus: plugins publish assets here so phase-2 chain
    # plugins can consume them. Keys: subdomains, js_files, endpoints,
    # tech, forms, params, emails, cert_sans.
    shared: Dict[str, List[Any]] = field(default_factory=dict)

    def publish(self, kind: str, item: Any) -> None:
        """Publish a discovered asset to the shared discovery bus."""
        bucket = self.shared.setdefault(kind, [])
        # light dedup for strings
        if isinstance(item, str):
            if item not in bucket:
                bucket.append(item)
        else:
            bucket.append(item)

    def consume(self, kind: str) -> List[Any]:
        """Read everything published under a discovery kind."""
        return list(self.shared.get(kind, []))


class Plugin(abc.ABC):
    id: str = "base"
    label: str = "Base"
    accepts: List[str] = []
    requires_keys: List[str] = []
    passive: bool = True
    cost: Cost = Cost.FREE
    group: str = "network"  # network | web | api | mobile | identity
    description: str = ""
    # Execution phase. Phase 1 plugins run first; phase 2 "chain" plugins
    # run after, consuming the discovery bus (ctx.shared) populated by
    # phase 1. Lets findings lead to more findings.
    phase: int = 1

    @abc.abstractmethod
    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        ...

    # -- helpers ---------------------------------------------------------
    def _ok(self, findings: List[Finding], reason: str = "") -> PluginResult:
        return PluginResult(plugin_id=self.id, status=PluginStatus.OK,
                            reason=reason, findings=findings)

    def _skipped(self, reason: str) -> PluginResult:
        return PluginResult(plugin_id=self.id, status=PluginStatus.SKIPPED, reason=reason)

    def _rate_limited(self, reason: str) -> PluginResult:
        return PluginResult(plugin_id=self.id, status=PluginStatus.RATE_LIMITED, reason=reason)

    def _error(self, reason: str) -> PluginResult:
        return PluginResult(plugin_id=self.id, status=PluginStatus.ERROR, reason=reason)

    def _f(self, category: str, key: str, value: str, source: str,
           source_url: Optional[str] = None, confidence: int = 80,
           evidence: Optional[Dict[str, Any]] = None, raw: Optional[Any] = None,
           passive: bool = True) -> Finding:
        return Finding(plugin_id=self.id, category=category, key=key, value=value,
                       source=source, source_url=source_url, confidence=confidence,
                       evidence=evidence, raw=raw, passive=passive)

    def module_mode(self, ctx: Ctx) -> str:
        """Per-module override wins over the global mode."""
        return ctx.module_overrides.get(self.id, ctx.mode)

    def missing_keys(self, ctx: Ctx) -> List[str]:
        return [k for k in self.requires_keys if not ctx.keys.get(k)]
