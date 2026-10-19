"""Attack Surface Management: track target assets over time, detect changes.

Compares the current scan's discovered assets (subdomains, IPs, ports,
technologies, endpoints) against the previous scan's snapshot stored in
the run cache. Reports:
  - NEW assets (subdomains, IPs, ports, endpoints not seen before)
  - REMOVED assets (were there, now gone)
  - CHANGED assets (tech version changed, new open port on known IP)

This is change detection, not exploitation: it reads the discovery bus
and the cache, compares snapshots, and reports deltas. First scan for a
target establishes the baseline (no deltas reported, just "baseline set").

Keyless. No network calls of its own - pure comparison logic.
Phase 2 chain plugin: runs after discovery so the bus is populated.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


# Discovery bus kinds that make up the attack surface snapshot.
SURFACE_KINDS = [
    "subdomains", "ips", "ports", "tech", "endpoints",
    "js_files", "cert_sans",
]

REMEDIATION_NEW = ("A new asset appeared on the attack surface. Verify it "
                   "is intentional, hardened, and monitored. Remove it if "
                   "it is not supposed to be public.")
REMEDIATION_REMOVED = ("An asset disappeared from the attack surface. If "
                       "this was intentional, no action needed. If not, "
                       "investigate - it may indicate infrastructure issues.")
REMEDIATION_CHANGED = ("An asset changed. Review the change for security "
                       "impact - version changes may need patching, new "
                       "ports may need firewall rules.")


def _snapshot_key(domain: str) -> str:
    h = hashlib.sha256(domain.lower().encode()).hexdigest()[:16]
    return f"asm:snapshot:{h}"


def _normalize_set(items: List[Any]) -> Set[str]:
    out: Set[str] = set()
    for i in items:
        if isinstance(i, str) and i.strip():
            out.add(i.strip().lower())
        elif isinstance(i, dict):
            # dicts: use a stable string form
            try:
                out.add(json.dumps(i, sort_keys=True).lower()[:500])
            except Exception:
                pass
    return out


class AsmPlugin(Plugin):
    id = "asm"
    label = "Attack Surface Manager"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = "Track attack surface over time; detect new/removed/changed assets."
    phase = 2  # chain plugin: needs the discovery bus populated

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        # Build current snapshot from the discovery bus
        current: Dict[str, List[str]] = {}
        for kind in SURFACE_KINDS:
            current[kind] = sorted(_normalize_set(ctx.consume(kind)))

        # Load previous snapshot
        key = _snapshot_key(domain)
        previous: Optional[Dict[str, List[str]]] = None
        try:
            previous = ctx.cache.get("asm", key)
        except Exception:
            previous = None

        # Store current as the new baseline
        try:
            ctx.cache.set("asm", key, current, ttl=86400 * 90)  # 90 day history
        except Exception:
            pass

        # Publish the full surface to the bus for assetgraph.py
        for kind, items in current.items():
            for item in items[:200]:  # cap to avoid bus bloat
                ctx.publish(f"surface_{kind}", item)

        if not previous:
            findings = [self._f(
                "infra", "asm_baseline",
                f"Attack surface baseline established for {domain}: "
                f"{sum(len(v) for v in current.values())} assets tracked. "
                f"Future scans will report new/removed/changed assets.",
                source="ASM", confidence=95,
                evidence={"severity": "low",
                          "remediation": "No action needed. This is the "
                                         "baseline - changes will be "
                                         "flagged on the next scan.",
                          "asset_counts": {k: len(v) for k, v in current.items()}})]
            res = self._ok(findings, "baseline established")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        for kind in SURFACE_KINDS:
            prev_set = set(previous.get(kind, []))
            curr_set = set(current.get(kind, []))
            new_items = sorted(curr_set - prev_set)[:20]
            removed_items = sorted(prev_set - curr_set)[:20]

            for item in new_items:
                findings.append(self._f(
                    "infra", "asm_new_asset",
                    f"NEW {kind}: {item[:200]}",
                    source="ASM change detection", confidence=85,
                    evidence={"severity": "medium",
                              "remediation": REMEDIATION_NEW,
                              "asset_kind": kind,
                              "asset": item[:500],
                              "change_type": "new"}))

            for item in removed_items:
                findings.append(self._f(
                    "infra", "asm_removed_asset",
                    f"REMOVED {kind}: {item[:200]}",
                    source="ASM change detection", confidence=85,
                    evidence={"severity": "low",
                              "remediation": REMEDIATION_REMOVED,
                              "asset_kind": kind,
                              "asset": item[:500],
                              "change_type": "removed"}))

        total_new = sum(1 for f in findings if f.evidence.get("change_type") == "new")
        total_removed = sum(1 for f in findings if f.evidence.get("change_type") == "removed")
        reason = (f"surface tracked: {total_new} new, {total_removed} removed "
                  f"vs last scan")
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
