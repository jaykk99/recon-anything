"""Finding deduplicator: filter duplicates across plugins and runs.

Problems it solves:
1. Multiple plugins flag the same issue (e.g. both headers.py and
   misconfig_sweep.py report a missing header) -> keep the best one.
2. Repeat scans re-report the same finding -> suppress if unchanged
   since last scan (uses the ASM snapshot cache).
3. Same finding with slightly different text -> fuzzy match on
   (plugin-agnostic key, normalized value).

How it works: consumes findings from the bus, groups by a canonical
fingerprint (category + key + normalized value hash), keeps the
highest-confidence instance, and checks the dedup cache for
previously-reported fingerprints.

Emits: a summary finding with dedup stats, plus re-publishes the
unique findings to "deduped_findings" for downstream consumers.

Pure logic - no network calls. Keyless.
Phase 2 chain plugin: runs after all discovery.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _canonical(value: str) -> str:
    """Normalize a finding value for fuzzy comparison."""
    v = value.lower()
    v = re.sub(r"https?://[^\s]+", "URL", v)       # URLs -> placeholder
    v = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "IP", v)  # IPs -> placeholder
    v = re.sub(r":\d{2,5}\b", ":PORT", v)          # ports -> placeholder
    v = re.sub(r"\s+", " ", v).strip()
    return v[:300]


def _fingerprint(category: str, key: str, value: str) -> str:
    canon = _canonical(value)
    raw = f"{category}|{key}|{canon}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class DedupPlugin(Plugin):
    id = "dedup"
    label = "Finding Deduplicator"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Remove duplicate findings across plugins and repeat scans."
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        raw_findings = ctx.consume("poc_findings")
        if not raw_findings:
            return self._ok([], "no findings on bus to dedup")

        # Group by fingerprint, keep highest confidence
        best: Dict[str, Dict[str, Any]] = {}
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            fp = _fingerprint(item.get("category", ""),
                              item.get("key", ""),
                              item.get("value", ""))
            conf = int(item.get("confidence", 0) or 0)
            if fp not in best or conf > int(best[fp].get("confidence", 0) or 0):
                best[fp] = item

        # Check against previously reported (cross-run dedup)
        cache_key = f"dedup:seen:{hashlib.sha256(domain.encode()).hexdigest()[:16]}"
        try:
            seen = set(ctx.cache.get("dedup", cache_key) or [])
        except Exception:
            seen = set()

        unique: List[Dict[str, Any]] = []
        suppressed_repeat = 0
        suppressed_dup = len(raw_findings) - len(best)
        for fp, item in best.items():
            if fp in seen:
                suppressed_repeat += 1
                continue
            unique.append(item)
            seen.add(fp)

        # Persist the seen set (cap at 5000 to bound cache size)
        try:
            ctx.cache.set("dedup", cache_key, sorted(seen)[-5000:],
                          ttl=86400 * 90)
        except Exception:
            pass

        # Re-publish unique findings for downstream consumers
        for item in unique:
            ctx.publish("deduped_findings", item)

        findings: List[Finding] = [self._f(
            "web", "dedup_summary",
            f"Dedup: {len(raw_findings)} raw -> {len(unique)} unique "
            f"({suppressed_dup} cross-plugin dups, {suppressed_repeat} "
            f"repeat-scan suppressions).",
            source="Dedup", confidence=95,
            evidence={"severity": "low",
                      "remediation": "No action needed - this is pipeline "
                                     "hygiene. Review the unique findings.",
                      "raw_count": len(raw_findings),
                      "unique_count": len(unique),
                      "cross_plugin_dups": suppressed_dup,
                      "repeat_suppressions": suppressed_repeat})]

        reason = f"{len(raw_findings)} -> {len(unique)} unique findings"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
