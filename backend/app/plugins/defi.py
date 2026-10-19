"""DeFi protocol security checker.

Detects DeFi interactions on the target: flash loan patterns, price
oracle usage, and risky DeFi integrations. Read-only analysis.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DEFI_PATTERNS = [
    (r"flash.?loan", "flash loan usage (check for unprotected callbacks)", "high"),
    (r"price.?oracle|chainlink|band.?protocol", "price oracle dependency (manipulation risk)", "medium"),
    (r"uniswap|pancakeswap|sushiswap|curve|balancer", "DEX integration detected", "low"),
    (r"aave|compound|venus", "lending protocol integration", "low"),
    (r"approve\(.*type\(uint256\)\.max", "unlimited token approval pattern", "high"),
    (r"onlyOwner|owner\(\)", "owner privileged functions", "medium"),
]

REMEDIATION = ("Use reputable oracle networks with TWAP, guard flash loan "
               "callbacks, limit approvals, and get professional audits.")


class DefiPlugin(Plugin):
    id = "defi"
    label = "DeFi Protocol Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Detect DeFi patterns: flash loans, oracles, approvals."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        # also scan discovered JS
        sources = [html] + [str(u) for u in ctx.consume("js_files")[:20]]
        seen = set()
        for src in sources:
            for pat, label, sev in DEFI_PATTERNS:
                for m in re.finditer(pat, src, re.I):
                    sample = m.group(0)[:70]
                    key = (label, sample)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._f(
                        "web3", "defi_pattern",
                        f"DeFi pattern: {label} ('{sample.strip()}').",
                        source="DeFi scan", source_url=page_url,
                        confidence=65, passive=passive,
                        evidence={"severity": sev, "pattern": label,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Read-only. Authorized testing only."}))
                    if len(seen) >= 20:
                        break
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} DeFi patterns")
        res.duration_ms = dur
        return res
