"""Rug pull / honeypot indicator detector.

Flags token contract patterns associated with rug pulls and honeypots:
mint functions, owner privileges, trading restrictions. Read-only.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

RUG_PATTERNS = [
    (r"function mint\(", "mint function (unlimited supply risk)", "high"),
    (r"onlyOwner|_owner", "owner-only privileged functions", "medium"),
    (r"maxTxAmount|maxWallet|_maxTx", "trading limits (honeypot indicator)", "high"),
    (r"setTax|_taxFee|_liquidityFee", "adjustable tax functions", "medium"),
    (r"blacklist|_isBlacklisted", "blacklist function (honeypot indicator)", "high"),
    (r"pause\(\)|_paused", "pausable transfers", "medium"),
    (r"renounceOwnership", "ownership renounced (positive signal)", "low"),
]

REMEDIATION = ("Verify ownership is renounced or timelocked, check liquidity "
               "locks, and audit tokenomics before interacting.")


class RugpullPlugin(Plugin):
    id = "rugpull"
    label = "Rug Pull Indicators"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Flag honeypot and rug pull contract patterns."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
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
        sources = [html] + [str(u) for u in ctx.consume("js_files")[:20]]
        seen = set()
        for src in sources:
            for pat, label, sev in RUG_PATTERNS:
                for m in re.finditer(pat, src, re.I):
                    sample = m.group(0)[:60]
                    key = (label, sample)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._f(
                        "web3", "rugpull_indicator",
                        f"Rug pull indicator: {label}.",
                        source="Rug pull scan", source_url=page_url,
                        confidence=60, passive=passive,
                        evidence={"severity": sev, "pattern": label,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Indicators only. DYOR. Authorized testing only."}))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} rug indicators")
        res.duration_ms = dur
        return res
