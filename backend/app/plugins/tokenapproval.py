"""Token approval risk checker.

Finds unlimited/overly-broad ERC-20 token approvals which are a common
phishing and drain vector. Read-only. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

APPROVAL_PATTERNS = [
    (r"approve\(\s*[\"']0x[a-fA-F0-9]{40}[\"']\s*,\s*(?:2\*\*256\s*-\s*1|type\(uint256\)\.max|0xffff+)",
     "unlimited token approval", "high"),
    (r"setApprovalForAll\(\s*true", "setApprovalForAll(true) - full NFT approval", "high"),
    (r"increaseAllowance", "allowance increase pattern", "medium"),
    (r"permit\(", "permit signature (check replay protection)", "medium"),
]

REMEDIATION = ("Request minimal approvals, support permit2/revoke flows, "
               "and warn users before unlimited approvals.")


class TokenapprovalPlugin(Plugin):
    id = "tokenapproval"
    label = "Token Approval Risk"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Find unlimited token approvals (drain vector)."

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
            for pat, label, sev in APPROVAL_PATTERNS:
                for m in re.finditer(pat, src, re.I):
                    sample = m.group(0)[:70]
                    if sample in seen:
                        continue
                    seen.add(sample)
                    findings.append(self._f(
                        "web3", "token_approval",
                        f"Risky approval: {label} ('{sample.strip()}').",
                        source="Approval scan", source_url=page_url,
                        confidence=70, passive=passive,
                        evidence={"severity": sev,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Read-only. Authorized testing only."}))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} approval risks")
        res.duration_ms = dur
        return res
