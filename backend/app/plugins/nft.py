"""NFT contract and metadata checker.

Flags NFT mint vulnerabilities: reentrancy in mint, metadata exposure,
unlimited supply. Read-only. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

NFT_PATTERNS = [
    (r"ERC721|ERC1155", "NFT standard detected", "low"),
    (r"function (safeMint|mint)\(", "mint function (check access control)", "medium"),
    (r"tokenURI|baseURI", "metadata URI (check for exposure/centralization)", "low"),
    (r"maxSupply|MAX_SUPPLY", "supply cap present", "low"),
    (r"onERC721Received", "ERC721 receiver hook (reentrancy surface)", "medium"),
    (r"ipfs://", "IPFS metadata (decentralized, good)", "low"),
]

REMEDIATION = ("Limit mint per wallet, use ReentrancyGuard on mint, pin "
               "metadata to IPFS, and audit before launch.")


class NftPlugin(Plugin):
    id = "nft"
    label = "NFT Contract Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Check NFT mint functions and metadata exposure."

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
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        sources = [html] + [str(u) for u in ctx.consume("js_files")[:20]]
        seen = set()
        for src in sources:
            for pat, label, sev in NFT_PATTERNS:
                for m in re.finditer(pat, src, re.I):
                    key = (label, m.group(0)[:50])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._f(
                        "web3", "nft_pattern",
                        f"NFT pattern: {label}.",
                        source="NFT scan", source_url=page_url,
                        confidence=60, passive=passive,
                        evidence={"severity": sev,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Read-only. Authorized testing only."}))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} NFT patterns")
        res.duration_ms = dur
        return res
