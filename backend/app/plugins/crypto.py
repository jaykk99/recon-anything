"""Cryptocurrency address finder (OSINT: cryptocurrency category).

Finds crypto wallet addresses published on the target (donation pages,
payment info, JS). Addresses are not secrets, but they pivot to
blockchain explorers for fund-flow analysis. Read-only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .injutil import same_domain
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

ADDR_PATTERNS = [
    ("btc", r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b", "Bitcoin",
     "https://www.blockchain.com/explorer/addresses/btc/"),
    ("eth", r"\b0x[0-9a-fA-F]{40}\b", "Ethereum",
     "https://etherscan.io/address/"),
    ("ltc", r"\b(ltc1|[LM])[a-zA-HJ-NP-Z0-9]{25,62}\b", "Litecoin",
     "https://litecoinspace.org/address/"),
    ("doge", r"\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b", "Dogecoin",
     "https://dogechain.info/address/"),
    ("xmr", r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", "Monero",
     "https://xmrchain.net/search?value="),
    ("trx", r"\bT[A-Za-z1-9]{33}\b", "Tron",
     "https://tronscan.org/#/address/"),
    ("sol", r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b", "Solana (candidate)",
     "https://solscan.io/account/"),
]

EXPLORER_NOTE = ("Pivot: paste the address into its blockchain explorer to "
                 "trace fund flows, cluster wallets and find linked identities.")


class CryptoPlugin(Plugin):
    id = "crypto"
    label = "Crypto Address Finder"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find published crypto addresses for fund-flow pivoting."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
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

        texts = [("homepage HTML", html, page_url)]
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(page_url, m.group(1))
            if same_domain(full, domain):
                try:
                    jr = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=15)
                    if jr.status_code == 200:
                        texts.append(("JS bundle", jr.text[:400000], full))
                except Exception:
                    continue
            if len(texts) > 10:
                break

        seen = set()
        for where, text, url in texts:
            for cid, pat, coin, explorer in ADDR_PATTERNS:
                try:
                    for m in re.finditer(pat, text):
                        addr = m.group(0)
                        if cid == "sol" and len(addr) < 40:
                            continue
                        key = (cid, addr)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(self._f(
                            "web", "crypto_address",
                            f"{coin} address published: {addr[:12]}...{addr[-6:]} ({where})",
                            source="crypto scan", source_url=url,
                            confidence=70, passive=passive,
                            evidence={"coin": coin, "address": addr,
                                      "explorer": explorer + addr,
                                      "note": EXPLORER_NOTE}))
                except re.error:
                    continue
                if len(seen) >= 25:
                    break
            if len(seen) >= 25:
                break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} crypto addresses")
        res.duration_ms = dur
        return res
