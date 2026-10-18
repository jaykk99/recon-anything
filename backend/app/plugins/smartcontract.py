"""Smart contract vulnerability detector.

Finds contract addresses on the target, checks for common vulnerability
patterns in any available source, and links to block explorers for
verification. Read-only: never sends transactions. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Ethereum-style addresses
ADDRESS_PAT = r"0x[a-fA-F0-9]{40}"

# Dangerous patterns often visible in published source or docs
VULN_PATTERNS = [
    (r"\.call\{value:", "low-level call with value (reentrancy risk)", "high"),
    (r"\.call\(", "low-level call (check return value)", "medium"),
    (r"\.delegatecall\(", "delegatecall (storage collision risk)", "high"),
    (r"tx\.origin", "tx.origin auth (phishing risk)", "high"),
    (r"block\.timestamp", "block.timestamp dependence (miner manipulation)", "medium"),
    (r"selfdestruct", "selfdestruct present", "medium"),
    (r"pragma solidity [\^<>=]*0\.4", "very old Solidity 0.4.x", "medium"),
    (r"pragma solidity [\^<>=]*0\.5", "old Solidity 0.5.x", "low"),
]

EXPLORERS = {
    "ethereum": "https://etherscan.io/address/{}",
    "bsc": "https://bscscan.com/address/{}",
    "polygon": "https://polygonscan.com/address/{}",
    "arbitrum": "https://arbiscan.io/address/{}",
}

REMEDIATION = ("Use ReentrancyGuard, checks-effects-interactions pattern, "
               "avoid tx.origin for auth, pull over push payments, and get "
               "a professional audit before mainnet.")


class SmartcontractPlugin(Plugin):
    id = "smartcontract"
    label = "Smart Contract Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find contract addresses and flag risky patterns."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Gather text from page + JS bundles
        texts = [html]
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(page_url, m.group(1))
            if urlparse(full).netloc.endswith(domain):
                try:
                    jr = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=15)
                    if jr.status_code == 200:
                        texts.append(jr.text[:500000])
                except Exception:
                    continue
            if len(texts) > 10:
                break

        seen_addr = set()
        for text in texts:
            for m in re.finditer(ADDRESS_PAT, text):
                addr = m.group(0)
                # skip zero address and common placeholders
                if addr.lower() in ("0x" + "0" * 40, "0x" + "f" * 40):
                    continue
                if addr in seen_addr:
                    continue
                seen_addr.add(addr)
                ctx.publish("contract_addresses", addr)
                findings.append(self._f(
                    "web", "contract_address",
                    f"MEDIUM: Ethereum-style contract address found: {addr}. "
                    f"Verify on explorer.",
                    source="address mining", source_url=page_url,
                    confidence=70, passive=passive,
                    evidence={"severity": "medium", "address": addr,
                              "explorers": {k: v.format(addr) for k, v in EXPLORERS.items()},
                              "remediation": REMEDIATION}))

            # Vuln patterns in any visible Solidity source
            for pat, label, sev in VULN_PATTERNS:
                for m in re.finditer(pat, text):
                    snippet = text[max(0, m.start() - 80):m.end() + 80].strip()
                    findings.append(self._f(
                        "web", "contract_risk_pattern",
                        f"{sev.upper()}: risky Solidity pattern: {label}.",
                        source="pattern scan", source_url=page_url,
                        confidence=60, passive=passive,
                        evidence={"severity": sev, "pattern": label,
                                  "snippet": snippet[:300],
                                  "remediation": REMEDIATION}))
                    break  # one finding per pattern type

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(seen_addr)} contract addresses, "
                                 f"{len(findings)} findings")
        res.duration_ms = dur
        return res
