"""Wallet security checker (extends wallet key finder).

Checks for weak wallet configurations: exposed mnemonics, keystore files,
unencrypted keys, and weak wallet setups. Defensive: helps find YOUR
exposed wallets. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# BIP39 wordlist sample for mnemonic detection (first few + pattern)
MNEMONIC_PATTERN = r"\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b"  # 12 words
MNEMONIC24_PATTERN = r"\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b"  # 24 words

# Wallet file paths to check
WALLET_PATHS = [
    ("/wallet.dat", "Bitcoin Core wallet file"),
    ("/.wallet.dat", "hidden wallet file"),
    ("/keystore/UTC--", "Ethereum keystore prefix"),
    ("/keystore", "keystore directory"),
    ("/wallets/", "wallets directory"),
    ("/.env", "env file (may contain keys)"),
    ("/config/wallet.json", "wallet config"),
    ("/data/wallet.dat", "wallet data file"),
]

# Weak patterns
WEAK_PATTERNS = [
    (r'"mnemonic"\s*:\s*"[^"]{20,}"', "mnemonic in JSON config", "critical"),
    (r'"private[_-]?key"\s*:\s*"[0-9a-fA-F]{32,}"', "private key in JSON", "critical"),
    (r"mnemonic\s*=\s*['\"][a-z\s]{20,}['\"]", "mnemonic assignment", "critical"),
    (r"xprv[a-km-zA-HJ-NP-Z1-9]{100,}", "extended private key (xprv)", "critical"),
]

REMEDIATION = ("Never store mnemonics or private keys in code, configs, or "
               "web-accessible paths. Use hardware wallets, encrypt keystores "
               "with strong passwords, and rotate any exposed keys immediately.")


class WalletcheckPlugin(Plugin):
    id = "walletcheck"
    label = "Wallet Security Check"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find exposed wallets, mnemonics, keystores."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (f"https://{domain}" if target.type == "domain"
                else target.normalized.rstrip("/"))
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        # 1. Check for wallet files
        if not passive:
            for path, label in WALLET_PATHS:
                url = base + path
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
                    if r.status_code == 200 and len(r.text.strip()) > 10:
                        findings.append(self._f(
                            "leak", "wallet_file_exposed",
                            f"CRITICAL: wallet file exposed: {path} ({label}).",
                            source="wallet file check", source_url=url,
                            confidence=90, passive=False,
                            evidence={"severity": "critical", "path": path,
                                      "label": label,
                                      "remediation": REMEDIATION}))
                except Exception:
                    continue

        # 2. Scan page + JS for mnemonics and weak patterns
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

        texts = [("homepage", html, page_url)]
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(page_url, m.group(1))
            if urlparse(full).netloc.endswith(domain):
                try:
                    jr = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=15)
                    if jr.status_code == 200:
                        texts.append(("JS bundle", jr.text[:500000], full))
                except Exception:
                    continue
            if len(texts) > 10:
                break

        for where, text, url in texts:
            # Mnemonic patterns (12 or 24 words)
            for pat, words in [(MNEMONIC24_PATTERN, 24), (MNEMONIC_PATTERN, 12)]:
                for m in re.finditer(pat, text):
                    candidate = m.group(0).strip()
                    # Basic sanity: all lowercase words
                    if re.match(r"^[a-z\s]+$", candidate):
                        findings.append(self._f(
                            "leak", "mnemonic_exposed",
                            f"CRITICAL: possible {words}-word mnemonic phrase "
                            f"in {where}.",
                            source="mnemonic scan", source_url=url,
                            confidence=65, passive=passive,
                            evidence={"severity": "critical",
                                      "words": words,
                                      "preview": candidate[:30] + "...",
                                      "remediation": REMEDIATION,
                                      "scope_note": "Verify manually. If real, the wallet is fully compromised."}))
                        break

            # Weak patterns
            for pat, label, sev in WEAK_PATTERNS:
                if re.search(pat, text):
                    findings.append(self._f(
                        "leak", "wallet_weak_config",
                        f"CRITICAL: {label} found in {where}.",
                        source="wallet config scan", source_url=url,
                        confidence=80, passive=passive,
                        evidence={"severity": sev,
                                  "remediation": REMEDIATION}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} wallet security findings")
        res.duration_ms = dur
        return res
