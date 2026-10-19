"""Exposed crypto wallet finder (Milestone: secret findings).

Looks for private keys, seed phrases, WIF keys, extended keys and
wallet files on the target's public pages, JS bundles and well-known
wallet file paths. Read-only GETs. Findings are CRITICAL, redacted in
the value, full match in evidence with sweep advice. Authorized testing
only: verify you own the asset or it is in an approved bounty scope.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, finding_value, is_placeholder, redact

# Private keys only count when they appear near wallet-ish context, to
# avoid flagging every 64-hex-char transaction hash.
WALLET_CTX = re.compile(
    r"(?i)(private[\s_-]?key|secret[\s_-]?key|wallet|mnemonic|seed|signer|keystore)", re.M)

PATTERNS = [
    # (name, regex, confidence, severity, needs_context)
    ("eth_private_key", r"0x[0-9a-fA-F]{64}", 75, "critical", True),
    ("raw_hex_private_key", r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", 55, "critical", True),
    ("wif_private_key", r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", 90, "critical", False),
    ("xprv_extended_key", r"\bxprv[1-9A-HJ-NP-Za-km-z]{100,112}\b", 92, "critical", False),
    ("xpub_extended_key", r"\bxpub[1-9A-HJ-NP-Za-km-z]{100,112}\b", 80, "high", False),
    ("btc_address", r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b", 60, "medium", False),
    ("eth_address", r"\b0x[0-9a-fA-F]{40}\b", 55, "medium", False),
    ("keystore_json", r'"crypto"\s*:\s*\{\s*"cipher"', 85, "high", False),
    ("mnemonic_keyword", r"(?i)\"mnemonic\"\s*:\s*\"([a-z\s]{20,200})\"", 80, "critical", False),
    ("keystore_filename", r"UTC--\d{4}-\d{2}-\d{2}T[0-9\-:]+--[0-9a-fA-F]{40}", 88, "high", False),
]

# 12- and 24-word candidate seed phrases near seed keywords.
SEED_RE_12 = re.compile(
    r"(?i)(mnemonic|seed|recovery|backup|pass[\s_-]?phrase)[\s\S]{0,80}?\"([a-z]{3,8}(?: [a-z]{3,8}){11})\"")
SEED_RE_24 = re.compile(
    r"(?i)(mnemonic|seed|recovery|backup|pass[\s_-]?phrase)[\s\S]{0,80}?\"([a-z]{3,8}(?: [a-z]{3,8}){23})\"")

WALLET_PATHS = [
    ("/wallet.dat", "Bitcoin Core wallet file", 90),
    ("/.wallet.dat", "hidden wallet file", 85),
    ("/keystore/UTC--", "keystore dir listing?", 70),
    ("/wallets/wallet.dat", "wallet file in wallets dir", 85),
    ("/.env", "env file (may hold keys)", 80),
    ("/config/wallet.json", "wallet config?", 80),
]

REMED_KEY = "wallet_key"


class WalletsPlugin(Plugin):
    id = "wallets"
    label = "Wallet Key Exposure"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Hunt exposed crypto private keys, seed phrases and wallet files."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen = set()

        async def get_home():
            try:
                # Shared homepage cache: first plugin pays, the rest read from cache.
                page = await ctx.fetch_page(base, timeout=25)
                if page is None:
                    raise RuntimeError("homepage fetch failed")
                return {"html": page["text"][:500000], "url": page["url"]}
            except Exception as e:
                return {"error": str(e)[:200] or type(e).__name__}

        home, _ = await ctx.cache.cached("http", f"wallets:{base}", get_home)
        if "error" in home:
            res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]
        texts = [("homepage HTML", html, page_url)]

        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        srcs = [s for s in srcs if not s.startswith("data:")][:25]
        for src in srcs:
            full = urljoin(page_url, src)
            host = urlparse(full).netloc
            if host and not host.endswith(domain):
                continue
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=20)
                if r.status_code == 200:
                    texts.append((f"JS bundle {host or 'inline'}", r.text[:800000], full))
            except Exception:
                continue

        def emit(name: str, match: str, where: str, conf: int,
                 severity: str, url: str | None):
            m = match.strip()[:300]
            if is_placeholder(m):
                return
            key = (name, m)
            if key in seen:
                return
            seen.add(key)
            findings.append(self._f(
                "leak", f"wallet_{name}",
                finding_value(severity, name.replace("_", " "), redact(m), where),
                source=f"wallet scan: {where}", source_url=url,
                confidence=conf, passive=passive,
                evidence=evidence_block(m, name, REMED_KEY, severity)))

        for where, text, url in texts:
            for name, pat, conf, sev, needs_ctx in PATTERNS:
                try:
                    for m in re.finditer(pat, text):
                        val = m.group(1) if name == "mnemonic_keyword" else m.group(0)
                        if needs_ctx and not WALLET_CTX.search(text[max(0, m.start() - 300):m.end() + 100]):
                            continue
                        emit(name, val, where, conf, sev, url)
                except re.error:
                    continue
            for pat, label in ((SEED_RE_12, "possible_12_word_seed"),
                               (SEED_RE_24, "possible_24_word_seed")):
                for m in pat.finditer(text):
                    emit(label, m.group(2), where, 70, "critical", url)

        # wallet file paths (passive: Wayback, active: direct GET)
        if passive:
            from urllib.parse import quote
            for path, label, conf in WALLET_PATHS:
                full = base.rstrip("/") + path
                url = ("https://web.archive.org/cdx/search/cdx?url="
                       + quote(full, safe="") + "&output=json&fl=timestamp&limit=1")
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
                    if r.status_code == 200:
                        data = r.json()
                        if isinstance(data, list) and len(data) > 1:
                            emit("wallet_file_archived", path, f"archived: {label}",
                                 conf - 15, "high", full)
                except Exception:
                    continue
        else:
            for path, label, conf in WALLET_PATHS:
                full = base.rstrip("/") + path
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=12)
                    if r.status_code == 200 and len(r.text.strip()) > 0:
                        emit("wallet_file_exposed", path, label, conf, "critical", full)
                except Exception:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} wallet exposure findings")
        res.duration_ms = dur
        return res
