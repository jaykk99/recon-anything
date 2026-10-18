"""Exposed gift card code finder.

Scans the homepage HTML and first-party JS bundles for gift card codes
(Amazon, Steam, Visa/MC gift, and generic formats) appearing near gift
card keywords. Read-only GETs of public pages.

Per operator order, the FULL code is shown in the finding value (not
redacted) so exposed codes can be verified for the client report.
Treat exposed codes as sensitive financial data: report them to the
site owner immediately. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, is_placeholder

# Gift card keywords that must appear near a code candidate. Codes alone
# are too generic (order IDs, serials), so context is required.
GIFT_CTX = re.compile(
    r"(?i)(gift[_\s-]?card|giftcode|gift[_\s-]?code|redeem|"
    r"prepaid[_\s-]?card|store[_\s-]?credit|balance[_\s-]?code|"
    r"claim[_\s-]?code)",
    re.M,
)

# (name, regex, confidence, severity, brand)
PATTERNS = [
    # Steam wallet: XXXXX-XXXXX-XXXXX (15 alphanumerics, no I/O/1/0 confusion
    # in real codes, but be lenient here).
    ("steam_wallet_code",
     r"\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b", 80, "critical", "Steam"),
    # Amazon claim code: typically XXXX-XXXXXX-XXXX (14 chars).
    ("amazon_claim_code",
     r"\b[A-Z0-9]{4}-[A-Z0-9]{6}-[A-Z0-9]{4}\b", 78, "critical", "Amazon"),
    # Amazon alt: 16-char continuous claim code. Real Amazon codes mix
    # letters and digits, so require at least 3 letters to avoid matching
    # plain 16-digit card PANs (those are handled by gift_card_pan).
    ("amazon_claim_code_long",
     r"\b(?=(?:[A-Z0-9]*[A-Z]){3})[A-Z0-9]{16}\b", 55, "high", "Amazon"),
    # Generic gift code: labelled assignment like gift_code = "ABCD-1234...".
    ("generic_gift_code",
     r"(?i)(?:gift[_\s-]?(?:card|code)|redeem[_\s-]?code|claim[_\s-]?code)"
     r"\s*[:=]\s*['\"]([A-Za-z0-9\-]{8,40})['\"]", 70, "high", "Generic"),
    # Visa/MC gift: 16-digit PAN-looking number near gift keywords. Luhn is
    # checked separately; this pattern just needs the gift context.
    ("gift_card_pan",
     r"\b(?:\d[ \-\.]?){16}\b", 70, "critical", "Visa/MC Gift"),
]

PCI_WARNING = (
    "SENSITIVE FINANCIAL DATA: this is a live gift card code. Report it to "
    "the site owner immediately so it can be revoked. Never store, share, "
    "or attempt to redeem it. This finding exists so the leak can be fixed, "
    "not exploited."
)


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    if len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class GiftcardsPlugin(Plugin):
    id = "giftcards"
    label = "Exposed Gift Card Codes"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find exposed gift card codes (Amazon, Steam, Visa gift) in pages and JS."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen = set()

        async def get_home():
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                                follow_redirects=True)
                return {"html": r.text[:500000], "url": str(r.url)}
            except Exception as e:
                return {"error": str(e)[:200]}

        home, _ = await ctx.cache.cached("http", f"giftcards:{base}", get_home)
        if home.get("error"):
            res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]

        def has_gift_ctx(text: str, pos: int, window: int = 400) -> bool:
            start = max(0, pos - window)
            end = min(len(text), pos + window)
            return bool(GIFT_CTX.search(text[start:end]))

        def emit(name: str, code: str, where: str, conf: int,
                 severity: str, brand: str, url: Optional[str]) -> None:
            code = code.strip()[:64]
            if is_placeholder(code):
                return
            # Dedupe by code across all patterns: one finding per code.
            if code in seen:
                return
            seen.add(code)
            value = (
                f"CRITICAL: {brand} gift code {code} ({where}). "
                f"FULL CODE SHOWN PER OPERATOR ORDER. {PCI_WARNING}"
            )
            ev = evidence_block(code, name, "credential", severity,
                                {"brand": brand,
                                 "pci_warning": PCI_WARNING})
            findings.append(self._f(
                "leak", f"exposed_{name}", value,
                source=f"gift card scan: {where}", source_url=url,
                confidence=conf, passive=passive, evidence=ev))

        def scan_text(text: str, where: str, url: Optional[str]) -> None:
            for name, pat, conf, sev, brand in PATTERNS:
                try:
                    for m in re.finditer(pat, text):
                        val = (m.group(1) if m.groups()
                               and name == "generic_gift_code" else m.group(0))
                        if name == "gift_card_pan":
                            digits = re.sub(r"[^\d]", "", val)
                            if len(digits) != 16 or not luhn_ok(digits):
                                continue
                            val = digits
                        if not has_gift_ctx(text, m.start()):
                            continue
                        emit(name, val, where, conf, sev, brand, url)
                except re.error:
                    continue

        scan_text(html, "homepage HTML", page_url)

        srcs = re.findall(r'<script[^>]+src=[\"\\\']([^\"\\\']+)[\"\\\']', html, re.I)
        srcs = [s for s in srcs if not s.startswith("data:")][:25]
        for src in srcs:
            full = urljoin(page_url, src)
            host = urlparse(full).netloc
            if host and not host.endswith(domain):
                continue
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=20)
                if r.status_code != 200:
                    continue
                js = r.text[:800000]
            except Exception:
                continue
            scan_text(js, f"JS bundle {host or 'inline'}", full)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"scanned page + {len(srcs)} bundles, "
                       f"{len(findings)} exposed gift card codes")
        res.duration_ms = dur
        return res
