"""Exposed credit/debit card number finder.

Scans the homepage HTML and first-party JS bundles for payment card
numbers, validates them with the Luhn checksum, and identifies the card
brand from the BIN (IIN) prefix. Read-only GETs of public pages.

Per operator order, the FULL card number is shown in the finding value
(not redacted) so exposed cards can be verified for the client report.
A PCI DSS handling warning is attached to every finding: treat exposed
PANs as toxic data, report them to the site owner, never store or reuse
them. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, is_placeholder

# Card brand detection by BIN (IIN) prefix.
BRANDS = [
    ("Visa", re.compile(r"^4")),
    ("Mastercard", re.compile(r"^(5[1-5]|2(2[2-9]|[3-6]|7[01]|720))")),
    ("Amex", re.compile(r"^3[47]")),
    ("Discover", re.compile(r"^6(?:011|5)")),
    ("Diners Club", re.compile(r"^3(?:0[0-5]|[68])")),
    ("JCB", re.compile(r"^35")),
    ("UnionPay", re.compile(r"^62")),
]

# Candidate PAN: 13-19 digits with optional space/dash separators.
PAN_RE = re.compile(r"\b(?:\d[ \-\.]?){13,19}\b")

# Boost confidence when card-ish words are nearby.
CARD_CTX = re.compile(
    r"(?i)(card[_\s-]?(number|num|no)|ccnum|credit[_\s-]?card|"
    r"debit[_\s-]?card|payment[_\s-]?(card|method)|pan\b|"
    r"cardholder|expir(y|ation)|cvv|cvc)",
    re.M,
)

PCI_WARNING = (
    "PCI DSS WARNING: this is a live payment card number (PAN). Handle as "
    "toxic data. Report it to the site owner immediately so it can be "
    "removed. Never store, share, or attempt to use it. This finding exists "
    "so the leak can be fixed, not exploited."
)


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Reject all-same-digit strings (not real PANs).
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


def brand_of(number: str) -> str:
    for brand, rx in BRANDS:
        if rx.match(number):
            return brand
    return "Unknown"


def clean(number: str) -> str:
    return re.sub(r"[^\d]", "", number)


class CardsPlugin(Plugin):
    id = "cards"
    label = "Exposed Card Numbers"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find Luhn-valid credit/debit card numbers exposed in pages and JS."

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
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                                follow_redirects=True)
                return {"html": r.text[:500000], "url": str(r.url)}
            except Exception as e:
                return {"error": str(e)[:200] or type(e).__name__}

        home, _ = await ctx.cache.cached("http", f"cards:{base}", get_home)
        if "error" in home:
            res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]

        def emit(raw: str, where: str, url: Optional[str]) -> None:
            num = clean(raw)
            if not luhn_ok(num):
                return
            if is_placeholder(num):
                return
            if num in seen:
                return
            seen.add(num)
            brand = brand_of(num)
            near = bool(CARD_CTX.search(where))
            conf = 95 if near else 80
            value = (
                f"CRITICAL: {brand} card {num} ({where}). "
                f"FULL PAN SHOWN PER OPERATOR ORDER. {PCI_WARNING}"
            )
            ev = evidence_block(num, "payment_card_pan", "credential",
                                "critical",
                                {"card_brand": brand,
                                 "last4": num[-4:],
                                 "luhn_valid": True,
                                 "pci_warning": PCI_WARNING,
                                 "context_boost": near})
            findings.append(self._f(
                "leak", "exposed_card_number", value,
                source=f"card scan: {where}", source_url=url,
                confidence=conf, passive=passive, evidence=ev))

        for m in PAN_RE.finditer(html):
            emit(m.group(0), "homepage HTML", page_url)

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
            label = f"JS bundle {host or 'inline'}"
            for m in PAN_RE.finditer(js):
                emit(m.group(0), label, full)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"scanned page + {len(srcs)} bundles, "
                       f"{len(findings)} exposed card numbers")
        res.duration_ms = dur
        return res
