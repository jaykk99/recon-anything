"""Credit card validator (dnschecker.org style).

Takes payment-card number candidates found during the scan (page HTML,
first-party JS bundles, and anything other plugins publish to the
"card_candidates" discovery-bus bucket) and runs them through the Luhn
checksum plus brand detection. ONLY Luhn-valid cards are reported -
fakes, typos, and known test PANs never become findings.

This is structural validation only (math, same as dnschecker.org's
public validator). It does NOT check whether a card is active, has
balance, or belongs to anyone. Detection only: read-only GETs of public
pages, no auth attempts, no transactions.

Findings show brand + BIN (first 6) + last 4 + Luhn status, never the
full middle digits. A PCI DSS handling warning is attached to every
finding: treat exposed PANs as toxic data, report them to the site
owner, never store or reuse them. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, is_placeholder

# Card brand detection by BIN (IIN) prefix. Mirrors cards.py.
BRANDS = [
    ("Visa", re.compile(r"^4")),
    ("Mastercard", re.compile(r"^(5[1-5]|2(2[2-9]|[3-6]|7[01]|720))")),
    ("Amex", re.compile(r"^3[47]")),
    ("Discover", re.compile(r"^6(?:011|5)")),
    ("Diners Club", re.compile(r"^3(?:0[0-5]|[68])")),
    ("JCB", re.compile(r"^35")),
    ("UnionPay", re.compile(r"^62")),
]

# Candidate PAN: 13-19 digits with optional space/dash/dot separators.
PAN_RE = re.compile(r"\b(?:\d[ \-\.]?){13,19}\b")

# Boost confidence when card-ish words are nearby.
CARD_CTX = re.compile(
    r"(?i)(card[_\s-]?(number|num|no)|ccnum|credit[_\s-]?card|"
    r"debit[_\s-]?card|payment[_\s-]?(card|method)|pan\b|"
    r"cardholder|expir(y|ation)|cvv|cvc)",
    re.M,
)

# Well-known published test PANs. They pass Luhn but are not real
# accounts - never report them as exposed cards.
TEST_PANS = {
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "5555555555554444",
    "5105105105105100",
    "2223000048400011",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "30569309025904",
    "3530111333300000",
    "3566002020360505",
}

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


class CardValidatorPlugin(Plugin):
    id = "card_validator"
    label = "Card Validator"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "financial"
    description = ("Luhn-validate card number candidates; only valid cards "
                   "reported (no fakes, no test PANs).")
    # Phase 2: runs after cards.py so it can re-validate anything published
    # to the card_candidates bus, then does its own sweep.
    phase = 2

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
        checked = 0
        valid = 0
        skipped_test = 0
        skipped_luhn = 0

        def validate(raw: str, where: str, url: Optional[str]) -> None:
            nonlocal checked, valid, skipped_test, skipped_luhn
            num = clean(raw)
            if num in seen:
                return
            seen.add(num)
            checked += 1
            if not luhn_ok(num):
                skipped_luhn += 1
                return
            if is_placeholder(num):
                skipped_luhn += 1
                return
            if num in TEST_PANS:
                skipped_test += 1
                return
            valid += 1
            brand = brand_of(num)
            near = bool(CARD_CTX.search(where))
            conf = 95 if near else 80
            bin6 = num[:6]
            last4 = num[-4:]
            value = (
                f"CRITICAL: Luhn-valid {brand} card exposed "
                f"(BIN {bin6}...{last4}, {len(num)} digits, {where}). "
                f"Luhn checksum passed, brand identified from BIN. "
                f"{PCI_WARNING}"
            )
            ev = evidence_block(f"{bin6}...{last4}", "payment_card_pan",
                                "credential", "critical",
                                {"card_brand": brand,
                                 "bin6": bin6,
                                 "last4": last4,
                                 "pan_length": len(num),
                                 "luhn_valid": True,
                                 "validator": "card_validator",
                                 "pci_warning": PCI_WARNING,
                                 "context_boost": near})
            findings.append(self._f(
                "leak", "card_validated", value,
                source=f"card validator: {where}", source_url=url,
                confidence=conf, passive=passive, evidence=ev))
            # Publish for any downstream chain plugin.
            ctx.publish("validated_cards",
                        {"brand": brand, "bin6": bin6, "last4": last4,
                         "length": len(num), "source": where})

        # 1. Re-validate anything other plugins published.
        for item in ctx.consume("card_candidates"):
            raw = item if isinstance(item, str) else str(item.get("number", ""))
            if raw:
                validate(raw, "discovery bus", None)

        # 2. Own sweep: homepage HTML.
        async def get_home():
            try:
                page = await ctx.fetch_page(base, timeout=25)
                if page is None:
                    raise RuntimeError("homepage fetch failed")
                return {"html": page["text"][:500000], "url": page["url"]}
            except Exception as e:
                return {"error": str(e)[:200] or type(e).__name__}

        home, _ = await ctx.cache.cached("http", f"cardvalidator:{base}", get_home)
        if "error" in home:
            # Still report bus-based results if we got any.
            if findings:
                res = self._ok(findings,
                               f"validated {valid}/{checked} candidates "
                               f"(homepage fetch failed: {home['error']})")
            else:
                res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]
        for m in PAN_RE.finditer(html):
            validate(m.group(0), "homepage HTML", page_url)

        # 3. Own sweep: first-party JS bundles.
        srcs = re.findall(r'<script[^>]+src=[\"\\\']([^\"\\\']+)[\"\\\']', html, re.I)
        srcs = [s for s in srcs if not s.startswith("data:")][:25]
        n_bundles = 0
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
                n_bundles += 1
            except Exception:
                continue
            label = f"JS bundle {host or 'inline'}"
            for m in PAN_RE.finditer(js):
                validate(m.group(0), label, full)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"checked {checked} candidates across page + {n_bundles} JS "
            f"bundles: {valid} Luhn-valid, {skipped_luhn} failed Luhn, "
            f"{skipped_test} test PANs skipped")
        res.duration_ms = dur
        return res
