"""Credit card validator (dnschecker.org style) - FULL RECORDS ONLY.

Jay's rule: never report a bare card number. A finding is emitted ONLY
when a 16-digit Luhn-valid PAN is found TOGETHER with an expiry date
(MM/YY) and a CVV (3-4 digits) in the same card record, e.g.::

    4111 1111 1111 1111  12/27  123
    {"number": "4111111111111111", "exp": "12/27", "cvv": "123"}

Partial numbers like "1221 1111 1111 1222" with no expiry/CVV never
become findings - they are silently dropped.

This is structural validation only (Luhn math + regex, same as
dnschecker.org's public validator). It does NOT check whether a card is
active, has balance, or belongs to anyone. Detection only: read-only
GETs of public pages, no auth attempts, no transactions.

Findings show brand + BIN (first 6) + last 4 + expiry/CVV presence
(CVV digits never stored), never the full middle digits. A PCI DSS
handling warning is attached to every finding: treat exposed PANs as
toxic data, report them to the site owner, never store or reuse them.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Dict, List, Optional
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

# Jay's rule: 16-digit PANs only (with optional space/dash/dot separators).
PAN16_RE = re.compile(r"\b(?:\d[ \-\.]?){16}\b")

# How far around a PAN we look for the matching expiry + CVV (chars).
RECORD_WINDOW = 400

# Expiry: labeled ("exp 12/27", "expiry: 12-27", "exp_date":"12/2027")
EXPIRY_LABELED_RE = re.compile(
    r"(?i)(?:exp(?:iry|iration)?|valid\s*(?:thru|through|until)|"
    r"exp_date|expirydate|expmonthyear)"
    r"[_\s:\-]*[\"']?\s*"
    r"(0[1-9]|1[0-2])\s*[/\-.]\s*(\d{2}|\d{4})"
)
# Expiry: bare MM/YY or MM/YYYY (validated by year range below).
EXPIRY_BARE_RE = re.compile(
    r"\b(0[1-9]|1[0-2])\s*[/\-.]\s*(\d{2}|\d{4})\b"
)

# CVV: labeled ("cvv 123", "cvc: 1234", "security_code": "123").
CVV_LABELED_RE = re.compile(
    r"(?i)(?:cvv2?|cvc2?|cid|security[_\s-]?code)"
    r"[_\s:\-]*[\"']?\s*(\d{3,4})\b"
)
# CVV: bare 3-4 digit number near the card record.
CVV_BARE_RE = re.compile(r"\b(\d{3,4})\b")

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
    if len(digits) != 16:
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


def expiry_is_plausible(month: str, year: str) -> bool:
    """Expiry must be roughly now..+10 years. Kills dates like 01/99."""
    now = datetime.now()
    yy = int(year[-2:])
    full = 2000 + yy
    return now.year - 1 <= full <= now.year + 10


def find_full_records(text: str) -> List[Dict[str, object]]:
    """Find complete card records: 16-digit PAN + expiry + CVV together.

    Returns a list of dicts with keys: pan, expiry, cvv, labeled (bool),
    offset. Partial numbers (PAN without expiry/CVV) are dropped here.
    """
    records: List[Dict[str, object]] = []
    seen_pans = set()
    for pan_m in PAN16_RE.finditer(text):
        raw = pan_m.group(0)
        num = clean(raw)
        if len(num) != 16 or num in seen_pans:
            continue
        seen_pans.add(num)
        start = max(0, pan_m.start() - RECORD_WINDOW)
        end = min(len(text), pan_m.end() + RECORD_WINDOW)
        window = text[start:end]

        def overlaps_pan(wstart: int, wend: int) -> bool:
            """A window-relative match overlaps the PAN itself
            (e.g. the PAN's own '4111' group matching the bare-CVV
            regex). Such matches must not count as expiry/CVV."""
            astart, aend = start + wstart, start + wend
            return astart < pan_m.end() and aend > pan_m.start()

        # Expiry: prefer labeled, fall back to bare + year validation.
        expiry = None
        exp_labeled = False
        m = EXPIRY_LABELED_RE.search(window)
        if m and not overlaps_pan(m.start(), m.end()) \
                and expiry_is_plausible(m.group(1), m.group(2)):
            expiry = f"{m.group(1)}/{m.group(2)[-2:]}"
            exp_labeled = True
        else:
            for bm in EXPIRY_BARE_RE.finditer(window):
                if overlaps_pan(bm.start(), bm.end()):
                    continue
                if expiry_is_plausible(bm.group(1), bm.group(2)):
                    expiry = f"{bm.group(1)}/{bm.group(2)[-2:]}"
                    break

        # CVV: prefer labeled, fall back to bare 3-4 digits in the window.
        cvv_present = False
        cvv_labeled = False
        lm = CVV_LABELED_RE.search(window)
        if lm and not overlaps_pan(lm.start(), lm.end()):
            cvv_present = True
            cvv_labeled = True
        else:
            for cm in CVV_BARE_RE.finditer(window):
                if overlaps_pan(cm.start(), cm.end()):
                    continue
                cvv_present = True
                break

        # Jay's rule: all three together, or it never becomes a finding.
        if expiry is None or not cvv_present:
            continue
        records.append({
            "pan": num,
            "expiry": expiry,
            "cvv": True,  # presence only - CVV digits are never stored
            "labeled": exp_labeled or cvv_labeled,
            "offset": pan_m.start(),
        })
    return records


class CardValidatorPlugin(Plugin):
    id = "card_validator"
    label = "Card Validator"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "financial"
    description = ("Report ONLY complete card records: 16-digit Luhn-valid "
                   "PAN + MM/YY expiry + CVV found together. Partial "
                   "numbers are never reported.")
    # Phase 2: runs after cards.py; does its own full-record sweep.
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
        checked_records = 0
        partial_dropped = 0
        full_valid = 0
        skipped_test = 0
        skipped_luhn = 0

        def report(rec: Dict[str, object], where: str,
                   url: Optional[str]) -> None:
            nonlocal checked_records, full_valid, skipped_test, skipped_luhn
            num = rec["pan"]
            if num in seen:
                return
            seen.add(num)
            checked_records += 1
            if not luhn_ok(num):
                skipped_luhn += 1
                return
            if is_placeholder(num):
                skipped_luhn += 1
                return
            if num in TEST_PANS:
                skipped_test += 1
                return
            full_valid += 1
            brand = brand_of(num)
            conf = 95 if rec["labeled"] else 80
            bin6 = num[:6]
            last4 = num[-4:]
            value = (
                f"CRITICAL: Complete {brand} card record exposed "
                f"(BIN {bin6}...{last4}, expiry {rec['expiry']}, "
                f"CVV present, {where}). 16-digit PAN passed Luhn, "
                f"expiry and CVV found with the PAN. {PCI_WARNING}"
            )
            ev = evidence_block(f"{bin6}...{last4}", "payment_card_full",
                                "credential", "critical",
                                {"card_brand": brand,
                                 "bin6": bin6,
                                 "last4": last4,
                                 "pan_length": 16,
                                 "luhn_valid": True,
                                 "expiry": rec["expiry"],
                                 "cvv_present": True,
                                 "cvv_stored": False,
                                 "validator": "card_validator",
                                 "pci_warning": PCI_WARNING,
                                 "labeled_record": rec["labeled"]})
            findings.append(self._f(
                "leak", "card_full_record", value,
                source=f"card validator: {where}", source_url=url,
                confidence=conf, passive=passive, evidence=ev))
            # Publish for any downstream chain plugin (no PAN digits).
            ctx.publish("validated_cards",
                        {"brand": brand, "bin6": bin6, "last4": last4,
                         "length": 16, "expiry": rec["expiry"],
                         "source": where})

        # Sweep helper: count partial PANs dropped, report full records.
        def sweep(text: str, where: str, url: Optional[str]) -> None:
            nonlocal partial_dropped
            # Count every 16-digit candidate so we can report how many
            # partials were dropped for not having expiry/CVV.
            partial_dropped += len(PAN16_RE.findall(text))
            for rec in find_full_records(text):
                report(rec, where, url)

        # 1. Homepage HTML.
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
            if findings:
                res = self._ok(findings,
                               f"full records {full_valid}, checked "
                               f"{checked_records} records "
                               f"(homepage fetch failed: {home['error']})")
            else:
                res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]
        sweep(html, "homepage HTML", page_url)

        # 2. First-party JS bundles.
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
            sweep(js, f"JS bundle {host or 'inline'}", full)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"full records {full_valid}/{checked_records} Luhn-valid; "
            f"{partial_dropped} partial PANs dropped (no expiry/CVV); "
            f"{skipped_luhn} failed Luhn; {skipped_test} test PANs skipped; "
            f"swept page + {n_bundles} JS bundles")
        res.duration_ms = dur
        return res
