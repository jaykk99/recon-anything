"""Phone lookup plugin.

Analyzes phone numbers: carrier/service provider, line type, region,
validity. Uses libphonenumber (offline, no API keys needed).
Does NOT do name lookup - that is doxxing, not legitimate OSINT.
"""
from __future__ import annotations

import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import number_type as pn_number_type
    from phonenumbers import timezone as pn_timezone
    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False

# Fallback area codes -> region (used only if phonenumbers unavailable)
AREA_CODES = {
    "204": "Manitoba, Canada", "431": "Manitoba, Canada",
    "416": "Toronto, Canada", "647": "Toronto, Canada",
    "604": "Vancouver, Canada", "778": "Vancouver, Canada",
    "514": "Montreal, Canada", "438": "Montreal, Canada",
    "403": "Alberta, Canada", "780": "Alberta, Canada",
    "902": "Nova Scotia, Canada", "506": "New Brunswick, Canada",
    "212": "New York, USA", "310": "Los Angeles, USA",
    "415": "San Francisco, USA", "312": "Chicago, USA",
}


class PhonesPlugin(Plugin):
    id = "phones"
    label = "Phone Lookup"
    accepts = ["phone", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Carrier, line type, region, and validity for phone numbers (offline, no keys). Extracts phone numbers from pages."

    # Phone number patterns for extraction from page content
    PHONE_PATTERNS = [
        (r"\+?1[-.\s]?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})", "NANP"),
        (r"\+?44[-.\s]?\(?(\d{2,5})\)?[-.\s]?(\d{3,4})[-.\s]?(\d{3,4})", "UK"),
        (r"\+?61[-.\s]?\(?(\d{1,2})\)?[-.\s]?(\d{4})[-.\s]?(\d{4})", "AU"),
        (r"tel:([+\d][\d\-.\s()]{7,20})", "tel: link"),
        (r'["\'](\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4})["\']', "intl quoted"),
    ]

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []

        if target.type == "phone":
            raw = target.normalized.strip()
            if HAVE_PHONENUMBERS:
                findings = self._analyze_libphonenumber(raw)
            else:
                findings = self._analyze_fallback(raw)
            if not findings:
                return self._skipped("could not parse as a phone number")
        else:
            # Extract phone numbers from the target's web pages
            from ..classifier import domain_from_target
            from ..ratelimit import fetch
            from ..net import web_base
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain for this target type")
            base = await web_base(ctx, target, domain)
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=15)
                if r.status_code == 200:
                    seen = set()
                    for pat, label in self.PHONE_PATTERNS:
                        for m in re.finditer(pat, r.text):
                            num = m.group(0)[:30]
                            if num in seen:
                                continue
                            seen.add(num)
                            findings.append(self._f(
                                "identity", "phone_found",
                                f"Phone ({label}): {num}",
                                source="page phone extraction",
                                source_url=base, confidence=70, passive=True))
                            # Analyze with libphonenumber if available
                            if HAVE_PHONENUMBERS and len(findings) < 20:
                                try:
                                    pn = phonenumbers.parse(num, "US")
                                    if phonenumbers.is_possible_number(pn):
                                        carrier_name = pn_carrier.name_for_number(pn, "en")
                                        e164 = phonenumbers.format_number(
                                            pn, phonenumbers.PhoneNumberFormat.E164)
                                        findings.append(self._f(
                                            "identity", "phone_detail",
                                            f"{e164}: carrier={carrier_name or 'unknown'}",
                                            source="libphonenumber",
                                            confidence=80, passive=True))
                                except Exception:
                                    pass
            except Exception:
                pass
            if not findings:
                return self._skipped("no phone numbers found on page")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"found {len(findings)} phone signals")
        res.duration_ms = dur
        return res

    def _analyze_libphonenumber(self, raw: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            num = phonenumbers.parse(raw, None)
        except Exception:
            # Try assuming NANP
            try:
                num = phonenumbers.parse(raw, "US")
            except Exception:
                return []

        # Validity
        possible = phonenumbers.is_possible_number(num)
        valid = phonenumbers.is_valid_number(num)
        findings.append(self._f(
            "identity", "phone_validity",
            f"Possible: {possible}, Valid: {valid}",
            source="libphonenumber", confidence=95, passive=True))

        if not possible:
            return findings

        # Normalized formats
        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        findings.append(self._f(
            "identity", "phone_format",
            f"E.164: {e164} | International: {intl}",
            source="libphonenumber", confidence=98, passive=True))

        # Carrier / service provider
        carrier_name = pn_carrier.name_for_number(num, "en")
        if carrier_name:
            findings.append(self._f(
                "identity", "phone_carrier",
                f"Carrier: {carrier_name}",
                source="libphonenumber", confidence=85, passive=True))
        else:
            findings.append(self._f(
                "identity", "phone_carrier",
                "Carrier: unknown (number may be ported or VoIP)",
                source="libphonenumber", confidence=60, passive=True))

        # Line type
        ntype = pn_number_type(num)
        type_names = {
            phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "landline or mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "shared cost",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal number",
            phonenumbers.PhoneNumberType.PAGER: "pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
        }
        type_label = type_names.get(ntype, "unknown")
        findings.append(self._f(
            "identity", "phone_line_type",
            f"Line type: {type_label}",
            source="libphonenumber", confidence=85, passive=True))

        # General location (country/region, not precise address)
        region = pn_geocoder.description_for_number(num, "en")
        if region:
            findings.append(self._f(
                "identity", "phone_region",
                f"Region: {region}",
                source="libphonenumber", confidence=80, passive=True))

        # Country code
        cc = num.country_code
        findings.append(self._f(
            "identity", "phone_country",
            f"Country code: +{cc}",
            source="libphonenumber", confidence=98, passive=True))

        # Timezones (useful for region confirmation)
        tzs = pn_timezone.time_zones_for_number(num)
        if tzs:
            findings.append(self._f(
                "identity", "phone_timezone",
                f"Timezone(s): {', '.join(tzs)}",
                source="libphonenumber", confidence=75, passive=True))

        # VoIP / spoofing risk note
        if ntype == phonenumbers.PhoneNumberType.VOIP:
            findings.append(self._f(
                "identity", "phone_voip_risk",
                "VoIP number - higher spoofing/fraud risk, carrier may be masked",
                source="libphonenumber", confidence=80, passive=True))

        return findings

    def _analyze_fallback(self, raw: str) -> List[Finding]:
        """Heuristic fallback when phonenumbers is not installed."""
        findings: List[Finding] = []
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 7:
            return []

        if len(digits) == 10:
            area = digits[:3]
            formatted = f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
        elif len(digits) == 11 and digits.startswith("1"):
            area = digits[1:4]
            formatted = f"+1 ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
        else:
            area = digits[:3] if len(digits) >= 3 else ""
            formatted = raw

        findings.append(self._f(
            "identity", "phone_format",
            f"Normalized: {formatted} (fallback mode, install phonenumbers for carrier data)",
            source="phone lookup", confidence=90, passive=True))

        region = AREA_CODES.get(area, "Unknown region")
        findings.append(self._f(
            "identity", "phone_region",
            f"Area code {area}: {region}",
            source="phone lookup", confidence=80, passive=True))
        return findings
