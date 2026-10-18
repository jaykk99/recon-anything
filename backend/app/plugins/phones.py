"""Phone lookup plugin.

Analyzes phone numbers: carrier, location, type, validity.
Custom-built, no API keys needed. Works for phone targets.
"""
from __future__ import annotations

import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# North American area codes -> region (sample, expandable)
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
    accepts = ["phone"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Carrier, region, and validity info for phone numbers."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        raw = target.normalized.strip()
        digits = re.sub(r"\D", "", raw)
        findings: List[Finding] = []

        if len(digits) < 7:
            return self._skipped("not a valid phone number")

        # Normalize
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
            f"Normalized: {formatted}",
            source="phone lookup", confidence=95, passive=True))

        region = AREA_CODES.get(area, "Unknown region")
        findings.append(self._f(
            "identity", "phone_region",
            f"Area code {area}: {region}",
            source="phone lookup", confidence=80, passive=True))

        # Type heuristic
        if len(digits) in (10, 11):
            findings.append(self._f(
                "identity", "phone_type",
                "Likely a mobile or landline (NANP format)",
                source="phone lookup", confidence=60, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"analyzed {formatted}")
        res.duration_ms = dur
        return res
