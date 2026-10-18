"""WAF detector plugin.

Identifies Web Application Firewalls via the shared vendor signature
registry in app.waf (headers, cookies, block/challenge page markers),
plus an active blocking-behavior probe. Custom-built, no API keys needed.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..waf import BLOCK_KINDS, VENDOR_COOKIES, VENDOR_HEADERS, classify_response, detect_vendors
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class WafPlugin(Plugin):
    id = "waf"
    label = "WAF Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Detect Web Application Firewalls via shared vendor signatures."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        detected = set()

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
        except Exception as e:
            return self._degraded(f"could not fetch: {str(e)[:150]}")

        headers = {k.lower(): v for k, v in r.headers.items()}
        cookies = r.headers.get("set-cookie", "")

        # Shared registry: header + cookie vendor attribution.
        for vendor in detect_vendors(headers, cookies):
            if vendor in detected:
                continue
            detected.add(vendor)
            via = next((n for n, v, w in VENDOR_HEADERS
                        if w == vendor and n in headers),
                       next((n for n, w in VENDOR_COOKIES
                             if w == vendor and n.lower() in cookies.lower()),
                            "fingerprint"))
            findings.append(self._f(
                "web", "waf_detected",
                f"WAF detected: {vendor} (via {via})",
                source="WAF detector", source_url=url,
                confidence=85, passive=True,
                evidence={"severity": "low", "vendor": vendor}))

        # Vendor attribution from the block/challenge classifier too: a
        # challenge page on the homepage means the WAF is actively
        # interfering, not just present.
        verdict = classify_response(r)
        if verdict.kind in BLOCK_KINDS and verdict.vendor \
                and verdict.vendor not in detected:
            detected.add(verdict.vendor)
            findings.append(self._f(
                "web", "waf_detected",
                f"WAF detected: {verdict.vendor} (via {verdict.kind} page)",
                source="WAF detector", source_url=url,
                confidence=85, passive=True,
                evidence={"severity": "low", "vendor": verdict.vendor,
                          "verdict": verdict.kind}))

        # Blocking behavior test: send a suspicious payload, classify the
        # response. Detection only - one probe, never repeated.
        try:
            evil = url + "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
            r2 = await fetch(ctx.http, ctx.limiter, "GET", evil, timeout=12)
            v2 = classify_response(r2)
            if v2.kind in BLOCK_KINDS:
                who = v2.vendor or "WAF"
                findings.append(self._f(
                    "web", "waf_blocking",
                    f"WAF actively blocking: {r2.status_code} on XSS probe "
                    f"({who}, {v2.kind})",
                    source="WAF detector", source_url=evil,
                    confidence=90, passive=True,
                    evidence={"severity": "medium", "vendor": v2.vendor,
                              "verdict": v2.kind,
                              "status": r2.status_code}))
        except Exception:
            pass

        if not detected:
            findings.append(self._f(
                "web", "waf_none",
                "No WAF detected - target may be directly exposed",
                source="WAF detector", source_url=url,
                confidence=60, passive=True,
                evidence={"severity": "low"}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(VENDOR_HEADERS)} header + "
                                 f"{len(VENDOR_COOKIES)} cookie signatures")
        res.duration_ms = dur
        return res
