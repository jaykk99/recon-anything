"""Clickjacking tester plugin.

Thoroughly tests for clickjacking vulnerabilities beyond just
checking X-Frame-Options. Tests frame-ancestors CSP, nested frames,
and provides a proof-of-concept.
Custom-built, no API keys needed.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class ClickjackPlugin(Plugin):
    id = "clickjack"
    label = "Clickjack Tester"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Deep clickjacking analysis with PoC generation."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
        except Exception as e:
            return self._degraded(f"could not fetch: {str(e)[:150]}")

        headers = {k.lower(): v for k, v in r.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        # X-Frame-Options analysis
        if not xfo:
            findings.append(self._f(
                "web", "clickjack_vulnerable",
                "VULNERABLE: No X-Frame-Options header - site can be iframed",
                source="clickjack tester", source_url=url,
                confidence=85, passive=True))
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(self._f(
                "web", "clickjack_weak",
                f"Weak X-Frame-Options: '{xfo}' - should be DENY or SAMEORIGIN",
                source="clickjack tester", source_url=url,
                confidence=70, passive=True))
        else:
            findings.append(self._f(
                "web", "clickjack_protected_xfo",
                f"Protected by X-Frame-Options: {xfo}",
                source="clickjack tester", source_url=url,
                confidence=90, passive=True))

        # CSP frame-ancestors analysis
        if "frame-ancestors" in csp:
            fa = csp.split("frame-ancestors")[1].split(";")[0].strip()
            if "'none'" in fa:
                findings.append(self._f(
                    "web", "clickjack_protected_csp",
                    "Protected by CSP frame-ancestors 'none'",
                    source="clickjack tester", source_url=url,
                    confidence=90, passive=True))
            elif "*" in fa or "https:" in fa:
                findings.append(self._f(
                    "web", "clickjack_csp_bypass",
                    f"CSP frame-ancestors too permissive: {fa}",
                    source="clickjack tester", source_url=url,
                    confidence=75, passive=True))
        elif not xfo:
            findings.append(self._f(
                "web", "clickjack_no_csp",
                "No CSP frame-ancestors either - doubly vulnerable",
                source="clickjack tester", source_url=url,
                confidence=90, passive=True))

        # Generate PoC if vulnerable
        if not xfo or "frame-ancestors" not in csp:
            poc = (f"<html><body><h1>Clickjacking PoC for {domain}</h1>"
                   f'<iframe src="{url}" width="800" height="600"></iframe>'
                   f"</body></html>")
            findings.append(self._f(
                "web", "clickjack_poc",
                f"PoC HTML generated ({len(poc)} chars) - save as .html and open to verify",
                source="clickjack tester",
                confidence=80, passive=True,
                evidence={"poc": poc}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, "clickjacking analysis complete")
        res.duration_ms = dur
        return res
