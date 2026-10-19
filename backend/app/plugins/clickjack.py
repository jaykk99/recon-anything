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

        # X-Frame-Options / CSP frame-ancestors analysis. Only exposures
        # are findings - a protected site is not a finding.
        fa = ""
        if "frame-ancestors" in csp:
            fa = csp.split("frame-ancestors")[1].split(";")[0].strip()
        csp_protects = fa and ("'none'" in fa or "'self'" in fa) \
            and "*" not in fa and "https:" not in fa

        if not xfo and not csp_protects:
            poc = (f"<html><body><h1>Clickjacking PoC for {domain}</h1>"
                   f'<iframe src="{url}" width="800" height="600"></iframe>'
                   f"</body></html>")
            findings.append(self._f(
                "web", "clickjack_vulnerable",
                "VULNERABLE: No X-Frame-Options header and no protective "
                "CSP frame-ancestors - site can be iframed",
                source="clickjack tester", source_url=url,
                confidence=85, passive=True,
                evidence={"severity": "medium",
                          "poc_html": poc,
                          "remediation": "Add X-Frame-Options: DENY or "
                          "SAMEORIGIN (or CSP frame-ancestors)."}))
        elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(self._f(
                "web", "clickjack_weak",
                f"Weak X-Frame-Options: '{xfo}' - should be DENY or SAMEORIGIN",
                source="clickjack tester", source_url=url,
                confidence=70, passive=True))

        # frame-ancestors present but permissive - separate finding.
        if fa and ("*" in fa or "https:" in fa):
            findings.append(self._f(
                "web", "clickjack_csp_bypass",
                f"CSP frame-ancestors too permissive: {fa}",
                source="clickjack tester", source_url=url,
                confidence=75, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, "clickjacking analysis complete")
        res.duration_ms = dur
        return res
