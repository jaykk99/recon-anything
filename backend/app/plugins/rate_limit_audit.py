"""Rate-limit header audit plugin.

Reads the homepage response headers for rate-limit signals:
X-RateLimit-*, RateLimit-* (IETF draft), Retry-After, and
X-Rate-Limit-Reset. An API with no rate-limit headers at all is a
(low-confidence) abuse-surface note; documented limits are reported
as informational so Jay knows the throttle budget before scanning.

Passive: one GET of the homepage (shared fetch_page cache).
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "ratelimit-policy", "x-rate-limit-limit", "retry-after",
]


class RateLimitAuditPlugin(Plugin):
    id = "rate_limit_audit"
    label = "Rate-Limit Headers"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Audit rate-limit signals (X-RateLimit-*, Retry-After): "
                   "documented limits vs no abuse signals at all.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable")
        present = {h: resp.headers.get(h) for h in LIMIT_HEADERS
                   if resp.headers.get(h)}
        findings: List = []
        if present:
            detail = ", ".join(f"{k}={v}" for k, v in list(present.items())[:4])
            findings.append(self._f(
                "web", "rate_limit_documented",
                f"Rate limiting advertised: {detail}",
                source="rate-limit audit", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": "low", "headers": present,
                          "remediation": ("Informational: honor these limits "
                                          "when scanning; no action needed.")}))
        else:
            findings.append(self._f(
                "web", "rate_limit_no_signals",
                "No rate-limit headers on the homepage - abuse throttling "
                "is undocumented (may still exist server-side)",
                source="rate-limit audit", source_url=base + "/",
                confidence=55, passive=True,
                evidence={"severity": "low",
                          "remediation": (
                              "If this is your app, document and enforce "
                              "rate limits on auth, API and form endpoints; "
                              "advertise them via RateLimit-* headers.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"{len(present)} rate-limit signals found")
