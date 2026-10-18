"""Security headers analysis plugin.

Checks for missing or misconfigured security headers on web targets.
Every missing header is a finding, so this generates lots of useful results.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# header -> (finding key, description, confidence, recommendation)
SECURITY_HEADERS = [
    ("strict-transport-security", "hsts_missing",
     "HSTS header missing - site vulnerable to SSL stripping", 85,
     "Add Strict-Transport-Security: max-age=31536000"),
    ("content-security-policy", "csp_missing",
     "CSP header missing - site vulnerable to XSS", 80,
     "Add Content-Security-Policy header"),
    ("x-frame-options", "xfo_missing",
     "X-Frame-Options missing - site vulnerable to clickjacking", 75,
     "Add X-Frame-Options: DENY or SAMEORIGIN"),
    ("x-content-type-options", "xcto_missing",
     "X-Content-Type-Options missing - MIME sniffing possible", 70,
     "Add X-Content-Type-Options: nosniff"),
    ("referrer-policy", "referrer_policy_missing",
     "Referrer-Policy missing - referrer leakage possible", 60,
     "Add Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "permissions_policy_missing",
     "Permissions-Policy missing - browser features not restricted", 55,
     "Add Permissions-Policy to restrict camera, mic, etc."),
]

INFO_HEADERS = [
    ("server", "server_header",
     "Server header reveals software", 65),
    ("x-powered-by", "powered_by_header",
     "X-Powered-By reveals technology stack", 70),
    ("x-aspnet-version", "aspnet_version_header",
     "ASP.NET version disclosed", 75),
    ("x-generator", "generator_header",
     "X-Generator reveals CMS/framework", 70),
]


class HeadersPlugin(Plugin):
    id = "headers"
    label = "Security Headers"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Missing security headers and information-disclosure headers."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20)
        except Exception as e:
            return self._degraded(f"could not fetch {url}: {str(e)[:150]}")

        headers = {k.lower(): v for k, v in r.headers.items()}

        # Missing security headers
        for hname, key, desc, conf, rec in SECURITY_HEADERS:
            if hname not in headers:
                findings.append(self._f(
                    "web", key, f"{desc}. Fix: {rec}",
                    source="header check", source_url=url,
                    confidence=conf, passive=True))

        # Information disclosure headers
        for hname, key, desc, conf in INFO_HEADERS:
            if hname in headers:
                val = headers[hname][:120]
                findings.append(self._f(
                    "web", key, f"{desc}: {val}",
                    source="header check", source_url=url,
                    confidence=conf, passive=True))

        # Cookie flags
        set_cookie = r.headers.get("set-cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                findings.append(self._f(
                    "web", "cookie_no_httponly",
                    "Cookies set without HttpOnly flag - XSS can steal sessions",
                    source="header check", source_url=url,
                    confidence=70, passive=True))
            if "secure" not in set_cookie.lower() and url.startswith("https"):
                findings.append(self._f(
                    "web", "cookie_no_secure",
                    "Cookies set without Secure flag on HTTPS site",
                    source="header check", source_url=url,
                    confidence=70, passive=True))

        # HSTS check details
        if "strict-transport-security" in headers:
            hsts = headers["strict-transport-security"]
            if "max-age" in hsts:
                try:
                    age = int(hsts.split("max-age=")[1].split(";")[0])
                    if age < 31536000:
                        findings.append(self._f(
                            "web", "hsts_short",
                            f"HSTS max-age only {age}s, recommend 31536000",
                            source="header check", source_url=url,
                            confidence=60, passive=True))
                except (ValueError, IndexError):
                    pass

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(SECURITY_HEADERS)} security headers")
        res.duration_ms = dur
        return res
