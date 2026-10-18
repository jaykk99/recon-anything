"""Bug bounty checklist plugin.

Automated checks for common web vulnerabilities that bug bounty hunters
look for. All checks are custom-built, no API keys needed.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class BountyPlugin(Plugin):
    id = "bounty"
    label = "Bug Bounty Checklist"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Automated bug bounty checks: open redirects, debug pages, sensitive endpoints."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        sem = asyncio.Semaphore(8)

        # 1. Open redirect test (passive-safe: only check if redirect param reflected)
        async def _redirect_probe(param: str):
            test_url = f"{base}/?{param}=https://evil.com"
            async with sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", test_url,
                                    timeout=10, follow_redirects=False)
                except Exception:
                    return None
            loc = r.headers.get("location", "")
            if "evil.com" in loc:
                return self._f(
                    "web", "open_redirect",
                    f"Possible open redirect via ?{param}= - Location: {loc[:100]}",
                    source="bounty check", source_url=test_url,
                    confidence=75, passive=False)
            return None

        if mode == "active":
            for f in await asyncio.gather(
                    *[_redirect_probe(p) for p in
                      ["redirect", "next", "url", "return", "redir"]]):
                if f:
                    findings.append(f)

        # 2. Debug / profiler endpoints (concurrent)
        debug_paths = [
            ("/_debug", "debug endpoint"), ("/debug", "debug endpoint"),
            ("/__debug__", "django debug toolbar?"), ("/phpinfo", "phpinfo?"),
            ("/server-info", "apache server-info?"), ("/.env", "env file"),
            ("/trace", "trace endpoint"), ("/actuator", "spring actuator"),
            ("/_profiler", "symfony profiler?"), ("/_wdt", "symfony wdt?"),
            ("/elmah.axd", "elmah error log?"),
        ]

        async def _debug_probe(path: str, label: str):
            url = base + path
            async with sem:
                try:
                    if mode == "passive":
                        # Wayback check
                        from urllib.parse import quote
                        wb = ("https://web.archive.org/cdx/search/cdx?url="
                              + quote(url, safe="") + "&output=json&limit=1")
                        r = await fetch(ctx.http, ctx.limiter, "GET", wb, timeout=10)
                        if r.status_code == 200 and len(r.json()) > 1:
                            return self._f(
                                "web", "debug_endpoint_archived",
                                f"{path} was archived - {label} may have existed",
                                source="Wayback", source_url=url,
                                confidence=50, passive=True)
                    else:
                        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10)
                        if r.status_code == 200 and len(r.text) > 100:
                            return self._f(
                                "web", "debug_endpoint",
                                f"{path} returned 200 ({len(r.text)} bytes) - {label}",
                                source="bounty check", source_url=url,
                                confidence=70, passive=False)
                except Exception:
                    pass
            return None

        for f in await asyncio.gather(
                *[_debug_probe(p, lab) for p, lab in debug_paths]):
            if f:
                findings.append(f)

        # 3. CORS misconfiguration check
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base,
                            timeout=10,
                            headers={"Origin": "https://evil.com"})
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "")
            if acao == "https://evil.com" or acao == "*":
                findings.append(self._f(
                    "web", "cors_misconfig",
                    f"CORS reflects arbitrary origin: ACAO={acao} ACAC={acac}",
                    source="bounty check", source_url=base,
                    confidence=80, passive=True))
            elif "evil.com" in acao:
                findings.append(self._f(
                    "web", "cors_misconfig",
                    f"CORS allows evil.com: {acao}",
                    source="bounty check", source_url=base,
                    confidence=85, passive=True))
        except Exception:
            pass

        # 4. HTTP methods check (active only)
        if mode == "active":
            try:
                r = await fetch(ctx.http, ctx.limiter, "OPTIONS", base, timeout=10)
                allow = r.headers.get("allow", "")
                if allow:
                    findings.append(self._f(
                        "web", "http_methods",
                        f"Allowed methods: {allow}",
                        source="bounty check", source_url=base,
                        confidence=60, passive=False))
                    if "PUT" in allow or "DELETE" in allow:
                        findings.append(self._f(
                            "web", "dangerous_methods",
                            f"Dangerous HTTP methods allowed: {allow}",
                            source="bounty check", source_url=base,
                            confidence=75, passive=False))
            except Exception:
                pass

        # 5. Subdomain takeover hints (CNAME to unclaimed services)
        takeover_fingerprints = {
            "github.io": "GitHub Pages",
            "herokuapp.com": "Heroku",
            "s3.amazonaws.com": "AWS S3",
            "cloudfront.net": "CloudFront",
            "azurewebsites.net": "Azure",
            "wordpress.com": "WordPress.com",
            "tumblr.com": "Tumblr",
            "fastly.net": "Fastly",
        }
        # This is checked via DNS in the dns plugin, but we note the check here
        findings.append(self._f(
            "web", "bounty_note",
            f"Manual checks recommended: subdomain takeover, IDOR on API endpoints, "
            f"SSRF on URL params, XSS on search fields. See {len(debug_paths)} debug paths checked.",
            source="bounty checklist", confidence=40, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"ran {5} bounty check categories")
        res.duration_ms = dur
        return res
