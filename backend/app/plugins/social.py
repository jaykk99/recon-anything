"""Social media footprint plugin.

Finds social media accounts associated with a domain or username.
Checks common platforms and generates profile URLs.
Custom-built, no API keys needed.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class SocialPlugin(Plugin):
    id = "social"
    label = "Social Footprint"
    accepts = ["domain", "url", "username", "person_or_company"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Find associated social media accounts."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []

        if target.type in ("domain", "url"):
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain")
            base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

            # Scrape homepage for social links
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=15)
                if r.status_code == 200:
                    import re
                    social_patterns = [
                        (r'https?://(?:www\.)?facebook\.com/([A-Za-z0-9._-]+)',
                         "Facebook", 85),
                        (r'https?://(?:www\.)?instagram\.com/([A-Za-z0-9._-]+)',
                         "Instagram", 85),
                        (r'https?://(?:www\.)?twitter\.com/([A-Za-z0-9_]+)',
                         "Twitter", 85),
                        (r'https?://(?:www\.)?x\.com/([A-Za-z0-9_]+)',
                         "X", 85),
                        (r'https?://(?:www\.)?linkedin\.com/(?:company|in)/([A-Za-z0-9-]+)',
                         "LinkedIn", 85),
                        (r'https?://(?:www\.)?youtube\.com/(?:c/|channel/|user/|@)([A-Za-z0-9_-]+)',
                         "YouTube", 80),
                        (r'https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9._-]+)',
                         "TikTok", 80),
                    ]
                    for pattern, plat, conf in social_patterns:
                        for m in re.finditer(pattern, r.text):
                            handle = m.group(1).rstrip("/")
                            if handle and len(handle) < 50:
                                findings.append(self._f(
                                    "identity", "social_account",
                                    f"{plat}: @{handle}",
                                    source="social footprint",
                                    source_url=m.group(0)[:200],
                                    confidence=conf, passive=True))
            except Exception:
                pass

            # Brand name guess for social search
            brand = domain.split(".")[0]
            if len(brand) >= 3:
                for plat, url_t in [
                    ("Twitter", f"https://twitter.com/{brand}"),
                    ("Instagram", f"https://instagram.com/{brand}"),
                    ("Facebook", f"https://facebook.com/{brand}"),
                    ("LinkedIn", f"https://linkedin.com/company/{brand}"),
                ]:
                    findings.append(self._f(
                        "identity", "social_guess",
                        f"Possible {plat}: {url_t} (verify manually)",
                        source="social footprint", source_url=url_t,
                        confidence=30, passive=True))
        else:
            # Username / person: use the usernames plugin approach for socials
            name = target.normalized.strip().lstrip("@")
            for plat, url_t in [
                ("Twitter", f"https://twitter.com/{name}"),
                ("Instagram", f"https://instagram.com/{name}"),
                ("GitHub", f"https://github.com/{name}"),
                ("LinkedIn", f"https://linkedin.com/in/{name}"),
            ]:
                findings.append(self._f(
                    "identity", "social_guess",
                    f"Check {plat}: {url_t}",
                    source="social footprint", source_url=url_t,
                    confidence=40, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"found {len(findings)} social signals")
        res.duration_ms = dur
        return res
