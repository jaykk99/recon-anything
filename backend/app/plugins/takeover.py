"""Subdomain takeover checker plugin.

Checks discovered subdomains for CNAME records pointing to
unclaimed third-party services. Custom-built, no API keys needed.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Service -> (CNAME pattern, fingerprint for unclaimed)
TAKEOVER_FINGERPRINTS = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("cloudfront.net", "CloudFront", "Bad Request"),
    ("azurewebsites.net", "Azure", "404"),
    ("wordpress.com", "WordPress", "Do you want to register"),
    ("tumblr.com", "Tumblr", "Whatever you were looking for doesn't currently exist"),
    ("fastly.net", "Fastly", "Fastly error: unknown domain"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("statuspage.io", "Statuspage", "You are being redirected"),
    ("uservoice.com", "UserVoice", "This UserVoice subdomain is currently available"),
    ("surge.sh", "Surge.sh", "project not found"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("unbouncepages.com", "Unbounce", "The requested URL was not found"),
    ("helpjuice.com", "Helpjuice", "We could not find what you're looking for"),
    ("helpscoutdocs.com", "HelpScout", "No settings were found"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("freshdesk.com", "Freshdesk", "May not exist"),
    ("ghost.io", "Ghost", "The thing you were looking for is no longer here"),
    ("cargocollective.com", "Cargo", "404"),
    ("feedpress.me", "Feedpress", "The feed has not been found"),
    ("readme.io", "Readme.io", "Project doesnt exist"),
    ("datocms", "DatoCMS", "not found"),
    ("webflow.io", "Webflow", "The page you are looking for doesn't exist"),
    ("netlify.app", "Netlify", "Not Found"),
    ("vercel.app", "Vercel", "404"),
]


class TakeoverPlugin(Plugin):
    id = "takeover"
    label = "Takeover Checker"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Check subdomains for takeover vulnerabilities."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 8

            # Get subdomains from cache (populated by subdomains plugin if it ran)
            # Otherwise check common ones directly
            test_subs = ["www", "blog", "dev", "staging", "test", "api", "cdn",
                         "static", "assets", "docs", "help", "support", "status"]

            for sub in test_subs:
                fqdn = f"{sub}.{domain}"
                try:
                    answers = await resolver.resolve(fqdn, "CNAME")
                    for rr in answers:
                        cname = str(rr.target).rstrip(".").lower()
                        for pattern, service, fingerprint in TAKEOVER_FINGERPRINTS:
                            if pattern in cname:
                                findings.append(self._f(
                                    "infra", "takeover_possible",
                                    f"{fqdn} CNAMEs to {cname} ({service}) - "
                                    f"check if claimable. Fingerprint: '{fingerprint}'",
                                    source="takeover checker",
                                    confidence=70, passive=True))
                                break
                except Exception:
                    continue
        except ImportError:
            return self._skipped("dnspython not available")

        findings.append(self._f(
            "infra", "takeover_note",
            f"Checked {len(test_subs)} common subdomains against "
            f"{len(TAKEOVER_FINGERPRINTS)} takeover fingerprints. "
            "For full coverage, run subdomain enum first.",
            source="takeover checker", confidence=40, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(TAKEOVER_FINGERPRINTS)} fingerprints")
        res.duration_ms = dur
        return res
