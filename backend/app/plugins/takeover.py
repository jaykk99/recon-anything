"""Subdomain takeover checker plugin.

Checks discovered subdomains for CNAME records pointing to
unclaimed third-party services. Custom-built, no API keys needed.
Detection only: reports claimability evidence (NXDOMAIN targets,
provider error fingerprints), never attempts to claim anything.
"""
from __future__ import annotations

import asyncio

import os
import socket
import time
from typing import List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Service -> (CNAME pattern, service name, unclaimed fingerprint in body)
TAKEOVER_FINGERPRINTS = [
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("amazonaws.com", "AWS CloudFront/other", "Bad Request"),
    ("cloudfront.net", "CloudFront", "Bad Request"),
    ("blob.core.windows.net", "Azure Blob Storage", "NoSuchAccount"),
    ("azurewebsites.net", "Azure App Service", "404"),
    ("cloudapp.net", "Azure Cloud Services", "404"),
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("pages.dev", "Cloudflare Pages", "couldn't find"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("herokudns.com", "Heroku DNS", "No such app"),
    ("netlify.app", "Netlify", "Not Found"),
    ("vercel.app", "Vercel", "404"),
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
    ("wpengine.com", "WP Engine", "404"),
    ("pantheonsite.io", "Pantheon", "404"),
    ("cargocollective.com", "Cargo", "404"),
    ("feedpress.me", "Feedpress", "The feed has not been found"),
    ("readme.io", "Readme.io", "Project doesnt exist"),
    ("datocms", "DatoCMS", "not found"),
    ("webflow.io", "Webflow", "The page you are looking for doesn't exist"),
    # 2026-10-27 detection expansion: more hosted-platform fingerprints.
    # Same contract as above: flag as possible takeover only when the
    # CNAME target is dangling or the provider's own "nothing here"
    # page matches. Never claim or register anything.
    ("storage.googleapis.com", "Google Cloud Storage", "NoSuchBucket"),
    ("appspot.com", "Google App Engine", "404"),
    ("azureedge.net", "Azure CDN", "404"),
    ("trafficmanager.net", "Azure Traffic Manager", "404"),
    ("cloudapp.azure.com", "Azure Cloud Services", "404"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk", "404"),
    ("squarespace.com", "Squarespace", "No Such Account"),
    ("blogger.com", "Blogger", "Blog not found"),
    ("weebly.com", "Weebly", "This site is not currently available"),
    ("strikingly.com", "Strikingly", "This page is not available"),
    ("bigcartel.com", "Big Cartel", "This shop is currently unavailable"),
    ("smugmug.com", "SmugMug", "Page Not Found"),
    ("hs-sites.com", "HubSpot", "This page doesn't exist"),
    ("intercom.help", "Intercom", "This page doesn't exist"),
    ("desk.com", "Salesforce Desk", "This page is no longer available"),
    ("list-manage.com", "Mailchimp", "404"),
]

REMEDIATION = ("Remove the stale DNS record (CNAME/A) pointing at the "
               "unclaimed service. If the service is still needed, reclaim "
               "it in the provider console first, then keep the record.")


def _match_service(cname: str) -> Optional[Tuple[str, str]]:
    """Return (service, fingerprint) for a CNAME target, or None."""
    for pattern, service, fingerprint in TAKEOVER_FINGERPRINTS:
        if pattern in cname:
            return service, fingerprint
    return None


class TakeoverPlugin(Plugin):
    id = "takeover"
    label = "Takeover Checker"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Detect dangling DNS / subdomain takeover potential. "
                   "Fingerprint CNAME targets, verify the target is "
                   "unclaimed (NXDOMAIN or provider error page). "
                   "Detection only - never claims anything.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        try:
            import dns.asyncresolver
            import dns.resolver
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 8
            use_dnspython = True
        except ImportError:
            resolver = None
            use_dnspython = False

        # Subdomains enumerated by the subdomains plugin are shared via
        # the discovery bus: check those first instead of re-enumerating,
        # plus the common takeover-prone names.
        bus_subs = [s for s in ctx.consume("subdomains")
                    if isinstance(s, str) and s.endswith("." + domain)]
        common = [f"{sub}.{domain}" for sub in
                  ["www", "blog", "dev", "staging", "test", "api", "cdn",
                   "static", "assets", "docs", "help", "support", "status"]]
        seen = set()
        test_subs = [s for s in bus_subs + common
                     if not (s in seen or seen.add(s))]
        test_subs = test_subs[:60]  # hard cap: stay well under the 30s ceiling

        dns_sem = asyncio.Semaphore(10)

        async def cname_of(fqdn: str) -> Optional[str]:
            """CNAME target via dnspython, with socket AI_CANONNAME fallback."""
            async with dns_sem:
                if use_dnspython and resolver is not None:
                    try:
                        answers = await resolver.resolve(fqdn, "CNAME")
                        for rr in answers:
                            return str(rr.target).rstrip(".").lower()
                    except Exception:
                        return None
                    return None
                # Fallback: no dnspython - socket canonical name
                try:
                    info = await asyncio.to_thread(
                        socket.getaddrinfo, fqdn, None, 0, 0, 0,
                        socket.AI_CANONNAME)
                    canon = (info[0][3] or "").rstrip(".").lower()
                    return canon if canon and canon != fqdn.lower() else None
                except Exception:
                    return None

        async def target_resolves(name: str) -> bool:
            """Does the CNAME target itself still resolve? NXDOMAIN = dangling."""
            async with dns_sem:
                try:
                    if use_dnspython and resolver is not None:
                        await resolver.resolve(name, "A")
                        return True
                    await asyncio.to_thread(socket.getaddrinfo, name, None)
                    return True
                except Exception:
                    return False

        async def check_one(fqdn: str):
            cname = await cname_of(fqdn)
            if not cname:
                return None
            match = _match_service(cname)
            if not match:
                return None
            service, fingerprint = match
            # Verify claimability: dangling (target NXDOMAIN) or the
            # provider's own "nothing here" page on the subdomain root.
            dangling = not await target_resolves(cname)
            fp_hit = False
            body_head = ""
            try:
                data = await ctx.probe(f"https://{fqdn}/", timeout=8)
                if not data or data.get("status", 0) == 0:
                    data = await ctx.probe(f"http://{fqdn}/", timeout=8)
                body_head = (data.get("text") or "")[:2000]
                fp_hit = bool(fingerprint) and fingerprint.lower() in body_head.lower()
            except Exception:
                fp_hit = False
            return fqdn, cname, service, fingerprint, dangling, fp_hit, body_head

        checked = 0
        for result in await asyncio.gather(*(check_one(s) for s in test_subs)):
            checked += 1
            if not result:
                continue
            fqdn, cname, service, fingerprint, dangling, fp_hit, _ = result
            if dangling or fp_hit:
                # Likely takeover: target gone or provider says "nothing here".
                why = ("CNAME target does not resolve (NXDOMAIN/dangling)"
                       if dangling else
                       f"provider error page matches fingerprint '{fingerprint}'")
                findings.append(self._f(
                    "infra", "subdomain_takeover",
                    f"HIGH: {fqdn} CNAMEs to {cname} ({service}) and looks "
                    f"CLAIMABLE - {why}. Verify ownership and claim or "
                    f"remove the record.",
                    source="takeover checker", source_url=f"https://{fqdn}/",
                    confidence=90 if fp_hit else 85, passive=True,
                    exploitability="public_poc",
                    evidence={"severity": "high", "cname_target": cname,
                              "service": service, "dangling": dangling,
                              "fingerprint_match": fp_hit,
                              "remediation": REMEDIATION,
                              "scope_note": "Detection only: never claim the "
                                            "resource yourself on an "
                                            "unauthorized target."}))
            else:
                # CNAME points at a known takeover-prone service, target
                # still resolves - suspicious, not confirmed.
                findings.append(self._f(
                    "infra", "takeover_possible",
                    f"{fqdn} CNAMEs to {cname} ({service}). Target still "
                    f"resolves, so not confirmed dangling - re-check "
                    f"periodically; fingerprint '{fingerprint}' was not "
                    f"seen on the root page.",
                    source="takeover checker", source_url=f"https://{fqdn}/",
                    confidence=60, passive=True,
                    evidence={"severity": "medium", "cname_target": cname,
                              "service": service,
                              "remediation": REMEDIATION}))

        findings.append(self._f(
            "infra", "takeover_note",
            f"Checked {checked} subdomains against "
            f"{len(TAKEOVER_FINGERPRINTS)} takeover fingerprints "
            f"({'dnspython' if use_dnspython else 'socket fallback'}). "
            "Detection only - nothing was claimed.",
            source="takeover checker", confidence=40, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {checked} subdomains, "
                                 f"{len(TAKEOVER_FINGERPRINTS)} fingerprints")
        res.duration_ms = dur
        return res
