"""Email harvester plugin.

Finds email addresses on the target website and validates them.
Custom-built, no API keys needed.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
# Pages likely to contain contact emails
CONTACT_PATHS = [
    "/", "/contact", "/contact-us", "/about", "/about-us",
    "/team", "/support", "/help", "/privacy", "/terms",
]


class EmailsPlugin(Plugin):
    id = "emails"
    label = "Email Harvester"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Find email addresses on the target site."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []
        seen: Set[str] = set()

        # Skip obvious false positives
        skip_patterns = ["example.com", "test.com", "email.com", "domain.com",
                         "sentry.io", "wixpress.com", ".png", ".jpg", ".gif"]

        # Fetch all contact pages concurrently (was sequential: 10 pages x
        # 12s timeouts could stall this plugin for 2 minutes on a tarpit).
        # Same pages, same parsing, same findings - just in parallel.
        async def fetch_one(path):
            url = base + path if path != "/" else base
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
                if r.status_code != 200:
                    return []
                return [m.group(0).lower() for m in EMAIL_RE.finditer(r.text)]
            except Exception:
                return []

        page_emails = await asyncio.gather(
            *(fetch_one(p) for p in CONTACT_PATHS))

        for path, emails_found in zip(CONTACT_PATHS, page_emails):
            url = base + path if path != "/" else base
            for email in emails_found:
                if email in seen:
                    continue
                if any(s in email for s in skip_patterns):
                    continue
                if len(email) > 80:  # likely garbage
                    continue
                seen.add(email)
                # Classify the email
                local, _, edomain = email.partition("@")
                note = ""
                if edomain == domain:
                    note = " (company email)"
                    conf = 85
                elif "gmail" in edomain or "yahoo" in edomain or "hotmail" in edomain:
                    note = " (personal email on company site)"
                    conf = 70
                else:
                    conf = 60
                findings.append(self._f(
                    "identity", "email_found",
                    f"{email}{note} found on {path}",
                    source="email harvester", source_url=url,
                    confidence=conf, passive=True))
                ctx.publish("emails", email)

        # Also check DNS TXT for SPF (reveals mail providers)
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 8
            answers = await resolver.resolve(domain, "TXT")
            for rr in answers:
                txt = str(rr).strip('"')
                if "spf" in txt.lower() or "v=spf" in txt.lower():
                    findings.append(self._f(
                        "identity", "email_spf",
                        f"SPF record: {txt[:150]}",
                        source="DNS TXT", confidence=90, passive=True))
                    break
        except Exception:
            pass

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(CONTACT_PATHS)} pages, found {len(seen)} emails")
        res.duration_ms = dur
        return res
