"""TheHarvester-style OSINT gatherer (keyless sources only).

Gathers emails, subdomains, and hostnames from public sources without API
keys: crt.sh certificate transparency, HackerTarget hostsearch, ThreatCrowd,
and email extraction from fetched pages. Publishes everything to the
discovery bus so chain plugins can consume it.

Detection only: passive public-source queries. No authentication attempts.
Authorized testing only.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_list

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
OBFUSCATED_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]{1,64}\s*(?:\[at\]|\(at\)|\sat\s)\s*[a-zA-Z0-9.\-]+\s*(?:\[dot\]|\(dot\)|\sdot\s)\s*[a-zA-Z]{2,}",
    re.I)


class HarvesterPlugin(Plugin):
    id = "harvester"
    label = "OSINT Harvester"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    description = ("TheHarvester-style: emails, subdomains, hostnames from "
                   "keyless public sources.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        emails: Set[str] = set()
        subdomains: Set[str] = set()

        # 1-3. External OSINT sources in parallel (were sequential: 3 x 20s
        # timeout = 60s worst case; now one 20s window).
        async def _crt():
            try:
                r = await fetch(
                    ctx.http, ctx.limiter, "GET",
                    f"https://crt.sh/?q=%25.{quote(domain)}&output=json",
                    timeout=20)
                subs = set()
                for entry in safe_json_list(r):
                    nv = str(entry.get("name_value", ""))
                    for part in nv.split("\n"):
                        part = part.strip().lower().lstrip("*.")
                        if part.endswith(domain) and part != domain:
                            subs.add(part)
                return subs, set()
            except Exception:
                return set(), set()

        async def _hackertarget():
            try:
                r = await fetch(
                    ctx.http, ctx.limiter, "GET",
                    f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}",
                    timeout=20)
                subs = set()
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        host = line.split(",")[0].strip().lower()
                        if host.endswith(domain) and host != domain:
                            subs.add(host)
                return subs, set()
            except Exception:
                return set(), set()

        async def _threatcrowd():
            try:
                r = await fetch(
                    ctx.http, ctx.limiter, "GET",
                    f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={quote(domain)}",
                    timeout=20)
                subs, ems = set(), set()
                try:
                    data = r.json()
                    for sub in data.get("subdomains", []) or []:
                        sub = str(sub).strip().lower()
                        if sub.endswith(domain):
                            subs.add(sub)
                    for em in data.get("emails", []) or []:
                        em = str(em).strip().lower()
                        if "@" in em:
                            ems.add(em)
                except Exception:
                    pass
                return subs, ems
            except Exception:
                return set(), set()

        for subs, ems in await asyncio.gather(_crt(), _hackertarget(),
                                              _threatcrowd()):
            subdomains.update(subs)
            emails.update(ems)

        # 4. Email extraction from homepage + common pages
        pages = [base]
        for p in ["/contact", "/contact-us", "/about", "/about-us",
                  "/team", "/our-team", "/staff", "/people", "/directory",
                  "/careers", "/jobs", "/press", "/media", "/news",
                  "/support", "/privacy", "/privacy-policy", "/legal",
                  "/imprint", "/footer"]:
            pages.append(base.rstrip("/") + p)

        def deobfuscate(m: re.Match) -> str:
            s = m.group(0)
            s = re.sub(r"\s*(?:\[at\]|\(at\)|\sat\s)\s*", "@", s, flags=re.I)
            s = re.sub(r"\s*(?:\[dot\]|\(dot\)|\sdot\s)\s*", ".", s, flags=re.I)
            return s.lower()

        for url in pages[:12]:
            try:
                page = await ctx.fetch_page(url, timeout=12)
                if not page:
                    continue
                text = page["text"][:200000]
                for m in EMAIL_RE.finditer(text):
                    em = m.group(0).lower()
                    if em.endswith(domain) and not em.startswith(("noreply@", "no-reply@")):
                        emails.add(em)
                    elif "@" in em and len(em) < 80:
                        # keep non-domain emails too (partners, vendors)
                        emails.add(em)
                # NEW: deobfuscated emails (user [at] domain [dot] com)
                for m in OBFUSCATED_RE.finditer(text):
                    em = deobfuscate(m)
                    if "@" in em and len(em) < 80:
                        emails.add(em)
            except Exception:
                continue

        # Publish to discovery bus + emit findings
        for sub in sorted(subdomains)[:200]:
            ctx.publish("subdomains", sub)
        if subdomains:
            findings.append(self._f(
                "graph", "harvested_subdomains",
                f"{len(subdomains)} subdomains from public sources: "
                + ", ".join(sorted(subdomains)[:10])
                + ("..." if len(subdomains) > 10 else ""),
                source="theharvester: crt.sh/hackertarget/threatcrowd",
                confidence=85, passive=True,
                evidence={"remediation": "Review subdomain inventory. Remove "
                          "stale records (takeover risk).",
                          "severity": "low", "risk": "low",
                          "subdomains": sorted(subdomains)[:200]}))
        for em in sorted(emails)[:100]:
            ctx.publish("emails", em)
        if emails:
            findings.append(self._f(
                "identity", "harvested_emails",
                f"{len(emails)} emails from public sources: "
                + ", ".join(sorted(emails)[:8])
                + ("..." if len(emails) > 8 else ""),
                source="theharvester: page scrape + threatcrowd",
                confidence=80, passive=True,
                evidence={"remediation": "Exposed emails enable phishing. "
                          "Remove from public pages where possible; enforce "
                          "MFA on all accounts.",
                          "severity": "low", "risk": "low",
                          "emails": sorted(emails)[:100]}))

        res = self._ok(
            findings,
            f"{len(subdomains)} subdomains, {len(emails)} emails harvested")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
