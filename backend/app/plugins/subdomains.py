"""Subdomain enumeration plugin (Milestone 2).

Sources: crt.sh certificate transparency (free, no key), plus optional
active-mode DNS brute force with a bundled wordlist.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

WORDLIST = """www mail ftp localhost webmail smtp pop imap blog shop api dev
staging test admin portal vpn remote gitlab jira confluence wiki docs
status monitor grafana kibana elastic db database cache redis mq queue
cdn static assets img images media files download upload backup old
beta alpha demo sandbox qa uat prod production dr backup1 backup2
ns1 ns2 mx1 mx2 autodiscover lync sip teams chat meet webinar
crm erp hr finance billing pay payment checkout cart order
support help helpdesk ticket kb community forum
app mobile m site ampamp
oauth sso login auth idp account profile settings
ci cd jenkins drone travis circle build deploy
k8s kubernetes docker registry harbor nexus artifactory
vpn1 firewall gw proxy socks bastion jump
iot printer scanner camera
test1 test2 dev1 dev2 stage1 prod1
partner partners affiliate reseller
legal privacy terms about contact careers press newsroom
graphql rest v1 v2 v3
webhook hooks events callback
sftp ftps
internal intranet corp extranet
legacy classic new old1
mx mail1 mail2
autoconfig
_dmarc
""".split()


class SubdomainsPlugin(Plugin):
    id = "subdomains"
    label = "Subdomain Enum"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Certificate-transparency subdomains via crt.sh, plus active DNS brute force."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        # --- crt.sh (always passive-safe, free, no key) ---
        async def crtsh():
            url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=30)
                if resp.status_code != 200:
                    return {"error": f"HTTP {resp.status_code}"}
                return resp.json()
            except Exception as e:
                return {"error": str(e)[:200]}

        rows, _ = await ctx.cache.cached("ct", domain, crtsh)
        seen = set()
        if isinstance(rows, list):
            for r in rows:
                name = (r.get("name_value") or "").strip().lower()
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub and sub.endswith(domain) and sub not in seen:
                        seen.add(sub)
            for sub in sorted(seen):
                findings.append(self._f("dns", "subdomain", sub,
                                        source="crt.sh certificate transparency",
                                        source_url=f"https://crt.sh/?q=%25.{domain}",
                                        confidence=90, passive=True))
        elif isinstance(rows, dict) and rows.get("error"):
            findings.append(self._f("dns", "subdomain_enum_note",
                                    f"crt.sh unavailable: {rows['error']}",
                                    source="crt.sh", confidence=40, passive=True))

        # --- active DNS brute force ---
        if mode == "active":
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 6
            found = 0
            for word in WORDLIST:
                cand = f"{word}.{domain}"
                if cand in seen:
                    continue
                try:
                    ans = await resolver.resolve(cand, "A")
                    ips = ", ".join(str(r) for r in ans)
                    findings.append(self._f("dns", "subdomain",
                                            f"{cand} -> {ips}",
                                            source="DNS brute force",
                                            confidence=95, passive=False))
                    found += 1
                    if found >= 100:
                        break
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    continue
                except Exception:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(seen)} subdomains from CT"
                       + (" + active brute force" if mode == "active" else ""))
        res.duration_ms = dur
        return res
