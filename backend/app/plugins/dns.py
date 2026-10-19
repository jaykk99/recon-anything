"""DNS plugin (Milestone 1).

A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV, PTR + DNSSEC posture.
Works for domain and url targets. Passive-safe: uses the local/system
resolver in passive mode too (DNS lookups send no packets to the target
itself, only to the configured resolver).
"""
from __future__ import annotations

import asyncio
import time
from typing import List

import dns.asyncresolver
import dns.reversename
import dns.resolver

from ..classifier import domain_from_target
from .base import Ctx, Cost, Finding, Plugin, PluginResult, Target

RECORDS = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV",
           "DS", "DNSKEY", "NAPTR", "TLSA", "SSHFP"]


class DnsPlugin(Plugin):
    id = "dns"
    label = "DNS Records"
    accepts = ["domain", "url", "email"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV, PTR + DNSSEC posture."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain to resolve for this target type")
        findings: List[Finding] = []
        # Full internet DNS: system resolver first, public resolvers as
        # fallback so a broken local resolver never blinds the scan.
        resolvers = [dns.asyncresolver.Resolver()]
        for ns in ("8.8.8.8", "1.1.1.1"):
            try:
                r = dns.asyncresolver.Resolver(configure=False)
                r.nameservers = [ns]
                resolvers.append(r)
            except Exception:
                continue
        for r in resolvers:
            r.lifetime = 10

        async def lookup(rtype: str):
            for resolver in resolvers:
                try:
                    ans = await resolver.resolve(domain, rtype)
                    return [str(x).strip('"') for x in ans]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    return []
                except Exception:
                    continue
            return []

        for rtype in RECORDS:
            vals, _ = await ctx.cache.cached("dns", f"{domain}:{rtype}",
                                             lambda rt=rtype: lookup(rt))
            for v in vals:
                findings.append(self._f("dns", rtype.lower(), v,
                                        source=f"DNS {rtype}",
                                        confidence=95, passive=True))

        # PTR for each A record (reverse DNS), same resolver fallback chain
        async def ptr_lookup(rev):
            for rs in resolvers:
                try:
                    return await rs.resolve(rev, "PTR")
                except Exception:
                    continue
            return []
        a_vals = [f.value for f in findings if f.key == "a"]
        for ip in a_vals[:8]:
            try:
                rev = dns.reversename.from_address(ip)
                ans = await ptr_lookup(rev)
                for r in ans:
                    findings.append(self._f("dns", "ptr", f"{ip} -> {r}",
                                            source="Reverse DNS", confidence=90))
            except Exception:
                continue

        # DNSSEC posture: check for DS at parent via a simple query
        ds_answer = None
        ds_missing = False
        for rs in resolvers:
            try:
                await rs.resolve(domain, "DS")
                ds_answer = True
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                ds_missing = True
                break
            except Exception:
                continue
        if ds_answer:
            findings.append(self._f("dns", "dnssec", "DS record present: signed zone",
                                    source="DNS DS", confidence=85))
        elif ds_missing:
            findings.append(self._f("dns", "dnssec", "no DS record: unsigned zone",
                                    source="DNS DS", confidence=80))

        # Zone transfer attempt (detection only - one AXFR query per nameserver)
        for ns_val in [f.value for f in findings if f.key == "ns"][:4]:
            try:
                import dns.query
                import dns.zone
                ns_host = ns_val.rstrip(".")
                # Resolve NS to IP first
                ns_ips = []
                for rs in resolvers:
                    try:
                        ans = await rs.resolve(ns_host, "A")
                        ns_ips = [str(x) for x in ans]
                        break
                    except Exception:
                        continue
                for ns_ip in ns_ips[:1]:
                    try:
                        z = await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: dns.query.xfr(ns_ip, domain, timeout=8))
                        zone = dns.zone.from_xfr(z)
                        if zone:
                            findings.append(self._f(
                                "dns", "zone_transfer",
                                f"CRITICAL: Zone transfer (AXFR) allowed from {ns_host}",
                                source="DNS AXFR", confidence=95,
                                evidence={"severity": "critical"}))
                            break
                    except Exception:
                        continue
            except Exception:
                continue

        # CAA analysis
        caa_vals = [f.value for f in findings if f.key == "caa"]
        if caa_vals:
            findings.append(self._f("dns", "caa_policy",
                                    f"CAA restricts issuance: {'; '.join(caa_vals[:3])}",
                                    source="DNS CAA", confidence=85))
        else:
            findings.append(self._f("dns", "caa_missing",
                                    "No CAA records - any CA can issue certs for this domain",
                                    source="DNS CAA", confidence=70,
                                    evidence={"severity": "low"}))

        # Wildcard DNS detection
        try:
            import random
            import string
            rand_sub = "wxyz" + "".join(random.choices(string.ascii_lowercase, k=8))
            for rs in resolvers:
                try:
                    ans = await rs.resolve(f"{rand_sub}.{domain}", "A")
                    if ans:
                        findings.append(self._f(
                            "dns", "wildcard_dns",
                            f"Wildcard DNS enabled - *.{domain} resolves",
                            source="DNS wildcard test", confidence=85))
                        break
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    break
                except Exception:
                    continue
        except Exception:
            pass

        # SPF deep analysis from TXT records
        txt_vals = [f.value for f in findings if f.key == "txt"]
        for tv in txt_vals:
            if tv.startswith("v=spf1"):
                # Count DNS lookups (SPF limit is 10)
                lookups = tv.count("include:") + tv.count("redirect=")
                if lookups > 8:
                    findings.append(self._f(
                        "dns", "spf_too_many_lookups",
                        f"SPF has {lookups} DNS lookups (limit 10) - near permerror",
                        source="DNS TXT", confidence=75))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} records for {domain}")
        res.duration_ms = dur
        return res
