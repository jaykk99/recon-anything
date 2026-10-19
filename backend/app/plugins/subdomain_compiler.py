"""Passive subdomain compiler (Anubis-style): fast multi-source enum.

Queries several keyless sources concurrently, deduplicates, and publishes
a clean subdomain list to the discovery bus for phase-2 chain plugins.
Sources: crt.sh, hackertarget hostsearch, threatcrowd, AlienVault OTX,
certspotter. All free, no API keys, passive (no packets to the target).

Emits one summary finding with the compiled list; individual subdomains
go to the bus so scanners like takeover.py and screenshots.py can use
them without re-enumerating.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, Target, safe_json_dict, safe_json_list

SRC_TIMEOUT = 12


class SubdomainCompilerPlugin(Plugin):
    id = "subdomain_compiler"
    label = "Passive Subdomain Compiler"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Fast keyless subdomain compilation from crt.sh, "
                   "hackertarget, threatcrowd, AlienVault OTX, certspotter, "
                   "urlscan.io, subdomain.center.")
    timeout_s = 30

    async def _fetch_text(self, ctx: Ctx, url: str) -> str:
        try:
            resp = await ctx.http.get(url, timeout=SRC_TIMEOUT,
                                      follow_redirects=True)
            if resp.status_code == 200:
                return resp.text[:500000]
        except Exception:
            pass
        return ""

    async def _crtsh(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        try:
            resp = await ctx.http.get(
                f"https://crt.sh/?q=%25.{quote(domain)}&output=json",
                timeout=SRC_TIMEOUT, follow_redirects=True)
            for row in safe_json_list(resp):
                name = str(row.get("name_value", "") or "")
                for n in name.split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith(domain) and n != domain:
                        out.add(n)
        except Exception:
            pass
        return out

    async def _hackertarget(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        txt = await self._fetch_text(
            ctx, f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}")
        for line in txt.splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(domain) and host != domain:
                out.add(host)
        return out

    async def _threatcrowd(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        try:
            resp = await ctx.http.get(
                "https://www.threatcrowd.org/searchApi/v2/domain/report/"
                f"?domain={quote(domain)}",
                timeout=SRC_TIMEOUT, follow_redirects=True)
            data = safe_json_dict(resp)
            for s in data.get("subdomains") or []:
                s = str(s).strip().lower()
                if s.endswith(domain) and s != domain:
                    out.add(s)
        except Exception:
            pass
        return out

    async def _otx(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        try:
            resp = await ctx.http.get(
                "https://otx.alienvault.com/api/v1/indicators/domain/"
                f"{quote(domain)}/url_list?limit=500&page=1",
                timeout=SRC_TIMEOUT, follow_redirects=True)
            data = safe_json_dict(resp)
            for row in data.get("url_list") or []:
                url = str((row or {}).get("url", ""))
                host = url.split("/")[2] if "://" in url else ""
                host = host.split(":")[0].lower()
                if host.endswith(domain) and host != domain:
                    out.add(host)
        except Exception:
            pass
        return out

    async def _certspotter(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        try:
            resp = await ctx.http.get(
                "https://api.certspotter.com/v1/issuances?"
                f"domain={quote(domain)}&include_subdomains=true"
                f"&expand=dns_names",
                timeout=SRC_TIMEOUT, follow_redirects=True)
            for row in safe_json_list(resp):
                for n in row.get("dns_names") or []:
                    n = str(n).strip().lower().lstrip("*.")
                    if n.endswith(domain) and n != domain:
                        out.add(n)
        except Exception:
            pass
        return out

    async def _urlscan(self, ctx: Ctx, domain: str) -> Set[str]:
        """urlscan.io search API (keyless): subdomains from scanned URLs."""
        out: Set[str] = set()
        try:
            resp = await ctx.http.get(
                "https://urlscan.io/api/v1/search/"
                f"?q=domain%3A{quote(domain)}&size=100",
                timeout=SRC_TIMEOUT, follow_redirects=True)
            data = safe_json_dict(resp)
            for row in data.get("results") or []:
                page = (row or {}).get("page") or {}
                u = str(page.get("url", ""))
                host = u.split("/")[2] if "://" in u else ""
                host = host.split(":")[0].lower()
                if host.endswith(domain) and host != domain:
                    out.add(host)
        except Exception:
            pass
        return out

    async def _subdomain_center(self, ctx: Ctx, domain: str) -> Set[str]:
        """subdomain.center API (keyless): passive subdomain list."""
        out: Set[str] = set()
        try:
            resp = await ctx.http.get(
                f"https://api.subdomain.center/?domain={quote(domain)}",
                timeout=SRC_TIMEOUT, follow_redirects=True)
            for s in safe_json_list(resp):
                s = str(s).strip().lower()
                if s.endswith(domain) and s != domain:
                    out.add(s)
        except Exception:
            pass
        return out

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        results = await asyncio.gather(
            self._crtsh(ctx, domain),
            self._hackertarget(ctx, domain),
            self._threatcrowd(ctx, domain),
            self._otx(ctx, domain),
            self._certspotter(ctx, domain),
            self._urlscan(ctx, domain),
            self._subdomain_center(ctx, domain),
            return_exceptions=True,
        )
        sources = ["crt.sh", "hackertarget", "threatcrowd",
                   "alienvault-otx", "certspotter", "urlscan",
                   "subdomain.center"]
        merged: Set[str] = set()
        working: List[str] = []
        for src, res in zip(sources, results):
            if isinstance(res, set) and res:
                working.append(src)
                merged |= res

        # publish clean list to the discovery bus for chain plugins
        for sub in sorted(merged):
            ctx.publish("subdomains", sub)

        elapsed = round((time.monotonic() - t0) * 1000)
        findings = []
        if merged:
            findings.append(self._f(
                "dns", "compiled_subdomains",
                f"{len(merged)} subdomains compiled for {domain}",
                source=",".join(working),
                source_url=f"https://crt.sh/?q=%25.{domain}",
                confidence=85,
                evidence={
                    "severity": "low",
                    "count": len(merged),
                    "sources": working,
                    "subdomains": sorted(merged)[:200],
                    "duration_ms": elapsed,
                    "remediation": (
                        "Review the subdomain list for forgotten, staging, "
                        "or dev hosts. Remove or secure anything "
                        "unnecessary; each one is attack surface."),
                },
                bounty_value="low",
            ))
            return self._ok(
                findings,
                reason=(f"compiled {len(merged)} subdomains from "
                        f"{len(working)}/7 sources in {elapsed}ms"))
        return self._ok(
            [], reason=(f"no subdomains from {len(working)}/7 sources "
                        f"({elapsed}ms)"))
