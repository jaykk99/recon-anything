"""Redirect chain analysis plugin.

Follows the homepage redirect chain (no redirects followed blindly -
each hop is a single logged step) and flags:
- http:// -> https:// downgrade gaps (first hop over plaintext),
- redirects to a different registrable domain (possible takeover of
  the redirect target, or just a www <-> bare shuffle),
- redirect loops and chains longer than 4 hops,
- open-redirect-shaped hops are NOT tested (no payloads) - only the
  site's own default chain is observed.

Detection only: observes the server's own redirect behavior.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

MAX_HOPS = 6


def _reg_domain(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


class RedirectChainPlugin(Plugin):
    id = "redirect_chain"
    label = "Redirect Chain"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Analyze the homepage redirect chain: downgrades, "
                   "off-domain hops, loops, long chains.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        start = (target.normalized if target.type == "url"
                 else f"https://{domain}/")

        chain: List = []
        url = start
        seen_urls = set()
        try:
            for _ in range(MAX_HOPS):
                if url in seen_urls:
                    chain.append({"url": url, "loop": True})
                    break
                seen_urls.add(url)
                r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                timeout=10, follow_redirects=False,
                                max_retries=0)
                loc = r.headers.get("location")
                chain.append({"url": url, "status": r.status_code,
                              "location": loc})
                if r.status_code in (301, 302, 303, 307, 308) and loc:
                    url = urljoin(url, loc)
                else:
                    break
        except Exception:
            if not chain:
                return self._degraded("could not fetch start URL")

        findings: List = []
        first = chain[0]
        if urlparse(first["url"]).scheme == "http":
            findings.append(self._f(
                "web", "redirect_plaintext_first_hop",
                f"Redirect chain starts over plaintext http: "
                f"{first['url'][:120]}",
                source="redirect chain analysis",
                source_url=first["url"], confidence=90, passive=True,
                evidence={"severity": "medium",
                          "remediation": (
                              "Serve the first hop over https or HSTS-preload "
                              "the domain so browsers never do plaintext.")}))
        hops = [c for c in chain if not c.get("loop")]
        if any(c.get("loop") for c in chain):
            findings.append(self._f(
                "web", "redirect_loop",
                "Redirect loop detected in the homepage chain",
                source="redirect chain analysis",
                source_url=start, confidence=95, passive=True,
                evidence={"severity": "medium",
                          "remediation": ("Fix the redirect loop - it breaks "
                                          "crawlers and users.")}))
        elif len(hops) > 4:
            findings.append(self._f(
                "web", "redirect_chain_long",
                f"Redirect chain is {len(hops)} hops - crawlers and users "
                "lose patience",
                source="redirect chain analysis",
                source_url=start, confidence=85, passive=True,
                evidence={"severity": "low", "hops": len(hops),
                          "remediation": ("Collapse the chain to 1-2 hops; "
                                          "each hop leaks referrer and "
                                          "slows the page.")}))
        home_reg = _reg_domain(urlparse(start).netloc or domain)
        for c in hops:
            loc = c.get("location") or ""
            if not loc:
                continue
            dest_host = urlparse(urljoin(c["url"], loc)).netloc
            if dest_host and _reg_domain(dest_host) != home_reg:
                findings.append(self._f(
                    "web", "redirect_off_domain",
                    f"Homepage redirects off-domain to {dest_host}",
                    source="redirect chain analysis",
                    source_url=start, confidence=85, passive=True,
                    evidence={"severity": "low", "destination": dest_host,
                              "remediation": (
                                  "Confirm the off-domain hop is intentional; "
                                  "a hijacked redirect target is a classic "
                                  "takeover/phishing vector.")}))
                break
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"chain of {len(hops)} hops, {len(findings)} findings")
