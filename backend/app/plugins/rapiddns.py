"""RapidDNS subdomain enumeration (hunter source plugin).

rapiddns.io indexes DNS data collected from multiple upstream feeds;
its subdomain listing regularly contains hosts that certificate
transparency alone misses (mail, vpn, and internal-style names that
never got a public cert). Free, no API key, and passive: the query
goes to rapiddns.io, never to the target.

Emits ordinary "subdomain" findings (source rapiddns.io) so the
hunter engine, the discovery bus and the UI treat them exactly like
crt.sh results. Detection only.
"""
from __future__ import annotations

import re
import time
from typing import List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}$")
MAX_SUBS = 500


def parse_rapiddns_subdomains(html: str, domain: str) -> List[str]:
    """RapidDNS result pages carry hostnames in subdomain links and
    table cells. Pull every token that ends with the target domain,
    canonicalize, dedupe, and validate."""
    out: Set[str] = set()
    text = html or ""
    suffix = "." + domain
    for m in re.finditer(r"([a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+)",
                         text.lower()):
        host = m.group(1).rstrip(".")
        if not host.endswith(suffix) or host == domain:
            continue
        if ".." in host or host.startswith("."):
            continue
        if _DOMAIN_RE.match(host):
            out.add(host)
    return sorted(out)[:MAX_SUBS]


class RapidDnsPlugin(Plugin):
    id = "rapiddns"
    label = "RapidDNS Subdomains"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Subdomain enumeration from the RapidDNS index "
                   "(multi-feed DNS data). Keyless, passive.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        async def grab():
            url = f"https://rapiddns.io/subdomain/{quote(domain)}?full=1"
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                   timeout=30)
                if resp.status_code != 200:
                    return {"subs": [], "error": f"HTTP {resp.status_code}"}
                return {"subs": parse_rapiddns_subdomains(resp.text, domain)}
            except Exception as e:
                return {"subs": [], "error": str(e)[:200] or
                        type(e).__name__}

        data, _ = await ctx.cache.cached("rapiddns", domain, grab)
        subs = (data or {}).get("subs") or []
        findings: List[Finding] = []
        if not subs and (data or {}).get("error"):
            findings.append(self._f(
                "dns", "subdomain_enum_note",
                f"rapiddns unavailable: {data['error']}",
                source="rapiddns.io", confidence=40, passive=True))
        for sub in subs:
            ctx.publish("subdomains", sub)
            findings.append(self._f(
                "dns", "subdomain", sub,
                source="rapiddns.io",
                source_url=f"https://rapiddns.io/subdomain/{domain}",
                confidence=75, passive=True))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(subs)} subdomains from RapidDNS")
        res.duration_ms = dur
        return res
