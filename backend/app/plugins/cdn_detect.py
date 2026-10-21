"""CDN provider detection plugin.

Identifies the CDN / edge provider in front of the target from response
headers (cf-ray, x-amz-cf-id, x-cache, via, server) and DNS CNAMEs.
Knowing the edge provider matters: it tells Jay where WAF/edge rules
live and which provider's bypass techniques apply to further
(authorized) testing.

Passive: homepage header read (shared fetch_page cache) + CNAME
lookups. No origin-hunting - this only names the edge, never the
origin behind it.
"""
from __future__ import annotations

import time
from typing import List

import dns.asyncresolver

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

# header substring -> provider
HEADER_SIGNS = [
    ("cf-ray", "Cloudflare"), ("cf-cache-status", "Cloudflare"),
    ("x-amz-cf-id", "Amazon CloudFront"), ("x-amz-cf-pop", "Amazon CloudFront"),
    ("x-cache", None),  # value-inspected below
    ("x-served-by", None), ("via", None), ("server", None),
]
VALUE_SIGNS = [
    ("cloudflare", "Cloudflare"), ("cloudfront", "Amazon CloudFront"),
    ("akamai", "Akamai"), ("fastly", "Fastly"),
    ("google frontend", "Google Cloud CDN"), ("gws", "Google"),
    ("bunnycdn", "Bunny CDN"), ("cdn77", "CDN77"),
    ("maxcdn", "StackPath"), ("edgecast", "Edgio/Edgecast"),
    ("azure", "Azure Front Door/CDN"), ("incap_ses", "Imperva"),
    ("sucuri", "Sucuri"), ("quantil", "Quantil"),
]
CNAME_SIGNS = [
    ("cloudflare", "Cloudflare"), ("cloudfront.net", "Amazon CloudFront"),
    ("akamai", "Akamai"), ("fastly", "Fastly"),
    ("googlehosted", "Google Cloud CDN"), ("azureedge", "Azure CDN"),
    ("bunnycdn", "Bunny CDN"), ("cdn77", "CDN77"),
]


class CdnDetectPlugin(Plugin):
    id = "cdn_detect"
    label = "CDN Detection"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Identify the CDN/edge provider from headers and DNS "
                   "CNAMEs (edge naming only, no origin hunting).")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        providers: List[str] = []
        evidence_bits: List[str] = []
        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is not None:
            for k, v in resp.headers.items():
                kl, vl = k.lower(), v.lower()
                for frag, name in HEADER_SIGNS:
                    if frag in kl and name and name not in providers:
                        providers.append(name)
                        evidence_bits.append(f"header {k}")
                for frag, name in VALUE_SIGNS:
                    if frag in vl and name not in providers:
                        providers.append(name)
                        evidence_bits.append(f"header {k}: {v[:40]}")
        try:
            res = dns.asyncresolver.Resolver(configure=False)
            res.nameservers = ["8.8.8.8", "1.1.1.1"]
            res.timeout = 6
            res.lifetime = 10
            ans = await res.resolve(domain, "CNAME")
            for rr in ans:
                cname = str(rr.target).lower()
                for frag, name in CNAME_SIGNS:
                    if frag in cname and name not in providers:
                        providers.append(name)
                        evidence_bits.append(f"CNAME {cname[:60]}")
        except Exception:
            pass

        findings: List = []
        if providers:
            findings.append(self._f(
                "infra", "cdn_detected",
                f"Edge provider: {', '.join(providers)} "
                f"({' / '.join(evidence_bits[:3])})",
                source="CDN detection", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": "low", "providers": providers,
                          "signals": evidence_bits[:5],
                          "remediation": (
                              "Informational: edge rules/WAF live at this "
                              "provider. Verify the origin is not directly "
                              "reachable (it should only accept the CDN).")}))
            ctx.publish("cdn", providers[0])
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"detected {len(providers)} edge provider(s)")
