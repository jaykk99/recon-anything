"""WAF detector plugin.

Identifies Web Application Firewalls by analyzing headers, cookies,
and blocking behavior. Custom-built, no API keys needed.
Checks 15+ known WAF signatures.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# WAF fingerprints: (header_or_cookie_name, match_value, waf_name)
WAF_SIGNATURES = [
    ("cf-ray", None, "Cloudflare"),
    ("__cfduid", None, "Cloudflare"),
    ("cf-cache-status", None, "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    ("x-sucuri-id", None, "Sucuri"),
    ("x-sucuri-cache", None, "Sucuri"),
    ("x-akamaized", None, "Akamai"),
    ("akamai", "akamai", "Akamai"),
    ("x-amz-cf-id", None, "AWS CloudFront / WAF"),
    ("x-amzn-requestid", None, "AWS WAF"),
    ("x-azure-ref", None, "Azure WAF"),
    ("x-f5", None, "F5 BIG-IP"),
    ("x-waf", None, "Generic WAF"),
    ("x-protected-by", None, "WAF (x-protected-by)"),
    ("x-imperva", None, "Imperva"),
    ("incap_ses", None, "Imperva Incapsula"),
    ("visid_incap", None, "Imperva Incapsula"),
    ("x-iinfo", None, "Imperva Incapsula"),
    ("x-cdn", "imperva", "Imperva"),
    ("x-distil", None, "Distil Networks"),
    ("x-plex", None, "Plex WAF"),
    ("x-shield", None, "Shield WAF"),
    ("x-edgecast", None, "Edgecast"),
    ("x-wallarm", None, "Wallarm"),
    ("x-datadome", None, "DataDome"),
    ("x-perimeterx", None, "PerimeterX / HUMAN"),
    ("x-kasada", None, "Kasada"),
    ("__kasada", None, "Kasada"),
    ("bm_sv", None, "Akamai Bot Manager"),
    ("_abck", None, "Akamai Bot Manager"),
    ("ak_bmsc", None, "Akamai Bot Manager"),
    ("x-fastly", None, "Fastly"),
    ("fastly", "fastly", "Fastly"),
    ("x-varnish", None, "Varnish (may front a WAF)"),
    ("x-sg-id", None, "Sucuri / GoDaddy"),
    ("x-origin-shield", None, "Origin Shield"),
    ("x-request-id", "aws", "AWS"),
    ("x-mod-pagespeed", None, "mod_pagespeed (Apache)"),
    ("x-powered-by", "bigip", "F5 BIG-IP"),
    ("bigipserver", None, "F5 BIG-IP"),
    ("tsv1", None, "F5 BIG-IP"),
    ("f5_cspm", None, "F5"),
    ("asg", None, "F5 ASM"),
    ("x-nginx-waf", None, "Nginx WAF"),
    ("x-hacker", None, "Honeypot? (x-hacker header)"),
]


class WafPlugin(Plugin):
    id = "waf"
    label = "WAF Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Detect Web Application Firewalls via 40+ signatures."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        detected = set()

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
        except Exception as e:
            return self._degraded(f"could not fetch: {str(e)[:150]}")

        headers = {k.lower(): v for k, v in r.headers.items()}
        cookies = r.headers.get("set-cookie", "").lower()

        for sig_name, sig_val, waf_name in WAF_SIGNATURES:
            lname = sig_name.lower()
            matched = False
            if lname in headers:
                if sig_val is None or sig_val.lower() in headers[lname].lower():
                    matched = True
            if lname in cookies:
                matched = True
            if matched and waf_name not in detected:
                detected.add(waf_name)
                findings.append(self._f(
                    "web", "waf_detected",
                    f"WAF detected: {waf_name} (via {sig_name})",
                    source="WAF detector", source_url=url,
                    confidence=85, passive=True))

        # Blocking behavior test: send a suspicious payload, see if blocked
        try:
            evil = url + "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
            r2 = await fetch(ctx.http, ctx.limiter, "GET", evil, timeout=12)
            if r2.status_code in (403, 406, 419, 501):
                findings.append(self._f(
                    "web", "waf_blocking",
                    f"WAF actively blocking: {r2.status_code} on XSS probe",
                    source="WAF detector", source_url=evil,
                    confidence=90, passive=True))
        except Exception:
            pass

        if not detected:
            findings.append(self._f(
                "web", "waf_none",
                "No WAF detected - target may be directly exposed",
                source="WAF detector", source_url=url,
                confidence=60, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(WAF_SIGNATURES)} signatures")
        res.duration_ms = dur
        return res
