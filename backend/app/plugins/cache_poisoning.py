"""Web cache poisoning potential detector.

GET/HEAD only, tiny canary values, bounded request count. Detection only.

Passive: inspects cache headers on the normal homepage fetch.
Active: sends unkeyed-ish inputs (query param, X-Forwarded-Host,
X-Forwarded-Scheme, X-Original-URL, X-Rewrite-URL) and checks whether
the canary lands in a CACHED response - the classic poisonable-cache
signal. Never tries to poison anything for real.
"""
from __future__ import annotations

import asyncio
import secrets
import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

CACHE_HEADERS = ("age", "x-cache", "cf-cache-status", "x-cache-status",
                 "x-served-by", "surrogate-control", "x-drupal-cache",
                 "x-varnish", "via", "akamai-cache-status", "x-edge-location")

# Responses that are actually served from a cache tier
HIT_VALUES = ("hit", "tcp_hit", "tcp_mem_hit", "tcp_disk_hit")

REMEDIATION = ("Treat unkeyed inputs as untrusted: add cache keys for any "
               "reflected header/query input (or strip them at the edge), "
               "send Vary on every header the response depends on, and "
               "mark personalized pages private/no-store.")


def _cache_state(headers: Dict[str, str]) -> Dict[str, object]:
    """Summarize caching posture from response headers."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    age = h.get("age")
    cache_hit = any(v.lower() in HIT_VALUES
                    for k in ("x-cache", "cf-cache-status", "x-cache-status",
                              "akamai-cache-status")
                    for v in [h.get(k, "")] if v)
    return {
        "age": age,
        "cache_hit": cache_hit,
        "cache_control": h.get("cache-control", ""),
        "vary": h.get("vary", ""),
        "cdn": h.get("via", "") or h.get("server", ""),
        "cache_headers_present": [k for k in CACHE_HEADERS if k in h],
    }


class CachePoisoningPlugin(Plugin):
    id = "cache_poisoning"
    label = "Cache Poisoning Check"
    accepts = ["domain", "url"]
    passive = True
    aggressive = True  # suppressed on WAF-protected hosts
    cost = Cost.FREE
    group = "web"
    description = ("Detect web cache poisoning potential: unkeyed inputs "
                   "reflected into cached responses. GET/HEAD only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            headers = page["headers"]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        state = _cache_state(headers)
        if state["cache_headers_present"]:
            findings.append(self._f(
                "web", "cache_detected",
                f"Cache tier visible ({', '.join(state['cache_headers_present'][:6])}). "
                f"Cache-Control: {state['cache_control'] or 'none'}; "
                f"Vary: {state['vary'] or 'none'}. "
                "A cache that stores responses without keying all inputs "
                "is poisonable - see active-mode checks.",
                source="cache header analysis", source_url=page_url,
                confidence=75, passive=passive,
                evidence={"severity": "low",
                          "cache_headers": state["cache_headers_present"],
                          "cache_control": state["cache_control"],
                          "vary": state["vary"],
                          "remediation": REMEDIATION}))
        if (not passive) and (not state["cache_headers_present"]):
            findings.append(self._f(
                "web", "no_cache_detected",
                "No cache headers seen on the homepage, so there is no "
                "cache to poison here. Retest authenticated/personalized "
                "pages if they exist.",
                source="cache header analysis", source_url=page_url,
                confidence=60, passive=False,
                evidence={"severity": "low", "remediation": REMEDIATION}))

        if not passive:
            token = "cp" + secrets.token_hex(4)  # short canary
            sem = asyncio.Semaphore(4)

            async def probe(label: str, url: str,
                            extra_headers: Optional[Dict[str, str]] = None):
                async with sem:
                    try:
                        r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                        timeout=10, follow_redirects=True,
                                        max_retries=1,
                                        headers=extra_headers or {})
                        body = r.text[:60000]
                        st = _cache_state(dict(r.headers))
                        return label, url, extra_headers or {}, r.status_code, body, st
                    except Exception:
                        return None

            tests = [
                ("unkeyed query param",
                 f"{base.rstrip('/')}/?{token}=1", None),
                ("X-Forwarded-Host",
                 base, {"X-Forwarded-Host": f"{token}.example.com"}),
                ("X-Forwarded-Scheme",
                 base, {"X-Forwarded-Scheme": f"https-{token}"}),
                ("X-Original-URL",
                 base, {"X-Original-URL": f"/?{token}=1"}),
                ("X-Rewrite-URL",
                 base, {"X-Rewrite-URL": f"/?{token}=1"}),
            ]
            for result in await asyncio.gather(
                    *(probe(*t) for t in tests)):
                if not result:
                    continue
                label, url, hdrs, status, body, st = result
                reflected = token in body
                cached = bool(st["age"]) or st["cache_hit"]
                if reflected and cached:
                    findings.append(self._f(
                        "web", "cache_poisoning_reflection",
                        f"HIGH: cache poisoning candidate - {label} input "
                        f"is reflected in a CACHED response "
                        f"(age={st['age']}, cache-hit={st['cache_hit']}). "
                        f"An attacker could poison the cache for other "
                        f"visitors. GET/HEAD only - nothing was poisoned.",
                        source="cache poison probe", source_url=url,
                        confidence=80, passive=False,
                        exploitability="public_poc",
                        evidence={"severity": "high", "vector": label,
                                  "age": st["age"],
                                  "cache_hit": st["cache_hit"],
                                  "remediation": REMEDIATION,
                                  "scope_note": "Detection only: the canary "
                                                "was unique and inert."}))
                elif reflected:
                    findings.append(self._f(
                        "web", "unkeyed_header_reflection",
                        f"MEDIUM: {label} value reflected in response but "
                        f"the response was not cached. Unkeyed header "
                        f"reflection - review for cache poisoning if a "
                        f"cache sits upstream, plus XSS/redirect risk.",
                        source="cache poison probe", source_url=url,
                        confidence=60, passive=False,
                        evidence={"severity": "medium", "vector": label,
                                  "remediation": REMEDIATION}))

            if not state["vary"] and state["cache_headers_present"]:
                findings.append(self._f(
                    "web", "cache_missing_vary",
                    "MEDIUM: cache tier present but responses carry no "
                    "Vary header. Responses that depend on request headers "
                    "can be served to the wrong visitor - audit which "
                    "inputs the cache keys on.",
                    source="cache header analysis", source_url=page_url,
                    confidence=55, passive=False,
                    evidence={"severity": "medium",
                              "remediation": REMEDIATION}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} cache findings "
                                 f"({'active' if not passive else 'passive'})")
        res.duration_ms = dur
        return res
