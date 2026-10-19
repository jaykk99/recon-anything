"""LinkFinder/Gf-style aggressive JS endpoint extractor.

Parses every first-party JS bundle for hidden endpoints: fetch/axios/XHR
calls, API URLs, GraphQL queries, WebSocket URLs, and relative paths.
More aggressive than jsminer.py: also reconstructs endpoints from string
concatenation patterns and template literals.

Detection only: read-only GETs of public JS files. Publishes endpoints
to the discovery bus for chain plugins. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Endpoint-ish patterns inside JS
ENDPOINT_RES = [
    # fetch("/api/users"), axios.get('/v1/...'), $.ajax({url: ...})
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax)\s*\(\s*['"`]([^'"`]{3,200})['"`]""",
    # url: "/api/..." inside objects
    r"""url\s*:\s*['"`]([^'"`]{3,200})['"`]""",
    # endpoint: "...", path: "...", apiUrl / baseURL assignments
    r"""(?i)(?:endpoint|api[_-]?url|base[_-]?url|api[_-]?path)\s*[:=]\s*['"`]([^'"`]{3,200})['"`]""",
    # template literals: `/api/${x}/users`
    r"""`((?:/[A-Za-z0-9_\-{}.$]+)+)`""",
    # GraphQL operation names
    r"""(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]{2,40})\s*[{(\[]""",
    # WebSocket URLs
    r"""['"`](wss?://[^'"`]{5,200})['"`]""",
    # absolute API-ish URLs
    r"""['"`](https?://[a-z0-9.\-]+\.[a-z]{2,}(?::\d+)?/(?:api|v\d|rest|graphql)[^'"`]{0,120})['"`]""",
]

INTERESTING_HINTS = ("api", "v1", "v2", "graphql", "admin", "internal",
                     "debug", "token", "auth", "user", "account")


class JsEndpointsPlugin(Plugin):
    id = "js_endpoints"
    label = "JS Endpoint Extractor"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = ("LinkFinder-style: aggressive endpoint extraction from "
                   "JS bundles (fetch/axios/XHR, GraphQL, WebSockets).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        endpoints: Set[str] = set()

        try:
            page = await ctx.fetch_page(base, timeout=25)
            if not page:
                res = self._degraded("homepage fetch failed")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            html = page["text"][:500000]
            page_url = page.get("url") or base

            # inline scripts too
            inline = " ".join(re.findall(
                r"<script(?![^>]+src=)[^>]*>(.*?)</script>", html,
                re.I | re.S))[:300000]

            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
            srcs = [s for s in srcs if not s.startswith("data:")][:25]

            bodies: List[tuple] = [("inline <script>", inline, page_url)]
            for src in srcs:
                full = urljoin(page_url, src)
                host = urlparse(full).netloc
                if host and not host.endswith(domain):
                    continue
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", full,
                                    timeout=12)
                    if r.status_code == 200 and r.text:
                        bodies.append((f"JS {src[:60]}", r.text[:300000], full))
                except Exception:
                    continue

            for where, body, url in bodies:
                if not body.strip():
                    continue
                for pat in ENDPOINT_RES:
                    try:
                        for m in re.finditer(pat, body):
                            ep = m.group(1).strip()
                            if len(ep) < 3 or len(ep) > 220:
                                continue
                            # skip obvious non-endpoints
                            if ep.startswith(("data:", "javascript:",
                                               "#", "mailto:")):
                                continue
                            if " " in ep and "://" not in ep:
                                continue
                            endpoints.add((ep, where, url))
                    except re.error:
                        continue

            for ep, where, url in sorted(endpoints)[:150]:
                ctx.publish("endpoints", ep)
                interesting = any(h in ep.lower() for h in INTERESTING_HINTS)
                sev = "medium" if interesting else "low"
                findings.append(self._f(
                    "api", "hidden_api_endpoint",
                    f"JS endpoint: {ep[:120]}",
                    source=f"js endpoint scan: {where}", source_url=url,
                    confidence=75 if interesting else 60, passive=passive,
                    evidence={"remediation": "Audit this endpoint for "
                              "authentication and object-level authorization. "
                              "Test with a second account.",
                              "severity": sev, "risk": sev,
                              "endpoint": ep}))

        except Exception as e:
            res = self._degraded(f"scan failed: {str(e)[:150]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        res = self._ok(findings,
                       f"{len(endpoints)} JS endpoints extracted" if findings
                       else "no JS endpoints found")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
