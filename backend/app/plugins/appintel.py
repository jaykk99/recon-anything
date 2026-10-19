"""App Intelligence (native, keyless).

Build the structured brief the AI uses for full-app analysis:
- frameworks & tech stack (from the tech discovery bus + own checks)
- API surface patterns (REST versions, GraphQL, base paths, auth schemes)
- auth flows detected (login/signup/oauth/sso URLs, JWT/session usage)
- file inventory rollup (from allsources/jsdeep/assetmap bus channels)
- ranked interesting files (configs, admin, api, source maps, docs)

Emits ONE structured finding (key `app_ai_brief`) whose evidence carries
the full brief as JSON. The frontend "AI App Analysis" section reads that
finding and sends it to POST /api/assistant/chat for the AI breakdown.

GET only, detection only, bounded under 30s.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                  bounded, gather_capped)

TIME_BUDGET = 25
CONCURRENCY = 10

FRAMEWORK_HINTS = [
    (re.compile(r'/_next/static/', re.I), "Next.js"),
    (re.compile(r'__NEXT_DATA__', re.I), "Next.js"),
    (re.compile(r'/static/js/main\.[a-f0-9]+\.js', re.I), "React (CRA)"),
    (re.compile(r'data-reactroot|react-dom', re.I), "React"),
    (re.compile(r'ng-version|angular\.js', re.I), "Angular"),
    (re.compile(r'vue(\.min)?\.js|__VUE__', re.I), "Vue"),
    (re.compile(r'nuxt', re.I), "Nuxt"),
    (re.compile(r'wp-content|wp-includes', re.I), "WordPress"),
    (re.compile(r'Joomla', re.I), "Joomla"),
    (re.compile(r'drupal\.js|/sites/default/files', re.I), "Drupal"),
    (re.compile(r'shopify', re.I), "Shopify"),
    (re.compile(r'wix\.com|wixstatic', re.I), "Wix"),
    (re.compile(r'squarespace', re.I), "Squarespace"),
    (re.compile(r'webflow', re.I), "Webflow"),
    (re.compile(r'laravel|csrf-token.*laravel', re.I), "Laravel"),
    (re.compile(r'django|csrftoken', re.I), "Django"),
    (re.compile(r'rails|authenticity_token', re.I), "Rails"),
    (re.compile(r'asp\.net|__VIEWSTATE', re.I), "ASP.NET"),
    (re.compile(r'php', re.I), "PHP"),
]
AUTH_URL_RE = re.compile(
    r'''(?:href|action)\s*=\s*["']([^"']*(?:login|signin|sign-in|log-in|signup|sign-up|register|auth|oauth|sso|password|reset|forgot)[^"']*)["']''',
    re.I)
AUTH_JS_RE = re.compile(
    r'''(?i)(/api/(?:auth|login|session|token|oauth)[\w\-/]*|jwt|bearer\s|localStorage\.getItem\(['"]token|refresh[_-]?token)''')
API_BASE_RE = re.compile(r'''(["'`])(/(?:api|v\d|rest|graphql)(?:/[\w\-]+){0,3})''')
GRAPHQL_RE = re.compile(r'/graphql|__schema|introspection', re.I)

INTERESTING_FILE_RE = re.compile(
    r'''(?i)(config|\.env|admin|dashboard|\.map$|swagger|openapi|\.sql$|backup|debug|test|staging|dev)''')


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


class AppIntelPlugin(Plugin):
    id = "appintel"
    label = "App Intelligence"
    accepts = ["domain", "url"]
    passive = True
    phase = 2
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Build the AI app-analysis brief: frameworks, API "
                   "patterns, auth flows, file inventory, hot files.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        # --- gather from the discovery bus (other plugins ran first) ---
        techs: Set[str] = set()
        for t in ctx.consume("tech"):
            if isinstance(t, str) and t.strip():
                techs.add(t.strip()[:80])
        js_files: Set[str] = set()
        for u in ctx.consume("js"):
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                js_files.add(u)
        endpoints: Set[str] = set()
        for e in ctx.consume("endpoints"):
            if isinstance(e, str) and e.startswith(("http://", "https://")):
                endpoints.add(e)
        assets: Set[str] = set()
        for a in ctx.consume("assets"):
            if isinstance(a, str) and a.startswith(("http://", "https://")):
                assets.add(a)

        # --- own homepage fetch for framework + auth detection ---
        frameworks: Set[str] = set()
        auth_urls: Set[str] = set()
        api_bases: Set[str] = set()
        has_graphql = False
        js_auth_hints: Set[str] = set()
        html = ""
        try:
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", base, timeout=10,
                max_retries=0), 12)
            if r is not None and r.status_code == 200:
                html = r.text[:400000]
        except Exception:
            pass
        if html:
            for rx, name in FRAMEWORK_HINTS:
                if rx.search(html):
                    frameworks.add(name)
            for m in AUTH_URL_RE.finditer(html):
                u = urljoin(base, m.group(1).strip())
                if u.startswith(("http://", "https://")):
                    auth_urls.add(u)
            for m in API_BASE_RE.finditer(html):
                api_bases.add(m.group(2)[:80])
            if GRAPHQL_RE.search(html):
                has_graphql = True

        # scan first-party JS for auth patterns (bounded sample)
        sem = asyncio.Semaphore(CONCURRENCY)
        checked_js = 0

        async def scan_js(u: str):
            nonlocal checked_js
            if (time.monotonic() - t0) > TIME_BUDGET:
                return
            async with sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", u,
                                    timeout=8, max_retries=0)
                    if r.status_code != 200:
                        return
                    blob = r.content[:500000].decode("utf-8", "ignore")
                except Exception:
                    return
            checked_js += 1
            for m in AUTH_JS_RE.finditer(blob):
                hit = m.group(0)[:100]
                if len(js_auth_hints) < 25:
                    js_auth_hints.add(hit)
            for m in API_BASE_RE.finditer(blob):
                if len(api_bases) < 30:
                    api_bases.add(m.group(2)[:80])
            if GRAPHQL_RE.search(blob):
                js_auth_hints.add("graphql-client-detected")

        same_site_js = [u for u in js_files if _host(u) == domain or
                        _host(u).endswith("." + domain)][:20]
        if same_site_js:
            await gather_capped([scan_js(u) for u in same_site_js],
                                TIME_BUDGET - (time.monotonic() - t0))

        # rank interesting files
        interesting: List[str] = []
        for u in sorted(js_files | assets):
            if INTERESTING_FILE_RE.search(u) and len(interesting) < 30:
                interesting.append(u)

        api_hosts = sorted({_host(e) for e in endpoints if _host(e)})[:15]

        brief: Dict = {
            "target": domain,
            "frameworks": sorted(frameworks) or ["unknown"],
            "tech_stack": sorted(techs)[:20],
            "api": {
                "endpoints_found": len(endpoints),
                "base_paths": sorted(api_bases)[:20],
                "api_hosts": api_hosts,
                "graphql": has_graphql or
                any("graphql" in h for h in js_auth_hints),
                "sample_endpoints": sorted(endpoints)[:25],
            },
            "auth": {
                "auth_pages": sorted(auth_urls)[:15],
                "js_auth_hints": sorted(js_auth_hints)[:20],
                "js_bundles_scanned": checked_js,
            },
            "files": {
                "js_files": len(js_files),
                "assets": len(assets),
                "interesting_files": interesting[:20],
            },
        }

        findings: List[Finding] = []
        fw = ", ".join(brief["frameworks"])
        findings.append(self._f(
            "web", "app_ai_brief",
            f"app brief ready: {fw}; {len(endpoints)} API endpoints; "
            f"{len(auth_urls)} auth pages; {len(js_files)} JS files, "
            f"{len(assets)} assets",
            "appintel", confidence=90,
            evidence={"severity": "low", "brief": brief,
                      "remediation": "Use the AI App Analysis tab to get a "
                                     "full breakdown of this app's structure, "
                                     "API patterns, and what to test next."}))

        if frameworks:
            findings.append(self._f(
                "web", "framework_detected",
                "frameworks: " + ", ".join(sorted(frameworks)),
                "appintel", confidence=85,
                evidence={"severity": "low",
                          "remediation": "Check the framework version for "
                                         "known CVEs."}))
        if auth_urls:
            findings.append(self._f(
                "web", "auth_flow",
                f"{len(auth_urls)} auth-related pages: " +
                ", ".join(sorted(auth_urls)[:8]),
                "appintel", confidence=85,
                evidence={"severity": "low",
                          "remediation": "Test auth flows for rate limiting, "
                                         "enumeration, and session issues."}))
        if api_bases:
            findings.append(self._f(
                "api", "api_pattern",
                "API base paths: " + ", ".join(sorted(api_bases)[:10]),
                "appintel", confidence=85,
                evidence={"severity": "low",
                          "remediation": "Enumerate each API base for "
                                         "undocumented endpoints."}))

        reason = (f"brief built: {fw}, {len(endpoints)} endpoints, "
                  f"{len(auth_urls)} auth pages")
        return self._ok(findings, reason)
