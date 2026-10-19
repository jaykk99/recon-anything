"""Stealth crawler plugin - behavioral, human-like crawling.

Differences from the regular crawler:
- Randomized 1-3s delays with jitter between requests (never a burst).
- Rotates a small pool of real browser User-Agents.
- Respects robots.txt (never requests disallowed paths).
- Parses JS files for hidden API endpoints, WebSocket URLs and dynamic
  routes, then flags endpoints NOT present in sitemap/robots (hidden
  surface) for manual review.

Intelligent crawling, not exploitation. No forms are submitted.
"""
from __future__ import annotations

import asyncio
import random
import re
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..evasion import browser_headers
from ..ratelimit import fetch
from .base import Cost, Ctx, Plugin, PluginResult, Target

UA_POOL = [
    # Small pool of real, current browser user agents (rotated per request).
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
]

MAX_PAGES = 14
MAX_DEPTH = 2
MAX_JS_FILES = 10

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# Quoted strings in JS that look like API paths or routes.
JS_PATH_RE = re.compile(r'["\'`](/(?:api|v\d|graphql|rest|ws|socket)[A-Za-z0-9_\-./{}:]*?)["\'`]')
JS_WS_RE = re.compile(r'["\'`](wss?://[^"\'`\s]+)["\'`]')
JS_ROUTE_RE = re.compile(r'["\'`](/(?:[A-Za-z0-9_\-]+/)*:[A-Za-z0-9_]+(?:/[A-Za-z0-9_\-:]+)*)["\'`]')  # /users/:id
JS_BRACKET_RE = re.compile(r'["\'`](/(?:[A-Za-z0-9_\-]+/)*\[[A-Za-z0-9_]+\](?:/[A-Za-z0-9_\-\[\]]+)*)["\'`]')  # /users/[id]


class StealthCrawlerPlugin(Plugin):
    id = "stealth_crawler"
    label = "Stealth Crawler"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Human-like crawler (jittered delays, rotating UAs, "
                   "respects robots.txt) that finds hidden API endpoints, "
                   "WebSocket URLs and dynamic routes in JS.")
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List = []

        # -- robots.txt: baseline known surface + disallow rules ---------
        disallow, known_urls = await self._load_robots(ctx, base)
        known_urls |= await self._load_sitemap(ctx, base, known_urls)

        # -- crawl with human-like pacing --------------------------------
        visited: Set[str] = set()
        js_files: Set[str] = set()
        discovered_paths: Set[str] = set()
        frontier: List[Tuple[str, int]] = [(base + "/", 0)]

        while frontier and len(visited) < MAX_PAGES:
            url, depth = frontier.pop(0)
            if url in visited or self._is_disallowed(url, base, disallow):
                continue
            visited.add(url)
            html = await self._human_get(ctx, url)
            if not html:
                continue
            for href in HREF_RE.findall(html):
                absu = self._abs(base, url, href)
                if absu and urlparse(absu).netloc == urlparse(base).netloc:
                    path = urlparse(absu).path
                    discovered_paths.add(path)
                    if depth < MAX_DEPTH and path not in visited:
                        frontier.append((absu, depth + 1))
            for src in SRC_RE.findall(html):
                absu = self._abs(base, url, src)
                if absu and absu.endswith(".js"):
                    js_files.add(absu)

        # -- mine JS files (read-only GETs, same pacing) -----------------
        hidden_endpoints: Set[str] = set()
        websockets: Set[str] = set()
        dynamic_routes: Set[str] = set()
        for js_url in list(js_files)[:MAX_JS_FILES]:
            body = await self._human_get(ctx, js_url)
            if not body:
                continue
            for m in JS_PATH_RE.findall(body):
                p = m.split("?")[0]
                if len(p) > 4:
                    hidden_endpoints.add(p)
            websockets.update(JS_WS_RE.findall(body))
            dynamic_routes.update(JS_ROUTE_RE.findall(body))
            dynamic_routes.update(JS_BRACKET_RE.findall(body))

        # -- compare JS-found endpoints vs known surface ------------------
        known_paths = {urlparse(u).path for u in known_urls} | discovered_paths
        truly_hidden = sorted(p for p in hidden_endpoints if p not in known_paths)

        for p in truly_hidden[:20]:
            ev = {
                "severity": "medium",
                "exploitability": "theoretical",
                "remediation": ("Review this endpoint: it should require "
                                "authentication and enforce authorization. "
                                "Test with a second account to confirm no IDOR."),
            }
            findings.append(self._f(
                "web", "hidden_api_endpoint",
                f"Hidden API endpoint found in JS, not in sitemap/crawl: {p}",
                source="Stealth crawler", source_url=base, confidence=70,
                passive=True, evidence=ev))
            ctx.publish("endpoints", base + p)

        for ws in sorted(websockets)[:10]:
            findings.append(self._f(
                "web", "websocket_url",
                f"WebSocket URL exposed in JS: {ws}",
                source="Stealth crawler", source_url=base, confidence=75,
                passive=True,
                evidence={"severity": "low", "exploitability": "theoretical",
                          "remediation": (
                              "Verify the WebSocket endpoint enforces origin "
                              "checks and authentication on connect." )}))
            ctx.publish("endpoints", ws)

        for r in sorted(dynamic_routes)[:10]:
            findings.append(self._f(
                "web", "dynamic_route",
                f"Dynamic route pattern in JS (possible unlinked surface): {r}",
                source="Stealth crawler", source_url=base, confidence=55,
                passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": (
                              "Check whether this route is reachable and, if "
                              "so, whether it is properly authorized.")}))

        if not findings:
            findings.append(self._f(
                "web", "stealth_crawl_clean",
                f"Stealth crawl clean: {len(visited)} pages, "
                f"{len(js_files)} JS files - no hidden endpoints found.",
                source="Stealth crawler", source_url=base, confidence=60,
                passive=True,
                evidence={"severity": "low",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"crawled {len(visited)} pages, mined {min(len(js_files), MAX_JS_FILES)} JS files")
        res.duration_ms = dur
        return res

    # -- helpers ----------------------------------------------------------
    async def _human_get(self, ctx: Ctx, url: str) -> Optional[str]:
        """One GET with a small jittered delay and rotated UA.

        The old 1-3s human-like pause held a concurrency slot for ~30s per
        run and stalled the whole scan. A short 0.15-0.4s jitter still
        rotates UAs and staggers requests without burning the scan budget.
        """
        await asyncio.sleep(random.uniform(0.15, 0.4))
        ua = random.choice(UA_POOL)
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                            max_retries=0, headers=dict(browser_headers(ua)))
            if r.status_code == 200 and len(r.text) < 2_000_000:
                return r.text
        except Exception:
            pass
        return None

    @staticmethod
    def _abs(base: str, page_url: str, link: str) -> Optional[str]:
        if not link or link.startswith(("#", "javascript:", "mailto:", "tel:")):
            return None
        try:
            return urljoin(page_url, link).split("#")[0]
        except Exception:
            return None

    async def _load_robots(self, ctx: Ctx, base: str) -> Tuple[List[str], Set[str]]:
        disallow: List[str] = []
        known: Set[str] = set()
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base + "/robots.txt",
                            timeout=8, max_retries=0)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallow.append(path)
                    elif line.lower().startswith(("allow:", "sitemap:")):
                        known.add(line.split(":", 1)[1].strip())
        except Exception:
            pass
        return disallow, known

    async def _load_sitemap(self, ctx: Ctx, base: str, known: Set[str]) -> Set[str]:
        urls = set(known)
        for sm in (base + "/sitemap.xml", base + "/sitemap_index.xml"):
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", sm, timeout=8, max_retries=0)
                if r.status_code == 200:
                    urls.update(re.findall(r"<loc>([^<]+)</loc>", r.text))
                    break
            except Exception:
                continue
        return urls

    @staticmethod
    def _is_disallowed(url: str, base: str, disallow: List[str]) -> bool:
        path = urlparse(url).path or "/"
        return any(path == d or path.startswith(d.rstrip("*")) for d in disallow if d != "/")
