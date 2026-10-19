"""Katana-style next-gen crawler (native, keyless).

Crawls the target and isolates three asset classes: page URLs, API
endpoints, and JavaScript files. Mines JS bundles for fetch/axios/XHR
calls, WebSocket URLs, and GraphQL endpoints. Everything discovered is
published to the discovery bus so phase-2 chain plugins and vuln
probes have maximum input.

GET only. Bounded: 50 pages, depth 4, 30s ceiling.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_PAGES = 30
MAX_DEPTH = 4
CONCURRENCY = 10

# Link-ish attributes to harvest
HREF_RE = re.compile(
    r'''(?:href|src|action|data-src|data-href)\s*=\s*["']([^"'\s<>]+)["']''', re.I)
# API-shaped paths
API_PATH_RE = re.compile(
    r'''["'`](/(?:api|v\d|v\d\.\d|rest|graphql|gql|ajax|rpc|ws|socket\.io|gateway)[\w\-./{}?=&#%]*?)["'`\s]''',
    re.I)
# JS network calls: fetch("/x"), axios.get('/y'), $.ajax, new WebSocket("wss://..")
JS_CALL_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|\.ajax|new\s+WebSocket)\s*\(\s*["'`]([^"'`]+)["'`]''',
    re.I)
WS_URL_RE = re.compile(r'''(wss?://[\w\-.]+(?::\d+)?[^\s"'`<>]*)''', re.I)
# JS bundle URLs
JS_FILE_RE = re.compile(r'''["'`\s=]([^"'`\s<>]+\.js(?:\?[^"'`\s<>]*)?)["'`\s]''', re.I)

API_EXT_HINTS = (".json", ".xml")
SKIP_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
            ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".pdf")


def _same_host(url: str, domain: str) -> bool:
    try:
        host = urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return False
    return host == domain or host.endswith("." + domain)


class KatanaPlugin(Plugin):
    id = "katana"
    label = "Katana Crawler"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Next-gen crawl: isolate page URLs, API endpoints, "
                   "and JS files. GET only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        findings: List[Finding] = []
        seen: Set[str] = set()
        queue = [(base, 0)]
        pages = 0
        sem = asyncio.Semaphore(CONCURRENCY)
        urls_found: Set[str] = set()
        apis_found: Set[str] = set()
        js_found: Set[str] = set()

        async def fetch_page(url: str):
            async with sem:
                # ctx.fetch_page: cross-plugin cache + singleflight, so
                # URLs already crawled by another plugin are instant cache
                # hits instead of redundant network fetches.
                page = await ctx.fetch_page(url, timeout=12)
                if page and page["status_code"] == 200 and "text/html" in \
                        page["headers"].get("content-type", ""):
                    return page["url"], page["text"][:400000]
            return None, None

        while queue and pages < MAX_PAGES and (time.monotonic() - t0) < 26:
            batch = []
            while queue and len(batch) < CONCURRENCY and \
                    pages + len(batch) < MAX_PAGES:
                url, depth = queue.pop(0)
                if url in seen or depth > MAX_DEPTH:
                    continue
                seen.add(url)
                batch.append((url, depth))
            if not batch:
                break
            results = await asyncio.gather(
                *[fetch_page(u) for u, _ in batch])
            for (url, depth), (final, html) in zip(batch, results):
                if not html:
                    continue
                pages += 1
                urls_found.add(final)
                ctx.publish("urls", final)
                # harvest links
                for m in HREF_RE.finditer(html):
                    link = urljoin(final, m.group(1).strip())
                    if link.startswith(("http://", "https://")) and \
                            _same_host(link, domain):
                        low = link.lower()
                        if not low.endswith(SKIP_EXTS):
                            if link not in seen:
                                queue.append((link, depth + 1))
                # API endpoints from raw text
                for m in API_PATH_RE.finditer(html):
                    p = m.group(1)
                    if len(p) > 3:
                        apis_found.add(urljoin(final, p))
                for m in JS_CALL_RE.finditer(html):
                    p = m.group(1).strip()
                    if p.startswith(("http://", "https://", "ws",
                                     "wss://", "/")):
                        apis_found.add(p if "://" in p
                                       else urljoin(final, p))
                for m in WS_URL_RE.finditer(html):
                    apis_found.add(m.group(1))
                # JS files
                for m in JS_FILE_RE.finditer(html):
                    j = urljoin(final, m.group(1).strip())
                    if _same_host(j, domain):
                        js_found.add(j)

        for u in sorted(urls_found)[:200]:
            ctx.publish("urls", u)
        for a in sorted(apis_found)[:100]:
            ctx.publish("endpoints", a)
            findings.append(self._f(
                "api", "endpoint", a,
                "katana crawl", source_url=a, confidence=75,
                evidence={"severity": "low",
                          "remediation": "Review exposed API endpoints; "
                                         "ensure auth and rate limits."},
                passive=True))
        for j in sorted(js_found)[:100]:
            ctx.publish("js_files", j)
            findings.append(self._f(
                "web", "js_file", j,
                "katana crawl", source_url=j, confidence=80,
                evidence={"severity": "low",
                          "remediation": "Audit JS bundles for leaked keys "
                                         "or internal endpoints."},
                passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"crawled {pages} pages: {len(urls_found)} URLs, "
                       f"{len(apis_found)} API endpoints, {len(js_found)} JS files")
        res.duration_ms = dur
        return res
