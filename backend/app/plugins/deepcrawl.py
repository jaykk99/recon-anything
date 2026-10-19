"""Deep source analysis plugin.

Goes deeper than the standard crawler: follows every link, every JS file,
every API reference. Builds a complete map of the target's surface.
Like having the sitemap the owner never published.
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

MAX_PAGES = 100
MAX_DEPTH = 4
CONCURRENCY = 10

# Patterns that reveal structure
LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.I)
ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.I)
API_CALL_RE = re.compile(r'(?:fetch|axios\.(?:get|post)|XMLHttpRequest|\.ajax)\s*\(\s*["\']([^"\']+)["\']', re.I)
IMPORT_RE = re.compile(r'(?:import|require)\s*\(?\s*["\']([^"\']+)["\']', re.I)
COMMENT_PATH_RE = re.compile(r'<!--.*?((?:/[a-zA-Z0-9_\-.]+){2,}).*?-->', re.S)


class DeepCrawlPlugin(Plugin):
    timeout_s = 30  # capped: 30s per-plugin ceiling (Jay's order 2026-10-18)
    id = "deepcrawl"
    label = "Deep Source Analyzer"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Deep crawl: every link, JS file, API call. Complete surface map."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        seen: Set[str] = set()
        queue = [(base + "/", 0)]
        pages_crawled = 0
        js_files: Set[str] = set()
        api_calls: Set[str] = set()

        async def fetch_page(url: str) -> str:
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url)
                if resp and resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct:
                        return resp.text[:500000]
            except Exception:
                pass
            return ""

        while queue and pages_crawled < MAX_PAGES:
            batch = []
            while queue and len(batch) < CONCURRENCY:
                url, depth = queue.pop(0)
                if url in seen or depth > MAX_DEPTH:
                    continue
                seen.add(url)
                batch.append((url, depth))
            if not batch:
                break
            pages = await asyncio.gather(*[fetch_page(u) for u, _ in batch])
            for (url, depth), html in zip(batch, pages):
                if not html:
                    continue
                pages_crawled += 1
                parsed_base = urlparse(url)
                # Extract all link types
                for pattern in (LINK_RE, SRC_RE, ACTION_RE):
                    for m in pattern.finditer(html):
                        link = m.group(1)
                        if link.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                            continue
                        abs_url = urljoin(url, link)
                        p = urlparse(abs_url)
                        if p.netloc == parsed_base.netloc or not p.netloc:
                            if abs_url.endswith((".js",)):
                                js_files.add(abs_url)
                            elif depth + 1 <= MAX_DEPTH and abs_url not in seen:
                                queue.append((abs_url, depth + 1))
                            ctx.publish("endpoints", abs_url)
                        elif "api" in p.netloc:
                            ctx.publish("endpoints", abs_url)
                # API calls in inline JS
                for m in API_CALL_RE.finditer(html):
                    api_calls.add(m.group(1))
                    ctx.publish("endpoints", urljoin(url, m.group(1)))
                # Imports
                for m in IMPORT_RE.finditer(html):
                    imp = m.group(1)
                    if imp.startswith(("http", "/")):
                        js_files.add(urljoin(url, imp))
                # Comment paths
                for m in COMMENT_PATH_RE.finditer(html):
                    ctx.publish("endpoints", urljoin(url, m.group(1)))

        for js in sorted(js_files)[:50]:
            findings.append(self._f("web", "js_file_deep", js,
                                    f"deepcrawl: JS file found at depth", confidence=75))
            ctx.publish("js_files", js)
        for api in sorted(api_calls)[:50]:
            findings.append(self._f("api", "api_call", api,
                                    "deepcrawl: API call in page JS", confidence=70))

        findings.append(self._f("web", "crawl_summary",
                                f"{pages_crawled} pages crawled to depth {MAX_DEPTH}, "
                                f"{len(js_files)} JS files, {len(api_calls)} API calls",
                                "deepcrawl", confidence=90))
        return self._ok(findings, f"deep crawled {pages_crawled} pages")
