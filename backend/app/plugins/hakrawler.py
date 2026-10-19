"""Hakrawler-style fast crawler (native, keyless).

A quick lightweight spider: from the start page it gathers URLs,
subdomains, and JavaScript files as fast as possible. Smaller and
faster than katana (25 pages, depth 3, high concurrency) - it trades
depth for speed so results stream in early.

GET only. Bounded to keep well under the 30s ceiling.
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
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                  gather_capped)

MAX_PAGES = 25
MAX_DEPTH = 3
CONCURRENCY = 15
LOOP_BUDGET = 24

LINK_RE = re.compile(
    r'''(?:href|src|action)\s*=\s*["']([^"'\s<>]+)["']''', re.I)
JS_RE = re.compile(r'''["'`\s=]([^"'`\s<>]+\.js(?:\?[^"'`\s<>]*)?)["'`\s]''', re.I)
SUB_HINT = re.compile(r'''https?://([\w\-.]+)''', re.I)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


class HakrawlerPlugin(Plugin):
    id = "hakrawler"
    label = "HaKrawler"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Fast lightweight crawl: URLs, subdomains, "
                   "JS files. GET only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        seen: Set[str] = set()
        queue = [(base, 0)]
        pages = 0
        sem = asyncio.Semaphore(CONCURRENCY)
        urls: Set[str] = set()
        subs: Set[str] = set()
        jsfiles: Set[str] = set()

        async def grab(url: str):
            async with sem:
                # ctx.fetch_page: cross-plugin cache + singleflight, so
                # URLs already crawled by another plugin are instant cache
                # hits instead of redundant network fetches.
                page = await ctx.fetch_page(url, timeout=10)
                if page and page["status_code"] == 200 and "text/html" in \
                        page["headers"].get("content-type", ""):
                    return page["url"], page["text"][:200000]
            return None, None

        while queue and pages < MAX_PAGES and \
                (time.monotonic() - t0) < LOOP_BUDGET:
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
            results = await gather_capped(
                [grab(u) for u, _ in batch],
                LOOP_BUDGET - (time.monotonic() - t0))
            for (url, depth), res in zip(batch, results):
                if not res:
                    continue
                final, html = res
                if not html:
                    continue
                pages += 1
                urls.add(final)
                ctx.publish("urls", final)
                host = _host(final)
                if host != domain and host.endswith("." + domain):
                    subs.add(host)
                for m in LINK_RE.finditer(html):
                    link = urljoin(final, m.group(1).strip())
                    if not link.startswith(("http://", "https://")):
                        continue
                    h = _host(link)
                    if h == domain or h.endswith("." + domain):
                        if h != domain:
                            subs.add(h)
                        if link not in seen and not link.lower().endswith(
                                (".png", ".jpg", ".jpeg", ".gif", ".svg",
                                 ".ico", ".woff", ".woff2", ".ttf", ".mp4")):
                            queue.append((link, depth + 1))
                for m in JS_RE.finditer(html):
                    j = urljoin(final, m.group(1).strip())
                    if _host(j) == domain or _host(j).endswith("." + domain):
                        jsfiles.add(j)
                # subdomains mentioned in text, not just in links
                # (SUB_HINT was defined but never used - battle-test
                # 2026-10-18)
                for m in SUB_HINT.finditer(html):
                    h = m.group(1).lower().rstrip(".")
                    if h != domain and h.endswith("." + domain):
                        subs.add(h)

        findings: List[Finding] = []
        for s in sorted(subs)[:60]:
            ctx.publish("subdomains", s)
            findings.append(self._f(
                "dns", "subdomain", s,
                "hakrawler", source_url=f"https://{s}", confidence=75,
                evidence={"severity": "low",
                          "remediation": "Inventory discovered subdomains; "
                                         "decommission or secure unused ones."},
                passive=True))
        for j in sorted(jsfiles)[:60]:
            ctx.publish("js_files", j)
            findings.append(self._f(
                "web", "js_file", j,
                "hakrawler", source_url=j, confidence=75,
                evidence={"severity": "low",
                          "remediation": "Audit JS bundles for leaked keys "
                                         "or internal endpoints."},
                passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{pages} pages in {dur}ms: {len(urls)} URLs, "
                       f"{len(subs)} subdomains, {len(jsfiles)} JS files")
        res.duration_ms = dur
        return res
