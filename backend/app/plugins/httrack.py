"""HTTrack-style website structure mapper (native, keyless).

Maps the full visible structure of a site without downloading
everything: crawls internal links and builds a directory tree
(HTML pages vs images vs assets per directory). Reports the tree,
the biggest sections, and orphan-looking directories that have
assets but no linking pages.

GET only. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_PAGES = 30
MAX_DEPTH = 3
CONCURRENCY = 10

LINK_RE = re.compile(
    r'''(?:href|src|action)\s*=\s*["']([^"'\s<>]+)["']''', re.I)
PAGE_EXT = (".html", ".htm", ".php", ".asp", ".aspx", ".jsp")


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _dir_of(url: str) -> str:
    try:
        p = urlparse(url).path or "/"
        if not p.endswith("/"):
            p = p.rsplit("/", 1)[0] + "/"
        return p or "/"
    except Exception:
        return "/"


def _looks_page(url: str) -> bool:
    low = url.lower().split("?")[0]
    if low.endswith("/") or low.endswith(PAGE_EXT):
        return True
    # extensionless paths are usually pages/routes
    return "." not in low.rsplit("/", 1)[-1]


class HttrackPlugin(Plugin):
    id = "httrack"
    label = "HTTrack Mapper"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Full site structure map: directory tree, section "
                   "sizes, orphan dirs. GET only.")

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
        tree: Dict[str, Dict[str, int]] = {}
        page_dirs: Set[str] = set()

        async def grab(url: str):
            async with sem:
                # ctx.fetch_page: cross-plugin cache + singleflight, so
                # URLs already crawled by another plugin are instant cache
                # hits instead of redundant network fetches.
                page = await ctx.fetch_page(url, timeout=10)
                if page and page["status_code"] == 200 and "text/html" in \
                        page["headers"].get("content-type", ""):
                    return page["url"], page["text"][:150000]
            return None, None

        while queue and pages < MAX_PAGES and (time.monotonic() - t0) < 25:
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
            for (url, depth), (final, html) in zip(
                    batch, await asyncio.gather(
                        *[grab(u) for u, _ in batch])):
                if not html:
                    continue
                pages += 1
                d = _dir_of(final)
                page_dirs.add(d)
                node = tree.setdefault(d, {"pages": 0, "assets": 0})
                node["pages"] += 1
                for m in LINK_RE.finditer(html):
                    link = urljoin(final, m.group(1).strip())
                    if not link.startswith(("http://", "https://")):
                        continue
                    h = _host(link)
                    if h != domain and not h.endswith("." + domain):
                        continue
                    ld = _dir_of(link)
                    lnode = tree.setdefault(ld, {"pages": 0, "assets": 0})
                    if _looks_page(link):
                        if link not in seen and depth < MAX_DEPTH:
                            queue.append((link, depth + 1))
                    else:
                        lnode["assets"] += 1

        # Orphan dirs: asset dirs with no crawled page
        orphans = sorted(d for d in tree
                         if d not in page_dirs and tree[d]["assets"] > 0)

        findings: List[Finding] = []
        top = sorted(tree.items(),
                     key=lambda kv: kv[1]["pages"] + kv[1]["assets"],
                     reverse=True)[:15]
        for d, counts in top:
            findings.append(self._f(
                "web", "site_section", d,
                "httrack mapper",
                source_url=f"https://{domain}{d}", confidence=85,
                evidence={"severity": "low",
                          "pages": counts["pages"],
                          "assets": counts["assets"],
                          "remediation": "Know your full public surface; "
                                         "unused sections should be removed."},
                passive=True))
        for d in orphans[:10]:
            findings.append(self._f(
                "web", "orphan_directory", d,
                "httrack mapper",
                source_url=f"https://{domain}{d}", confidence=65,
                evidence={"severity": "medium",
                          "assets": tree[d]["assets"],
                          "remediation": "Orphan directories often hold "
                                         "forgotten files. Audit and remove "
                                         "what is not needed."},
                passive=True))
            ctx.publish("endpoints", f"https://{domain}{d}")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"mapped {len(tree)} directories across {pages} pages; "
            f"{len(orphans)} orphan dirs",
            )
        res.duration_ms = dur
        return res
