"""Wget-style recursive downloader report (native, keyless).

Recursively walks the site like `wget -r -np`: follows internal
links, catalogs every asset discovered (images, stylesheets,
scripts, fonts, media, documents), verifies each is reachable, and
reports the inventory with sizes. Bodies are not stored - only
URLs, content types, and sizes are recorded.

GET only, no writes to the target. Bounded to keep under 30s.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_PAGES = 20
MAX_DEPTH = 2
MAX_ASSETS = 120

ASSET_RE = re.compile(
    r'''(?:href|src|data-src|poster)\s*=\s*["']([^"'\s<>]+)["']''', re.I)

IMG = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp")
CSS = (".css",)
JS = (".js", ".mjs")
FONT = (".woff", ".woff2", ".ttf", ".eot", ".otf")
MEDIA = (".mp4", ".webm", ".mp3", ".wav", ".ogg", ".avi")
DOC = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
       ".txt", ".csv")
JUICY = (".bak", ".old", ".zip", ".tar", ".gz", ".sql", ".env",
         ".log", ".swp", ".git", ".svn", ".map")


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _kind(url: str) -> str:
    low = url.lower().split("?")[0]
    if low.endswith(IMG):
        return "image"
    if low.endswith(CSS):
        return "stylesheet"
    if low.endswith(JS):
        return "script"
    if low.endswith(FONT):
        return "font"
    if low.endswith(MEDIA):
        return "media"
    if low.endswith(DOC):
        return "document"
    if low.endswith(JUICY):
        return "juicy"
    return "other"


class WgetPlugin(Plugin):
    id = "wget"
    label = "Wget Mirror"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Recursive asset inventory (wget -r -np style). "
                   "Reports URLs/types/sizes, stores nothing.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        seen: Set[str] = set()
        queue = [(base, 0)]
        pages = 0
        assets: Dict[str, str] = {}  # url -> kind

        async def grab(url: str):
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                timeout=10, follow_redirects=True,
                                max_retries=1)
                if r.status_code == 200 and "text/html" in \
                        r.headers.get("content-type", ""):
                    return str(r.url), r.text[:200000]
            except Exception:
                pass
            return None, None

        while queue and pages < MAX_PAGES and (time.monotonic() - t0) < 18:
            batch = []
            while queue and len(batch) < 6 and pages + len(batch) < MAX_PAGES:
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
                for m in ASSET_RE.finditer(html):
                    link = urljoin(final, m.group(1).strip())
                    if not link.startswith(("http://", "https://")):
                        continue
                    h = _host(link)
                    if h != domain and not h.endswith("." + domain):
                        continue
                    k = _kind(link)
                    if k == "other":
                        if link not in seen and depth < MAX_DEPTH:
                            queue.append((link, depth + 1))
                        continue
                    if len(assets) < MAX_ASSETS and link not in assets:
                        assets[link] = k

        # Verify assets exist and record sizes (headers only where possible)
        asset_urls = list(assets.keys())[:MAX_ASSETS]
        sizes: Dict[str, int] = {}
        reqs = [("GET", u, {"timeout": 10, "max_retries": 0})
                for u in asset_urls]
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=12)
        for u, r in zip(asset_urls, resps):
            try:
                if r is not None and r.status_code == 200:
                    cl = r.headers.get("content-length")
                    sizes[u] = int(cl) if cl and cl.isdigit() else \
                        min(len(r.content), 2000000)
                else:
                    sizes[u] = -1
            except Exception:
                sizes[u] = -1

        findings: List[Finding] = []
        counts: Dict[str, int] = {}
        total_bytes = 0
        juicy: List[str] = []
        for u, k in assets.items():
            counts[k] = counts.get(k, 0) + 1
            sz = sizes.get(u, -1)
            if sz and sz > 0:
                total_bytes += sz
            if k == "juicy" and sz != -1:
                juicy.append(u)
            ctx.publish("assets", u)
        for u in juicy[:25]:
            findings.append(self._f(
                "web", "exposed_asset", u,
                "wget mirror", source_url=u, confidence=80,
                evidence={"severity": "medium",
                          "size_bytes": sizes.get(u, -1),
                          "remediation": "Backup/config/archive files should "
                                         "not be web-accessible. Remove or "
                                         "restrict them."},
                passive=True))

        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"mirrored {pages} pages, {len(assets)} assets "
            f"({summary}), ~{total_bytes // 1024}KB, {len(juicy)} juicy")
        res.duration_ms = dur
        return res
