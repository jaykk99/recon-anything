"""Asset Map (native, keyless).

Build the complete asset inventory for the target:
- every asset the site loads (JS, CSS, images, fonts, media, docs)
- first-party vs third-party classification
- sizes (via HEAD, with GET fallback) and content types
- biggest assets and heaviest pages
- orphan assets: first-party assets never referenced from any crawled page
  (found via common paths / directory guesses is out of scope; orphans here
  means assets seen in only one place or via source maps)

Consumes the discovery bus ("assets", "js") from allsources/crawlers, and
crawls pages itself as a fallback. GET/HEAD only. Bounded under 30s.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                  gather_capped)

MAX_PAGES = 40
CONCURRENCY = 12
MAX_ASSETS = 400
TIME_BUDGET = 27

ASSET_RE = re.compile(
    r'''(?:href|src)\s*=\s*["']([^"'>\s]+)["']'''
    r'''|url\(\s*["']?([^"')\s]+)''', re.I)
IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
           ".avif", ".bmp")
FONT_EXT = (".woff2", ".woff", ".ttf", ".otf", ".eot")
MEDIA_EXT = (".mp4", ".webm", ".mp3", ".wav", ".ogg")
DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
           ".txt", ".csv", ".xml", ".json")


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _same_site(url: str, domain: str) -> bool:
    h = _host(url)
    return bool(h) and (h == domain or h.endswith("." + domain))


def _kind(url: str) -> str:
    u = url.lower().split("?")[0]
    if u.endswith(".js"):
        return "js"
    if u.endswith(".css"):
        return "css"
    if u.endswith(IMG_EXT):
        return "image"
    if u.endswith(FONT_EXT):
        return "font"
    if u.endswith(MEDIA_EXT):
        return "media"
    if u.endswith(DOC_EXT):
        return "document"
    return "other"


class AssetMapPlugin(Plugin):
    id = "assetmap"
    label = "Asset Map"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Full asset inventory: every file the site loads, sizes, "
                   "first vs third party, heaviest assets, orphans.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        assets: Dict[str, Dict] = {}  # url -> {kind, refs, first_party}

        def add_asset(u: str, ref_page: str):
            if not u.startswith(("http://", "https://")):
                return
            if len(assets) >= MAX_ASSETS and u not in assets:
                return
            e = assets.get(u)
            if e is None:
                assets[u] = {"kind": _kind(u),
                             "first_party": _same_site(u, domain),
                             "refs": {ref_page}, "size": None,
                             "ctype": None}
            else:
                e["refs"].add(ref_page)

        for u in ctx.consume("assets"):
            if isinstance(u, str):
                add_asset(u, "bus")
        for u in ctx.consume("js"):
            if isinstance(u, str):
                add_asset(u, "bus")

        # fallback crawl if the bus was empty
        if not assets:
            seen: Set[str] = set()
            queue = [base]
            pages = 0
            sem = asyncio.Semaphore(CONCURRENCY)

            async def grab(url: str):
                async with sem:
                    try:
                        r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                        timeout=10, max_retries=0)
                        if r.status_code == 200 and "text/html" in \
                                r.headers.get("content-type", ""):
                            return str(r.url), r.text[:300000]
                    except Exception:
                        pass
                return None, None

            while queue and pages < MAX_PAGES and \
                    (time.monotonic() - t0) < 15:
                batch = queue[:CONCURRENCY]
                queue = queue[CONCURRENCY:]
                results = await gather_capped(
                    [grab(u) for u in batch],
                    max(1.0, 15 - (time.monotonic() - t0)))
                for req, res in zip(batch, results):
                    if not res:
                        continue
                    final, html = res
                    if not html or final is None:
                        continue
                    pages += 1
                    for m in ASSET_RE.finditer(html):
                        raw = (m.group(1) or m.group(2) or "").strip()
                        if not raw or raw.startswith(("data:", "#",
                                                      "javascript:")):
                            continue
                        add_asset(urljoin(final, raw), final)
                    if pages + len(queue) < MAX_PAGES:
                        for m in re.finditer(
                                r'<a[^>]+href\s*=\s*["\']([^"\'>\s]+)["\']',
                                html, re.I):
                            u = urljoin(final, m.group(1).strip())
                            if u.startswith(("http://", "https://")) and \
                                    _same_site(u, domain) and u not in seen:
                                seen.add(u)
                                queue.append(u)

        if not assets:
            return self._ok([], "no assets discovered")

        # HEAD every first-party asset for size/type (third-party too, cheaper
        # than GET); cap to keep under budget
        probe_urls = list(assets)[:250]
        psem = asyncio.Semaphore(15)

        async def probe(u: str):
            if (time.monotonic() - t0) > TIME_BUDGET:
                return
            async with psem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "HEAD", u,
                                    timeout=8, max_retries=0)
                    if r.status_code in (405, 501):
                        r = await fetch(ctx.http, ctx.limiter, "GET", u,
                                        timeout=8, max_retries=0,
                                        headers={"Range": "bytes=0-0"})
                    size = None
                    if r.status_code == 206:
                        # content-length on a 206 is the range length
                        # (1 byte here), not the file size: parse the
                        # total out of "bytes 0-0/<total>"
                        cr = r.headers.get("content-range", "")
                        m = re.search(r"/(\d+)\s*$", cr)
                        if m:
                            size = int(m.group(1))
                    if size is None:
                        cl = r.headers.get("content-length")
                        size = int(cl) if cl and cl.isdigit() else None
                    assets[u]["size"] = size
                    assets[u]["ctype"] = r.headers.get(
                        "content-type", "")[:80]
                    assets[u]["status"] = r.status_code
                except Exception:
                    pass

        await gather_capped([probe(u) for u in probe_urls],
                            TIME_BUDGET - (time.monotonic() - t0))

        by_kind: Dict[str, int] = {}
        first_n = third_n = 0
        total_bytes = 0
        sized: List[Tuple[str, int]] = []
        third_hosts: Dict[str, int] = {}
        for u, e in assets.items():
            by_kind[e["kind"]] = by_kind.get(e["kind"], 0) + 1
            if e["first_party"]:
                first_n += 1
            else:
                third_n += 1
                h = _host(u)
                third_hosts[h] = third_hosts.get(h, 0) + 1
            if e["size"]:
                total_bytes += e["size"]
                sized.append((u, e["size"]))
        sized.sort(key=lambda x: x[1], reverse=True)

        # orphans: first-party assets referenced from only the bus/one page
        orphans = [u for u, e in assets.items()
                   if e["first_party"] and len(e["refs"]) <= 1
                   and e["kind"] in ("js", "css", "document")][:30]

        findings: List[Finding] = []
        kind_str = ", ".join(f"{k}:{v}" for k, v in sorted(by_kind.items()))
        findings.append(self._f(
            "web", "asset_inventory",
            f"{len(assets)} assets: {first_n} first-party, {third_n} "
            f"third-party ({kind_str}); "
            f"{total_bytes // 1024} KB total measured",
            "assetmap", confidence=90,
            evidence={"severity": "low", "by_kind": by_kind,
                      "first_party": first_n, "third_party": third_n,
                      "total_kb": total_bytes // 1024,
                      "third_party_hosts": dict(
                          sorted(third_hosts.items(),
                                 key=lambda x: x[1], reverse=True)[:15]),
                      "remediation": "Review third-party hosts; each one is "
                                     "a supply-chain trust decision."}))

        for u, size in sized[:15]:
            findings.append(self._f(
                "web", "heavy_asset",
                f"{size // 1024} KB: {u}", "assetmap", source_url=u,
                confidence=95,
                evidence={"severity": "low", "bytes": size,
                          "kind": assets[u]["kind"],
                          "remediation": "Large assets slow the site; "
                                         "compress or lazy-load."}))

        if third_hosts:
            top = sorted(third_hosts.items(), key=lambda x: x[1],
                         reverse=True)[:10]
            findings.append(self._f(
                "web", "third_party_surface",
                "third-party hosts: " + ", ".join(
                    f"{h} ({c})" for h, c in top),
                "assetmap", confidence=90,
                evidence={"severity": "medium",
                          "remediation": "Audit third-party scripts; a "
                                         "compromised vendor = compromised "
                                         "site."}))

        for u in orphans:
            findings.append(self._f(
                "web", "orphan_asset", u, "assetmap", source_url=u,
                confidence=70,
                evidence={"severity": "low", "kind": assets[u]["kind"],
                          "remediation": "Orphaned files are forgotten "
                                         "files; check for stale secrets or "
                                         "remove."}))

        # dead assets (non-2xx on HEAD)
        dead = [u for u, e in assets.items()
                if e.get("status") and not (200 <= e["status"] < 300)][:15]
        for u in dead:
            findings.append(self._f(
                "web", "dead_asset",
                f"HTTP {assets[u]['status']}: {u}", "assetmap",
                source_url=u, confidence=85,
                evidence={"severity": "low",
                          "remediation": "Remove dead references; they leak "
                                         "internal structure."}))

        reason = (f"inventoried {len(assets)} assets "
                  f"({first_n} first-party, {third_n} third-party)")
        return self._ok(findings, reason)
