"""Firecrawl-style site mapper (native, keyless).

Builds a comprehensive index of a site's paths and files without any
external API: parses sitemap.xml (including sitemap indexes,
recursively), robots.txt, and combines with a quick shallow crawl.
Reports the full path index, file-type breakdown, and hidden paths
found in sitemaps/robots that are not linked from pages.

GET only. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded

LINK_RE = re.compile(
    r'''(?:href|src|action)\s*=\s*["']([^"'\s<>]+)["']''', re.I)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _filetype(url: str) -> str:
    low = url.lower().split("?")[0].rsplit("/", 1)[-1]
    if "." not in low:
        return "page/route"
    return low.rsplit(".", 1)[-1]


class FirecrawlPlugin(Plugin):
    id = "firecrawl"
    label = "Firecrawl Mapper"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Sitemap + robots + crawl path index. "
                   "Keyless, no external API.")

    async def _sitemap_urls(self, ctx: Ctx, sm_url: str,
                            seen_sm: Set[str]) -> Set[str]:
        """Recursively expand sitemap index -> urls."""
        out: Set[str] = set()
        if sm_url in seen_sm or len(seen_sm) > 10:
            return out
        seen_sm.add(sm_url)
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", sm_url,
                            timeout=12, follow_redirects=True, max_retries=1)
            if r.status_code != 200:
                return out
            root = ET.fromstring(r.text[:1000000])
        except Exception:
            return out
        tag = root.tag.lower()
        ns = ""
        if "}" in root.tag:
            ns = root.tag.split("}")[0] + "}"
        if "sitemapindex" in tag:
            subs = [e.text.strip() for e in
                    root.findall(f".//{ns}sitemap/{ns}loc")
                    if e.text]
            reqs = [("GET", u, {"timeout": 12, "max_retries": 0})
                    for u in subs[:10]]
            for sub, resp in zip(subs[:10],
                                 await fetch_many(ctx.http, ctx.limiter,
                                                  reqs, concurrency=6)):
                if resp is not None and resp.status_code == 200:
                    try:
                        sroot = ET.fromstring(resp.text[:1000000])
                        sns = ""
                        if "}" in sroot.tag:
                            sns = sroot.tag.split("}")[0] + "}"
                        out |= {e.text.strip() for e in
                                sroot.findall(f".//{sns}url/{sns}loc")
                                if e.text}
                    except Exception:
                        continue
        elif "urlset" in tag:
            out |= {e.text.strip() for e in
                    root.findall(f".//{ns}url/{ns}loc") if e.text}
        return out

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        sitemap_urls: Set[str] = set()
        robots_paths: Set[str] = set()
        crawled: Set[str] = set()

        # 1. sitemaps (hard-capped: slow sitemap hosts used to be
        # able to stall this plugin past its ceiling)
        for sm in (f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"):
            try:
                sitemap_urls |= await bounded(
                    self._sitemap_urls(ctx, sm, set()), 18)
            except Exception:
                continue

        # 2. robots.txt
        try:
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", f"{base}/robots.txt",
                timeout=10, max_retries=0), 12)
            if r is not None and r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(
                            ("disallow:", "allow:", "sitemap:")):
                        path = line.split(":", 1)[1].strip()
                        if path.startswith("/"):
                            robots_paths.add(urljoin(base + "/", path))
                        elif path.startswith("http"):
                            robots_paths.add(path)
        except Exception:
            pass

        # 3. quick shallow crawl (12 pages) for linked paths
        queue = [base]
        seen = set()
        while queue and len(crawled) < 12 and (time.monotonic() - t0) < 20:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                r = await bounded(fetch(
                    ctx.http, ctx.limiter, "GET", url,
                    timeout=10, follow_redirects=True, max_retries=0), 12)
                if r is not None and r.status_code == 200 and \
                        "text/html" in r.headers.get("content-type", ""):
                    crawled.add(str(r.url))
                    for m in LINK_RE.finditer(r.text[:150000]):
                        link = urljoin(str(r.url), m.group(1).strip())
                        if link.startswith(("http://", "https://")):
                            h = _host(link)
                            if (h == domain or h.endswith("." + domain)) \
                                    and link not in seen:
                                queue.append(link)
            except Exception:
                continue

        all_paths = sitemap_urls | robots_paths | crawled
        for u in sorted(all_paths):
            ctx.publish("urls", u)

        # Hidden: in sitemap/robots but not linked from crawl
        hidden = sorted((sitemap_urls | robots_paths) - crawled)

        findings: List[Finding] = []
        for u in hidden[:40]:
            findings.append(self._f(
                "web", "unlinked_path", u,
                "firecrawl", source_url=u, confidence=75,
                evidence={"severity": "medium",
                          "in_sitemap": u in sitemap_urls,
                          "in_robots": u in robots_paths,
                          "remediation": "Paths in sitemaps/robots but not "
                                         "linked are often forgotten. Audit "
                                         "or remove them."},
                passive=True))
            ctx.publish("endpoints", u)

        types: Dict[str, int] = {}
        for u in all_paths:
            t = _filetype(u)
            types[t] = types.get(t, 0) + 1
        top_types = ", ".join(f"{v} {k}" for k, v in
                              sorted(types.items(), key=lambda x: -x[1])[:8])

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"index: {len(all_paths)} paths "
            f"(sitemap {len(sitemap_urls)}, robots {len(robots_paths)}, "
            f"crawled {len(crawled)}); {len(hidden)} unlinked; {top_types}")
        res.duration_ms = dur
        return res
