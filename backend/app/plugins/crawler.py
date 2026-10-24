"""Site crawler (phase 1, feeds the discovery bus).

Crawls the target 5 levels deep: extracts every link, form action,
script src, stylesheet, and input name; parses sitemap.xml (including
sitemap indexes) for listed URLs; mines CSS url() references, HTML
comments for paths and secrets; collects external resources (CDNs,
APIs, third-party). Everything discovered is published to ctx.shared
so phase-2 chain plugins and vuln probes have maximum input.
Fast: capped pages, concurrent fetches.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .injutil import same_domain
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_PAGES = 50
MAX_DEPTH = 5
CONCURRENCY = 10

COMMENT_SECRET_HINTS = re.compile(
    r"(api[_-]?key|secret|password|token|passwd|aws_|private[_-]?key)",
    re.I)


class CrawlerPlugin(Plugin):
    timeout_s = 90  # raised 2026-10-20: 30s cap truncated this enumerator mid-work (Jay: find more)
    id = "crawler"
    label = "Site Crawler"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "5-level crawl: links, forms, comments, sitemap, CSS, externals."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        seen = set()
        queue = [(base, 0)]
        pages = 0
        sem = asyncio.Semaphore(CONCURRENCY)
        externals = set()
        comment_hits = 0

        async def fetch_page(url: str):
            async with sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                    timeout=15, follow_redirects=True)
                    if r.status_code == 200 and "text/html" in \
                            r.headers.get("content-type", ""):
                        return str(r.url), r.text[:500000]
                except Exception:
                    pass
            return None, None

        while queue and pages < MAX_PAGES:
            batch = []
            while queue and len(batch) < CONCURRENCY and pages + len(batch) < MAX_PAGES:
                url, depth = queue.pop(0)
                if url in seen or depth > MAX_DEPTH:
                    continue
                seen.add(url)
                batch.append((url, depth))
            if not batch:
                break
            results = await asyncio.gather(
                *[fetch_page(u) for u, _ in batch])
            for (url, depth), res in zip(batch, results):
                furl, html = res
                if not html:
                    continue
                pages += 1
                ctx.publish("endpoints", furl or url)

                # links
                for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
                    link = urljoin(furl or url, m.group(1).strip())
                    p = urlparse(link)
                    if p.scheme not in ("http", "https"):
                        continue
                    if p.netloc == domain or p.netloc.endswith("." + domain):
                        if link not in seen and depth < MAX_DEPTH:
                            queue.append((link, depth + 1))
                    else:
                        externals.add(f"{p.scheme}://{p.netloc}")

                # srcset (responsive images often leak CDN paths)
                for m in re.finditer(r'srcset=["\']([^"\']+)["\']', html, re.I):
                    for part in m.group(1).split(","):
                        src_url = part.strip().split(" ")[0]
                        if src_url:
                            link = urljoin(furl or url, src_url)
                            p = urlparse(link)
                            if p.netloc and p.netloc != domain \
                                    and not p.netloc.endswith("." + domain):
                                externals.add(f"{p.scheme}://{p.netloc}")
                            elif link not in seen and depth < MAX_DEPTH:
                                queue.append((link, depth + 1))

                # data-* attributes that hold URLs (lazy-load, API endpoints)
                for m in re.finditer(
                        r'data-(?:src|url|href|api|endpoint)=["\']([^"\']+)["\']',
                        html, re.I):
                    durl = m.group(1).strip()
                    if durl.startswith(("http", "/")):
                        link = urljoin(furl or url, durl)
                        ctx.publish("endpoints", link)

                # meta refresh redirects
                for m in re.finditer(
                        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+'
                        r'content=["\']?[^"\']*url=([^"\';\s]+)',
                        html, re.I):
                    link = urljoin(furl or url, m.group(1).strip())
                    ctx.publish("endpoints", link)
                    if link not in seen and depth < MAX_DEPTH \
                            and domain in urlparse(link).netloc:
                        queue.append((link, depth + 1))

                # canonical / alternate links
                for m in re.finditer(
                        r'<link[^>]+href=["\']([^"\']+)["\']', html, re.I):
                    link = urljoin(furl or url, m.group(1).strip())
                    p = urlparse(link)
                    if p.netloc and p.netloc != domain \
                            and not p.netloc.endswith("." + domain):
                        externals.add(f"{p.scheme}://{p.netloc}")

                # inline JSON-LD / embedded JSON blobs with URLs
                for m in re.finditer(
                        r'"(https?://[a-zA-Z0-9.-]+\.[a-z]{2,24}[^"]*)"',
                        html):
                    ctx.publish("endpoints", m.group(1))

                # scripts -> discovery bus for JS mining chain
                for m in re.finditer(
                        r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                    src = urljoin(furl or url, m.group(1).strip())
                    if same_domain(src, domain) or \
                            urlparse(src).netloc == domain:
                        ctx.publish("js_files", src)
                    else:
                        externals.add(urlparse(src).netloc)

                # stylesheets -> fetch and mine url() references (often leak
                # backend asset paths, upload dirs, API hosts)
                css_urls = []
                for m in re.finditer(
                        r'<link[^>]+rel=["\']stylesheet["\'][^>]+'
                        r'href=["\']([^"\']+)["\']', html, re.I):
                    css_urls.append(urljoin(furl or url, m.group(1).strip()))
                for m in re.finditer(
                        r'<link[^>]+href=["\']([^"\']+\.css(?:\?[^"\']*)?)["\']',
                        html, re.I):
                    css_urls.append(urljoin(furl or url, m.group(1).strip()))
                for css_url in list(dict.fromkeys(css_urls))[:15]:
                    ctx.publish("css_files", css_url)
                    try:
                        cr = await fetch(ctx.http, ctx.limiter, "GET",
                                         css_url, timeout=12)
                        if cr.status_code == 200:
                            css = cr.text[:300000]
                            for um in re.finditer(
                                    r'url\(\s*["\']?([^)"\']+)["\']?\s*\)',
                                    css, re.I):
                                ref = um.group(1).strip()
                                if ref.startswith(("data:", "#")):
                                    continue
                                rlink = urljoin(css_url, ref)
                                p = urlparse(rlink)
                                if p.netloc == domain or \
                                        p.netloc.endswith("." + domain):
                                    ctx.publish("endpoints", rlink)
                                elif p.netloc:
                                    externals.add(
                                        f"{p.scheme}://{p.netloc}")
                            # CSS comments often hold paths/TODOs
                            for ccm in re.finditer(r"/\*(.*?)\*/", css, re.S):
                                ctext = ccm.group(1)
                                for pm in re.finditer(
                                        r"((?:/[a-zA-Z0-9_\-.]+){2,})",
                                        ctext):
                                    ctx.publish(
                                        "endpoints",
                                        urljoin(css_url, pm.group(1)))
                    except Exception:
                        pass

                # forms (with and without action)
                for m in re.finditer(
                        r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I):
                    ctx.publish("endpoints",
                                urljoin(furl or url, m.group(1) or furl or url))
                # forms without action submit to current page
                for m in re.finditer(r'<form(?![^>]*action=)[^>]*>', html, re.I):
                    ctx.publish("endpoints", furl or url)
                # form methods worth noting
                for m in re.finditer(
                        r'<form[^>]+method=["\']([^"\']+)["\'][^>]*'
                        r'action=["\']([^"\']*)["\']',
                        html, re.I):
                    method, action = m.group(1).upper(), m.group(2)
                    if method in ("PUT", "DELETE", "PATCH"):
                        findings.append(self._f(
                            "web", "form_risky_method",
                            f"Form uses {method} on {action or furl or url}",
                            source="form mining", source_url=furl or url,
                            confidence=65))
                for m in re.finditer(
                        r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I):
                    ctx.publish("params", m.group(1))
                # input types that hint at functionality
                for m in re.finditer(
                        r'<input[^>]+type=["\']([^"\']+)["\']', html, re.I):
                    itype = m.group(1).lower()
                    if itype in ("file", "password", "hidden"):
                        ctx.publish("params", f"input_type:{itype}")

                # HTML comments: often contain paths, keys, TODOs
                for cm in re.finditer(r"<!--(.*?)-->", html, re.S):
                    comment = cm.group(1).strip()
                    if len(comment) < 8 or len(comment) > 2000:
                        continue
                    if COMMENT_SECRET_HINTS.search(comment):
                        comment_hits += 1
                        findings.append(self._f(
                            "leak", "comment_secret",
                            f"HIGH: HTML comment mentions secrets/keys on "
                            f"{furl or url}: "
                            f"{comment[:160]}"
                            f"{'...' if len(comment) > 160 else ''}",
                            source="HTML comment mining",
                            source_url=furl or url, confidence=70,
                            evidence={"severity": "high",
                                      "comment": comment[:500]}))

            # Checkpoint after each batch: a 50-page, depth-5 crawl can
            # still outrun the 90s timeout_s (clamped to the scan's
            # remaining budget by the runner, sometimes well under 90s).
            # Every other enumerator in this codebase (dns, subdomains,
            # sqli, git, ...) checkpoints so a mid-run kill keeps what it
            # already found; this crawl used to lose every comment_secret
            # and form_risky_method finding on timeout even after
            # crawling dozens of pages. Cheap: just a list snapshot.
            self._checkpoint(findings)

        # sitemap.xml: crawl every listed URL (cheap, high value).
        # Handles sitemap indexes (nested sitemaps) recursively.
        sitemap_urls = 0

        async def fetch_sitemap(surl: str, depth: int = 0):
            nonlocal sitemap_urls
            if depth > 2:
                return
            try:
                sr = await fetch(ctx.http, ctx.limiter, "GET", surl,
                                 timeout=15)
                if sr.status_code != 200:
                    return
                body = sr.text[:1000000]
                is_index = "<sitemapindex" in body or \
                    re.search(r"<sitemap>", body)
                for m in re.finditer(r"<loc>([^<]+)</loc>", body):
                    loc = m.group(1).strip()
                    if is_index and depth < 2 and \
                            loc.lower().endswith((".xml", ".xml.gz")):
                        await fetch_sitemap(loc, depth + 1)
                    elif domain in urlparse(loc).netloc:
                        ctx.publish("endpoints", loc)
                        sitemap_urls += 1
            except Exception:
                pass

        for spath in ("/sitemap.xml", "/sitemap_index.xml",
                      "/sitemap-index.xml"):
            await fetch_sitemap(f"{base}{spath}")
        if sitemap_urls:
            findings.append(self._f(
                "web", "sitemap",
                f"INFO: sitemap.xml listed {sitemap_urls} URLs, all queued "
                f"for analysis.",
                source="sitemap.xml", confidence=95,
                evidence={"count": sitemap_urls}))

        if externals:
            findings.append(self._f(
                "web", "external_resources",
                f"INFO: {len(externals)} external hosts referenced: "
                f"{', '.join(sorted(externals)[:10])}"
                f"{'...' if len(externals) > 10 else ''}.",
                source="crawl", confidence=85,
                evidence={"hosts": sorted(externals)[:25]}))

        n_endpoints = len(ctx.consume("endpoints"))
        n_js = len(ctx.consume("js_files"))
        n_params = len(ctx.consume("params"))
        findings.append(self._f(
            "web", "crawl_summary",
            f"INFO: crawled {pages} pages, discovered {n_endpoints} "
            f"endpoints, {n_js} JS files, {n_params} parameters.",
            source="crawl", confidence=95,
            evidence={"pages": pages, "endpoints": n_endpoints,
                      "js_files": n_js, "params": n_params}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"crawled {pages} pages, "
                                 f"{comment_hits} secret comments")
        res.duration_ms = dur
        return res
