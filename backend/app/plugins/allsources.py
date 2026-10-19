"""All Sources Extractor (native, keyless).

Extract EVERYTHING publicly visible from the target:
- all JS files (URLs published to the discovery bus for jsdeep)
- all CSS files
- all images (listed, not downloaded)
- linked documents (PDF, DOC, XLS, PPT, TXT, CSV, XML)
- all API responses seen (fetch/XHR URLs in HTML)
- inline <script> and <style> blocks (counted + secrets-shaped strings flagged)
- HTML comments (flag interesting ones: TODO, FIXME, credentials, paths)
- meta tags and structured data (JSON-LD / microdata)

GET only. Passive-safe. Bounded under the 30s ceiling.
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
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_PAGES = 60
CONCURRENCY = 12
TIME_BUDGET = 28

TAG_RE = {
    "js": re.compile(r'<script[^>]+src\s*=\s*["\']([^"\'>\s]+)["\']', re.I),
    "css": re.compile(
        r'<link[^>]+rel\s*=\s*["\']stylesheet["\'][^>]*href\s*=\s*["\']([^"\'>\s]+)["\']'
        r'|<link[^>]+href\s*=\s*["\']([^"\'>\s]+\.css[^"\'>\s]*)["\']', re.I),
    "img": re.compile(r'<img[^>]+src\s*=\s*["\']([^"\'>\s]+)["\']', re.I),
    "doc": re.compile(
        r'''(?:href|src)\s*=\s*["']([^"'>\s]+\.(?:pdf|docx?|xlsx?|pptx?|txt|csv|xml|json|log)[^"'>\s]*)["']''',
        re.I),
    "a": re.compile(r'<a[^>]+href\s*=\s*["\']([^"\'>\s]+)["\']', re.I),
    "font": re.compile(
        r'''(?:href|src)\s*=\s*["']([^"'>\s]+\.(?:woff2?|ttf|otf|eot)[^"'>\s]*)["']'''
        r'''|url\(\s*["']?([^"')\s]+\.(?:woff2?|ttf|otf|eot)[^"')\s]*)''', re.I),
    "sitemap_url": re.compile(r'<loc>([^<]+)</loc>'),
}
COMMENT_RE = re.compile(r'<!--(.*?)-->', re.S)
META_RE = re.compile(
    r'<meta\s+(?:name|property)\s*=\s*["\']([^"\']+)["\'][^>]*content\s*=\s*["\']([^"\']{0,200})["\']',
    re.I)
JSONLD_RE = re.compile(
    r'<script[^>]+type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.I | re.S)
INLINE_JS_RE = re.compile(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', re.I | re.S)
INLINE_CSS_RE = re.compile(r'<style[^>]*>(.*?)</style>', re.I | re.S)
XHR_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post)|XMLHttpRequest|\.ajax)\s*\(\s*["'`]([^"'`]{1,200})["'`]''')

INTERESTING_COMMENT_RE = re.compile(
    r'todo|fixme|hack|xxx|password|passwd|secret|key\s*[:=]|admin|debug|'
    r'internal|staging|dev\.|localhost|\.env|backup|private',
    re.I)
SECRETISH_RE = re.compile(
    r'''(?:api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*["']?([\w\-./]{8,64})''',
    re.I)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _same_site(url: str, domain: str) -> bool:
    h = _host(url)
    return h == domain or h.endswith("." + domain)


class AllSourcesPlugin(Plugin):
    id = "allsources"
    label = "All Sources"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Extract every public source: JS, CSS, images, docs, "
                   "inline code, comments, meta, JSON-LD.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        seen: Set[str] = set()
        queue = [base]
        # seed from sitemap.xml so deep pages are found fast
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            urljoin(base, "sitemap.xml"),
                            timeout=8, max_retries=0)
            if r.status_code == 200:
                for m in TAG_RE["sitemap_url"].finditer(r.text[:200000]):
                    u = m.group(1).strip()
                    if u.startswith(("http://", "https://")) and \
                            _same_site(u, domain) and u not in seen:
                        seen.add(u)
                        queue.append(u)
        except Exception:
            pass
        js: Set[str] = set()
        css: Set[str] = set()
        imgs: Set[str] = set()
        fonts: Set[str] = set()
        docs: Set[str] = set()
        xhrs: Set[str] = set()
        comments: List[str] = []
        metas: Dict[str, str] = {}
        jsonld_types: Set[str] = set()
        inline_js_bytes = 0
        inline_css_bytes = 0
        pages = 0
        sem = asyncio.Semaphore(CONCURRENCY)

        async def grab(url: str):
            async with sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                    timeout=10, follow_redirects=True,
                                    max_retries=0)
                    if r.status_code == 200 and "text/html" in \
                            r.headers.get("content-type", ""):
                        return str(r.url), r.text[:300000]
                except Exception:
                    pass
            return None, None

        while queue and pages < MAX_PAGES and (time.monotonic() - t0) < TIME_BUDGET:
            batch = [u for u in queue[:CONCURRENCY]]
            queue = queue[CONCURRENCY:]
            results = await asyncio.gather(*[grab(u) for u in batch])
            for req_url, (final, html) in zip(batch, results):
                if not html:
                    continue
                pages += 1
                for m in TAG_RE["js"].finditer(html):
                    u = urljoin(final, m.group(1).strip())
                    if u.startswith(("http://", "https://")):
                        js.add(u)
                        if _same_site(u, domain):
                            ctx.publish("js", u)
                for m in TAG_RE["css"].finditer(html):
                    u = urljoin(final, m.group(2) or m.group(1) or "").strip()
                    if u.startswith(("http://", "https://")):
                        css.add(u)
                        ctx.publish("assets", u)
                for m in TAG_RE["img"].finditer(html):
                    u = urljoin(final, m.group(1).strip())
                    if u.startswith(("http://", "https://")):
                        imgs.add(u)
                        ctx.publish("assets", u)
                for m in TAG_RE["doc"].finditer(html):
                    u = urljoin(final, m.group(1).strip())
                    if u.startswith(("http://", "https://")):
                        docs.add(u)
                        ctx.publish("assets", u)
                for m in TAG_RE["font"].finditer(html):
                    u = urljoin(final, (m.group(1) or m.group(2) or "").strip())
                    if u.startswith(("http://", "https://")):
                        fonts.add(u)
                        ctx.publish("assets", u)
                for m in XHR_RE.finditer(html):
                    ep = m.group(1).strip()
                    if ep.startswith("/"):
                        ep = urljoin(final, ep)
                    if ep.startswith(("http://", "https://")):
                        xhrs.add(ep)
                        ctx.publish("endpoints", ep)
                for m in INLINE_JS_RE.finditer(html):
                    inline_js_bytes += len(m.group(1))
                    for s in SECRETISH_RE.finditer(m.group(1)[:50000]):
                        ctx.publish("secrets", s.group(0)[:120])
                for m in INLINE_CSS_RE.finditer(html):
                    inline_css_bytes += len(m.group(1))
                for m in COMMENT_RE.finditer(html):
                    c = m.group(1).strip()
                    if c and INTERESTING_COMMENT_RE.search(c):
                        comments.append(c[:300])
                for m in META_RE.finditer(html):
                    metas[m.group(1).lower()[:60]] = m.group(2)[:120]
                for m in JSONLD_RE.finditer(html):
                    t = re.search(r'"@type"\s*:\s*"([^"]+)"', m.group(1))
                    if t:
                        jsonld_types.add(t.group(1)[:60])
                if pages + len(queue) < MAX_PAGES:
                    for m in TAG_RE["a"].finditer(html):
                        u = urljoin(final, m.group(1).strip())
                        if u.startswith(("http://", "https://")) and \
                                _same_site(u, domain) and u not in seen:
                            seen.add(u)
                            queue.append(u)
            seen.update(batch)

        findings: List[Finding] = []
        counts = {
            "js_files": len(js), "css_files": len(css), "images": len(imgs),
            "fonts": len(fonts), "documents": len(docs),
            "api_calls_seen": len(xhrs),
            "interesting_comments": len(comments),
            "inline_js_bytes": inline_js_bytes,
            "inline_css_bytes": inline_css_bytes,
        }
        findings.append(self._f(
            "web", "source_inventory",
            f"{pages} pages crawled: {len(js)} JS, {len(css)} CSS, "
            f"{len(imgs)} images, {len(fonts)} fonts, {len(docs)} documents, "
            f"{len(xhrs)} API calls",
            "allsources", confidence=95,
            evidence={"severity": "low", "counts": counts,
                      "remediation": "Review the full source inventory for "
                                     "unintended exposures."}))

        for u in sorted(js)[:80]:
            findings.append(self._f(
                "web", "js_file", u, "allsources", source_url=u,
                confidence=90,
                evidence={"severity": "low", "first_party": _same_site(u, domain),
                          "remediation": "Audit JS bundles for secrets and "
                                         "internal endpoints."}))
        for u in sorted(css)[:40]:
            findings.append(self._f(
                "web", "css_file", u, "allsources", source_url=u,
                confidence=90,
                evidence={"severity": "low", "first_party": _same_site(u, domain),
                          "remediation": "CSS rarely leaks secrets but can "
                                         "reveal internal paths."}))
        for u in sorted(fonts)[:30]:
            findings.append(self._f(
                "web", "font_file", u, "allsources", source_url=u,
                confidence=90,
                evidence={"severity": "low", "first_party": _same_site(u, domain),
                          "remediation": "Fonts are public assets; included "
                                         "for complete inventory."}))
        for u in sorted(docs)[:40]:
            findings.append(self._f(
                "web", "exposed_document", u, "allsources", source_url=u,
                confidence=85,
                evidence={"severity": "medium", "first_party": _same_site(u, domain),
                          "remediation": "Verify linked documents contain no "
                                         "sensitive data."}))
        for u in sorted(xhrs)[:40]:
            findings.append(self._f(
                "api", "client_api_call", u, "allsources", source_url=u,
                confidence=80,
                evidence={"severity": "low",
                          "remediation": "Map and test client-side API calls "
                                         "for auth gaps."}))
        for c in comments[:15]:
            findings.append(self._f(
                "web", "interesting_comment", c, "allsources", confidence=75,
                evidence={"severity": "low",
                          "remediation": "Strip dev comments from production "
                                         "HTML."}))
        if metas:
            findings.append(self._f(
                "web", "meta_tags",
                f"{len(metas)} meta tags: " + ", ".join(sorted(metas)[:12]),
                "allsources", confidence=95,
                evidence={"severity": "low", "meta": dict(list(metas.items())[:20]),
                          "remediation": "Meta tags are public by design; "
                                         "ensure none leak internals."}))
        if jsonld_types:
            findings.append(self._f(
                "web", "structured_data",
                "JSON-LD types: " + ", ".join(sorted(jsonld_types)),
                "allsources", confidence=95,
                evidence={"severity": "low",
                          "remediation": "Structured data is public; verify "
                                         "it reveals nothing sensitive."}))
        if inline_js_bytes:
            findings.append(self._f(
                "web", "inline_script",
                f"{inline_js_bytes} bytes of inline JavaScript across pages",
                "allsources", confidence=90,
                evidence={"severity": "low",
                          "remediation": "Inline scripts bypass CSP nonces; "
                                         "move to external bundles where "
                                         "possible."}))

        reason = (f"crawled {pages} pages, found {len(js)} JS / {len(css)} CSS / "
                  f"{len(imgs)} images / {len(fonts)} fonts / {len(docs)} docs / "
                  f"{len(xhrs)} API calls")
        return self._ok(findings, reason)
