"""DevTools-equivalent page analyzer (native, keyless).

For any URL, analyzes what browser DevTools would show: page
structure (forms, inputs, iframes, meta), network surface (all
subresource requests the page makes), console-error hints (broken
refs, JS errors visible in markup), and performance basics (page
weight, resource count, render-blocking resources).

GET only. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded

FORM_RE = re.compile(r'''<form\b([^>]*)>''', re.I)
INPUT_RE = re.compile(r'''<input\b([^>]*)>''', re.I)
IFRAME_RE = re.compile(r'''<iframe\b[^>]*src\s*=\s*["']([^"']+)["']''', re.I)
META_RE = re.compile(
    r'''<meta\b[^>]*name\s*=\s*["']([^"']+)["'][^>]*content\s*=\s*["']([^"']*)["']''',
    re.I)
# same, but content-before-name attribute order (missed before -
# battle-test 2026-10-18)
META_RE_REV = re.compile(
    r'''<meta\b[^>]*content\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']([^"']+)["']''',
    re.I)
RES_RE = re.compile(
    r'''(?:href|src)\s*=\s*["']([^"'\s<>]+)["']''', re.I)
SCRIPT_SRC_RE = re.compile(
    r'''<script\b[^>]*src\s*=\s*["']([^"']+)["']''', re.I)
INLINE_SCRIPT_RE = re.compile(
    r'''<script\b(?![^>]*src=)[^>]*>(.*?)</script>''', re.I | re.S)
LINK_CSS_RE = re.compile(
    r'''<link\b[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']([^"']+)["']''',
    re.I)
ONERROR_RE = re.compile(r'''\bon\w+\s*=\s*["'][^"']{0,200}["']''', re.I)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


class DevtoolsPlugin(Plugin):
    id = "devtools"
    label = "DevTools Analyzer"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("DevTools equivalent: page structure, network "
                   "surface, error hints, performance.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        try:
            # hard wall-clock cap: a trickling server can keep the
            # connection alive past the per-operation timeout
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", base,
                timeout=12, follow_redirects=True, max_retries=0), 20)
            if r is None:
                return self._degraded("fetch timed out (20s wall-clock)")
        except Exception as e:
            return self._degraded(f"could not fetch: {str(e)[:120]}")
        if "text/html" not in r.headers.get("content-type", ""):
            return self._skipped("not an HTML page")

        html = r.text[:500000]
        final = str(r.url)
        findings: List[Finding] = []

        # --- Structure: forms, inputs, iframes, meta ---
        forms = FORM_RE.findall(html)
        inputs = INPUT_RE.findall(html)
        iframes = [urljoin(final, s.strip()) for s in IFRAME_RE.findall(html)]
        metas = META_RE.findall(html) + \
            [(n, c) for c, n in META_RE_REV.findall(html)]
        for i, f in enumerate(forms[:10]):
            act = re.search(r'''action\s*=\s*["']([^"']+)["']''', f, re.I)
            meth = re.search(r'''method\s*=\s*["']([^"']+)["']''', f, re.I)
            findings.append(self._f(
                "web", "form", urljoin(final, act.group(1)) if act else final,
                "devtools", source_url=final, confidence=85,
                evidence={"severity": "low",
                          "method": meth.group(1).upper() if meth else "GET",
                          "form_index": i,
                          "remediation": "Forms are input points; ensure "
                                         "CSRF tokens and server-side "
                                         "validation."},
                passive=True))
            ctx.publish("forms", final)
        for src in iframes[:10]:
            findings.append(self._f(
                "web", "iframe", src,
                "devtools", source_url=src, confidence=80,
                evidence={"severity": "low",
                          "remediation": "Iframes embed third-party content; "
                                         "verify each source is trusted."},
                passive=True))

        # --- Network surface ---
        resources: Set[str] = set()
        for m in RES_RE.finditer(html):
            link = urljoin(final, m.group(1).strip())
            if link.startswith(("http://", "https://")):
                resources.add(link)
        scripts = [urljoin(final, s.strip())
                   for s in SCRIPT_SRC_RE.findall(html)]
        styles = [urljoin(final, s.strip())
                  for s in LINK_CSS_RE.findall(html)]
        render_blocking = len(scripts) + len(styles)
        page_weight = len(r.content)
        third_party = sorted({_host(u) for u in resources
                              if _host(u) and _host(u) != domain
                              and not _host(u).endswith("." + domain)})

        findings.append(self._f(
            "web", "performance", final,
            "devtools", source_url=final, confidence=90,
            evidence={"severity": "low",
                      "page_weight_bytes": page_weight,
                      "resource_count": len(resources),
                      "render_blocking": render_blocking,
                      "third_party_domains": len(third_party),
                      "remediation": "Heavy pages hurt UX and hide bloat; "
                                     "trim unused resources."},
            passive=True))

        # --- Console-error hints ---
        err_hints = 0
        for attr in ONERROR_RE.findall(html):
            err_hints += 1
        for s in INLINE_SCRIPT_RE.findall(html[:50000]):
            if "console.error" in s or "throw new Error" in s:
                err_hints += 1
        if err_hints:
            findings.append(self._f(
                "web", "js_error_hints", final,
                "devtools", source_url=final, confidence=60,
                evidence={"severity": "low",
                          "hint_count": err_hints,
                          "remediation": "JS error handlers can leak debug "
                                         "info; check console output for "
                                         "secrets."},
                passive=True))

        # interesting meta (generator versions etc.)
        for name, content in metas[:20]:
            if name.lower() in ("generator", "version", "author"):
                findings.append(self._f(
                    "web", "meta_info", f"{name}: {content[:80]}",
                    "devtools", source_url=final, confidence=70,
                    evidence={"severity": "low",
                              "remediation": "Meta tags can disclose "
                                             "versions; remove if sensitive."},
                    passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"{len(forms)} forms, {len(inputs)} inputs, {len(iframes)} "
            f"iframes, {len(resources)} resources, {page_weight // 1024}KB, "
            f"{len(third_party)} third-party")
        res.duration_ms = dur
        return res
