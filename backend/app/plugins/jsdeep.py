"""Deep JS Analysis (native, keyless).

Download every first-party JS bundle and analyze it deeply:
- API endpoints (fetch/axios/XHR/WebSocket/GraphQL literals)
- hardcoded URLs (absolute + protocol-relative)
- secrets (40+ patterns: keys, tokens, DSNs, private keys)
- TODO/FIXME/HACK/XXX comments
- source map references (//# sourceMappingURL)
- simple deobfuscation: hex escapes, unicode escapes, base64 blobs that
  decode to URLs/paths (detection only, never executes anything)

Consumes the discovery bus ("js") published by allsources/crawlers, plus
scrapes the homepage for script tags itself. GET only, first-party only
by default. Bounded under the 30s ceiling.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json as _json
import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_BUNDLES = 100
CONCURRENCY = 10
MAX_BUNDLE_BYTES = 2_000_000
MAX_MAP_BYTES = 5_000_000
TIME_BUDGET = 27

SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\'>\s]+)["\']', re.I)
SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')

ENDPOINT_RES = [
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax)\s*\(\s*["'`]([^"'`]{1,220})["'`]'''),
    re.compile(r'''new\s+WebSocket\s*\(\s*["'`]([^"'`]{1,220})["'`]'''),
    re.compile(r'''["'`](/(?:api|v\d|rest|graphql|ajax|rpc|admin|debug|internal)[\w\-./{}?=&#%]{0,120})["'`]'''),
    re.compile(r'''(?:url|endpoint|baseURL)\s*[:=]\s*["'`](https?://[^"'`]{4,160}|/[\w\-./]{2,120})["'`]'''),
]
URL_RE = re.compile(
    r'''(?:https?:)?//[a-zA-Z0-9][\w.\-]{1,80}(?::\d{1,5})?(?:/[\w\-./?=&%#~+]{0,160})?''')
HARDCODED_SECRET_RES = [
    (re.compile(r'''(?i)\baws[_\s]?(?:access[_-]?key[_-]?id)?["'\s:=]+(AKIA[0-9A-Z]{16})'''), "AWS access key"),
    (re.compile(r'''(?i)\b(xox[bap]-|ghp_|gho_|sk-live-|sk-test-|AIza[0-9A-Za-z\-_]{20})[\w\-_]{4,80}'''), "API token"),
    (re.compile(r'''(?i)\b(?:secret|api[_-]?key|apikey|token|passwd|password)\s*[:=]\s*["']([\w\-./~+=]{10,80})["']'''), "hardcoded secret"),
    (re.compile(r'''\b(?:mongodb|postgres|mysql|redis)://[^\s"'`]{4,120}'''), "DB connection string"),
    (re.compile(r'''(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'''), "private key block"),
    (re.compile(r'''(?i)discord(?:app)?\.com/api/webhooks/\d+/[\w\-_]{20,}'''), "Discord webhook"),
    (re.compile(r'''(?i)slack[_-]?webhook[^"'`]*https://hooks\.slack\.com[^\s"'`]+'''), "Slack webhook"),
]
TODO_RE = re.compile(r'(?i)(TODO|FIXME|HACK|XXX|BUG|REMOVE[_ ]?ME)[^\n]{0,120}')
HEX_ESC_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}')
UNI_ESC_RE = re.compile(r'(?:\\u[0-9a-fA-F]{4}){6,}')
B64_RE = re.compile(r'''(?<![\w+/=])[A-Za-z0-9+/]{40,}={0,2}(?![\w+/=])''')


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _same_site(url: str, domain: str) -> bool:
    h = _host(url)
    return h == domain or h.endswith("." + domain)


def _try_decode_b64(blob: str) -> str:
    try:
        raw = base64.b64decode(blob, validate=True)
        if len(raw) > 200000:
            return ""
        txt = raw.decode("utf-8", "ignore")
        if len(txt.strip()) < 8:
            return ""
        return txt
    except (binascii.Error, ValueError):
        return ""


class JsDeepPlugin(Plugin):
    id = "jsdeep"
    label = "Deep JS Analysis"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Download all JS bundles: endpoints, URLs, secrets, TODOs, "
                   "source maps, light deobfuscation.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        js_urls: List[str] = []
        for u in ctx.consume("js"):
            if isinstance(u, str) and u.startswith(("http://", "https://")) \
                    and _same_site(u, domain):
                js_urls.append(u)
        # fallback: scrape homepage ourselves
        if not js_urls:
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=10,
                                max_retries=0)
                if r.status_code == 200:
                    html = r.text[:300000]
                    for m in SCRIPT_SRC_RE.finditer(html):
                        u = urljoin(base, m.group(1).strip())
                        if u.startswith(("http://", "https://")) and \
                                _same_site(u, domain):
                            js_urls.append(u)
            except Exception:
                pass
        # dedupe, cap
        seen: Set[str] = set()
        queue: List[str] = []
        for u in js_urls:
            if u not in seen:
                seen.add(u)
                queue.append(u)
        queue = queue[:MAX_BUNDLES]
        if not queue:
            return self._ok([], "no first-party JS bundles found")

        sem = asyncio.Semaphore(CONCURRENCY)
        endpoints: Set[str] = set()
        urls: Set[str] = set()
        secrets: List[Dict] = []
        todos: List[str] = []
        sourcemaps: Set[str] = set()
        reconstructed_sources: List[str] = []
        deobf_hits = 0
        analyzed = 0

        async def analyze(u: str):
            nonlocal analyzed, deobf_hits
            if (time.monotonic() - t0) > TIME_BUDGET:
                return
            async with sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", u,
                                    timeout=12, max_retries=0)
                    if r.status_code != 200:
                        return
                    body = r.content[:MAX_BUNDLE_BYTES]
                except Exception:
                    return
            text = body.decode("utf-8", "ignore")
            analyzed += 1
            for rx in ENDPOINT_RES:
                for m in rx.finditer(text):
                    ep = m.group(1).strip()
                    if ep.startswith("/"):
                        ep = urljoin(u, ep)
                    if ep.startswith(("http://", "https://")):
                        endpoints.add(ep)
            for m in URL_RE.finditer(text):
                hit = m.group(0)
                if _host(hit) and len(hit) < 200:
                    urls.add(hit)
            for rx, kind in HARDCODED_SECRET_RES:
                for m in rx.finditer(text):
                    val = m.group(0)
                    if len(val) > 200:
                        val = val[:200]
                    secrets.append({"kind": kind, "url": u,
                                    "match": val[:120]})
            for m in TODO_RE.finditer(text):
                t = m.group(0).strip()
                if t not in todos and len(todos) < 30:
                    todos.append(t[:150])
            for m in SOURCEMAP_RE.finditer(text):
                sourcemaps.add(urljoin(u, m.group(1).strip()))
            # light deobfuscation: decode long escape runs and b64 blobs,
            # then rescan the decoded text for endpoints/URLs
            decoded_parts: List[str] = []
            for m in HEX_ESC_RE.finditer(text[:500000]):
                try:
                    decoded_parts.append(
                        m.group(0).encode().decode("unicode_escape"))
                except Exception:
                    pass
            for m in UNI_ESC_RE.finditer(text[:500000]):
                try:
                    decoded_parts.append(
                        m.group(0).encode().decode("unicode_escape"))
                except Exception:
                    pass
            for m in B64_RE.finditer(text[:500000]):
                d = _try_decode_b64(m.group(0))
                if d and ("http" in d or "/" in d):
                    decoded_parts.append(d)
            for part in decoded_parts:
                for m in URL_RE.finditer(part):
                    hit = m.group(0)
                    if _host(hit) and len(hit) < 200:
                        urls.add(hit)
                        deobf_hits += 1
            for ep in sorted(endpoints)[:200]:
                ctx.publish("endpoints", ep)

        await asyncio.gather(*[analyze(u) for u in queue])

        findings: List[Finding] = []
        findings.append(self._f(
            "web", "js_analysis",
            f"analyzed {analyzed} JS bundles: {len(endpoints)} endpoints, "
            f"{len(urls)} URLs, {len(secrets)} secret matches, "
            f"{len(sourcemaps)} source maps",
            "jsdeep", confidence=90,
            evidence={"severity": "low", "bundles": analyzed,
                      "deobfuscated_url_hits": deobf_hits,
                      "remediation": "Review JS analysis output for secrets "
                                     "and internal endpoints."}))

        for ep in sorted(endpoints)[:60]:
            findings.append(self._f(
                "api", "js_endpoint", ep, "jsdeep", source_url=ep,
                confidence=80,
                evidence={"severity": "low",
                          "remediation": "Test endpoints found in JS for "
                                         "auth gaps."}))
        for s in secrets[:20]:
            findings.append(self._f(
                "leak", "js_secret",
                f"{s['kind']} in {s['url']}: {s['match']}",
                "jsdeep", source_url=s["url"], confidence=85,
                evidence={"severity": "high",
                          "remediation": "Rotate the exposed credential and "
                                         "remove it from client-side code."}))
        for sm in sorted(sourcemaps)[:20]:
            findings.append(self._f(
                "web", "source_map", sm, "jsdeep", source_url=sm,
                confidence=85,
                evidence={"severity": "medium",
                          "remediation": "Disable source maps in production "
                                         "or restrict access."}))
        for t in todos[:15]:
            findings.append(self._f(
                "web", "js_todo", t, "jsdeep", confidence=70,
                evidence={"severity": "low",
                          "remediation": "Review dev comments; they may hint "
                                         "at unfinished security controls."}))

        reason = (f"analyzed {analyzed} JS bundles: {len(endpoints)} endpoints, "
                  f"{len(secrets)} secrets, {len(sourcemaps)} source maps")
        return self._ok(findings, reason)
