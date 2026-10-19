"""Photon-style OSINT crawler (native, keyless).

Scrapes the target fast and extracts OSINT gold: background files
(JS/CSS), hidden endpoints (API shapes, params), email addresses,
and interesting parameters. Lightweight single-page-plus-links
approach - quick, not deep.

GET only. Bounded to keep well under the 30s ceiling.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse, parse_qsl

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_PAGES = 20
CONCURRENCY = 12

FILE_RE = re.compile(
    r'''(?:href|src)\s*=\s*["']([^"'\s<>]+)["']''', re.I)
ENDPOINT_RE = re.compile(
    r'''["'`](/(?:api|v\d|rest|graphql|ajax|rpc|admin|debug|internal)[\w\-./{}?=&#%]*?)["'`\s]''',
    re.I)
EMAIL_RE = re.compile(
    r'''\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b''')
PARAM_RE = re.compile(r'''[?&]([\w\-]{1,40})=([^&#\s"']{0,80})''')


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


class PhotonPlugin(Plugin):
    id = "photon"
    label = "Photon OSINT"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Fast OSINT scrape: background files, hidden "
                   "endpoints, params, emails.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        seen: Set[str] = set([base])
        queue = [base]
        pages = 0
        sem = asyncio.Semaphore(CONCURRENCY)
        files: Set[str] = set()
        endpoints: Set[str] = set()
        emails: Set[str] = set()
        params: Set[str] = set()

        async def grab(url: str):
            async with sem:
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

        while queue and pages < MAX_PAGES and (time.monotonic() - t0) < 22:
            batch = [u for u in queue[:CONCURRENCY]]
            queue = queue[CONCURRENCY:]
            for (url, (final, html)) in zip(
                    batch, await asyncio.gather(*[grab(u) for u in batch])):
                if not html:
                    continue
                pages += 1
                for m in FILE_RE.finditer(html):
                    f = urljoin(final, m.group(1).strip())
                    if f.startswith(("http://", "https://")) and \
                            (_host(f) == domain or
                             _host(f).endswith("." + domain)):
                        files.add(f)
                        if f not in seen and pages + len(queue) < MAX_PAGES \
                                and f.lower().split("?")[0].endswith(
                                    (".html", ".htm", ".php")):
                            seen.add(f)
                            queue.append(f)
                for m in ENDPOINT_RE.finditer(html):
                    endpoints.add(urljoin(final, m.group(1)))
                for m in EMAIL_RE.finditer(html):
                    e = m.group(0).lower()
                    if not e.endswith((".png", ".jpg", ".js", ".css")):
                        emails.add(e)
                for m in PARAM_RE.finditer(html):
                    params.add(f"{m.group(1)}={m.group(2)[:40]}")

        findings: List[Finding] = []
        for f in sorted(files)[:60]:
            ctx.publish("assets", f)
        for e in sorted(endpoints)[:60]:
            ctx.publish("endpoints", e)
            findings.append(self._f(
                "api", "hidden_endpoint", e,
                "photon", source_url=e, confidence=70,
                evidence={"severity": "low",
                          "remediation": "Verify hidden endpoints are "
                                         "authenticated and rate-limited."},
                passive=True))
        for e in sorted(emails)[:40]:
            ctx.publish("emails", e)
            findings.append(self._f(
                "identity", "email", e,
                "photon", confidence=70,
                evidence={"severity": "low",
                          "remediation": "Exposed emails attract spam and "
                                         "phishing. Remove where possible."},
                passive=True))
        for p in sorted(params)[:40]:
            findings.append(self._f(
                "web", "parameter", p,
                "photon", confidence=60,
                evidence={"severity": "low",
                          "remediation": "Interesting parameters may be "
                                         "injection points; test manually."},
                passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"{pages} pages: {len(files)} files, {len(endpoints)} endpoints, "
            f"{len(emails)} emails, {len(params)} params")
        res.duration_ms = dur
        return res
