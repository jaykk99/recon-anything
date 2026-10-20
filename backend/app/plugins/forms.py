"""Form Catalog (native, keyless).

Crawls up to ~30 same-site pages and catalogs every <form> element:
method, absolute action URL, and every input (name/type/required),
plus select/textarea names. Detection only: pages are fetched with
GET, and no form is ever submitted.

Consumes nothing from the bus; publishes each discovered form to the
"forms" discovery bus so other chain plugins can consume it.
"""
from __future__ import annotations

import asyncio
import re
import time
from html.parser import HTMLParser
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   gather_capped)

MAX_PAGES = 30
CONCURRENCY = 8
CRAWL_BUDGET = 20
LINK_RE = re.compile(r'<a[^>]+href\s*=\s*["\']([^"\'>\s]+)["\']', re.I)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _same_site(url: str, domain: str) -> bool:
    h = _host(url)
    return bool(h) and (h == domain or h.endswith("." + domain))


class _FormParser(HTMLParser):
    """Collect <form> elements: method, action, and all inputs."""

    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: List[Dict] = []
        self._cur: Dict | None = None

    def _close_form(self):
        if self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def handle_starttag(self, tag: str, attrs):
        a = {k.lower(): v for k, v in attrs}
        t = tag.lower()
        if t == "form":
            self._close_form()  # tolerate malformed nested forms
            action = a.get("action") or self.page_url
            self._cur = {
                "method": (a.get("method") or "GET").strip().upper(),
                "action": urljoin(self.page_url, action),
                "name": (a.get("name") or a.get("id") or "").strip()[:80],
                "inputs": [],
            }
        elif self._cur is not None and t == "input":
            self._cur["inputs"].append({
                "name": (a.get("name") or "").strip()[:80],
                "type": ((a.get("type") or "text").strip().lower())[:20],
                "required": "required" in a,
                "placeholder": (a.get("placeholder") or "").strip()[:60],
            })
        elif self._cur is not None and t in ("select", "textarea"):
            self._cur["inputs"].append({
                "name": (a.get("name") or "").strip()[:80],
                "type": t,
                "required": "required" in a,
                "placeholder": "",
            })

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self._close_form()


def _kind(form: Dict) -> str | None:
    """Interesting-form classifier. Returns None for plain forms."""
    inputs = form.get("inputs", [])
    if any(i.get("type") == "password" for i in inputs):
        return "login"
    if any(i.get("type") == "file" for i in inputs):
        return "upload"
    if any(i.get("type") == "search" for i in inputs):
        return "search"
    names = " ".join(i.get("name", "") for i in inputs).lower()
    form_name = (form.get("name") or "").lower()
    if "search" in names or "search" in form_name:
        return "search"
    return None


class FormsPlugin(Plugin):
    id = "forms"
    label = "Form Catalog"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    phase = 2
    timeout_s = 30
    description = ("Crawl same-site pages and catalog every HTML form "
                   "(method, action, inputs). Detection only, never "
                   "submitted.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        seen: Set[str] = set([base])
        queue = [base]
        pages = 0
        forms: List[Dict] = []
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
                (time.monotonic() - t0) < CRAWL_BUDGET:
            batch = queue[:CONCURRENCY]
            queue = queue[CONCURRENCY:]
            results = await gather_capped(
                [grab(u) for u in batch],
                max(1.0, CRAWL_BUDGET - (time.monotonic() - t0)))
            for res in results:
                if not res:
                    continue
                final, html = res
                if not html or final is None:
                    continue
                pages += 1
                try:
                    parser = _FormParser(final)
                    parser.feed(html)
                    page_forms = parser.forms
                except Exception:
                    page_forms = []
                for f in page_forms:
                    record = {"page": final, "method": f["method"],
                              "action": f["action"], "name": f["name"],
                              "inputs": f["inputs"]}
                    forms.append(record)
                    ctx.publish("forms", record)
                if pages + len(queue) < MAX_PAGES:
                    for m in LINK_RE.finditer(html):
                        raw = m.group(1).strip()
                        if not raw or raw.startswith(
                                ("#", "javascript:", "mailto:", "tel:",
                                 "data:")):
                            continue
                        u = urljoin(final, raw).split("#")[0]
                        if u.startswith(("http://", "https://")) and \
                                _same_site(u, domain) and u not in seen:
                            seen.add(u)
                            queue.append(u)

        if not forms:
            return self._ok([], f"crawled {pages} pages, no forms found")

        findings: List[Finding] = []
        counts: Dict[str, int] = {}
        for f in forms:
            kind = _kind(f) or "plain"
            counts[kind] = counts.get(kind, 0) + 1

        kind_str = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
        findings.append(self._f(
            "web", "form_inventory",
            f"{len(forms)} forms across {pages} pages ({kind_str})",
            "forms", confidence=90,
            evidence={"severity": "low", "pages_crawled": pages,
                      "form_count": len(forms), "by_kind": counts,
                      "forms": forms,
                      "remediation": "Inventory is reconnaissance fuel: "
                                     "every form is a potential injection "
                                     "or auth surface. Review and harden "
                                     "the interesting ones."}))

        for f in forms:
            kind = _kind(f)
            if kind is None:
                continue
            n_in = len(f["inputs"])
            findings.append(self._f(
                "web", "interesting_form",
                f"{kind} form: {f['method']} {f['action']} ({n_in} inputs)",
                "forms", source_url=f["page"], confidence=85,
                evidence={"severity": "medium", "kind": kind,
                          "page": f["page"], "method": f["method"],
                          "action": f["action"], "inputs": f["inputs"],
                          "remediation": {
                              "login": "Login forms are credential-stuffing "
                                       "and brute-force targets. Enforce "
                                       "rate limiting, MFA, and account "
                                       "lockout.",
                              "upload": "Upload forms are RCE/file-abuse "
                                        "targets. Validate type and content "
                                        "server-side, store outside the "
                                        "webroot, strip EXIF.",
                              "search": "Search forms are reflected-XSS and "
                                        "injection probes. Sanitize and "
                                        "encode all echoed input.",
                          }.get(kind, "Review this form for injection and "
                                      "abuse vectors.")}))

        reason = (f"cataloged {len(forms)} forms on {pages} pages "
                  f"({kind_str})")
        return self._ok(findings, reason)
