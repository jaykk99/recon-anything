"""Directory / path traversal detector (active, non-destructive).

Probes file-ish query parameters with traversal payloads and checks for
/etc/passwd leakage (read-only GET, extracts nothing else). Also checks
for Windows-style (..\\..\\windows\\win.ini) markers.

GET only. No file writes, no data extraction beyond the passwd marker.
Authorized testing only.
"""
from __future__ import annotations

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
    description = "Probe file params for directory traversal (read-only passwd check)."

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

        tested = 0
        confirmed = False
        for u in sorted(urls)[:12]:
            if over_budget(t0, budget_s=50):
                break
            parts = urlparse(u)
            try:
                params = parse_qsl(parts.query, keep_blank_values=True)
            except Exception:
                continue
            if not params and u != base:
                continue
            if params:
                # Prefer file-ish params; fall back to the first 2 params.
                fileish = [n for n, _ in params if n.lower() in FILEISH_PARAMS]
                names = fileish or [n for n, _ in params[:2]]
                base_params = params
            else:
                names = ["file", "path", "page", "include", "template", "name"]
                base_params = [(n, "1") for n in names]
            for name in names[:6]:
                for payload in TRAVERSAL_PAYLOADS[:3]:
                    if over_budget(t0, budget_s=50):
                        break
                    purl = probe_url(parts, base_params, name, payload)
                    try:
                        r = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                        timeout=12, follow_redirects=True)
                    except Exception:
                        continue
                    tested += 1
                    body = r.text[:50000]
                    # Baseline FP guard: markers like "root:x:0:0" or
                    # "[extensions]" can exist in the page's normal content
                    # (docs, tutorials). Only flag when the marker appears
                    # in the probed response but NOT in the baseline.
                    base_body, _ = await fetch_baseline(ctx, u, timeout=12)
                    base_body = base_body[:50000]
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
                        confirmed = True
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
                        confirmed = True
                        break
                if confirmed:
                    break
            if confirmed:
                break

        dur = int((time.monotonic() - t0) * 1000)
        note = f"traversal probes sent: {tested}"
        if not findings:
            note += " - no /etc/passwd or win.ini leakage detected"
        res = self._ok(findings, note)
        res.duration_ms = dur
        return res
