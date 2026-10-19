"""Retire.js-style vulnerable JS library detector.

Fingerprints JavaScript library versions from script URLs, file content,
and version banners, then matches against a database of known-vulnerable
versions (jQuery, Bootstrap, AngularJS, React, Vue, Lodash, Moment, etc.).

Detection only: read-only GETs of public JS files. Version strings are
public metadata. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (library, version regex, vulnerable versions / notes, CVE)
# A version is flagged if it is < the fixed version listed.
VULN_LIBS = [
    # (name, detect_re, fixed_in, cve, severity)
    ("jQuery", r"jquery[/-](\d+\.\d+\.\d+)", "3.5.0",
     "CVE-2020-11022/CVE-2020-11023 (XSS)", "high"),
    ("jQuery", r"jQuery\s*(?:v|=)?(\d+\.\d+\.\d+)", "3.5.0",
     "CVE-2020-11022/CVE-2020-11023 (XSS)", "high"),
    ("Bootstrap", r"bootstrap[/-](\d+\.\d+\.\d+)", "4.6.2",
     "CVE-2024-6484/CVE-2024-6485 (XSS)", "medium"),
    ("AngularJS", r"angular(?:js)?[/-](\d+\.\d+\.\d+)", "1.8.3",
     "CVE-2023-26116/CVE-2023-26117 (XSS)", "high"),
    ("Lodash", r"lodash[/-](\d+\.\d+\.\d+)", "4.17.21",
     "CVE-2021-23337/CVE-2020-28500 (prototype pollution/RCE)", "high"),
    ("Moment.js", r"moment[/-](\d+\.\d+\.\d+)", "2.29.4",
     "CVE-2022-24785/CVE-2022-31129 (ReDoS/path traversal)", "medium"),
    ("Handlebars", r"handlebars[/-](\d+\.\d+\.\d+)", "4.7.8",
     "CVE-2021-20922 (RCE via template)", "high"),
    ("Vue", r"vue[/-](\d+\.\d+\.\d+)", "2.7.16",
     "CVE-2024-6783 (XSS, Vue 2 EOL)", "medium"),
    ("React", r"react[/-](\d+\.\d+\.\d+)", "16.14.0",
     "CVE advisory: upgrade React <16.14 (XSS vectors)", "medium"),
    ("D3", r"d3[/-](\d+\.\d+\.\d+)", "7.9.0",
     "outdated D3 (known XSS in <7)", "low"),
    ("Underscore", r"underscore[/-](\d+\.\d+\.\d+)", "1.13.4",
     "CVE-2021-23358 (arbitrary code exec)", "high"),
    ("Mustache", r"mustache[/-](\d+\.\d+\.\d+)", "4.2.0",
     "CVE-2021-28066 (XSS)", "medium"),
    ("Three.js", r"three[/-](\d+\.\d+\.\d+)", "0.160.0",
     "outdated Three.js (memory-safety fixes)", "low"),
]


def _ver_tuple(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0,)


class JsRetirePlugin(Plugin):
    id = "js_retire"
    label = "Vulnerable JS Libraries"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Retire.js-style: detect outdated/vulnerable JS "
                   "libraries with CVE mapping.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen: set = set()

        def emit(lib: str, ver: str, fixed: str, cve: str, sev: str,
                 where: str, url: str | None):
            key = (lib, ver)
            if key in seen:
                return
            seen.add(key)
            findings.append(self._f(
                "web", "vuln_js_library",
                f"Vulnerable {lib} {ver} (fixed in {fixed}): {cve}",
                source=f"js library scan: {where}", source_url=url,
                confidence=85, passive=passive,
                evidence={"remediation": f"Upgrade {lib} to >= {fixed} and "
                          "re-scan. Pin versions; enable SRI hashes.",
                          "severity": sev, "risk": sev,
                          "library": lib, "version": ver,
                          "fixed_in": fixed, "cve": cve},
                exploitability="public_poc"))

        try:
            page = await ctx.fetch_page(base, timeout=25)
            if not page:
                res = self._degraded("homepage fetch failed")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            html = page["text"][:500000]
            page_url = page.get("url") or base

            # Check script src URLs first (fast path)
            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
            srcs = [s for s in srcs if not s.startswith("data:")][:25]
            for name, pat, fixed, cve, sev in VULN_LIBS:
                for src in srcs:
                    m = re.search(pat, src, re.I)
                    if m and _ver_tuple(m.group(1)) < _ver_tuple(fixed):
                        emit(name, m.group(1), fixed, cve, sev,
                             f"script tag {src[:60]}", page_url)

            # Check first-party bundle contents for version banners
            for src in srcs:
                full = urljoin(page_url, src)
                host = urlparse(full).netloc
                if host and not host.endswith(domain):
                    continue
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", full,
                                    timeout=12)
                    if r.status_code != 200 or not r.text:
                        continue
                    body = r.text[:300000]
                    for name, pat, fixed, cve, sev in VULN_LIBS:
                        for m in re.finditer(pat, body, re.I):
                            if _ver_tuple(m.group(1)) < _ver_tuple(fixed):
                                emit(name, m.group(1), fixed, cve, sev,
                                     f"JS bundle {src[:60]}", full)
                                break
                except Exception:
                    continue
        except Exception as e:
            res = self._degraded(f"scan failed: {str(e)[:150]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        res = self._ok(findings,
                       f"{len(findings)} vulnerable libraries" if findings
                       else "no vulnerable JS libraries detected")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
