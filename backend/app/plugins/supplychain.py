"""Supply chain vulnerability detector.

Detects third-party scripts/libraries, checks for known vulnerable
versions (jQuery, Bootstrap, etc.), and flags compromised CDN usage.
Read-only. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# library -> (version regex, known-vulnerable versions note)
VULN_LIBS = [
    (r"jquery[/-](\d+\.\d+\.\d+)", "jQuery", "< 3.5.0 has XSS CVEs"),
    (r"bootstrap[/-](\d+\.\d+\.\d+)", "Bootstrap", "< 4.6.1 / < 5.2.3 have XSS"),
    (r"angular[/-](\d+\.\d+\.\d+)", "AngularJS", "1.x is EOL with known XSS"),
    (r"lodash[/-](\d+\.\d+\.\d+)", "Lodash", "< 4.17.21 has prototype pollution"),
    (r"moment[/-](\d+\.\d+\.\d+)", "Moment.js", "< 2.29.2 has ReDoS/path traversal"),
    (r"handlebars[/-](\d+\.\d+\.\d+)", "Handlebars", "< 4.7.7 has RCE"),
    (r"underscore[/-](\d+\.\d+\.\d+)", "Underscore.js", "< 1.13.1 has arbitrary code"),
    (r"vue[/-](\d+\.\d+\.\d+)", "Vue", "< 2.7.14 / < 3.2.47 notes"),
    (r"react[/-](\d+\.\d+\.\d+)", "React", "check for outdated builds"),
]

REMEDIATION = ("Pin dependencies, use SRI hashes, monitor for CVEs, and "
               "update vulnerable libraries promptly.")


class SupplychainPlugin(Plugin):
    id = "supplychain"
    label = "Supply Chain Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Flag vulnerable third-party JS libraries."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        # third-party script sources
        third_party = set()
        for m in re.finditer(r'<script[^>]+src=["\'](https?://[^"\']+)["\']', html, re.I):
            src = m.group(1)
            if domain not in src:
                third_party.add(src)
                ctx.publish("third_party_scripts", src)
        if third_party:
            findings.append(self._f(
                "web", "third_party_scripts",
                f"{len(third_party)} third-party scripts loaded. Review for "
                f"compromised or unnecessary dependencies.",
                source="Supply chain scan", source_url=page_url,
                confidence=70, passive=passive,
                evidence={"severity": "low", "count": len(third_party),
                          "samples": sorted(third_party)[:10],
                          "remediation": REMEDIATION}))
        seen = set()
        for pat, name, note in VULN_LIBS:
            for m in re.finditer(pat, html, re.I):
                ver = m.group(1)
                key = (name, ver)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._f(
                    "web", "vuln_library",
                    f"Potentially vulnerable library: {name} {ver}. {note}.",
                    source="Supply chain scan", source_url=page_url,
                    confidence=75, passive=passive,
                    evidence={"severity": "medium", "library": name,
                              "version": ver, "remediation": REMEDIATION,
                              "scope_note": "Version-based heuristic. Verify manually."}))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} supply chain findings")
        res.duration_ms = dur
        return res
