"""CMS vulnerability checker plugin.

Detects CMS/framework versions and flags known CVEs.
Custom-built with an embedded CVE database for common software.
No API keys needed.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (detection_pattern, software, cve, severity, description)
CVE_DB = [
    (r"wp-content", "WordPress", "CVE-2024-XXXX",
     "check version", "WordPress detected - enumerate version via /wp-json/wp/v2 or readme.html"),
    (r"Joomla", "Joomla", "CVE-2023-23752",
     "critical", "Joomla < 4.2.8 has improper API access (CVE-2023-23752)"),
    (r"drupal", "Drupal", "CVE-2018-7600",
     "critical", "Drupalgeddon2 RCE - check version immediately"),
    (r"laravel", "Laravel", "CVE-2021-3129",
     "critical", "Laravel debug mode RCE - check /_ignition/execute-solution"),
    (r"phpmyadmin", "phpMyAdmin", "CVE-2019-12922",
     "high", "phpMyAdmin < 4.9.0.1 has CSRF to RCE chain"),
    (r"struts", "Apache Struts", "CVE-2017-5638",
     "critical", "Struts2 Jakarta RCE - check version"),
    (r"weblogic", "WebLogic", "CVE-2020-14882",
     "critical", "WebLogic RCE - check /console/login"),
    (r"jboss", "JBoss", "CVE-2017-12149",
     "critical", "JBoss deserialization RCE"),
    (r"tomcat/7", "Tomcat 7", "CVE-2020-1938",
     "high", "Ghostcat AJP file read - check port 8009"),
    (r"tomcat/8\.5\.([0-9]|[1-4][0-9])[^0-9]", "Tomcat 8.5", "CVE-2020-1938",
     "high", "Ghostcat - update to 8.5.51+"),
    (r"express", "Express.js", "CVE-2017-16995",
     "medium", "Old Express - check qs prototype pollution"),
    (r"jquery/1\.", "jQuery 1.x", "CVE-2020-11022",
     "medium", "jQuery 1.x XSS - upgrade to 3.5+"),
    (r"jquery/2\.", "jQuery 2.x", "CVE-2020-11022",
     "medium", "jQuery 2.x XSS - upgrade to 3.5+"),
    (r"bootstrap/3\.", "Bootstrap 3", "CVE-2018-14041",
     "medium", "Bootstrap 3 XSS in collapse plugin"),
    (r"angularjs/1\.[0-5]", "AngularJS", "CVE-2020-7676",
     "high", "AngularJS < 1.6 has CSP bypass and XSS"),
]


class CvesPlugin(Plugin):
    id = "cves"
    label = "CVE Checker"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Detect software versions, flag known CVEs."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
        except Exception as e:
            return self._error(f"could not fetch: {str(e)[:150]}")

        body = r.text[:100000].lower()
        headers_text = " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        combined = body + " " + headers_text

        for pattern, software, cve, severity, desc in CVE_DB:
            if re.search(pattern.lower(), combined):
                findings.append(self._f(
                    "web", "cve_match",
                    f"{software}: {desc} [{cve}] (severity: {severity})",
                    source="CVE checker", source_url=url,
                    confidence=70, passive=True))

        # WordPress version enum
        if "wp-content" in body:
            try:
                r2 = await fetch(ctx.http, ctx.limiter, "GET",
                                 url.rstrip("/") + "/wp-json/wp/v2",
                                 timeout=10)
                if r2.status_code == 200:
                    findings.append(self._f(
                        "web", "wp_api_exposed",
                        "WordPress REST API exposed at /wp-json/wp/v2 - user enumeration possible",
                        source="CVE checker",
                        source_url=url.rstrip("/") + "/wp-json/wp/v2",
                        confidence=80, passive=True))
            except Exception:
                pass

        if not findings:
            findings.append(self._f(
                "web", "cve_none",
                f"No known-vulnerable software detected from {len(CVE_DB)} signatures",
                source="CVE checker", source_url=url,
                confidence=50, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(CVE_DB)} CVE signatures")
        res.duration_ms = dur
        return res
