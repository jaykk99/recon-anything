"""Google dork generator plugin.

Generates targeted Google dorks for the domain. These are passive
(search engine queries the hunter runs manually) but we generate
the exact dork URLs so Jay can click through them.
Custom-built, no API key needed.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote_plus

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DORKS = [
    ("site:{d} filetype:pdf", "PDF files indexed", 60),
    ("site:{d} filetype:xls OR filetype:xlsx", "Spreadsheets indexed", 65),
    ("site:{d} filetype:doc OR filetype:docx", "Documents indexed", 60),
    ("site:{d} inurl:admin", "Admin pages indexed", 70),
    ("site:{d} inurl:login", "Login pages indexed", 60),
    ("site:{d} inurl:dashboard", "Dashboards indexed", 65),
    ("site:{d} intext:password", "Password mentions", 75),
    ("site:{d} intext:\"api_key\"", "API key mentions", 80),
    ("site:{d} ext:log", "Log files indexed", 75),
    ("site:{d} ext:sql", "SQL dumps indexed", 85),
    ("site:{d} ext:env", "Env files indexed", 85),
    ("site:{d} \"index of /\"", "Open directories indexed", 80),
    ("site:{d} inurl:wp-content", "WordPress content", 55),
    ("site:{d} inurl:.git", "Git repos indexed", 80),
]


class DorksPlugin(Plugin):
    id = "dorks"
    label = "Google Dorks"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Targeted Google dork queries for the domain."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        for template, label, conf in DORKS:
            query = template.format(d=domain)
            url = "https://www.google.com/search?q=" + quote_plus(query)
            findings.append(self._f(
                "web", "google_dork",
                f"{label}: {query}",
                source="dork generator", source_url=url,
                confidence=conf, passive=True))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"generated {len(DORKS)} dorks")
        res.duration_ms = dur
        return res
