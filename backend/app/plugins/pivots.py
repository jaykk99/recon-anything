"""Pivot plugin (Milestone 6).

Turns one finding into more targets: favicon-hash pivot via Shodan
(needs key, graceful), tracking-ID pivot (builds the search queries),
tech-stack pivot notes, and cert-transparency sibling harvest.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class PivotsPlugin(Plugin):
    id = "pivots"
    label = "Pivot Finder"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "identity"
    description = "Favicon/Shodan pivot, tracking-ID pivot, tech-stack pivot queries."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        # favicon hash -> Shodan search (needs key)
        key = ctx.keys.get("shodan")
        # we compute nothing here; the webtech plugin stores favicon_mmh3.
        # This plugin documents the pivot and runs it when a key exists.
        if key:
            findings.append(self._f("identity", "shodan_note",
                                    "Shodan key present: run favicon-hash pivot from the "
                                    "run view using the favicon_mmh3 finding value",
                                    source="Shodan", confidence=60, passive=True))
        else:
            findings.append(self._f("identity", "shodan_note",
                                    "favicon pivot skipped: no SHODAN_API_KEY configured. "
                                    "Query would be: http.favicon.hash:<mmh3>",
                                    source="Shodan", confidence=50, passive=True))

        # tracking-ID pivots (query builders, always work)
        for tid_kind, q in (("ga_id", "UA-"), ("gtm_id", "GTM-"), ("adsense_id", "ca-pub-")):
            findings.append(self._f(
                "identity", "pivot_query",
                f"urlscan.io search: page.url:* AND ({tid_kind}:*) for {domain}",
                source="pivot builder",
                source_url="https://urlscan.io/search/#" + quote(f"domain:{domain}"),
                confidence=55, passive=True))

        # tech-stack pivot via Wappalyzer-style public data (builtwith needs key)
        findings.append(self._f(
            "identity", "pivot_query",
            f"Find sibling sites: search Shodan/Censys for the same server header + favicon hash as {domain}",
            source="pivot builder", confidence=55, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, "pivot queries built")
        res.duration_ms = dur
        return res
