"""Paste search plugin.

Searches public paste sites for leaks mentioning the target domain.
Uses public APIs where available. Custom-built.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote_plus

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class PastesPlugin(Plugin):
    id = "pastes"
    label = "Paste Search"
    accepts = ["domain", "url", "email", "username"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Search paste sites for leaked data."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        query = target.normalized.strip()
        if not query:
            return self._skipped("no query")
        findings: List[Finding] = []

        # Generate search URLs for manual checking
        searches = [
            ("Google", "https://www.google.com/search?q=" +
             quote_plus(f'site:pastebin.com "{query}"')),
            ("Google", "https://www.google.com/search?q=" +
             quote_plus(f'site:ghostbin.com "{query}"')),
            ("Google", "https://www.google.com/search?q=" +
             quote_plus(f'site:hastebin.com "{query}"')),
            ("psbdmp", f"https://psbdmp.ws/api/search/{quote_plus(query)}"),
        ]
        for name, url in searches:
            if name == "Google":
                findings.append(self._f(
                    "leak", "paste_dork",
                    f"Paste search: {url[:80]}...",
                    source="paste search", source_url=url,
                    confidence=40, passive=True))
            else:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
                    if r.status_code == 200:
                        data = r.json()
                        count = data.get("count", 0) if isinstance(data, dict) else 0
                        if count and count != "0":
                            findings.append(self._f(
                                "leak", "paste_found",
                                f"psbdmp.ws found {count} pastes mentioning {query}",
                                source="psbdmp", source_url=url,
                                confidence=75, passive=True))
                except Exception:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, "searched paste sources")
        res.duration_ms = dur
        return res
