"""GitHub code search plugin.

Searches GitHub for mentions of the target domain using the public
GitHub code search API. Finds leaked keys, exposed repos, and references.
Custom-built, works without API key (rate-limited) or with one if configured.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote_plus

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class GithubPlugin(Plugin):
    id = "github"
    label = "GitHub Dorker"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Search GitHub code for target mentions and leaks."
    requires_keys = []  # optional: github_token for higher limits

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        # GitHub code search queries (also useful as clickable dorks)
        queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" credentials',
        ]
        for q in queries:
            url = "https://github.com/search?q=" + quote_plus(q) + "&type=code"
            findings.append(self._f(
                "identity", "github_dork",
                f"GitHub code search: {q}",
                source="GitHub dorker", source_url=url,
                confidence=50, passive=True))

        # Try the API (works without key, 10 req/min)
        try:
            api_url = ("https://api.github.com/search/code?q=" +
                       quote_plus(f'"{domain}"') + "&per_page=5")
            headers = {}
            gh_token = ctx.keys.get("github_token", "")
            if gh_token:
                headers["Authorization"] = f"Bearer {gh_token}"
            r = await fetch(ctx.http, ctx.limiter, "GET", api_url,
                            timeout=15, headers=headers)
            if r.status_code == 200:
                data = r.json()
                total = data.get("total_count", 0)
                findings.append(self._f(
                    "identity", "github_results",
                    f"GitHub found {total} code results mentioning {domain}",
                    source="GitHub API",
                    source_url="https://github.com/search?q=" + quote_plus(f'"{domain}"') + "&type=code",
                    confidence=70, passive=True))
                for item in data.get("items", [])[:10]:
                    repo = item.get("repository", {}).get("full_name", "?")
                    path = item.get("path", "?")
                    findings.append(self._f(
                        "identity", "github_hit",
                        f"{repo}: {path}",
                        source="GitHub API", source_url=item.get("html_url", ""),
                        confidence=65, passive=True))
            elif r.status_code == 403:
                findings.append(self._f(
                    "identity", "github_rate_limit",
                    "GitHub API rate limited - use the dork links manually",
                    source="GitHub API", confidence=40, passive=True))
        except Exception:
            pass

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"generated {len(queries)} dorks")
        res.duration_ms = dur
        return res
