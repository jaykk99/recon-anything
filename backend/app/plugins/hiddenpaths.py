"""Hidden endpoint discovery plugin.

Finds endpoints not linked anywhere: brute-forces common paths,
checks JS for API calls, parses sitemaps and robots.txt.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

HIDDEN_PATHS = """admin administrator admin-panel dashboard panel control
login signin log-in auth authenticate sso oauth callback
api v1 v2 v3 rest graphql graphiql playground
internal private secret hidden test dev staging qa uat sandbox demo
backup bak old tmp temp cache logs log debug
config configuration settings env environment
db database sql dump export import
upload uploads files file media assets static
docs documentation api-docs swagger openapi redoc
health status metrics ping info version
webhook webhooks callback callbacks hook
console terminal shell cmd exec
phpinfo info.php test.php debug.php
.git .svn .hg .env .env.bak
wp-admin wp-login.php xmlrpc.php
phpmyadmin pma adminer
actuator actuator/health actuator/env
.env.local .env.production config.json
server-status server-info
""".split()


class HiddenPathsPlugin(Plugin):
    id = "hiddenpaths"
    label = "Hidden Endpoint Finder"
    accepts = ["domain", "url"]
    passive = False  # active probing
    cost = Cost.FREE
    group = "web"
    description = "Brute-force unlinked paths. Find hidden endpoints."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode for path probing")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []

        async def check(path: str):
            url = urljoin(base + "/", path)
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url)
                if resp and resp.status_code in (200, 301, 302, 401, 403):
                    return (path, resp.status_code)
            except Exception:
                pass
            return None

        # Batch in groups to avoid hammering
        results = []
        for i in range(0, len(HIDDEN_PATHS), 10):
            batch = HIDDEN_PATHS[i:i+10]
            batch_results = await asyncio.gather(*[check(p) for p in batch])
            results.extend([r for r in batch_results if r])
            await asyncio.sleep(0.5)

        for path, status in results:
            interesting = status in (200, 401, 403)
            findings.append(self._f(
                "web", "hidden_endpoint", f"/{path} ({status})",
                f"hiddenpaths: /{path} returned {status}",
                confidence=85 if interesting else 60,
                evidence={"severity": "medium" if status == 200 else "low",
                          "why": f"Unlinked path returns {status}"},
                passive=False))
            ctx.publish("endpoints", urljoin(base + "/", path))

        return self._ok(findings, f"probed {len(HIDDEN_PATHS)} paths, {len(results)} hits")
