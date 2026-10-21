"""Exposed debug toolbar / profiler detection plugin.

Scans the homepage HTML for markers of development debug toolbars left
enabled in production: Django Debug Toolbar, Symfony Web Profiler,
Laravel Telescope/Debugbar, Rails better_errors/web-console, and
phpDebugBar. These expose queries, env vars and stack traces to any
visitor. Detection only: reads the already-fetched homepage HTML.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

# (key, description, regexes)
TOOLBARS = [
    ("debug_django_toolbar", "Django Debug Toolbar enabled in production",
     [r"djdt", r"django-debug-toolbar", r"djDebug"]),
    ("debug_symfony_profiler", "Symfony Web Profiler exposed",
     [r"_profiler", r"sf-toolbar", r"symfony.*profiler"]),
    ("debug_laravel_telescope", "Laravel Telescope / Debugbar exposed",
     [r"laravel.*telescope", r"phpdebugbar", r"debugbar"]),
    ("debug_rails_console", "Rails web-console / better_errors exposed",
     [r"web-console", r"better_errors", r"Binding\.of_caller"]),
    ("debug_phpdebugbar", "phpDebugBar exposed",
     [r"phpdebugbar", r"PhpDebugBar"]),
    ("debug_react_devtools", "React dev build served in production",
     [r"react-dom.*development", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"]),
]

COMPILED = [(k, d, [re.compile(p, re.I) for p in ps])
            for k, d, ps in TOOLBARS]


class ExposedDebugPlugin(Plugin):
    id = "exposed_debug"
    label = "Exposed Debug Toolbars"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Detect dev debug toolbars/profilers (Django, Symfony, "
                   "Laravel, Rails) left enabled in production.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable")
        html = (resp.text or "")[:200000]
        findings: List = []
        for key, desc, res in COMPILED:
            m = next((x for x in res if x.search(html)), None)
            if m:
                findings.append(self._f(
                    "web", key, f"{desc} (marker: {m.group(0)[:60]!r})",
                    source="debug toolbar detection",
                    source_url=base + "/", confidence=90, passive=True,
                    evidence={"severity": "high", "marker": m.group(0)[:80],
                              "remediation": (
                                  "Disable the debug toolbar/profiler in "
                                  "production (env-gated, IP-restricted, or "
                                  "removed from the prod build).")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"checked {len(TOOLBARS)} toolbar signatures, "
                   f"{len(findings)} exposed")
