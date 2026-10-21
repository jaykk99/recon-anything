"""phpinfo() exposure detection plugin.

Checks the handful of conventional phpinfo locations (phpinfo.php,
info.php, php-info.php, test.php) for a live phpinfo() page, which
discloses the full PHP config, loaded extensions, server paths and
environment variables. Confirmed by the "PHP Version" + "phpinfo()"
markers, not just a 200 status.

Detection only: plain GETs of conventional filenames.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch_many
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

PATHS = ["phpinfo.php", "info.php", "php-info.php", "test.php",
         "phpinfo", "info"]
MARKERS = [re.compile(p, re.I) for p in
           (r"<title>phpinfo\(\)</title>", r"PHP Version",
            r"phpinfo\(\)", r"Zend Engine", r"PHP Extension.*Build")]


class PhpinfoPlugin(Plugin):
    id = "phpinfo"
    label = "phpinfo() Exposure"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Detect exposed phpinfo() pages disclosing PHP config, "
                   "paths and environment.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        reqs = [("GET", f"{base}/{p}") for p in PATHS]
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=3, max_retries=0)
        findings: List = []
        for (_m, url), resp in zip(reqs, resps):
            if resp is None or resp.status_code != 200:
                continue
            body = (resp.text or "")[:50000]
            if sum(1 for rx in MARKERS if rx.search(body)) >= 2:
                findings.append(self._f(
                    "web", "phpinfo_exposed",
                    f"phpinfo() page exposed at {url}",
                    source="phpinfo detection", source_url=url,
                    confidence=98, passive=True,
                    evidence={"severity": "high",
                              "remediation": (
                                  "Remove the phpinfo file from production "
                                  "immediately; it discloses full PHP config, "
                                  "paths and env vars.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"checked {len(PATHS)} conventional paths, "
                   f"{len(findings)} exposed")
