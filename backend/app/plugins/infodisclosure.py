"""Information disclosure prober (active detection, read-only).

Probes debug and info endpoints that leak versions, internals, or secrets:
phpinfo, Apache server-status/server-info, Spring actuator, Go pprof,
Prometheus metrics. GET/HEAD only, never writes, never authenticates.

Each hit includes the exact curl command that proves it (Jay wants real
commands and real output).
"""
from __future__ import annotations

import re
import time
from typing import List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (path, marker_re, key, severity, exploitability, confidence, title, remediation, method)
PROBES = [
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version",
     "phpinfo_exposed", "high", "public_poc", 92,
     "phpinfo() exposed - full PHP version, config, and environment disclosed",
     "Remove phpinfo.php from production. It hands attackers exact versions for CVE targeting."),
    ("/info.php", r"phpinfo\(\)|PHP Version",
     "phpinfo_exposed", "high", "public_poc", 90,
     "info.php exposes phpinfo() - full PHP version and config disclosed",
     "Remove info.php from production."),
    ("/server-status", r"Apache Status",
     "server_status_exposed", "medium", "theoretical", 90,
     "Apache /server-status exposed - internal request and worker details visible",
     "Restrict /server-status to localhost or remove the status module from public vhosts."),
    ("/server-info", r"Apache Server Information",
     "server_info_exposed", "medium", "theoretical", 88,
     "Apache /server-info exposed - loaded modules and config visible",
     "Restrict /server-info to localhost."),
    ("/actuator/env", r'"propertySources"|"profiles"',
     "actuator_env_exposed", "high", "public_poc", 90,
     'Spring /actuator/env exposed - environment properties (often secrets) disclosed',
     "Lock down Spring actuator endpoints. Never expose /actuator/env publicly."),
    ("/actuator/heapdump", None,
     "actuator_heapdump_exposed", "critical", "public_poc", 85,
     "Spring /actuator/heapdump reachable - full JVM memory (secrets, sessions) downloadable",
     "Disable or restrict /actuator/heapdump. Rotate any secrets it may have contained.",
     "HEAD"),
    ("/debug/pprof/", r"pprof|profiles:",
     "pprof_exposed", "medium", "theoretical", 88,
     "Go /debug/pprof exposed - runtime profiles and goroutine stacks visible",
     "Disable the pprof handler in production builds."),
    ("/metrics", r"# HELP|# TYPE",
     "prometheus_metrics_exposed", "low", "theoretical", 85,
     "Prometheus /metrics exposed - internal counters and labels visible",
     "Restrict /metrics to monitoring IPs."),
]


class InfodisclosurePlugin(Plugin):
    id = "infodisclosure"
    label = "Info Disclosure Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "Probe debug/info endpoints: phpinfo, server-status, actuator, pprof."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        if self.module_mode(ctx) == "passive":
            return self._skipped("active probing only (passive mode)")
        findings: List[Finding] = []

        async def check(path: str, marker: Optional[str], method: str = "GET"):
            full = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, method, full,
                                timeout=12, follow_redirects=True)
            except Exception:
                return None
            if r.status_code != 200:
                return None
            if marker and not re.search(marker, r.text[:20000], re.I):
                return None
            return full

        for probe in PROBES:
            path, marker, key, severity, exploit, conf, title, remediation = probe[:8]
            method = probe[8] if len(probe) > 8 else "GET"
            hit = await check(path, marker, method)
            if not hit:
                continue
            curl_cmd = (f"curl -sI {hit}" if method == "HEAD"
                        else f"curl -s {hit} | head -20")
            findings.append(self._f(
                "web", key,
                f"{severity.upper()}: {title} - proved with: {curl_cmd}",
                source="info disclosure probe", source_url=hit,
                confidence=conf, passive=False,
                exploitability=exploit,
                evidence={"severity": severity,
                          "remediation": remediation,
                          "poc_command": curl_cmd}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} info-disclosure hits")
        res.duration_ms = dur
        return res
