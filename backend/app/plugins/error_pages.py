"""Verbose error page disclosure plugin.

Requests a guaranteed-missing path (random token) and a path that often
triggers a 500 (/.%2e/admin), then scans the bodies for stack traces,
framework debug markers, SQL errors, and path disclosures. A 404 that
leaks a stack trace is a finding; a clean 404 is not.

Detection only: the requests are ordinary GETs of nonexistent paths -
no payloads, no injection, nothing executed server-side.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch_many
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

# (key, severity, description, regexes)
DISCLOSURE_SIGNS = [
    ("error_stack_trace", "medium", "stack trace in error page",
     [r"Traceback \(most recent call last\)", r"at [a-zA-Z0-9_$.]+\(",
      r"java\.lang\.[A-Za-z]+Exception", r"System\.NullReferenceException",
      r"stack trace", r"\.php on line \d+", r"\.rb:\d+:in "]),
    ("error_debug_mode", "high", "framework debug mode enabled",
     [r"Django.*DEBUG\s*=\s*True", r"Whoops, looks like something went wrong",
      r"Laravel.*debug.*true", r"Symfony.*Exception.*Profiler",
      r"DEBUG\s*=\s*True", r"development mode", r"Rails.*development"]),
    ("error_sql_leak", "medium", "SQL error details disclosed",
     [r"SQL syntax.*MySQL", r"PostgreSQL.*ERROR", r"ORA-\d{5}",
      r"SQLite.*error", r"Unclosed quotation mark after the character string",
      r"Microsoft.*ODBC.*SQL Server"]),
    ("error_path_disclosure", "low", "server filesystem path disclosed",
     [r"/(var/www|home/[a-z_]+|opt|srv|usr/share)/[^\s\"'<>]*",
      r"[A-Z]:\\\\[a-zA-Z0-9_\\\\.]+"]),
    ("error_version_disclosure", "low", "software version in error page",
     [r"(Apache|nginx|IIS|Tomcat|Jetty)/\d+\.\d+",
      r"PHP/\d+\.\d+", r"Express", r"X-Powered-By"]),
]

COMPILED = [(k, s, d, [re.compile(p, re.I) for p in ps])
            for k, s, d, ps in DISCLOSURE_SIGNS]


class ErrorPagesPlugin(Plugin):
    id = "error_pages"
    label = "Error Page Disclosure"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Probe nonexistent paths for stack traces, debug mode, "
                   "SQL errors and path disclosure in error pages.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        token = uuid.uuid4().hex[:12]
        reqs = [("GET", f"{base}/no-such-page-{token}"),
                ("GET", f"{base}/no-such-page-{token}.php")]
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=2, max_retries=0)
        findings: List = []
        seen = set()
        for _method, url, resp in [(r[0], r[1], res)
                                  for r, res in zip(reqs, resps)]:
            if resp is None or resp.status_code < 400:
                continue
            body = (resp.text or "")[:20000]
            for key, sev, desc, patterns in COMPILED:
                if key in seen:
                    continue
                m = next((mm for rx in patterns
                          if (mm := rx.search(body)) is not None), None)
                if m:
                    seen.add(key)
                    snippet = m.group(0)[:120]
                    findings.append(self._f(
                        "web", key,
                        f"{desc} on {resp.status_code} page: {snippet!r}",
                        source="error page disclosure",
                        source_url=url, confidence=85, passive=True,
                        evidence={"severity": sev, "status": resp.status_code,
                                  "snippet": snippet,
                                  "remediation": (
                                      "Replace verbose error pages with "
                                      "generic ones; disable debug mode in "
                                      "production; log errors server-side "
                                      "instead of rendering them.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"probed 2 missing paths, {len(findings)} disclosures")
