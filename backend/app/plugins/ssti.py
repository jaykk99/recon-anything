"""Server-Side Template Injection detector (critical findings).

Non-destructive math-canary method: inject 1336*7 style arithmetic
in each template engine's syntax and look for the computed result
9352 in the response. Unique math avoids false positives. Engines:
Jinja2/Twig ({{ }}), Freemarker (${ }), Velocity (#set),
ERB (<%= %>), Smarty ({ }). No file access or command execution.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Tuple
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url

REMEDIATION = ("Never render user input as a template. Use logic-less "
               "templates or sandboxed engines with code execution "
               "disabled, and validate/escape all user input.")

A, B = 1336, 7
RESULT = str(A * B)  # "9352"

# (payload, engine_label) -- math canary only, no dangerous constructs
SSTI_PAYLOADS: List[Tuple[str, str]] = [
    ("{{" + f"{A}*{B}" + "}}", "jinja2/twig"),
    ("${" + f"{A}*{B}" + "}", "freemarker/spring"),
    ("#set($x=" + f"{A}*{B}" + ")$x", "velocity"),
    ("<%=" + f"{A}*{B}" + "%>", "erb"),
    ("{" + f"{A}*{B}" + "}", "smarty"),
    ("#{'${" + f"{A}*{B}" + "}'}", "spring-el"),
    ("{{" + f"{A}*{B}" + "}}", "django/jinja2"),
    ("${" + f"{A}*{B}" + "}#{''}", "thymeleaf"),
]

SSTI_ERRORS = [
    (r"TemplateSyntaxError|jinja2\.exceptions", "Jinja2 error"),
    (r"twig.*?exception|Twig_Error", "Twig error"),
    (r"freemarker\.core", "Freemarker error"),
    (r"velocity.*?exception|ParseErrorException", "Velocity error"),
    (r"ERB|ActionView::Template", "ERB/Rails error"),
    (r"smarty.*?error|SmartyCompiler", "Smarty error"),
    (r"thymeleaf.*?exception", "Thymeleaf error"),
]


class SstiPlugin(Plugin):
    id = "ssti"
    label = "SSTI Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "SSTI check: math-canary probes across template engines."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []

        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        tested = 0
        for u in list(urls)[:8]:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            for name, val in params[:3]:
                found = False
                for payload, engine in SSTI_PAYLOADS:
                    tested += 1
                    purl = probe_url(parts, params, name, payload)
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                         timeout=15)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    # --- Method 1: math canary evaluated ---
                    if RESULT in body and payload not in body:
                        findings.append(self._f(
                            "leak", "ssti_template_evaluated",
                            f"CRITICAL: server-side template injection in "
                            f"parameter '{name}' at {parts.path or '/'} "
                            f"({engine}: {A}*{B} evaluated to {RESULT}).",
                            source="ssti probe", source_url=purl,
                            confidence=90, passive=False,
                            evidence={"severity": "critical",
                                      "method": "math canary",
                                      "engine": engine,
                                      "parameter": name,
                                      "payload": payload,
                                      "result": RESULT,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Authorized testing only. "
                                                    "Math canary only."}))
                        found = True
                        break
                    # --- Method 2: template engine error leak ---
                    for pat, label in SSTI_ERRORS:
                        if re.search(pat, body, re.I | re.S):
                            findings.append(self._f(
                                "leak", "ssti_error_based",
                                f"HIGH: template engine error in parameter "
                                f"'{name}' at {parts.path or '/'} "
                                f"({label}) suggests injectable template.",
                                source="ssti probe", source_url=purl,
                                confidence=70, passive=False,
                                evidence={"severity": "high",
                                          "method": "error-based",
                                          "engine": engine,
                                          "parameter": name,
                                          "error_label": label,
                                          "payload": payload,
                                          "remediation": REMEDIATION,
                                          "scope_note": "Authorized testing only. "
                                                        "Candidate: verify manually."}))
                            found = True
                            break
                    if found:
                        break
                if found:
                    continue

        res = self._ok(findings, f"probed {tested} payloads across "
                                 f"{len(urls)} URLs, {len(findings)} SSTI signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
