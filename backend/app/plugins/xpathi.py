"""XPath injection detector (high findings).

Non-destructive, error-based method only: send safe XPath query
metacharacters (' or '1'='1, '] | //* | //*[) in params and look
for XPath/XQuery error text in the response. No XML data extraction.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url

REMEDIATION = ("Never build XPath expressions by string concatenation. "
               "Use parameterized XPath queries (variable binding), "
               "apply strict input allowlists, and hide XPath error "
               "details in production responses.")

XPATH_ERRORS = [
    (r"XPathException", "XPathException"),
    (r"Invalid XPath expression", "invalid XPath expression"),
    (r"MSXML[0-9]?", "MSXML parser error"),
    (r"javax\.xml\.xpath", "JAXP XPath error"),
    (r"System\.Xml\.XPath", ".NET XPath error"),
    (r"libxml2.*?error", "libxml2 error"),
    (r"XPath syntax error", "syntax error"),
    (r"Undefined (axis|function|namespace)", "XPath evaluation error"),
    (r"XQuery.*?error", "XQuery error"),
    (r"Supplied XPath expression is invalid", "invalid XPath"),
    (r"xmlXPathEval", "xmlXPathEval error"),
]

# Safe error-based payloads (detection only, no data extraction)
XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or '1'='2",
    "'] | //* | //*[",
    "')] | //* | //*[('",
    "x'] | //user/*[contains(.,'",
    "\" or \"1\"=\"1",
    "') or ('1'='1",
    "count(/*)",
]


class XpathInjectionPlugin(Plugin):
    id = "xpathi"
    label = "XPath Injection"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "XPath injection detection via safe error-based probes."

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
                for payload in XPATH_PAYLOADS:
                    tested += 1
                    purl = probe_url(parts, params, name, v + payload)
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                         timeout=15)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    for pat, label in XPATH_ERRORS:
                        if re.search(pat, body, re.I | re.S):
                            findings.append(self._f(
                                "leak", "xpath_injection",
                                f"HIGH: XPath injection signal in parameter "
                                f"'{name}' at {parts.path or '/'} "
                                f"({label}).",
                                source="xpath probe", source_url=purl,
                                confidence=80, passive=False,
                                evidence={"severity": "high",
                                          "method": "error-based",
                                          "parameter": name,
                                          "error_label": label,
                                          "payload": payload,
                                          "remediation": REMEDIATION,
                                          "scope_note": "Authorized testing only. "
                                                        "No data extracted."}))
                            found = True
                            break
                    if found:
                        break
                if found:
                    continue

        res = self._ok(findings, f"probed {tested} payloads across "
                                 f"{len(urls)} URLs, {len(findings)} XPath signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
