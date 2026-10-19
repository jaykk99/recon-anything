"""LDAP injection detector (high findings).

Non-destructive, error-based method only: send safe LDAP filter
metacharacters (*, )(, *()) in params and look for LDAP server
error text in the response. No authentication bypass attempts,
no data extraction. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url, sample_urls, \
    fetch_baseline, baseline_pattern_hits, over_budget

REMEDIATION = ("Sanitize LDAP search filters: escape special characters "
               "(*, (, ), \\, NUL) per RFC 4515, use allowlists for "
               "user-controlled filter input, and hide LDAP error "
               "details in production responses.")

LDAP_ERRORS = [
    (r"supplied argument is not a valid ldap", "LDAP PHP error"),
    (r"ldap_search\(\).*?error", "LDAP search error"),
    (r"LDAP.*?Invalid DN syntax", "invalid DN syntax"),
    (r"LDAP.*?Operations error", "operations error"),
    (r"ldap_.*?\b(error|exception|warning)", "LDAP API error"),
    (r"Invalid LDAP filter", "invalid filter"),
    (r"Bad search filter", "bad search filter"),
    (r"javax\.naming.*?(InvalidSearchFilter|Ldap)", "JNDI/LDAP error"),
    (r"System\.DirectoryServices", ".NET DirectoryServices error"),
]

# Safe error-based payloads (detection only, no auth bypass attempts)
LDAP_PAYLOADS = [
    "*",
    ")(",
    "*()",
    ")(&",
    "*)(uid=*))(|(uid=*",
    ")(|(uid=*",
    "\\",
]


class LdapInjectionPlugin(Plugin):
    id = "ldapi"
    label = "LDAP Injection"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "LDAP injection detection via safe error-based probes."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        tested = 0
        for u in sample_urls(urls, 8):
            if over_budget(t0):
                break
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            # Baseline FP guard: LDAP error strings can appear in normal
            # content (docs, changelogs). Only flag error text that appears
            # AFTER the probe, not in the baseline.
            baseline_body, _ = await fetch_baseline(ctx, u)
            baseline_err_hits = baseline_pattern_hits(baseline_body,
                                                      LDAP_ERRORS)
            for name, val in params[:3]:
                found = False
                for payload in LDAP_PAYLOADS:
                    tested += 1
                    purl = probe_url(parts, params, name, val + payload)
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                         timeout=15)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    for pat, label in LDAP_ERRORS:
                        if pat in baseline_err_hits:
                            continue
                        if re.search(pat, body, re.I | re.S):
                            findings.append(self._f(
                                "leak", "ldap_injection",
                                f"HIGH: LDAP injection signal in parameter "
                                f"'{name}' at {parts.path or '/'} "
                                f"({label}).",
                                source="ldap probe", source_url=purl,
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
                                 f"{len(urls)} URLs, {len(findings)} LDAP signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
