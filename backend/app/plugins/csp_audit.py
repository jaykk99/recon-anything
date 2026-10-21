"""CSP (Content-Security-Policy) audit plugin.

headers.py reports a *missing* CSP; this plugin grades an *existing*
one. It parses the policy for the classic bypasses: unsafe-inline /
unsafe-eval, wildcards in script-src, data:/blob: script sources,
missing object-src / base-uri fallbacks, and http: on an https page.
Each weakness is its own finding with the offending directive quoted.

Passive: one GET of the homepage (shared fetch_page cache).
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target


def _parse_csp(value: str) -> Dict[str, List[str]]:
    """Parse a CSP header value into {directive: [sources]}."""
    out: Dict[str, List[str]] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        out[tokens[0].lower()] = tokens[1:]
    return out


def _grade_csp(policy: Dict[str, List[str]], is_https: bool) -> List[dict]:
    """Return [{key, severity, message, directive}] weaknesses."""
    weak = []

    def eff(name: str) -> List[str]:
        # effective sources: directive or default-src fallback
        return policy.get(name, policy.get("default-src", []))

    script = eff("script-src")
    joined = " ".join(script).lower()
    if "'unsafe-inline'" in joined:
        weak.append({"key": "csp_unsafe_inline", "severity": "medium",
                     "directive": "script-src",
                     "message": "script-src allows 'unsafe-inline' - inline "
                                "scripts run, blunting XSS protection"})
    if "'unsafe-eval'" in joined:
        weak.append({"key": "csp_unsafe_eval", "severity": "medium",
                     "directive": "script-src",
                     "message": "script-src allows 'unsafe-eval' - eval() and "
                                "friends run, blunting XSS protection"})
    wild = [s for s in script if s in ("*", "*.com", "*.net", "*.org")
            or s.startswith("*.") or s == "*"]
    if wild:
        weak.append({"key": "csp_wildcard_script_src", "severity": "medium",
                     "directive": "script-src",
                     "message": f"script-src allows wildcard sources "
                                f"({', '.join(wild[:3])}) - any subdomain "
                                "takeover becomes script injection"})
    for src in script:
        s = src.lower().strip("'\"")
        if s in ("data:", "blob:"):
            weak.append({"key": "csp_data_script_src", "severity": "high",
                         "directive": "script-src",
                         "message": f"script-src allows {s} - attacker-crafted "
                                    "data: URIs execute as scripts"})
            break
    if is_https and any(s.startswith("http:") for s in script):
        weak.append({"key": "csp_http_on_https", "severity": "low",
                     "directive": "script-src",
                     "message": "script-src allows plain http: sources on an "
                                "https page - MITM can inject scripts"})
    if "object-src" not in policy and "default-src" not in policy:
        weak.append({"key": "csp_no_object_src", "severity": "low",
                     "directive": "object-src",
                     "message": "no object-src (or default-src) - plugins/"
                                "applets unrestricted"})
    if "base-uri" not in policy:
        weak.append({"key": "csp_no_base_uri", "severity": "low",
                     "directive": "base-uri",
                     "message": "no base-uri - <base> tag injection can "
                                "reroute relative URLs"})
    if "frame-ancestors" not in policy:
        weak.append({"key": "csp_no_frame_ancestors", "severity": "low",
                     "directive": "frame-ancestors",
                     "message": "no frame-ancestors - framing policy relies "
                                "on X-Frame-Options alone"})
    if ("report-uri" not in policy and "report-to" not in policy
            and not any(k.endswith("-report-only") for k in policy)):
        weak.append({"key": "csp_no_reporting", "severity": "low",
                     "directive": "report-uri",
                     "message": "no violation reporting (report-uri/report-to) "
                                "- CSP breaks go unnoticed"})
    return weak


class CspAuditPlugin(Plugin):
    id = "csp_audit"
    label = "CSP Policy Audit"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Parse and grade the Content-Security-Policy: unsafe-inline, "
                   "wildcards, data: sources, missing fallbacks.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        is_https = urlparse(base).scheme == "https"

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable, no CSP to audit")
        csp = resp.headers.get("content-security-policy", "")
        if not csp:
            # headers.py already reports the missing header; stay silent.
            return self._skipped("no CSP header (headers plugin covers it)")
        policy = _parse_csp(csp)
        weaknesses = _grade_csp(policy, is_https)
        findings = [self._f(
            "web", w["key"], w["message"],
            source="CSP audit", source_url=base + "/",
            confidence=90, passive=True,
            evidence={"severity": w["severity"],
                      "directive": w["directive"],
                      "policy": csp[:300],
                      "remediation": (
                          f"Tighten the {w['directive']} directive: remove "
                          "unsafe values/wildcards, add nonces or hashes "
                          "for inline scripts, and set object-src 'none' "
                          "plus base-uri 'self'.")})
            for w in weaknesses]
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"CSP present ({len(policy)} directives), "
                   f"{len(weaknesses)} weaknesses")
