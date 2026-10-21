"""HSTS (Strict-Transport-Security) analysis plugin.

headers.py reports a *missing* HSTS header; this plugin grades an
*existing* one: max-age too short for preload (< 31536000), missing
includeSubDomains, missing preload token, and http:// downgrade of the
bare domain (the classic SSL-stripping gap when only www is HSTS).

Passive: homepage header read (shared fetch_page cache) + one http://
probe of the bare domain.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

MIN_PRELOAD_AGE = 31536000  # 1 year, per hstspreload.org


def _parse_hsts(value: str) -> Dict[str, object]:
    out: Dict[str, object] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
        else:
            out[part.strip().lower()] = True
    return out


class HstsPlugin(Plugin):
    id = "hsts"
    label = "HSTS Analysis"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Grade the HSTS policy: max-age, includeSubDomains, "
                   "preload readiness, bare-domain downgrade.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable, no HSTS to analyze")
        raw = resp.headers.get("strict-transport-security", "")
        if not raw:
            return self._skipped("no HSTS header (headers plugin covers it)")

        h = _parse_hsts(raw)
        findings: List = []
        try:
            max_age = int(str(h.get("max-age", "0")).strip('"'))
        except (ValueError, TypeError):
            max_age = 0
        if max_age <= 0:
            findings.append(self._f(
                "web", "hsts_invalid_max_age",
                f"HSTS max-age is invalid ({h.get('max-age')!r}) - "
                "browsers ignore the policy",
                source="HSTS analysis", source_url=base + "/",
                confidence=90, passive=True,
                evidence={"severity": "medium", "header": raw[:200],
                          "remediation": (
                              "Set Strict-Transport-Security: "
                              "max-age=31536000; includeSubDomains.")}))
        elif max_age < MIN_PRELOAD_AGE:
            findings.append(self._f(
                "web", "hsts_short_max_age",
                f"HSTS max-age={max_age} (< 31536000) - too short for "
                "preload, brief policy gaps after expiry",
                source="HSTS analysis", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": "low", "max_age": max_age,
                          "remediation": (
                              "Raise max-age to 31536000 (1 year) minimum; "
                              "preload requires it.")}))
        if "includesubdomains" not in h:
            findings.append(self._f(
                "web", "hsts_no_includesubdomains",
                "HSTS lacks includeSubDomains - subdomains stay "
                "SSL-strippable",
                source="HSTS analysis", source_url=base + "/",
                confidence=90, passive=True,
                evidence={"severity": "medium", "header": raw[:200],
                          "remediation": (
                              "Add includeSubDomains to the HSTS header.")}))
        if "preload" not in h:
            findings.append(self._f(
                "web", "hsts_no_preload",
                "HSTS lacks the preload token - first visit still "
                "vulnerable to SSL stripping",
                source="HSTS analysis", source_url=base + "/",
                confidence=75, passive=True,
                evidence={"severity": "low", "header": raw[:200],
                          "remediation": (
                              "Add 'preload' and submit the domain at "
                              "hstspreload.org (requires max-age >= "
                              "31536000 + includeSubDomains).")}))

        # Bare-domain downgrade probe: http://domain must not serve 200.
        if target.type == "domain":
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET",
                                f"http://{domain}/", timeout=10,
                                follow_redirects=False, max_retries=0)
                if r.status_code == 200:
                    findings.append(self._f(
                        "web", "hsts_bare_domain_downgrade",
                        f"http://{domain}/ returns 200 instead of "
                        "redirecting to https - HSTS can't protect the "
                        "first plaintext visit",
                        source="HSTS analysis",
                        source_url=f"http://{domain}/",
                        confidence=95, passive=True,
                        evidence={"severity": "medium", "status": 200,
                                  "remediation": (
                                      f"Redirect all http://{domain}/ traffic "
                                      "to https with a 301.")}))
            except Exception:
                pass

        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"HSTS present, {len(findings)} weaknesses")
