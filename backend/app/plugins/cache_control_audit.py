"""Cache-Control audit plugin.

headers.py reports a *missing* Cache-Control; this plugin grades an
*existing* one. It parses the directives for the classic cache-safety
failures: `public` (or a long max-age) on a response that sets cookies,
session content left cacheable by shared caches, a missing
`Vary: Cookie` when a cookie-setting response is cacheable, a
far-future max-age on HTML, conflicting directives, and unknown
directives.

Passive: one GET of the homepage (shared fetch_page cache).
"""
from __future__ import annotations

import time
from typing import Dict, List

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

LONG_HTML_MAX_AGE = 86400  # 1 day: HTML cached longer than this goes stale

KNOWN_DIRECTIVES = {
    "max-age", "s-maxage", "no-cache", "no-store", "no-transform",
    "public", "private", "must-revalidate", "proxy-revalidate",
    "must-understand", "immutable", "stale-while-revalidate",
    "stale-if-error", "min-fresh", "max-stale", "only-if-cached",
}


def _parse_cache_control(value: str) -> Dict[str, object]:
    """Parse a Cache-Control header value into {directive: value|True}."""
    out: Dict[str, object] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().strip('"')
        else:
            out[part.strip().lower()] = True
    return out


def _grade_cache_control(directives: Dict[str, object],
                         has_cookie: bool, vary: str,
                         is_html: bool) -> List[dict]:
    """Return [{key, severity, message}] weaknesses."""
    weak = []

    def _int(name: str) -> int:
        try:
            return int(str(directives.get(name, "0")))
        except (ValueError, TypeError):
            return 0

    no_store = "no-store" in directives
    private = "private" in directives
    public = "public" in directives
    cacheable = not no_store and not private
    max_age = _int("max-age")
    s_maxage = _int("s-maxage")

    if public and has_cookie:
        weak.append({"key": "cache_control_public_with_cookie",
                     "severity": "high",
                     "message": "Cache-Control: public on a response that "
                                "sets a cookie - shared caches may store and "
                                "serve one user's session content to another"})
    if cacheable and has_cookie:
        weak.append({"key": "cache_control_session_cacheable",
                     "severity": "medium",
                     "message": "response sets a cookie but is cacheable "
                                "(no private/no-store) - session content may "
                                "be stored by shared caches"})
        if "cookie" not in vary.lower():
            weak.append({"key": "cache_control_no_vary_cookie",
                         "severity": "medium",
                         "message": "cacheable response sets a cookie but "
                                    "has no Vary: Cookie - a shared cache "
                                    "may serve one user's page to another"})
    if is_html and max_age > LONG_HTML_MAX_AGE and not no_store:
        weak.append({"key": "cache_control_long_max_age_html",
                     "severity": "low",
                     "message": f"HTML max-age={max_age} (> {LONG_HTML_MAX_AGE}s) "
                                "- stale pages served long after the site "
                                "changes"})
    if no_store and (public or max_age > 0):
        weak.append({"key": "cache_control_conflicting_directives",
                     "severity": "low",
                     "message": "Cache-Control mixes no-store with "
                                f"{'public' if public else 'max-age'} - "
                                "caches disagree on whether to store it"})
    if s_maxage and max_age and s_maxage > max_age:
        weak.append({"key": "cache_control_s_maxage_exceeds_max_age",
                     "severity": "low",
                     "message": f"s-maxage={s_maxage} exceeds "
                                f"max-age={max_age} - shared caches keep the "
                                "response longer than browsers"})
    if "immutable" in directives and is_html:
        weak.append({"key": "cache_control_immutable_html",
                     "severity": "low",
                     "message": "immutable on HTML - browsers will never "
                                "revalidate the page, even after the site "
                                "changes"})
    unknown = sorted(set(directives) - KNOWN_DIRECTIVES)
    if unknown:
        weak.append({"key": "cache_control_unknown_directive",
                     "severity": "low",
                     "message": f"unknown Cache-Control directive(s): "
                                f"{', '.join(unknown)} - likely a typo, "
                                "caches ignore it"})
    return weak


class CacheControlAuditPlugin(Plugin):
    id = "cache_control_audit"
    label = "Cache-Control Audit"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Grade the Cache-Control policy: public/session-content "
                   "caching, missing Vary: Cookie, stale HTML, conflicts.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable, no Cache-Control "
                                  "to audit")
        raw = resp.headers.get("cache-control", "")
        if not raw:
            # headers.py already reports the missing header; stay silent.
            return self._skipped("no Cache-Control header (headers plugin "
                                 "covers it)")
        directives = _parse_cache_control(raw)
        has_cookie = bool(resp.headers.get("set-cookie", ""))
        vary = resp.headers.get("vary", "") or ""
        content_type = (resp.headers.get("content-type", "") or "").lower()
        is_html = "text/html" in content_type
        weaknesses = _grade_cache_control(directives, has_cookie, vary,
                                          is_html)
        findings = [self._f(
            "web", w["key"], w["message"],
            source="Cache-Control audit", source_url=base + "/",
            confidence=90, passive=True,
            evidence={"severity": w["severity"],
                      "header": raw[:300],
                      "remediation": (
                          "Mark session responses private, no-store (or "
                          "private, no-cache, must-revalidate), add "
                          "Vary: Cookie when a cacheable response sets a "
                          "cookie, and keep HTML max-age short.")})
            for w in weaknesses]
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"Cache-Control present ({len(directives)} directives), "
                   f"{len(weaknesses)} weaknesses")
