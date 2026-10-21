"""HTTP methods audit plugin.

Sends one OPTIONS request and (only if OPTIONS reveals them) checks
for dangerous leftovers: TRACE enabled (XST), WebDAV verbs (PUT/DELETE/
PROPFIND/MOVE/COPY on a non-WebDAV site), and DEBUG. Detection only -
OPTIONS is a standard discovery request; no method is ever exercised
beyond asking what the server advertises.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

RISKY_VERBS = {
    "TRACE": ("http_trace_enabled",
              "TRACE is enabled - XST (cross-site tracing) can steal "
              "HttpOnly cookies via script", "medium"),
    "TRACK": ("http_track_enabled",
              "TRACK is enabled - same XST risk as TRACE", "medium"),
    "PUT": ("http_put_allowed",
            "PUT advertised - file upload may be possible if ACLs are "
            "also misconfigured", "medium"),
    "DELETE": ("http_delete_allowed",
               "DELETE advertised - resource deletion may be possible if "
               "ACLs are also misconfigured", "medium"),
    "PROPFIND": ("http_webdav_enabled",
                 "WebDAV verbs advertised (PROPFIND) - review whether "
                 "WebDAV is intentionally enabled", "low"),
    "DEBUG": ("http_debug_enabled",
              "DEBUG verb advertised - legacy debug handler, disable it",
              "low"),
}


class HttpMethodsPlugin(Plugin):
    id = "http_methods"
    label = "HTTP Methods Audit"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("OPTIONS-based audit: TRACE/XST, PUT/DELETE, WebDAV "
                   "verbs, DEBUG. Advertised methods only, never exercised.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        try:
            r = await fetch(ctx.http, ctx.limiter, "OPTIONS", base + "/",
                            timeout=12, max_retries=0)
        except Exception:
            return self._degraded("OPTIONS request failed")
        allow = r.headers.get("allow", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        # Some servers answer in a Public header instead.
        public = r.headers.get("public", "")
        methods |= {m.strip().upper() for m in public.split(",") if m.strip()}

        findings: List = []
        for verb, (key, message, sev) in RISKY_VERBS.items():
            if verb in methods:
                findings.append(self._f(
                    "web", key, message,
                    source="HTTP methods audit", source_url=base + "/",
                    confidence=90, passive=True,
                    evidence={"severity": sev, "verb": verb,
                              "allow": allow[:200],
                              "remediation": (
                                  f"Disable the {verb} method unless it is "
                                  "required (web server config: Limit "
                                  "directives / request filtering).")}))
        if methods - {"GET", "HEAD", "POST", "OPTIONS"} - set(RISKY_VERBS):
            extra = sorted(methods - {"GET", "HEAD", "POST", "OPTIONS"}
                           - set(RISKY_VERBS))
            findings.append(self._f(
                "web", "http_unusual_verbs",
                f"Unusual verbs advertised: {', '.join(extra)}",
                source="HTTP methods audit", source_url=base + "/",
                confidence=70, passive=True,
                evidence={"severity": "low", "verbs": extra,
                          "remediation": ("Review the advertised verbs; "
                                          "disable anything the app does "
                                          "not need.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"OPTIONS advertised {len(methods)} verbs, "
                   f"{len(findings)} findings")
