"""HTML injection detector (high findings).

Broader than reflected XSS: send an inert markup canary
(<b>htmlprobe9</b>) in params and check for RAW, unencoded
reflection in the response body. No script tags, no event
handlers, no script execution. Authorized testing only.
"""
from __future__ import annotations

import time
import uuid
from typing import List
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url

REMEDIATION = ("Encode all user input on output with context-aware "
               "HTML encoding, apply strict input validation, and "
               "ship a Content-Security-Policy as defense in depth.")

CANARY_OPEN = "<b>"
CANARY_CLOSE = "</b>"


class HtmlInjectionPlugin(Plugin):
    id = "htmli"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "HTML Injection"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "HTML injection: inert markup canary reflection check."

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
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        tested = 0
        for u in list(urls)[:10]:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            for name, val in params[:3]:
                tested += 1
                tag = "htmlprobe" + uuid.uuid4().hex[:6]
                canary = CANARY_OPEN + tag + CANARY_CLOSE
                purl = probe_url(parts, params, name, canary)
                try:
                    pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                     timeout=15)
                    body = pr.text[:200000]
                except Exception:
                    continue
                raw_hit = canary in body
                encoded_hit = ("&lt;b&gt;" + tag in body) or \
                    ("&lt;/b&gt;" in body)
                if raw_hit and not encoded_hit:
                    findings.append(self._f(
                        "leak", "html_injection",
                        f"HIGH: HTML injection in parameter '{name}' at "
                        f"{parts.path or '/'} (inert <b> canary reflected "
                        f"unencoded).",
                        source="html canary probe", source_url=purl,
                        confidence=75, passive=False,
                        evidence={"severity": "high",
                                  "method": "canary reflection",
                                  "parameter": name,
                                  "canary": canary,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Authorized testing only. "
                                                "Inert markup only, no script."}))
                    break

        res = self._ok(findings, f"probed {tested} params across "
                                 f"{len(urls)} URLs, {len(findings)} HTML signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
