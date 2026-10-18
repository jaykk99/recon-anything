"""Reflected XSS canary detector (Milestone: critical findings).

Non-destructive: injects a unique inert canary string into discovered
query parameters and checks whether it is reflected unencoded in the
response. No script execution, no stored payloads. One probe per
parameter. Authorized testing only.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Encode all user input on output (context-aware encoding), "
               "set a strict Content-Security-Policy, and validate input "
               "on the server side.")


class XssPlugin(Plugin):
    id = "xss"
    label = "XSS Canary"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "Reflected XSS check: inert canary per query param."

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
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:300000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        urls = set()
        for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', html, re.I):
            u = m.group(1)
            if u.startswith("/"):
                p = urlparse(page_url)
                u = f"{p.scheme}://{p.netloc}{u}"
            if domain in urlparse(u).netloc:
                urls.add(u)
        # chain: URLs discovered by crawler/forms/jsminer
        for eu in ctx.consume("endpoints"):
            if isinstance(eu, str) and "?" in eu and \
                    domain in urlparse(eu).netloc:
                urls.add(eu)

        tested = 0
        for u in list(urls)[:10]:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            for name, val in params[:3]:
                tested += 1
                canary = "rxss" + uuid.uuid4().hex[:8]
                probe = [(n, (canary) if n == name else v) for n, v in params]
                purl = urlunparse(parts._replace(query=urlencode(probe)))
                try:
                    pr = await fetch(ctx.http, ctx.limiter, "GET", purl, timeout=15)
                    body = pr.text[:200000]
                except Exception:
                    continue
                if canary in body:
                    # check if it lands inside an executable context
                    ctx_flags = []
                    for m in re.finditer(re.escape(canary), body):
                        win = body[max(0, m.start() - 60):m.end() + 60]
                        if "<script" in win.lower() or "onerror=" in win.lower() \
                                or "onload=" in win.lower():
                            ctx_flags.append("script/event context")
                        elif "<" in win and ">" in win:
                            ctx_flags.append("HTML context")
                    detail = ", ".join(sorted(set(ctx_flags))) or "reflected"
                    findings.append(self._f(
                        "leak", "xss_reflected",
                        f"CRITICAL: reflected input in parameter '{name}' "
                        f"({detail}) at {parts.path or '/'}",
                        source="xss canary probe", source_url=purl,
                        confidence=80 if ctx_flags else 65, passive=False,
                        evidence={"severity": "critical",
                                  "parameter": name,
                                  "context": detail,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Authorized testing only. Canary was inert; no script executed."}))
                    break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested} params across {len(urls)} URLs, "
                                 f"{len(findings)} XSS reflections")
        res.duration_ms = dur
        return res
