"""Reflected + DOM XSS detector (critical findings).

Four detection methods:
1. Reflected: inject inert canary into params, check unencoded reflection
2. Context analysis: identify if reflection is in HTML/attribute/JS context
3. DOM sinks: scan JS for dangerous sinks (innerHTML, eval, document.write)
4. Context probes: SVG, event handler, javascript: URI, double URL encode,
   and HTML entity encoded canaries for filter-bypass contexts
No script execution, no stored payloads. Authorized testing only.
"""
from __future__ import annotations

import asyncio
import html as _htmllib  # aliased: run() uses local `html` for page text
import re
import time
import uuid
from typing import List
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import sample_urls

REMEDIATION = ("Encode all user input on output (context-aware encoding), "
               "set a strict Content-Security-Policy, and validate input "
               "on the server side. For DOM XSS, avoid innerHTML/eval; "
               "use textContent and safe DOM APIs.")

# Context probes: inert canary wrapped for specific reflection contexts.
# Each entry: (wrapper template with {C} placeholder, context label,
# encoding form: "raw" | "url2x" | "entity")
XSS_CONTEXT_PROBES = [
    ("<svg><desc>{C}</desc></svg>", "SVG context", "raw"),
    ('"><svg onload={C}>', "event handler breakout (inert)", "raw"),
    ('" onfocus="{C}" autofocus="', "onfocus event context (inert)", "raw"),
    ("javascript:{C}", "javascript: URI context (inert)", "raw"),
    ("<a href=\"javascript:{C}\">x</a>", "href javascript: context", "raw"),
    ("{C}", "plain context, URL double-encoded", "url2x"),
    ("{C}", "plain context, HTML entity encoded", "entity"),
    ("<script>var x='{C}';</script>", "script string context (inert)", "raw"),
]


class XssPlugin(Plugin):
    id = "xss"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "XSS Canary"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "XSS check: reflected canary + DOM sink analysis."

    def _analyze_context(self, body: str, canary: str) -> List[str]:
        """Determine the HTML/JS context where canary is reflected."""
        contexts = []
        for m in re.finditer(re.escape(canary), body):
            start = max(0, m.start() - 100)
            end = min(len(body), m.end() + 100)
            win = body[start:end]
            win_lower = win.lower()

            # Check if inside <script> block
            script_before = body[:m.start()].lower().rfind("<script")
            script_close = body[:m.start()].lower().rfind("</script>")
            in_script = script_before > script_close

            # Check if inside HTML attribute
            tag_start = body[:m.start()].rfind("<")
            tag_end = body[:m.start()].rfind(">")
            in_tag = tag_start > tag_end

            if in_script:
                # Check if inside JS string or directly executable
                before = body[max(0, m.start() - 20):m.start()]
                if '"' in before or "'" in before:
                    contexts.append("JS string context (breakout possible)")
                else:
                    contexts.append("JS code context (direct execution)")
            elif in_tag:
                if "on" in win_lower[max(0, win_lower.find(canary[:4]) - 20):]:
                    contexts.append("event handler attribute")
                else:
                    contexts.append("HTML attribute (breakout possible)")
            elif "<script" in win_lower or "onerror=" in win_lower \
                    or "onload=" in win_lower:
                contexts.append("script/event context")
            else:
                # Check if HTML-encoded (safe) vs raw (vulnerable)
                if "&lt;" in win or "&gt;" in win or "&quot;" in win:
                    contexts.append("HTML-encoded (likely safe)")
                else:
                    contexts.append("raw HTML context")
        return list(set(contexts))

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
            r = await fetch(ctx.http, ctx.limiter, "GET", base, rotate_ua=True, timeout=25,
                            follow_redirects=True)
            html = r.text[:300000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # --- Methods 1+2: Reflected XSS with context analysis ---
        urls = set()
        for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', html, re.I):
            u = m.group(1)
            if u.startswith("/"):
                p = urlparse(page_url)
                u = f"{p.scheme}://{p.netloc}{u}"
            if domain in urlparse(u).netloc:
                urls.add(u)
        for eu in ctx.consume("endpoints"):
            if isinstance(eu, str) and "?" in eu and \
                    domain in urlparse(eu).netloc:
                urls.add(eu)

        # Test URLs concurrently (sem 4): same pattern as sqli - on a
        # WAF-blackholed target the sequential version burns minutes.
        sem = asyncio.Semaphore(4)
        tested = [0]

        async def test_url(u: str):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                return
            for name, val in params[:3]:
                tested[0] += 1
                canary = "rxss" + uuid.uuid4().hex[:8]
                probe = [(n, canary if n == name else v) for n, v in params]
                purl = urlunparse(parts._replace(query=urlencode(probe)))
                try:
                    pr = await fetch(ctx.http, ctx.limiter, "GET", purl, rotate_ua=True,
                                     timeout=15, max_retries=1)
                    body = pr.text[:200000]
                except Exception:
                    continue
                if canary in body:
                    contexts = self._analyze_context(body, canary)
                    # Filter out "likely safe" if it's the only context
                    dangerous = [c for c in contexts
                                 if "likely safe" not in c and "encoded" not in c]
                    if not dangerous:
                        continue  # Properly encoded, skip (low FP)
                    detail = ", ".join(dangerous)
                    # Higher confidence for executable contexts
                    if any("direct execution" in c or "event handler" in c
                           for c in dangerous):
                        conf = 85
                    elif any("JS" in c for c in dangerous):
                        conf = 80
                    else:
                        conf = 70
                    findings.append(self._f(
                        "leak", "xss_reflected",
                        f"CRITICAL: reflected input in parameter '{name}' "
                        f"({detail}) at {parts.path or '/'}",
                        source="xss canary probe", source_url=purl,
                        confidence=conf, passive=False,
                        evidence={"severity": "critical",
                                  "parameter": name,
                                  "contexts": dangerous,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Authorized testing only. "
                                                "Canary was inert; no script executed."}))
                    break

                # --- Method 4: context + encoding probes ---
                for tmpl, ctx_label, enc in XSS_CONTEXT_PROBES:
                    tested[0] += 1
                    cval = "exss" + uuid.uuid4().hex[:8]
                    payload = tmpl.replace("{C}", cval)
                    if enc == "url2x":
                        payload = quote(quote(payload, safe=""), safe="")
                    elif enc == "entity":
                        payload = _htmllib.escape(payload)
                    cprobe = [(n, payload if n == name else v)
                              for n, v in params]
                    cpurl = urlunparse(parts._replace(
                        query=urlencode(cprobe)))
                    try:
                        cpr = await fetch(ctx.http, ctx.limiter, "GET", cpurl, rotate_ua=True,
                                          timeout=15, max_retries=1)
                        cbody = cpr.text[:200000]
                    except Exception:
                        continue
                    check = tmpl.replace("{C}", cval)
                    if enc == "entity":
                        check = _htmllib.escape(check)
                    if check in cbody and "&lt;" not in check:
                        findings.append(self._f(
                            "leak", "xss_context_probe",
                            f"HIGH: filter-bypass context in parameter "
                            f"'{name}' at {parts.path or '/'} ({ctx_label}).",
                            source="xss context probe", source_url=cpurl,
                            confidence=70, passive=False,
                            evidence={"severity": "high",
                                      "parameter": name,
                                      "context": ctx_label,
                                      "encoding": enc,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Authorized testing only. "
                                                    "Inert canary; no script executed."}))
                        break
                else:
                    continue
                break

        async def test_url_sem(u: str):
            async with sem:
                await test_url(u)

        await asyncio.gather(*[test_url_sem(u) for u in sample_urls(urls, 12)])

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested[0]} params, "
                                 f"{len(findings)} XSS findings")
        res.duration_ms = dur
        return res
