"""Subresource Integrity (SRI) audit plugin.

Parses the homepage for <script> and <link rel=stylesheet> tags with
cross-origin src/href and reports those missing an integrity attribute.
A third-party script without SRI can be swapped by a compromised CDN;
with SRI the browser refuses the tampered file.

Passive: parses the already-fetched homepage HTML. No extra requests.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

TAG_RE = re.compile(
    r"<(script|link)\b[^>]*?(src|href)\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.I)


class SriAuditPlugin(Plugin):
    id = "sri_audit"
    label = "Subresource Integrity"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Audit cross-origin scripts/stylesheets for missing "
                   "SRI integrity attributes.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        host = urlparse(base).netloc

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable")
        html = (resp.text or "")[:300000]

        findings: List = []
        seen = set()
        for m in TAG_RE.finditer(html):
            tag, _attr, url = m.group(1).lower(), m.group(2), m.group(3)
            if tag == "link" and "stylesheet" not in m.group(0).lower():
                continue
            u = url.strip()
            if u.startswith("data:") or u.startswith("//"):
                u = ("https:" if urlparse(base).scheme == "https"
                     else "http:") + u if u.startswith("//") else u
            parsed = urlparse(u)
            if not parsed.netloc or parsed.netloc == host:
                continue  # same-origin, SRI optional
            tag_html = m.group(0)
            if "integrity" in tag_html.lower():
                continue
            key = parsed.netloc + parsed.path
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._f(
                "web", "sri_missing",
                f"Cross-origin <{tag}> from {parsed.netloc} has no SRI "
                f"integrity attribute",
                source="SRI audit", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": "low", "tag": tag,
                          "src": u[:160],
                          "remediation": (
                              "Add an integrity=\"sha384-...\" attribute "
                              "(generate with: openssl dgst -sha384 -binary "
                              "file.js | openssl base64 -A) and keep "
                              "crossorigin=\"anonymous\".")}))
            if len(findings) >= 20:
                break
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"checked cross-origin subresources, {len(findings)} "
                   "missing SRI")
