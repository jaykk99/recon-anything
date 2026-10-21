"""Mixed content detection plugin.

On https pages, any subresource loaded over plain http:// (scripts,
stylesheets, images, iframes, XHR/fetch, fonts) is mixed content:
browsers block active mixed content and warn on the rest, and a MITM
can replace the http:// resources. Scans the homepage HTML for
http:// subresource references.

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

# tag/attr pairs whose values are subresource URLs
SUBRESOURCE_ATTRS = [
    ("script", "src"), ("link", "href"), ("img", "src"),
    ("iframe", "src"), ("embed", "src"), ("object", "data"),
    ("source", "src"), ("video", "src"), ("audio", "src"),
    ("track", "src"),
]

# active mixed content (browsers block it) vs passive (warning only)
ACTIVE_TAGS = {"script", "iframe", "embed", "object", "link"}


class MixedContentPlugin(Plugin):
    id = "mixed_content"
    label = "Mixed Content"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Find http:// subresources on https pages (active vs "
                   "passive mixed content).")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        if urlparse(base).scheme != "https":
            return self._skipped("page is not https, mixed content N/A")

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable")
        html = (resp.text or "")[:300000]

        findings: List = []
        seen = set()
        for tag, attr in SUBRESOURCE_ATTRS:
            for m in re.finditer(
                    rf"<{tag}\b[^>]*\b{attr}\s*=\s*[\"']([^\"']+)[\"']",
                    html, re.I):
                url = m.group(1).strip()
                if not url.lower().startswith("http://"):
                    continue
                host = urlparse(url).netloc
                key = (tag, host)
                if key in seen:
                    continue
                seen.add(key)
                active = tag in ACTIVE_TAGS
                findings.append(self._f(
                    "web",
                    "mixed_content_active" if active else "mixed_content_passive",
                    f"{'Active' if active else 'Passive'} mixed content: "
                    f"<{tag}> loads http://{host}/... on an https page",
                    source="mixed content scan", source_url=base + "/",
                    confidence=90, passive=True,
                    evidence={"severity": "medium" if active else "low",
                              "tag": tag, "host": host,
                              "url": url[:160],
                              "remediation": (
                                  "Serve the subresource over https or host "
                                  "it locally; use protocol-relative or "
                                  "https:// URLs everywhere.")}))
                if len(findings) >= 25:
                    break
            if len(findings) >= 25:
                break

        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"scanned homepage subresources, {len(findings)} "
                   "mixed-content refs")
