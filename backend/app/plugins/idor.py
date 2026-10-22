"""IDOR pattern detector with sequential vs UUID analysis.

Passive analysis: finds predictable object references in URLs and API
paths, distinguishes sequential numeric IDs (high risk) from UUIDs
(low risk), and mines JSON API responses for ID patterns. No
exploitation: we never request another user's object. Each finding
explains how to test with two accounts on an authorized target.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .injutil import same_domain
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (pattern, label, risk)
# Only object references tied to accounts/orders/APIs are flagged.
# Plain numeric query params (?id=123), document/file paths, blog post
# IDs and product IDs are NORMAL on benign sites - flagging them was
# pure noise, so those patterns were removed. UUIDs are not guessable
# and are never flagged (below the confidence floor by design).
ID_PATTERNS = [
    (r"/(users?|accounts?|profiles?|customers?|members?)/(\d{1,10})([/\"'?\s]|$)",
     "user object with numeric ID", "high"),
    (r"/(orders?|invoices?|payments?|transactions?)/(\d{1,10})([/\"'?\s]|$)",
     "order object with numeric ID", "high"),
    (r"/api/(?:v\d+/)?([a-z_]+)/(\d{1,10})([/\"'?\s]|$)",
     "API object with numeric ID", "high"),
]

REMEDIATION = ("Enforce server-side authorization on every object access: "
               "check that the requesting user owns the requested ID. "
               "Prefer unguessable UUIDs and never trust client-supplied IDs.")


class IdorPlugin(Plugin):
    id = "idor"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "IDOR Pattern Finder"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Flag predictable IDs; sequential=high risk, UUID=low."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        seen = set()

        def emit_idor(label: str, sample: str, risk: str):
            key = (label, sample)
            if key in seen or len(seen) >= 25:
                return
            seen.add(key)
            findings.append(self._f(
                "web", "idor_candidate",
                f"HIGH: {label} like '{sample.strip()}'. SEQUENTIAL IDs "
                f"are trivially enumerable. Test ID+1, ID-1 with two accounts.",
                source="IDOR pattern mining", source_url=page_url,
                confidence=65, passive=passive,
                evidence={"severity": "high", "pattern": label,
                          "sample": sample.strip(),
                          "id_risk": risk,
                          "remediation": REMEDIATION,
                          "scope_note": "Candidate only. Never access another "
                                        "user's data without explicit authorization."}))

        # 1. URL/path patterns
        for pat, label, risk in ID_PATTERNS:
            for m in re.finditer(pat, html):
                emit_idor(label, m.group(0)[:80], risk)

        # 2. Check JS files for API endpoints with IDs
        if not passive or True:  # lightweight, always try
            for sm in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']',
                                  html, re.I):
                from urllib.parse import urljoin
                full = urljoin(page_url, sm.group(1))
                if same_domain(full, domain):
                    try:
                        jr = await fetch(ctx.http, ctx.limiter, "GET", full,
                                         timeout=10)
                        if jr.status_code == 200:
                            js = jr.text[:300000]
                            for pat, label, risk in ID_PATTERNS:
                                for m in re.finditer(pat, js):
                                    emit_idor(f"JS: {label}",
                                              m.group(0)[:80], risk)
                    except Exception:
                        continue
                if len(seen) >= 25:
                    break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} IDOR candidates")
        res.duration_ms = dur
        return res
