"""IDOR pattern detector (Milestone: critical findings).

Passive analysis: finds predictable object references in URLs and API
paths (numeric IDs, sequential UUIDs, /users/123 style routes) and
flags them as IDOR test candidates. No exploitation: we never request
another user's object. Each finding explains how to test with two
accounts on an authorized target.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

ID_PATTERNS = [
    (r"/(users?|accounts?|profiles?|customers?|members?)/(\d{1,10})([/\"'?\s]|$)", "user object with numeric ID"),
    (r"/(orders?|invoices?|payments?|transactions?)/(\d{1,10})([/\"'?\s]|$)", "order object with numeric ID"),
    (r"/api/(?:v\d+/)?([a-z_]+)/(\d{1,10})([/\"'?\s]|$)", "API object with numeric ID"),
    (r"[?&](id|user_id|account_id|order_id|uid)=(\d{1,10})(&|\"|'|\s|$)", "numeric ID query param"),
    (r"/(documents?|files?|reports?|attachments?)/(\d{1,10})([/\"'?\s]|$)", "document object with numeric ID"),
]

REMEDIATION = ("Enforce server-side authorization on every object access: "
               "check that the requesting user owns the requested ID. "
               "Prefer unguessable UUIDs and never trust client-supplied IDs.")


class IdorPlugin(Plugin):
    id = "idor"
    label = "IDOR Pattern Finder"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Flag predictable object IDs as IDOR test candidates."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        seen = set()
        for pat, label in ID_PATTERNS:
            for m in re.finditer(pat, html):
                sample = m.group(0)[:80]
                key = (label, sample)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._f(
                    "web", "idor_candidate",
                    f"HIGH: {label} like '{sample.strip()}'. Test by swapping "
                    f"the ID with a second account's object on an authorized target.",
                    source="IDOR pattern mining", source_url=page_url,
                    confidence=65, passive=passive,
                    evidence={"severity": "high", "pattern": label,
                              "sample": sample.strip(),
                              "remediation": REMEDIATION,
                              "scope_note": "Candidate only. Never access another user's data without explicit authorization."}))
                if len(seen) >= 25:
                    break
            if len(seen) >= 25:
                break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} IDOR candidates")
        res.duration_ms = dur
        return res
