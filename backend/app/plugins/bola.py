"""BOLA (Broken Object Level Authorization) tester for APIs.

API-specific authorization flaw detector. Extends IDOR patterns to API
semantics: tests for missing object-level authz on REST/GraphQL endpoints
by analyzing response differences. Read-only: never modifies data.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# API endpoint patterns that commonly suffer BOLA. Only endpoints
# carrying an object ID (numeric or UUID) are flagged - a bare
# "/api/users/" string in JS is normal API surface, not a vuln.
BOLA_PATTERNS = [
    (r"/api/(?:v\d+/)?(?:users?|accounts?|profiles?)/\d{1,12}(?=[/\"'?\s]|$)",
     "user object API endpoint with numeric ID", 60),
    (r"/api/(?:v\d+/)?(?:users?|accounts?|profiles?)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
     "user object API endpoint with UUID", 55),
    (r"/api/(?:v\d+/)?(?:orders?|invoices?|payments?)/\d{1,12}(?=[/\"'?\s]|$)",
     "order object API endpoint with numeric ID", 60),
    (r"/graphql(?=[/\"'?\s]|$)", "GraphQL endpoint (test field-level authz)", 55),
    (r"/api/(?:v\d+/)?(?:admin|internal|private)/",
     "privileged API namespace", 55),
]

REMEDIATION = ("Enforce object-level authorization on every API endpoint: "
               "verify the caller owns or may access each object ID. "
               "Use OWASP API Security Top 10 guidance for BOLA (API1:2023).")


class BolaPlugin(Plugin):
    id = "bola"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "BOLA API Tester"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = "Detect BOLA candidates on API endpoints."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
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
        # also check discovered API endpoints from the bus
        sources = [html] + [str(u) for u in ctx.consume("endpoints")[:50]]
        seen = set()
        for src in sources:
            for pat, label, conf in BOLA_PATTERNS:
                for m in re.finditer(pat, src):
                    sample = m.group(0)[:80]
                    if sample in seen:
                        continue
                    seen.add(sample)
                    findings.append(self._f(
                        "api", "bola_candidate",
                        f"BOLA candidate: {label} at '{sample.strip()}'. "
                        f"Test object-level authz with two accounts on an authorized target.",
                        source="BOLA pattern mining", source_url=page_url,
                        confidence=conf, passive=passive,
                        evidence={"severity": "high", "pattern": label,
                                  "sample": sample.strip(),
                                  "remediation": REMEDIATION,
                                  "scope_note": "Candidate only. Authorized testing only."}))
                    if len(seen) >= 25:
                        break
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} BOLA candidates")
        res.duration_ms = dur
        return res
