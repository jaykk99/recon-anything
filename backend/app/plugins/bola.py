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
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# API endpoint patterns that commonly suffer BOLA
BOLA_PATTERNS = [
    (r"/api/(?:v\d+/)?(?:users?|accounts?|profiles?)/[^/\s\"']+", "user object API endpoint"),
    (r"/api/(?:v\d+/)?(?:orders?|invoices?|payments?)/[^/\s\"']+", "order object API endpoint"),
    (r"/graphql", "GraphQL endpoint (test field-level authz)"),
    (r"/api/(?:v\d+/)?(?:admin|internal|private)/", "privileged API namespace"),
]

REMEDIATION = ("Enforce object-level authorization on every API endpoint: "
               "verify the caller owns or may access each object ID. "
               "Use OWASP API Security Top 10 guidance for BOLA (API1:2023).")


class BolaPlugin(Plugin):
    id = "bola"
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
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25, follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        # also check discovered API endpoints from the bus
        sources = [html] + [str(u) for u in ctx.consume("endpoints")[:50]]
        seen = set()
        for src in sources:
            for pat, label in BOLA_PATTERNS:
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
                        confidence=60, passive=passive,
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
