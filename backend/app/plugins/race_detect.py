"""Race condition DETECTOR plugin (detection only, never exploitation).

Flags endpoints that LOOK race-prone so a human can test them manually:

1. State-changing endpoints with no visible rate limiting
   (no x-ratelimit-*/ratelimit-* response headers) -> flag for manual
   double-submit / concurrent-request testing.
2. Payment/transfer/cart-style endpoints with no idempotency evidence
   (no Idempotency-Key support visible in headers or API docs) ->
   flag for manual duplicate-submission testing.

BOUNDARY: this plugin NEVER sends concurrent or duplicate requests,
never submits real payments, and never tries to trigger a double-spend.
It only inspects headers/docs and reports "manually test".
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Set, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Plugin, PluginResult, Target

# Path fragments that strongly suggest a state change (money, carts,
# orders). Only these endpoints are probed, so the scan stays quiet.
STATE_CHANGE_KEYWORDS = (
    "pay", "payment", "checkout", "cart", "order", "transfer", "withdraw",
    "purchase", "subscribe", "refund", "deposit", "tip", "donate", "bid",
)

# High-value subset used for the idempotency check.
MONEY_KEYWORDS = (
    "pay", "payment", "checkout", "transfer", "withdraw", "purchase",
    "refund", "deposit",
)

# A small fixed set of common state-changing paths. Probed with GET/OPTIONS
# only, sequentially, one request each - never submitted, never posted.
COMMON_PATHS = (
    "/api/checkout", "/api/cart", "/api/order", "/api/payment",
    "/api/transfer", "/api/pay", "/api/purchase", "/api/subscribe",
    "/api/withdraw", "/api/deposit", "/checkout", "/cart",
)

# Headers that indicate server-side rate limiting is active.
RATELIMIT_HEADERS = (
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "x-ratelimit-policy", "ratelimit-limit", "ratelimit-remaining",
    "ratelimit-reset", "ratelimit-policy", "retry-after",
    "x-ratelimit-by", "x-rate-limit-limit",
)

# Where API docs usually live. Fetched read-only, parsed for
# Idempotency-Key mentions.
DOC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/docs",
             "/api/openapi.json", "/v1/openapi.json")


class RaceDetectPlugin(Plugin):
    id = "race_detect"
    label = "Race Condition Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "api"
    phase = 2  # runs after phase-1 discovery populates the endpoint bus
    description = ("Detects endpoints that may be race-prone (no rate "
                   "limiting, no idempotency keys). Detection only - never "
                   "sends concurrent or duplicate requests.")
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List = []

        # -- gather candidate endpoints ---------------------------------
        # 1. Endpoints other (phase-1) plugins already discovered.
        # 2. A small fixed set of common state-changing paths.
        candidates: List[str] = []
        seen: Set[str] = set()
        for ep in ctx.consume("endpoints"):
            url = str(ep)
            if not url.startswith("http"):
                url = base + (url if url.startswith("/") else "/" + url)
            if any(k in url.lower() for k in STATE_CHANGE_KEYWORDS) and url not in seen:
                seen.add(url)
                candidates.append(url)
        for path in COMMON_PATHS:
            url = base + path
            if url not in seen:
                seen.add(url)
                candidates.append(url)

        idempotency_evidence: bool = False
        checked: List[Tuple[str, Dict[str, str], int]] = []  # (url, headers, status)

        # -- inspect headers on candidates (GET/OPTIONS only) ------------
        for url in candidates[:15]:  # hard cap: stay quiet
            headers, status = await self._safe_probe(ctx, url)
            if status == 0:
                continue
            checked.append((url, headers, status))
            # Check API docs once for idempotency-key support.
            if any(k in url.lower() for k in MONEY_KEYWORDS) and not idempotency_evidence:
                if "idempotency-key" in str(headers).lower():
                    idempotency_evidence = True

        # -- scan API docs for Idempotency-Key mentions ------------------
        for doc_path in DOC_PATHS:
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base + doc_path,
                                timeout=8, max_retries=0)
                if r.status_code == 200 and "idempotency-key" in r.text.lower():
                    idempotency_evidence = True
                    break
            except Exception:
                continue

        # -- report -------------------------------------------------------
        for url, headers, status in checked:
            if status >= 400:
                continue  # dead endpoint - nothing to say
            low = {k.lower() for k in headers}
            has_rl = any(h in low for h in RATELIMIT_HEADERS)
            if not has_rl:
                findings.append(self._f(
                    "api", "race_no_ratelimit",
                    f"State-changing endpoint without rate limiting: {url} - "
                    "manually test for race conditions (sequential testing "
                    "only, do not exploit).",
                    source="Race condition detector", source_url=url,
                    confidence=60, passive=True,
                    evidence={
                        "severity": "medium",
                        "exploitability": "theoretical",
                        "checked_headers": sorted(low)[:8],
                        "remediation": (
                            "Add per-user/per-IP rate limiting to this "
                            "endpoint (e.g. X requests/minute) and re-test. "
                            "Manual race testing only - never attempt to "
                            "trigger a real double-spend."),
                    }))

        money_endpoints = [u for u, _, s in checked
                           if s < 400 and any(k in u.lower() for k in MONEY_KEYWORDS)]
        if money_endpoints and not idempotency_evidence:
            for url in money_endpoints[:5]:
                findings.append(self._f(
                    "api", "race_no_idempotency",
                    f"Payment-style endpoint without idempotency keys: {url} - "
                    "no Idempotency-Key support found in headers or API docs. "
                    "Manually verify duplicate submissions are rejected.",
                    source="Race condition detector", source_url=url,
                    confidence=55, passive=True,
                    evidence={
                        "severity": "medium",
                        "exploitability": "theoretical",
                        "remediation": (
                            "Require an Idempotency-Key header on all "
                            "payment/transfer endpoints and reject replays "
                            "server-side. Verify manually; never submit real "
                            "duplicate payments."),
                    }))

        if not findings:
            findings.append(self._f(
                "api", "race_checks_clean",
                f"Race-condition surface checked ({len(checked)} endpoints): "
                "rate limiting present and/or no payment endpoints exposed.",
                source="Race condition detector", source_url=base,
                confidence=60, passive=True,
                evidence={"severity": "low",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"inspected {len(checked)} candidate endpoints (headers/docs only)")
        res.duration_ms = dur
        return res

    @staticmethod
    async def _safe_probe(ctx: Ctx, url: str) -> Tuple[Dict[str, str], int]:
        """Single read-only GET (fallback OPTIONS). Returns (headers, status).

        Never sends POST/PUT/DELETE and never submits anything - this is
        header inspection, not a state change.
        """
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=8, max_retries=0)
            return dict(r.headers), r.status_code
        except Exception:
            pass
        try:
            r = await fetch(ctx.http, ctx.limiter, "OPTIONS", url, timeout=8, max_retries=0)
            return dict(r.headers), r.status_code
        except Exception:
            return {}, 0
