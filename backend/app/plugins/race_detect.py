"""Race condition DETECTOR plugin (detection only, never exploitation).

Flags payment-style endpoints that show no idempotency-key support in
headers or API docs, so a human can manually test duplicate
submissions. Absence of x-ratelimit-* headers is NOT flagged: most
APIs rate-limit without advertising it, so that check was pure
noise (fired on nearly every target, never a true positive).

BOUNDARY: this plugin NEVER sends concurrent or duplicate requests,
never submits real payments, and never tries to trigger a double-spend.
It only inspects headers/docs and reports "manually test".
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Set, Tuple

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

# NOTE: an earlier version also probed a fixed list of common
# state-changing paths (/api/checkout, /cart, ...). That was removed:
# fabricated paths 404 on real targets (pure noise) and 200 on
# catch-all servers (false positives). Only endpoints actually
# discovered by phase-1 plugins are inspected now.

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
    description = ("Detects payment-style endpoints without idempotency-key "
                   "support. Detection only - never sends concurrent or "
                   "duplicate requests.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List = []

        # -- gather candidate endpoints ---------------------------------
        # Only endpoints other (phase-1) plugins already discovered on
        # the target. No fabricated paths (see note above).
        candidates: List[str] = []
        seen: Set[str] = set()
        for ep in ctx.consume("endpoints"):
            url = str(ep)
            if not url.startswith("http"):
                url = base + (url if url.startswith("/") else "/" + url)
            if any(k in url.lower() for k in STATE_CHANGE_KEYWORDS) and url not in seen:
                seen.add(url)
                candidates.append(url)

        idempotency_evidence: bool = False
        checked: List[Tuple[str, Dict[str, str], int]] = []  # (url, headers, status)

        # -- inspect headers on candidates (GET only, concurrent) --------
        # Single read-only GET each (no OPTIONS fallback - one probe per
        # endpoint keeps the plugin inside the 30s budget).
        sem = asyncio.Semaphore(5)

        async def probe_one(url: str):
            async with sem:
                hdrs, status = await self._safe_probe(ctx, url)
                if status:
                    checked.append((url, hdrs, status))

        await asyncio.gather(*(probe_one(u) for u in candidates[:10]))

        # -- scan API docs for Idempotency-Key mentions ------------------
        async def doc_one(doc_path: str):
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base + doc_path,
                                timeout=6, max_retries=0)
                return r.status_code == 200 and \
                    "idempotency-key" in r.text.lower()
            except Exception:
                return False

        async with sem:
            doc_hits = await asyncio.gather(
                *(doc_one(p) for p in DOC_PATHS))
        if any(doc_hits):
            idempotency_evidence = True

        # -- report -------------------------------------------------------
        # Only money-movement endpoints that actually respond (2xx/3xx)
        # with no idempotency-key support anywhere. This is a manual-test
        # lead, not a confirmed flaw.
        money_endpoints = [u for u, _, s in checked
                           if s < 400 and any(k in u.lower() for k in MONEY_KEYWORDS)]
        if money_endpoints and not idempotency_evidence:
            for url, headers, _ in checked:
                if "idempotency-key" in str(headers).lower():
                    idempotency_evidence = True
                    break
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

        dur = int((time.monotonic() - t0) * 1000)
        note = f"inspected {len(checked)} candidate endpoints (headers/docs only)"
        if not findings:
            note += " - no payment endpoints without idempotency support"
        res = self._ok(findings, note)
        res.duration_ms = dur
        return res

    @staticmethod
    async def _safe_probe(ctx: Ctx, url: str) -> Tuple[Dict[str, str], int]:
        """Single read-only GET. Returns (headers, status).

        Never sends POST/PUT/DELETE and never submits anything - this is
        header inspection, not a state change.
        """
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=8, max_retries=0)
            return dict(r.headers), r.status_code
        except Exception:
            return {}, 0
