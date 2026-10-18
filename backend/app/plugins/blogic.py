"""Business logic flaw detector.

Flags patterns that enable price manipulation, coupon abuse, paywall
bypass, and referral fraud. Detection only: never completes purchases
or abuses systems. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

PRICE_PATTERNS = [
    (r"[?&](price|amount|total|cost|fee|subtotal|grand_total)=(\d+)", "client-side price parameter"),
    (r"[?&](discount|coupon|promo|voucher|referral|promo_code|discount_code)=([^&\s\"']+)", "coupon/referral parameter"),
    (r"[?&](quantity|qty|count|units|amount_items)=(\d+)", "quantity parameter (test negative/zero/large)"),
    (r"/(checkout|cart|payment|billing|order)", "checkout flow page"),
    (r"(paywall|premium|subscribe|upgrade|pro_plan)", "paywall/premium gate"),
    (r"[?&](currency|cur)=([A-Z]{3})", "currency parameter (test mismatch)"),
    (r"[?&](trial|free_trial|promo_period)=(true|1|yes)", "free trial parameter"),
    (r"[?&](user_id|customer_id|account_id)=(\d+)", "user ID in transaction (test swap)"),
    (r"(add_to_cart|apply_coupon|redeem)", "cart/coupon action endpoint"),
]

REMEDIATION = ("Never trust client-supplied prices or discounts. Validate "
               "all pricing server-side, rate-limit coupon use, and enforce "
               "entitlements on the backend.")


class BlogicPlugin(Plugin):
    id = "blogic"
    label = "Business Logic Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Flag price params, coupons, paywalls for logic testing."

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
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        seen = set()
        for pat, label in PRICE_PATTERNS:
            for m in re.finditer(pat, html, re.I):
                sample = m.group(0)[:80]
                if sample in seen:
                    continue
                seen.add(sample)
                findings.append(self._f(
                    "web", "blogic_candidate",
                    f"Business logic test candidate: {label} '{sample.strip()}'. "
                    f"Verify pricing/discounts are enforced server-side on an "
                    f"authorized target. Never complete fraudulent transactions.",
                    source="Business logic mining", source_url=page_url,
                    confidence=60, passive=passive,
                    evidence={"severity": "medium", "pattern": label,
                              "sample": sample.strip(),
                              "remediation": REMEDIATION,
                              "scope_note": "Detection only. Authorized testing only."}))
                if len(seen) >= 20:
                    break
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} logic candidates")
        res.duration_ms = dur
        return res
