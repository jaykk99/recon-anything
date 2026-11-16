"""Pay/checkout + client-side auth state-machine probe.

What the existing plugins miss for a payment platform like Crypto.com:
- graphql_probe checks conventional /graphql paths, but a target can hide
  its whole auth model in its client JS without any GraphQL at all.
- blogic flags price/coupon URL params, but never reads the auth flow the
  checkout depends on (magic-token login, email/phone OTP, password reset).

This plugin (detection only, GET requests only, no credentials, no state
changes) does three read-only things for a domain target:
1. Unauthenticated GET on the payment-creation API path — auth must fail
   closed (401/403) before any processing; anything else is flagged.
2. Fetches the target's login page, extracts same-origin JS chunk URLs,
   and scans a bounded set of chunks for GraphQL client strings.
3. Scans those same chunks for the client-side auth state machine:
   verify_magic_token / verify_email_otp / verify_phone_otp / reset_password
   / verify_2fa / set_passcode etc. — mapping the ATO-relevant flows
   (password reset, magic-link login, OTP verification) from public code
   so a human can chain them on a local replica instead of live accounts.

Built for lane B of the Crypto.com deep scan (2026-11-15). No live
Crypto.com account, payment, order, or password-reset request is ever
made; the payment probe sends no credentials and no payment body.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, Target

# Auth action names observed in public client bundles (accounts.crypto.com
# login JS, 2026-11-15). These are the ATO-chain links: magic-token login,
# OTP verification, password reset, passcode set.
AUTH_ACTIONS = (
    "verify_magic_token", "verify_email_otp", "verify_phone_otp",
    "verify_login_phone_otp", "verify_2fa", "verify_passcode",
    "verify_password", "reset_password", "set_password", "set_passcode",
    "set_phone", "forgot_password",
)

# Payment-creation paths that must reject unauthenticated callers.
PAY_PATHS = ("api/payments", "api/v1/payments", "api/checkout",
             "api/orders", "api/pay")

MAX_CHUNKS = 6
MAX_CHUNK_BYTES = 200_000
SCRIPT_RE = re.compile(r'(?:src|href)="([^"]+\.js[^"]*)"', re.I)


class PayAuthProbePlugin(Plugin):
    id = "pay_auth_probe"
    label = "Pay + Auth Surface Probe"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = ("Unauthenticated payment-API check plus client-JS scan "
                   "for GraphQL strings and the auth state machine "
                   "(magic token / OTP / password reset).")
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List = []

        # Phase 1: unauthenticated payment-API probe (GET only, no body).
        for p in PAY_PATHS:
            url = f"{base}/{p}"
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                                max_retries=0)
            except Exception:
                continue
            if r is None:
                continue
            if r.status_code in (401, 403):
                continue  # auth enforced before processing: expected
            if r.status_code < 500:
                findings.append(self._f(
                    "api", "payment_api_unauth",
                    f"Payment API {url} answered unauthenticated GET with "
                    f"HTTP {r.status_code} (expected 401/403)",
                    source="Pay/auth probe", source_url=url, confidence=70,
                    passive=True,
                    evidence={"severity": "medium",
                              "remediation": ("Payment creation must reject "
                                              "unauthenticated callers "
                                              "before any processing.")}))

        # Phase 2: login page -> same-origin JS chunks -> scan for GraphQL
        # strings and auth state-machine actions.
        login_url = f"{base}/login"
        try:
            page = await fetch(ctx.http, ctx.limiter, "GET", login_url,
                               timeout=10, max_retries=0)
        except Exception:
            page = None
        html = (page.text or "") if page is not None else ""
        chunk_urls: List[str] = []
        for m in SCRIPT_RE.finditer(html):
            src = m.group(1)
            if src.startswith("http"):
                if domain in src:
                    chunk_urls.append(src)
            elif src.startswith("/"):
                chunk_urls.append(base + src)
            if len(chunk_urls) >= MAX_CHUNKS:
                break
        if not chunk_urls:
            # Fall back to the homepage so the scan still says something.
            try:
                home = await fetch(ctx.http, ctx.limiter, "GET", base,
                                   timeout=10, max_retries=0)
                html = (home.text or "") if home is not None else ""
                for m in SCRIPT_RE.finditer(html):
                    src = m.group(1)
                    if src.startswith("http"):
                        if domain in src:
                            chunk_urls.append(src)
                    elif src.startswith("/"):
                        chunk_urls.append(base + src)
                    if len(chunk_urls) >= MAX_CHUNKS:
                        break
            except Exception:
                pass
        gql_hits, auth_hits = [], set()
        for url in chunk_urls:
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                timeout=10, max_retries=0)
            except Exception:
                continue
            if r is None:
                continue
            body = (r.text or "")[:MAX_CHUNK_BYTES]
            if "graphql" in body.lower():
                gql_hits.append(url)
            low = body.lower()
            for action in AUTH_ACTIONS:
                if action in low:
                    auth_hits.add(action)
        if gql_hits:
            findings.append(self._f(
                "api", "graphql_in_client_js",
                f"GraphQL strings present in client JS: {', '.join(gql_hits)}",
                source="Pay/auth probe", source_url=gql_hits[0], confidence=75,
                passive=True,
                evidence={"severity": "low",
                          "remediation": ("Confirm the GraphQL endpoint "
                                          "requires auth and disables public "
                                          "introspection.")}))
        if auth_hits:
            findings.append(self._f(
                "identity", "auth_state_machine",
                "Client-side auth state machine exposes: "
                + ", ".join(sorted(auth_hits)),
                source="Pay/auth probe", source_url=login_url, confidence=90,
                passive=True,
                evidence={"severity": "low",
                          "remediation": ("Map each exposed action to its "
                                          "server control (single-use magic "
                                          "tokens, OTP expiry/attempt caps, "
                                          "reset-link invalidation); test "
                                          "each link on a local replica, "
                                          "never against a real account.")}))
        return PluginResult(plugin_id=self.id, status="ok",
                            duration_s=time.monotonic() - t0,
                            findings=findings)
