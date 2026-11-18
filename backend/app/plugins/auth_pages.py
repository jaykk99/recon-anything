"""Auth-surface plugin (ported from ARTEX modules/enumeration.py).

Probes the target for login / password-reset pages and for auth-provider
endpoints (Office365, GSuite, Okta, Auth0). Read-only GETs only: pages are
fetched and classified by their HTML (password fields, auth keywords);
no credentials are ever submitted and no login is ever attempted.

Ported from ARTEX AuthPageScanner:
- common_login_paths (15) + password_reset_paths (11) + auth keywords.
- _check_auth_providers: Office365 / GSuite / Okta / Auth0 endpoints.

ARTEX fixes applied in the port: ARTEX used blocking requests with
verify=False and no concurrency cap; here probes go through ctx.probe
(shared per-URL cache, rate-limited) in capped concurrent batches, and
TLS verification stays on. ARTEX also crawled the homepage for links;
ReconAnything already has link/crawl plugins, so this plugin sticks to
the path + IdP probes.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, gather_capped

# ARTEX AuthPageScanner.common_login_paths
LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/oauth", "/admin",
    "/wp-login.php", "/log-in", "/sign-in", "/account/login",
    "/user/login", "/auth/login", "/authentication/login",
    "/signin/auth", "/member/login", "/portal/login",
]

# ARTEX AuthPageScanner.password_reset_paths
RESET_PATHS = [
    "/password-reset", "/reset-password", "/forgot-password",
    "/account/recovery", "/user/password", "/password/forgot",
    "/auth/reset", "/recover", "/account/forgot",
    "/wp-login.php?action=lostpassword", "/passwordreset",
]

# ARTEX AuthPageScanner.common_auth_keywords (page classification)
_AUTH_KEYWORDS = [
    "login", "sign in", "username", "password", "email",
    "forgot password", "reset password", "credentials",
    "authentication", "two-factor", "2fa", "otp",
]
_RESET_KEYWORDS = ["reset", "forgot", "recover"]

# ARTEX AuthPageScanner._check_auth_providers (URL templates; {domain}
# is filled in at run time).
IDP_PROVIDERS = {
    "office365": [
        "https://login.microsoftonline.com/{domain}",
        "https://{domain}/_forms/default.aspx",
        "https://{domain}/_windows/default.aspx",
    ],
    "gsuite": [
        "https://accounts.google.com/ServiceLogin?service=CPanel"
        "&passive=1209600&continue=https://admin.google.com/{domain}/AdminHome",
        "https://admin.google.com/{domain}/AdminHome",
    ],
    "okta": [
        "https://{domain}.okta.com",
        "https://{domain}/login/login.htm",
    ],
    "auth0": [
        "https://{domain}.auth0.com",
        "https://{domain}/login/callback",
    ],
}

_PASSWORD_FIELD_RE = re.compile(
    r'<input[^>]*type\s*=\s*["\']password["\']', re.I)


def classify_auth_page(text: str, path: str) -> str:
    """Classify fetched HTML as 'login', 'reset', or '' (not an auth page).

    Pure helper, unit-tested: a password field means login; reset/forgot
    keywords (or a reset path) mean reset; auth keywords alone are not
    enough to call a page an auth page.
    """
    low = (text or "").lower()
    if _PASSWORD_FIELD_RE.search(text or ""):
        return "login"
    if any(k in low for k in _RESET_KEYWORDS) or "reset" in path.lower():
        if any(k in low for k in ("password", "email", "username", "account")):
            return "reset"
    if "forgot password" in low or "reset password" in low:
        return "reset"
    return ""


class AuthPagesPlugin(Plugin):
    id = "auth_pages"
    label = "Auth Surface"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Login / password-reset pages and auth-provider "
                   "(Office365, GSuite, Okta, Auth0) endpoints.")
    phase = 1

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []

        probes: List[Dict] = []
        for path in LOGIN_PATHS:
            probes.append({"url": base + path, "kind": "login", "path": path})
        for path in RESET_PATHS:
            probes.append({"url": base + path, "kind": "reset", "path": path})
        for provider, templates in IDP_PROVIDERS.items():
            for template in templates:
                probes.append({"url": template.format(domain=domain),
                               "kind": "idp", "path": provider})

        # ctx.probe is the shared bulk-sweep GET (cached per URL across
        # plugins); gather_capped bounds the whole batch.
        results = await gather_capped(
            [ctx.probe(p["url"]) for p in probes], budget_s=45)

        for probe, result in zip(probes, results):
            if not isinstance(result, dict):
                continue
            status = result.get("status") or 0
            if status < 200 or status >= 400:
                continue
            text = result.get("text") or ""
            if probe["kind"] == "idp":
                findings.append(self._f(
                    "web", "auth_provider",
                    f"Auth provider endpoint reachable: {probe['path']} "
                    f"({probe['url']})",
                    source="auth provider probe", source_url=probe["url"],
                    confidence=75, passive=True,
                    evidence={"severity": "medium",
                              "provider": probe["path"],
                              "why": "A reachable IdP endpoint confirms "
                                     "which identity provider this org "
                                     "uses — the starting point for "
                                     "targeted phishing and SSO-abuse "
                                     "research. It does not by itself "
                                     "mean the IdP is misconfigured."}))
                continue
            page_type = classify_auth_page(text, probe["path"])
            if not page_type:
                continue
            key = ("login_page" if page_type == "login"
                   else "password_reset_page")
            findings.append(self._f(
                "web", key,
                f"{page_type.capitalize()} page at {probe['url']} "
                f"(HTTP {status})",
                source="auth page probe", source_url=probe["url"],
                confidence=80, passive=True,
                evidence={"severity": "low",
                          "why": "A reachable login/reset page is part of "
                                 "the public auth surface. Check it enforces "
                                 "rate limiting, lockout, and MFA before "
                                 "treating it as safe."}))

        res = self._ok(findings,
                       f"probed {len(probes)} auth paths/endpoints, "
                       f"found {len(findings)} auth page(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
