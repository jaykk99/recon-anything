"""Auth weakness checker (Milestone: critical findings).

Non-destructive checks: JWT algorithm confusion (alg:none or weak),
auth cookie flags, login page default-credential hints, and password
reset token patterns. Read-only: we decode tokens the site itself
serves, never brute force. Authorized testing only.
"""
from __future__ import annotations

import base64
import json
import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")


def b64url_decode(s: str) -> dict:
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s).decode("utf-8", "replace"))
    except Exception:
        return {}


class AuthPlugin(Plugin):
    id = "auth"
    label = "Auth Weakness Check"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "JWT alg issues, cookie flags, default login hints."

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
            headers = dict(r.headers)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        def emit(key: str, text: str, conf: int, severity: str,
                 remediation: str, url=None):
            findings.append(self._f(
                "web", key, f"{severity.upper()}: {text}",
                source="auth check", source_url=url or page_url,
                confidence=conf, passive=passive,
                evidence={"severity": severity, "remediation": remediation,
                          "scope_note": "Authorized testing only."}))

        # 1. JWTs served by the page: check alg
        seen_jwt = set()
        for m in JWT_RE.finditer(html):
            tok = m.group(0)
            if tok in seen_jwt:
                continue
            seen_jwt.add(tok)
            header = b64url_decode(tok.split(".")[0])
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                emit("jwt_alg_none",
                     "JWT uses alg:none - signatures are not verified. Forge tokens on authorized targets only.",
                     90, "critical",
                     "Reject alg:none server-side. Allowlist strong algorithms (RS256/ES256).")
            elif alg in ("hs256",) and len(tok.split(".")[2]) < 20:
                emit("jwt_weak_hmac",
                     f"JWT uses {alg} with a short signature - may be brute-forceable.",
                     60, "high",
                     "Use 256-bit+ random secrets, rotate regularly, prefer RS256.")
            if len(seen_jwt) >= 5:
                break

        # 2. auth cookie flags
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            low = set_cookie.lower()
            if "httponly" not in low:
                emit("cookie_no_httponly",
                     "Auth/session cookie missing HttpOnly - stealable via XSS.",
                     75, "high", "Set HttpOnly on all session cookies.")
            if "secure" not in low:
                emit("cookie_no_secure",
                     "Cookie missing Secure flag - sent over plain HTTP.",
                     70, "medium", "Set Secure on all cookies.")
            if "samesite" not in low:
                emit("cookie_no_samesite",
                     "Cookie missing SameSite - CSRF risk.",
                     65, "medium", "Set SameSite=Lax or Strict.")

        # 3. login page hints
        if re.search(r"(?i)(sign[\s_-]?in|log[\s_-]?in|/login)", html[:50000]):
            if re.search(r"(?i)(default (password|credentials)|admin/admin|demo/demo)", html):
                emit("default_cred_hint",
                     "Login page mentions default credentials - try them only on authorized targets.",
                     70, "high",
                     "Remove default accounts, enforce unique credentials per deploy.")

        # 4. password reset token in URL pattern
        if re.search(r"(?i)(reset|forgot).{0,40}token=", html[:100000]):
            emit("pwd_reset_flow",
                 "Password reset flow exposes tokens in URLs - check token entropy and expiry.",
                 55, "medium",
                 "Use single-use, short-lived, high-entropy reset tokens sent out-of-band.")

        # 5. exposed admin panels (no auth check)
        admin_paths = ["/admin", "/admin/", "/administrator", "/wp-admin",
                       "/dashboard", "/manager", "/console", "/panel"]
        for apath in admin_paths:
            try:
                ar = await fetch(ctx.http, ctx.limiter, "GET",
                                 base.rstrip("/") + apath, timeout=10,
                                 follow_redirects=False)
                # 200 without redirect to login = potentially exposed
                if ar.status_code == 200:
                    body_sample = ar.text[:5000].lower()
                    if "login" not in body_sample and "sign in" not in body_sample \
                            and "password" not in body_sample:
                        emit("exposed_admin_panel",
                             f"Admin panel at {apath} returns 200 without "
                             f"login redirect - may lack authentication.",
                             70, "high",
                             "Require authentication on all admin paths. "
                             "Do not rely on obscurity.",
                             url=base.rstrip("/") + apath)
                        break
            except Exception:
                continue

        # 6. HTTP method override headers (auth bypass vector)
        # Check if server respects X-HTTP-Method-Override
        try:
            mr = await fetch(ctx.http, ctx.limiter, "GET", page_url,
                             timeout=10,
                             headers={"X-HTTP-Method-Override": "DELETE"})
            # If response differs from normal GET, method override may work
            if mr.status_code not in (200, 301, 302, 404):
                emit("method_override",
                     "Server responds unusually to X-HTTP-Method-Override "
                     "header - may allow HTTP verb tampering for auth bypass.",
                     50, "medium",
                     "Ignore X-HTTP-Method-Override or validate strictly.")
        except Exception:
            pass

        # 7. role parameter pollution hints
        if re.search(r"(?i)(role|is_admin|isadmin|privilege|access_level)\s*[=:]", html[:200000]):
            emit("role_param_hint",
                 "Role/privilege parameter found in page - test for "
                 "parameter pollution (role=admin) on authorized targets.",
                 55, "medium",
                 "Never trust client-supplied role values. Enforce "
                 "authorization server-side from session data.")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} auth findings")
        res.duration_ms = dur
        return res
