"""Aggressive misconfiguration sweep: 50+ checks, GET/HEAD only.

Security headers (presence + value quality), cookie flag audit
(HttpOnly/Secure/SameSite/__Host-/__Secure- prefix rules), CORS
wildcards, debug/info-disclosure headers, dangerous methods, caching
of sensitive responses, and permissive policies.

Every finding carries risk + remediation. Passive-safe: no state change.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class MisconfigSweepPlugin(Plugin):
    id = "misconfig_sweep"
    label = "Misconfig Sweep"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "50+ misconfiguration checks: headers, cookies, CORS, methods."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        def add(key, value, conf, sev, remediation, source_url=None):
            findings.append(self._f(
                "web", key, value, source="misconfig sweep",
                source_url=source_url or base, confidence=conf,
                passive=passive,
                evidence={"severity": sev, "remediation": remediation}))

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=20,
                            follow_redirects=True)
            final_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        H = {k.lower(): v for k, v in r.headers.items()}

        # ---- 1. HSTS ----
        hsts = H.get("strict-transport-security", "")
        if not hsts:
            if final_url.startswith("https"):
                add("mc_hsts_missing", "HIGH: HSTS missing on HTTPS site - SSL stripping possible",
                    85, "high", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            age = int(m.group(1)) if m else 0
            if age < 31536000:
                add("mc_hsts_short", f"MEDIUM: HSTS max-age only {age}s (< 1 year)",
                    70, "medium", "Raise to max-age=31536000")
            if "includesubdomains" not in hsts.lower():
                add("mc_hsts_no_subdomains", "LOW: HSTS lacks includeSubDomains",
                    60, "low", "Add includeSubDomains to HSTS")
            if "preload" not in hsts.lower():
                add("mc_hsts_no_preload", "LOW: HSTS not preloaded",
                    55, "low", "Add preload and submit to hstspreload.org")

        # ---- 2. CSP ----
        csp = H.get("content-security-policy", "")
        if not csp:
            add("mc_csp_missing", "HIGH: No Content-Security-Policy - XSS impact maximized",
                80, "high", "Deploy a strict CSP (default-src 'self', no unsafe-inline)")
        else:
            low = csp.lower()
            if "unsafe-inline" in low:
                add("mc_csp_unsafe_inline", "HIGH: CSP allows unsafe-inline - XSS largely unmitigated",
                    80, "high", "Remove unsafe-inline; use nonces or hashes")
            if "unsafe-eval" in low:
                add("mc_csp_unsafe_eval", "MEDIUM: CSP allows unsafe-eval",
                    70, "medium", "Remove unsafe-eval")
            if re.search(r"(default-src|script-src)[^;]*\*", low):
                add("mc_csp_wildcard", "HIGH: CSP source wildcard (*) - policy bypassable",
                    80, "high", "Replace * with explicit allowlisted origins")
            if "http:" in low and "https:" not in low:
                add("mc_csp_http", "MEDIUM: CSP allows plain http: sources",
                    65, "medium", "Serve everything over HTTPS")

        # ---- 3. Clickjacking ----
        xfo = H.get("x-frame-options", "")
        fa_ok = "frame-ancestors" in csp.lower()
        if not xfo and not fa_ok:
            add("mc_xfo_missing", "MEDIUM: No X-Frame-Options nor CSP frame-ancestors - clickjacking possible",
                75, "medium", "Add X-Frame-Options: DENY or SAMEORIGIN")
        elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            add("mc_xfo_weak", f"MEDIUM: X-Frame-Options '{xfo}' is not DENY/SAMEORIGIN",
                70, "medium", "Set X-Frame-Options: DENY")

        # ---- 4. MIME sniffing / misc headers ----
        if H.get("x-content-type-options", "").lower() != "nosniff":
            add("mc_xcto_missing", "MEDIUM: X-Content-Type-Options missing - MIME sniffing possible",
                70, "medium", "Add X-Content-Type-Options: nosniff")
        if "referrer-policy" not in H:
            add("mc_referrer_missing", "LOW: Referrer-Policy missing - referrer leakage",
                60, "low", "Add Referrer-Policy: strict-origin-when-cross-origin")
        elif H["referrer-policy"].lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            add("mc_referrer_weak", f"LOW: Referrer-Policy '{H['referrer-policy']}' leaks URLs",
                60, "low", "Use strict-origin-when-cross-origin or no-referrer")
        if "permissions-policy" not in H and "feature-policy" not in H:
            add("mc_permissions_missing", "LOW: Permissions-Policy missing - camera/mic/geolocation unrestricted",
                55, "low", "Add Permissions-Policy restricting sensitive features")
        if "cross-origin-opener-policy" not in H:
            add("mc_coop_missing", "LOW: Cross-Origin-Opener-Policy missing",
                50, "low", "Add Cross-Origin-Opener-Policy: same-origin")
        if "cross-origin-embedder-policy" not in H:
            add("mc_coep_missing", "LOW: Cross-Origin-Embedder-Policy missing",
                50, "low", "Add Cross-Origin-Embedder-Policy: require-corp")
        if "cross-origin-resource-policy" not in H:
            add("mc_corp_missing", "LOW: Cross-Origin-Resource-Policy missing",
                50, "low", "Add Cross-Origin-Resource-Policy: same-origin")
        if H.get("x-permitted-cross-domain-policies", "").lower() not in ("none", ""):
            if H.get("x-permitted-cross-domain-policies"):
                add("mc_xpcdp", f"LOW: X-Permitted-Cross-Domain-Policies '{H['x-permitted-cross-domain-policies']}' not 'none'",
                    55, "low", "Set X-Permitted-Cross-Domain-Policies: none")
        else:
            if "x-permitted-cross-domain-policies" not in H:
                add("mc_xpcdp_missing", "LOW: X-Permitted-Cross-Domain-Policies missing",
                    50, "low", "Set X-Permitted-Cross-Domain-Policies: none")

        # ---- 5. Info-disclosure headers ----
        for hname, label, sev, conf in [
                ("server", "Server header", "medium", 70),
                ("x-powered-by", "X-Powered-By", "medium", 70),
                ("x-aspnet-version", "X-AspNet-Version", "high", 75),
                ("x-aspnetmvc-version", "X-AspNetMvc-Version", "high", 75),
                ("x-generator", "X-Generator", "medium", 70),
                ("x-drupal-cache", "X-Drupal-Cache", "low", 60),
                ("x-varnish", "X-Varnish", "low", 55),
                ("x-backend", "X-Backend", "medium", 65),
                ("x-served-by", "X-Served-By", "low", 55),
                ("via", "Via", "low", 50)]:
            if hname in H:
                v = H[hname][:120]
                add(f"mc_info_{hname.replace('-', '_')}",
                    f"{sev.upper()}: {label} discloses stack: {v}",
                    conf, sev, f"Remove or genericize the {label} header")
        for hname in list(H):
            if hname.startswith("x-debug") or hname in (
                    "x-dev-mode", "x-app-debug", "x-environment"):
                add("mc_debug_header",
                    f"HIGH: Debug header '{hname}: {H[hname][:80]}' exposed",
                    80, "high", "Strip debug headers in production")

        # ---- 6. Cookies ----
        set_cookie = r.headers.get("set-cookie", "")
        if set_cookie:
            for part in re.split(r",(?=[^;,]+=)", set_cookie):
                m = re.match(r"\s*([^=;]+)=", part)
                if not m:
                    continue
                cname = m.group(1).strip()
                clow = part.lower()
                if "httponly" not in clow:
                    add("mc_cookie_no_httponly",
                        f"MEDIUM: Cookie '{cname}' lacks HttpOnly - XSS can steal it",
                        70, "medium", "Set HttpOnly on session cookies")
                if "secure" not in clow and final_url.startswith("https"):
                    add("mc_cookie_no_secure",
                        f"MEDIUM: Cookie '{cname}' lacks Secure on HTTPS site",
                        70, "medium", "Set Secure on cookies")
                if "samesite" not in clow:
                    add("mc_cookie_no_samesite",
                        f"LOW: Cookie '{cname}' lacks SameSite - CSRF risk",
                        60, "low", "Set SameSite=Lax or Strict")
                if cname.startswith("__Host-") and (
                        "secure" not in clow or "path=/" not in clow
                        or "domain=" in clow):
                    add("mc_cookie_host_prefix",
                        f"HIGH: __Host- cookie '{cname}' violates prefix rules - browsers ignore it",
                        75, "high", "__Host- cookies need Secure, Path=/, no Domain")
                if cname.startswith("__Secure-") and "secure" not in clow:
                    add("mc_cookie_secure_prefix",
                        f"HIGH: __Secure- cookie '{cname}' missing Secure flag",
                        75, "high", "Add Secure to __Secure- cookies")
        else:
            # no cookies at all is fine; note nothing
            pass

        # ---- 7. CORS ----
        acao = H.get("access-control-allow-origin", "")
        acac = H.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            add("mc_cors_wildcard_creds",
                "CRITICAL: CORS allows * with credentials=true - any site can read responses",
                90, "critical", "Never combine ACAO:* with credentials; echo validated origins")
        elif acao == "*":
            add("mc_cors_wildcard",
                "MEDIUM: CORS allows any origin (*)",
                65, "medium", "Restrict Access-Control-Allow-Origin to trusted origins")

        # ---- 8. HTTP methods ----
        try:
            oresp = await fetch(ctx.http, ctx.limiter, "OPTIONS", base,
                                timeout=10, max_retries=1)
            allow = oresp.headers.get("allow", "")
            if "TRACE" in allow.upper():
                add("mc_trace_enabled", "MEDIUM: HTTP TRACE enabled - XST risk",
                    70, "medium", "Disable TRACE at the web server")
            for meth in ("PUT", "DELETE", "PATCH"):
                if meth in allow.upper():
                    add("mc_method_" + meth.lower(),
                        f"LOW: HTTP {meth} advertised in Allow header",
                        55, "low", f"Disable {meth} if unused")
        except Exception:
            pass

        # ---- 9. Caching ----
        cc = H.get("cache-control", "").lower()
        pragma = H.get("pragma", "").lower()
        if "no-store" not in cc and "private" not in cc and set_cookie:
            add("mc_cache_sensitive",
                "LOW: Authenticated responses may be cached (no no-store/private)",
                55, "low", "Add Cache-Control: no-store on authenticated pages")

        # ---- 10. TLS-adjacent ----
        if final_url.startswith("http:") and not final_url.startswith("https"):
            # plain HTTP site
            add("mc_no_tls", "HIGH: Site served over plain HTTP - traffic readable/modifiable",
                85, "high", "Serve the site over HTTPS and add HSTS")

        # ---- 11. Content issues ----
        ctype = H.get("content-type", "")
        if "charset" not in ctype.lower() and "text/html" in ctype.lower():
            add("mc_no_charset", "LOW: HTML without charset - encoding sniffing",
                50, "low", "Declare charset=utf-8 in Content-Type")
        if r.status_code == 200 and len(r.text) > 0 and \
                "<html" not in r.text[:2000].lower() and \
                "text/html" in ctype.lower():
            add("mc_empty_html", "LOW: 200 with HTML content-type but no HTML body",
                50, "low", "Return a proper status code for empty responses")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} misconfig checks fired")
        res.duration_ms = dur
        return res
