"""Exchange-web detectors, block 8: security configuration for
login/trading pages.

Ten detectors over the homepage response headers (plus page text
for mixed content): CSP, session-cookie flags, CORS, HSTS,
clickjacking protection on account/withdrawal surfaces.
Response/fixture analysis only (see _exchange_common). These are
exchange-scoped: they grade the session cookies and policies of a
trading site, distinct from the generic header plugins.
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web8"

SPECS = [
    S("exch_csp_missing_login", "No Content-Security-Policy on Login/Trading Page",
      "medium",
      "The login/trading page response carries no Content-Security-Policy, so any injected script runs unrestricted on the pages where sessions and withdrawal forms live.",
      "Serve a strict CSP (default-src 'self', no unsafe-inline) on login, trading and withdrawal pages.",
      kind="header_missing", header="content-security-policy",
      category="web"),
    S("exch_csp_unsafe_inline_script", "CSP Allows unsafe-inline/unsafe-eval Scripts",
      "medium",
      "The Content-Security-Policy allows unsafe-inline or unsafe-eval in script-src, which neutralizes CSP as an XSS barrier on trading pages.",
      "Remove unsafe-inline/unsafe-eval from script-src; use nonces or hashes for the few inline scripts that remain.",
      patterns=[r"script-src[^;]*['\"]?(?:unsafe-inline|unsafe-eval)",
                r"default-src[^;]*['\"]?(?:unsafe-inline|unsafe-eval)"],
      kind="header_weak", header="content-security-policy",
      category="web"),
    S("exch_session_cookie_no_secure", "Exchange Session Cookie Without Secure Flag",
      "high",
      "A session/auth cookie for the exchange is set without the Secure flag, so it can travel over plain HTTP and be captured on hostile networks.",
      "Set Secure on every session cookie and serve the site HTTPS-only with HSTS.",
      kind="cookie_flag", header="set-cookie", flag="secure",
      category="web"),
    S("exch_session_cookie_no_httponly", "Exchange Session Cookie Without HttpOnly Flag",
      "high",
      "A session/auth cookie is set without HttpOnly, so any script on the page (including any future XSS) can read the trading session cookie directly.",
      "Set HttpOnly on session cookies; frontend code should never need to read them.",
      kind="cookie_flag", header="set-cookie", flag="httponly",
      category="web"),
    S("exch_session_cookie_samesite_weak", "Exchange Session Cookie With Weak SameSite",
      "medium",
      "A session cookie has no SameSite attribute, or uses SameSite=None without Secure, leaving the trading session exposed to cross-site request flows.",
      "Set SameSite=Lax or Strict on session cookies; if None is required for a flow, pair it with Secure and CSRF tokens.",
      kind="cookie_flag", header="set-cookie", flag="samesite",
      category="web"),
    S("exch_cors_star_with_credentials", "CORS Wildcard Origin Combined With Credentials",
      "high",
      "The response pairs Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true - a combination that signals credentialed cross-origin access was configured carelessly on an API that carries sessions.",
      "Reflect only an allowlist of exact origins when credentials are allowed; never pair a wildcard origin with credentials.",
      kind="cors_star_credentials", header="access-control-allow-origin",
      category="api"),
    S("exch_hsts_missing_account", "No HSTS on Account/Trading Site",
      "medium",
      "The site sends no Strict-Transport-Security header, so first-visit and downgrade attacks can pull login traffic onto plain HTTP.",
      "Send Strict-Transport-Security with a long max-age and includeSubDomains on all pages.",
      kind="header_missing", header="strict-transport-security",
      category="web"),
    S("exch_hsts_weak_max_age", "HSTS max-age Too Short",
      "low",
      "The HSTS max-age is far below the one-year floor, so browsers forget the HTTPS-only policy quickly and the downgrade window reopens.",
      "Raise HSTS max-age to at least 31536000 (one year) with includeSubDomains.",
      kind="header_below", header="strict-transport-security",
      threshold=31536000,
      category="web"),
    S("exch_clickjacking_protection_missing", "No Clickjacking Protection on Account Pages",
      "medium",
      "The response has neither X-Frame-Options nor a CSP frame-ancestors directive, so login and withdrawal pages can be framed by another site for clickjacking against signed-in traders.",
      "Send X-Frame-Options: DENY (or SAMEORIGIN) and CSP frame-ancestors 'none' on account and withdrawal pages.",
      kind="header_missing", header="x-frame-options",
      alt_header="content-security-policy", alt_pattern=r"frame-ancestors",
      category="web"),
    S("exch_mixed_content_trading", "Mixed Content Referenced From Trading Page",
      "medium",
      "The HTTPS trading page references an http:// script or API endpoint, so part of the trading surface loads over a channel an attacker on the network can rewrite.",
      "Load every script, stream and API call over HTTPS/WSS and add upgrade-insecure-requests to the CSP.",
      patterns=[r"<script[^>]+src=['\"]http://[^'\"]+['\"]",
                r"(?:apiBase|apiUrl|endpoint)\s*[:=]\s*['\"]http://[^'\"]+['\"]"],
      category="web"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web8(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
