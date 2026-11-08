"""Exchange-web detectors, block 5: auth/session frontend patterns.

Ten detectors for authentication and session mistakes visible in
an exchange site's own frontend code: tokens in web storage, TOTP
logic client-side, reset tokens handled in URLs. Code-pattern
detection only - nothing is submitted or tested against a live
account (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web5"

SPECS = [
    S("exch_jwt_localstorage_trading", "JWT Stored in localStorage on Trading Pages",
      "high",
      "Frontend code stores the session JWT/access token in localStorage, where any script on the page - including any future XSS or a compromised dependency - can read a full trading-session token.",
      "Keep session tokens in HttpOnly cookies or in memory; never persist bearer tokens to localStorage on trading pages.",
      patterns=[r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(?:jwt|access[_-]?token|auth[_-]?token|id[_-]?token)[^'\"]*['\"]",
                r"localStorage\s*\[\s*['\"][^'\"]*token[^'\"]*['\"]\s*\]\s*="],
      category="web"),
    S("exch_refresh_token_web_storage", "Refresh Token Stored in Web Storage",
      "high",
      "A refresh token is written to localStorage/sessionStorage. A stolen refresh token outlives the session and can mint new access tokens until it is revoked.",
      "Keep refresh tokens in HttpOnly, Secure cookies with rotation and reuse detection; never in web storage.",
      patterns=[r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*refresh[^'\"]*['\"]",
                r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"]refreshToken['\"]"],
      category="web"),
    S("exch_oauth_redirect_wildcard", "OAuth Redirect URI Wildcard in Config",
      "high",
      "OAuth/OIDC config in shipped code uses a wildcard or any-host redirect URI, which lets authorization codes be redirected to an attacker-chosen origin.",
      "Pin redirect URIs to an exact allowlist of full URLs; never use wildcards in production OAuth clients.",
      patterns=[r"redirect[_-]?uri\s*[:=]\s*['\"][^'\"]*\*[^'\"]*['\"]",
                r"redirectUri\s*[:=]\s*['\"]https?://\*[^'\"]*['\"]"],
      category="web"),
    S("exch_totp_logic_client", "TOTP Secret/Verification Logic in Client Code",
      "high",
      "Client code holds TOTP secret material or generates/validates TOTP codes in the browser (otpauth URI / totpSecret in shipped code), which defeats the second factor if the secret can be extracted.",
      "Generate and verify TOTP server-side; the client should only collect the 6-digit code, never see the secret or the verification logic's secret inputs.",
      patterns=[r"(?:totpSecret|otpSecret|twoFactorSecret)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"otpauth://totp/[^'\"\s]*[?&]secret=[A-Z2-7]{16,}"],
      category="leak"),
    S("exch_session_timeout_disabled", "Session/Idle Timeout Disabled in Trading UI Config",
      "medium",
      "Trading UI config disables the session or idle timeout (0 / null / false), so a stolen or unattended trading session stays valid indefinitely.",
      "Set a finite idle timeout for trading sessions and require re-authentication for withdrawals regardless of session age.",
      patterns=[r"(?:sessionTimeout|idleTimeout|session_timeout)\s*[:=]\s*(?:0|null|false)\b",
                r"['\"](?:sessionTimeout|idleTimeout)['\"]\s*:\s*(?:0|null|false)"],
      category="web"),
    S("exch_remember_me_long_token", "Remember-Me Token With Long Expiry in Config",
      "medium",
      "Remember-me config pairs the persistent token with a very long expiry (a year-scale value), turning a convenience cookie into a near-permanent credential for the trading account.",
      "Cap remember-me lifetimes in days, bind them to device signals, and never let a remember-me token authorize withdrawals.",
      patterns=[r"rememberMe\s*[:=]\s*\{[^}]{0,200}?(?:expires|maxAge|ttl)\s*[:=]\s*(?:365|31536000|2592000)\b",
                r"remember[_-]?me[^}]{0,200}?(?:365\s*\*\s*24|days\s*[:=]\s*365)"],
      category="web"),
    S("exch_reset_token_from_url", "Password Reset Token Read From URL in Frontend Route",
      "medium",
      "A frontend reset route reads the password-reset token from the URL query string, so the token lands in browser history, analytics and referrer headers - and any script on the page can read it.",
      "Handle reset tokens on a minimal, analytics-free page, clear them from the URL immediately, and expire them on first view.",
      patterns=[r"(?:reset|passwordReset)[\s\S]{0,300}?(?:URLSearchParams|location\.search)[\s\S]{0,200}?get\s*\(\s*['\"]token['\"]\s*\)",
                r"(?:URLSearchParams|location\.search)[\s\S]{0,200}?get\s*\(\s*['\"](?:reset_)?token['\"]\s*\)[\s\S]{0,300}?(?:reset|password)"],
      category="web"),
    S("exch_auth_token_url_param", "Auth Token Passed as URL Query Parameter in Client Links",
      "medium",
      "Client code builds links or API calls carrying the auth token as a URL query parameter, leaking session tokens into logs, history and third-party referrers.",
      "Pass auth in headers or HttpOnly cookies only; strip tokens from URLs and rotate any token that has travelled in one.",
      patterns=[r"['\"][^'\"]*\?(?:auth_)?token=\s*['\"]\s*\+",
                r"['\"][^'\"]*[?&](?:access_token|authToken)=\$\{"],
      category="web"),
    S("exch_bearer_token_hardcoded_client", "Hardcoded Bearer Token in Client Code",
      "high",
      "Client code contains a hardcoded Bearer token literal, a live credential shipped to every visitor.",
      "Revoke the token, find what it authorized, and move that call behind the server tier with its own credential.",
      patterns=[r"['\"]Bearer\s+[A-Za-z0-9_\-.+/=]{24,}['\"]",
                r"Authorization\s*[:=]\s*['\"]Bearer\s+[A-Za-z0-9_\-.+/=]{24,}['\"]"],
      negatives=[r"example|placeholder|your[_-]|xxxx"],
      category="leak"),
    S("exch_2fa_backup_codes_storage", "2FA Backup Codes Generated/Stored Client-Side",
      "medium",
      "Frontend code generates or stores 2FA backup/recovery codes in web storage, so a script-level compromise yields both the session and the account-recovery path.",
      "Generate backup codes server-side, show them once, store only hashes server-side, and never persist them in the browser.",
      patterns=[r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(?:backup|recovery)[^'\"]*code[^'\"]*['\"]",
                r"(?:generateBackupCodes|generateRecoveryCodes)\s*\([\s\S]{0,300}?(?:localStorage|sessionStorage)"],
      category="web"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web5(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
