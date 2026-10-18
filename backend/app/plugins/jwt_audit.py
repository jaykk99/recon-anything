"""JWT security AUDITOR plugin (detection only, never forgery).

Analyzes JWTs found during the scan (in responses, JS files, headers):

- alg == "none" in the token as found            -> high
- missing exp / overly long exp                  -> medium
- sensitive data in payload (email, roles, admin flags) -> medium
- weak HMAC secrets: verified OFFLINE and LOCALLY against the
  signature using a tiny common-secret list. The token is never sent
  back to any server for verification, and no brute-forcing of the
  server ever happens.

BOUNDARY: this plugin NEVER forges tokens, NEVER modifies a token to
change privileges, and NEVER attempts privilege escalation. When a
finding needs hands-on confirmation it says so: "manual verification
required".
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, Target

JWT_RE = re.compile(
    r'\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*')

# Offline-only check list. Kept tiny on purpose: this is a "is the dev
# key still the default" smell test, NOT a dictionary attack.
COMMON_SECRETS = (
    "secret", "password", "123456", "jwtsecret", "jwt_secret", "secretkey",
    "secret_key", "changeme", "test", "dev", "mysecret", "supersecret",
)

SENSITIVE_CLAIMS = ("email", "role", "roles", "isAdmin", "is_admin", "admin",
                    "permissions", "scope", "privileges", "password")

# exp longer than 30 days counts as "overly long".
MAX_EXP_SECONDS = 30 * 24 * 3600


class JwtAuditPlugin(Plugin):
    id = "jwt_audit"
    label = "JWT Security Auditor"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    phase = 2  # consumes js_files published by phase-1 miners
    description = ("Audits JWTs found during the scan for weak config "
                   "(alg none, missing/long exp, sensitive claims, weak "
                   "HMAC secrets checked offline). Detection only - never "
                   "forges tokens.")
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List = []

        tokens = await self._collect_tokens(ctx, base)
        if not tokens:
            findings.append(self._f(
                "identity", "jwt_none_found",
                "No JWTs observed in responses, headers, or JS files.",
                source="JWT auditor", source_url=base, confidence=60,
                passive=True,
                evidence={"severity": "low",
                          "remediation": "No action needed."}))
            res = self._ok(findings, "no JWTs found to audit")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        seen: set = set()
        for token, origin in tokens:
            if token in seen:
                continue
            seen.add(token)
            findings.extend(self._audit_token(token, origin, base))

        if not findings:
            findings.append(self._f(
                "identity", "jwt_config_ok",
                f"Audited {len(seen)} JWT(s): configuration looks sane "
                "(signed, exp present and reasonable, no sensitive claims).",
                source="JWT auditor", source_url=base, confidence=60,
                passive=True,
                evidence={"severity": "low",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"audited {len(seen)} unique JWT(s)")
        res.duration_ms = dur
        return res

    # -- collection -------------------------------------------------------
    async def _collect_tokens(self, ctx: Ctx, base: str) -> List[Tuple[str, str]]:
        """Pull candidate JWTs from sources already gathered this run.

        Uses the shared cached page fetcher - anything phase-1 plugins
        already fetched costs nothing extra. No token is ever sent
        anywhere; all analysis is local.
        """
        out: List[Tuple[str, str]] = []

        def _scan(text: str, origin: str) -> None:
            if not text:
                return
            for m in JWT_RE.finditer(text):
                cand = m.group(0)
                if self._decodable(cand):
                    out.append((cand, origin))

        # Homepage (cached across plugins).
        page = await ctx.fetch_page(base + "/", timeout=10)
        if isinstance(page, dict) and page.get("text"):
            _scan(page["text"], "homepage")
        # JS files other plugins discovered (cached across plugins).
        for js_url in ctx.consume("js_files")[:15]:
            js = await ctx.fetch_page(str(js_url), timeout=10)
            if isinstance(js, dict) and js.get("text"):
                _scan(js["text"], f"JS file {js_url}")
        # Probe bus: response headers/bodies from phase-1 sweeps.
        bus = ctx.shared.get("probe_cache") or {}
        for url, data in list(bus.items())[:60]:
            if isinstance(data, dict):
                _scan(str(data.get("headers", "")), f"probe headers of {url}")
                _scan(data.get("text", ""), f"probe body of {url}")
        return out

    @staticmethod
    def _decodable(token: str) -> bool:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            _b64d(parts[0]); _b64d(parts[1])
            return True
        except Exception:
            return False

    # -- audit ------------------------------------------------------------
    def _audit_token(self, token: str, origin: str, base: str) -> List:
        out: List = []
        short = token[:24] + "..."
        try:
            header = json.loads(_b64d(token.split(".")[0]))
            payload = json.loads(_b64d(token.split(".")[1]))
        except Exception:
            return out
        alg = str(header.get("alg", "")).lower()

        def _mk(key, value, severity, confidence, exploitability, remediation):
            return self._f(
                "identity", key, value, source="JWT auditor",
                source_url=base, confidence=confidence, passive=True,
                evidence={"severity": severity,
                          "exploitability": exploitability,
                          "token_prefix": short, "origin": origin,
                          "remediation": remediation})

        # 1. alg none -----------------------------------------------------
        if alg == "none":
            out.append(_mk(
                "jwt_alg_none",
                f"JWT uses alg=none (unsigned) - found in {origin}. Anyone "
                "can mint valid tokens. Manual verification required.",
                "high", 90, "theoretical",
                "Reject alg=none server-side; require a signed algorithm "
                "(RS256/ES256) and verify the signature on every request. "
                "Rotate any sessions issued with alg=none."))

        # 2. exp checks ---------------------------------------------------
        exp = payload.get("exp")
        now = int(time.time())
        if exp is None:
            out.append(_mk(
                "jwt_missing_exp",
                f"JWT has no exp claim (never expires) - found in {origin}. "
                "Manual verification required.",
                "medium", 80, "theoretical",
                "Add a short exp (minutes to hours) and implement refresh "
                "tokens; revoke long-lived tokens."))
        else:
            try:
                exp_i = int(exp)
                if exp_i <= now:
                    pass  # expired token - harmless as found
                elif exp_i - now > MAX_EXP_SECONDS:
                    days = (exp_i - now) // 86400
                    out.append(_mk(
                        "jwt_long_exp",
                        f"JWT exp is {days} days out - overly long lifetime "
                        f"(found in {origin}). Manual verification required.",
                        "medium", 75, "theoretical",
                        "Shorten token lifetime to the minimum the app needs "
                        "(ideally under 24h) with refresh-token rotation."))
            except (TypeError, ValueError):
                pass

        # 3. sensitive claims ----------------------------------------------
        leaked = [c for c in SENSITIVE_CLAIMS if c in payload]
        if leaked:
            out.append(_mk(
                "jwt_sensitive_claims",
                f"JWT payload exposes sensitive claims {leaked} - found in "
                f"{origin}. Payloads are only base64, not encrypted. Manual "
                "verification required.",
                "medium", 80, "theoretical",
                "Move sensitive data server-side; keep only an opaque "
                "subject id in the token. If secrecy is required, use JWE."))

        # 4. weak HMAC secret - OFFLINE LOCAL ONLY -------------------------
        # We recompute the signature locally with common secrets. The token
        # is never sent anywhere; nothing touches the server.
        if alg in ("hs256", "hs384", "hs512") and token.split(".")[2]:
            weak = self._offline_secret_check(token, alg)
            if weak:
                out.append(_mk(
                    "jwt_weak_secret",
                    f"JWT HMAC secret appears to be the weak value {weak!r} "
                    f"(verified offline, locally - found in {origin}). "
                    "Manual verification required - rotate the secret.",
                    "high", 85, "theoretical",
                    "Replace with a long random secret (>=256 bits) stored "
                    "in a secrets manager, rotate immediately, and revoke "
                    "all tokens signed with the old secret. Never forge "
                    "tokens or use this to access other accounts."))

        # 5. kid / jku oddities (detection only) ----------------------------
        kid = header.get("kid")
        if isinstance(kid, str) and (".." in kid or kid.startswith("/") or
                                    kid.startswith("http")):
            out.append(_mk(
                "jwt_kid_suspicious",
                f"JWT 'kid' header looks injectable: {kid!r} (found in "
                f"{origin}). Manual verification required.",
                "medium", 65, "theoretical",
                "Use a fixed allow-list of key ids; never resolve 'kid' to "
                "a filesystem path or URL. Verify manually."))
        return out

    @staticmethod
    def _offline_secret_check(token: str, alg: str) -> Optional[str]:
        """Verify the signature locally against common secrets.

        Pure local computation on the token as found. Sends nothing,
        attacks nothing - just answers "is this signed with 'secret'?".
        """
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except ValueError:
            return None
        signing_input = f"{header_b64}.{payload_b64}".encode()
        digest_fn = {"hs256": hashlib.sha256,
                     "hs384": hashlib.sha384,
                     "hs512": hashlib.sha512}.get(alg)
        if digest_fn is None:
            return None  # not an HMAC alg - nothing to check locally
        try:
            want = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        except Exception:
            return None
        for secret in COMMON_SECRETS:
            got = hmac.new(secret.encode(), signing_input, digest_fn).digest()
            if hmac.compare_digest(got, want):
                return secret
        return None


def _b64d(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
