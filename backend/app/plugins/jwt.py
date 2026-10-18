"""JWT discovery and offline analysis plugin.

Finds JWTs in page bodies, linked JS files, and localStorage usage
patterns. Every check is performed OFFLINE on the token itself:
- alg=none acceptance risk
- missing exp claim (tokens that never expire)
- weak HMAC secrets tested LOCALLY against a tiny common-secret list
  (secret, password, 123456, ...) - the signature is verified on this
  machine only, never brute-forced against the server
- sensitive data in the payload (emails, roles, admin flags, user IDs)
Detection only. No requests are made with discovered tokens.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_\-]*")
LS_TOKEN_RE = re.compile(
    r"localStorage\s*\.\s*(?:setItem|getItem)\s*\(\s*['\"]([^'\"]*(?:token|jwt|auth)[^'\"]*)['\"]",
    re.I)
SESSION_TOKEN_RE = re.compile(
    r"sessionStorage\s*\.\s*(?:setItem|getItem)\s*\(\s*['\"]([^'\"]*(?:token|jwt|auth)[^'\"]*)['\"]",
    re.I)

# Tiny offline wordlist - only the most common defaults. Local HMAC only.
WEAK_SECRETS = ["secret", "password", "123456", "jwt-secret", "changeme",
                "test", "admin", "qwerty", "letmein", "password123",
                "12345678", "supersecret", "jwt_secret", "mysecret"]

SENSITIVE_CLAIMS = {"email", "mail", "role", "roles", "admin", "is_admin",
                    "isadmin", "user_id", "userid", "uid", "sub", "username",
                    "name", "password", "ssn", "phone", "permissions", "scope"}


def _b64url_decode(seg: str) -> Optional[bytes]:
    try:
        pad = "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg + pad)
    except Exception:
        return None


def _parse_jwt(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    hb = _b64url_decode(parts[0])
    pb = _b64url_decode(parts[1])
    if not hb or not pb:
        return None
    try:
        header = json.loads(hb.decode("utf-8", "replace"))
        payload = json.loads(pb.decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    return header, payload, parts[2]


def _offline_weak_secret(token: str, alg: str) -> Optional[str]:
    """Test tiny secret list against the signature LOCALLY. Never online."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return None
    digestmod = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                 "HS512": hashlib.sha512}.get(alg.upper())
    if digestmod is None:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        expected = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except Exception:
        return None
    for secret in WEAK_SECRETS:
        mac = hmac.new(secret.encode(), signing_input, digestmod).digest()
        if hmac.compare_digest(mac, expected):
            return secret
    return None


class JwtPlugin(Plugin):
    id = "jwt"
    label = "JWT Analyzer"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = ("Finds JWTs in responses and JS, checks alg=none, weak "
                   "secrets (offline), missing exp, and payload data.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

        findings: List[Finding] = []
        seen: set = set()

        async def fetch_text(url: str) -> str:
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                                max_retries=1, follow_redirects=True)
                return r.text[:300000]
            except Exception:
                return ""

        texts: List[Tuple[str, str]] = []  # (label, text)
        home = await fetch_text(base + "/")
        if home:
            texts.append(("homepage", home))
        for js_url in ctx.consume("js_files")[:12]:
            full = js_url if js_url.startswith("http") else base + js_url
            txt = await fetch_text(full)
            if txt:
                texts.append((full, txt))

        def analyze_token(token: str, where: str) -> None:
            if token in seen:
                return
            seen.add(token)
            parsed = _parse_jwt(token)
            if not parsed:
                return
            header, payload, sig = parsed
            alg = str(header.get("alg", "")).upper()
            short = token[:24] + "..."

            # alg=none
            if alg == "NONE":
                findings.append(self._f(
                    "identity", "jwt_alg_none",
                    f"JWT using alg=none discovered ({where}, {short}) - "
                    "signature verification can be bypassed if the server "
                    "accepts it",
                    source="JWT analyzer", source_url=base + "/",
                    confidence=85, passive=True,
                    evidence={"severity": "high", "exploitability": "public_poc",
                              "remediation": "Reject alg=none tokens "
                              "server-side; pin the expected algorithm "
                              "(e.g. RS256) and never trust the token's own "
                              "alg header."}))
            # missing exp
            if "exp" not in payload:
                findings.append(self._f(
                    "identity", "jwt_no_exp",
                    f"JWT without exp claim ({where}, alg={alg or '?'} {short}) "
                    "- tokens never expire, stolen tokens stay valid forever",
                    source="JWT analyzer", source_url=base + "/",
                    confidence=85, passive=True,
                    evidence={"severity": "medium",
                              "exploitability": "theoretical",
                              "remediation": "Add short-lived exp claims "
                              "(minutes, not days) and enforce them "
                              "server-side; add refresh-token rotation."}))
            # weak secret - OFFLINE check only
            if alg.startswith("HS"):
                weak = _offline_weak_secret(token, alg)
                if weak:
                    findings.append(self._f(
                        "identity", "jwt_weak_secret",
                        f"JWT HMAC secret cracked OFFLINE: the signing key is "
                        f"the guessable default '{weak}' ({where}) - anyone "
                        "can forge tokens",
                        source="JWT analyzer", source_url=base + "/",
                        confidence=95, passive=True,
                        evidence={"severity": "high",
                                  "exploitability": "weaponized",
                                  "remediation": "Replace the HMAC secret "
                                  "immediately with a long random value from "
                                  "a secure generator, rotate all issued "
                                  "tokens, and audit access logs."}))
            # sensitive payload claims
            sensitive = sorted(k for k in payload.keys()
                               if k.lower() in SENSITIVE_CLAIMS)
            if sensitive:
                adminish = any("admin" in k.lower() or
                               str(payload.get(k)).lower() in ("admin", "true")
                               for k in sensitive)
                findings.append(self._f(
                    "identity", "jwt_sensitive_payload",
                    f"JWT payload contains sensitive claims: "
                    f"{', '.join(sensitive)} ({where}, {short}) - JWT bodies "
                    "are only base64, readable by anyone holding the token",
                    source="JWT analyzer", source_url=base + "/",
                    confidence=80, passive=True,
                    evidence={"severity": "medium" if adminish else "low",
                              "exploitability": "theoretical",
                              "remediation": "Keep only an opaque user ID in "
                              "the token; look up roles/permissions "
                              "server-side instead of embedding them."}))
            # weak alg
            if alg in ("HS256",) and sig == "":
                findings.append(self._f(
                    "identity", "jwt_empty_sig",
                    f"JWT with empty signature section ({where}, {short})",
                    source="JWT analyzer", source_url=base + "/",
                    confidence=75, passive=True,
                    evidence={"severity": "medium",
                              "exploitability": "theoretical",
                              "remediation": "Require a valid signature on "
                              "every token; reject tokens with missing or "
                              "empty signatures."}))

        for label, txt in texts:
            for m in JWT_RE.finditer(txt):
                analyze_token(m.group(0), label)
            for m in LS_TOKEN_RE.finditer(txt):
                findings.append(self._f(
                    "identity", "jwt_localstorage",
                    f"Auth token kept in localStorage under key "
                    f"'{m.group(1)}' ({label}) - any XSS can steal it",
                    source="JWT analyzer", source_url=base + "/",
                    confidence=70, passive=True,
                    evidence={"severity": "medium",
                              "exploitability": "theoretical",
                              "remediation": "Store session tokens in "
                              "HttpOnly, Secure, SameSite cookies instead of "
                              "localStorage."}))
            for m in SESSION_TOKEN_RE.finditer(txt):
                findings.append(self._f(
                    "identity", "jwt_sessionstorage",
                    f"Auth token kept in sessionStorage under key "
                    f"'{m.group(1)}' ({label}) - readable by any script on "
                    "the page",
                    source="JWT analyzer", source_url=base + "/",
                    confidence=65, passive=True,
                    evidence={"severity": "low", "exploitability": "theoretical",
                              "remediation": "Prefer HttpOnly Secure cookies "
                              "for session tokens."}))

        if not findings:
            findings.append(self._f(
                "identity", "jwt_clean",
                "No JWTs found in pages or JS; no localStorage token patterns "
                "detected",
                source="JWT analyzer", source_url=base + "/",
                confidence=70, passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"analyzed {len(seen)} JWTs across "
                                 f"{len(texts)} sources")
        res.duration_ms = dur
        return res
