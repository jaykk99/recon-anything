"""Authenticated endpoint scanner.

Jay provides credentials via environment variables for targets he is
authorized to test (his own apps, bug bounty programs with test accounts):

    RECON_AUTH_BEARER         - Bearer token, sent as Authorization: Bearer <token>
    RECON_AUTH_COOKIE         - Raw cookie header value, sent as Cookie: <value>
    RECON_AUTH_APIKEY         - API key value
    RECON_AUTH_APIKEY_HEADER  - Header name for the API key (default: X-API-Key)
    RECON_AUTH_HEADERS        - JSON object of extra headers, e.g.
                                {"Authorization": "Basic abc", "X-Tenant": "123"}

For each endpoint taken from the scan's discovery bus (GET only,
read-only), the plugin:
  1. Requests it WITHOUT auth (baseline).
  2. Requests it WITH the provided auth headers.
  3. Compares and reports:
     - endpoints that require auth (401/403 without, 200 with)
     - endpoints unexpectedly open (200 both ways - auth not enforced)
     - auth-protected content now visible (titles, API shapes)

CREDENTIAL SAFETY:
- Credentials are read only from the environment, never from args/files.
- Credentials are NEVER stored in findings, NEVER logged, NEVER echoed in
  error messages or reasons. Evidence carries status codes and
  fingerprints only.
- If no credentials are provided, the plugin reports ok(0) with a note
  explaining the env vars (Jay's rule: no skips, ever).

Authorized testing only: only run against assets Jay owns or that are
in an approved bounty scope. The plugin never attempts logins, never
brute-forces, never tries credential guessing - it only USES the
credentials Jay explicitly provided.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Plugin, PluginResult, Target

ENV_BEARER = "RECON_AUTH_BEARER"
ENV_COOKIE = "RECON_AUTH_COOKIE"
ENV_APIKEY = "RECON_AUTH_APIKEY"
ENV_APIKEY_HEADER = "RECON_AUTH_APIKEY_HEADER"
ENV_HEADERS = "RECON_AUTH_HEADERS"

MAX_ENDPOINTS = 25
DENIED = (401, 403)

REMEDIATION_OPEN = ("This endpoint returns data without authentication. If it "
                    "should be protected, enforce authentication and "
                    "object-level authorization on the server side.")
REMEDIATION_AUTH_OK = ("Authenticated access works as expected. Keep "
                       "enforcing auth on this endpoint and review that the "
                       "returned data matches the caller's privilege level.")


def _load_auth_headers() -> Optional[Dict[str, str]]:
    """Build auth headers from env vars. Never logs values."""
    headers: Dict[str, str] = {}
    bearer = os.environ.get(ENV_BEARER, "").strip()
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    cookie = os.environ.get(ENV_COOKIE, "").strip()
    if cookie:
        headers["Cookie"] = cookie
    apikey = os.environ.get(ENV_APIKEY, "").strip()
    if apikey:
        hname = os.environ.get(ENV_APIKEY_HEADER, "").strip() or "X-API-Key"
        headers[hname] = apikey
    raw = os.environ.get(ENV_HEADERS, "").strip()
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(k, str) and isinstance(v, str) and k and v:
                        headers[k] = v
        except (json.JSONDecodeError, ValueError):
            pass
    return headers or None


def _fingerprint(body: bytes) -> str:
    return hashlib.sha256(body[:4096]).hexdigest()[:12]


def _sniff_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:80] if m else ""


class AuthscanPlugin(Plugin):
    id = "authscan"
    label = "Authenticated Scanner"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "api"
    description = ("Test endpoints with your credentials (env-provided). "
                   "Finds auth-gated vs unexpectedly open endpoints.")
    requires_keys = []
    phase = 2
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List = []
        auth_headers = _load_auth_headers()
        if not auth_headers:
            res = self._ok(
                [],
                "no credentials provided - set RECON_AUTH_BEARER, "
                "RECON_AUTH_COOKIE, RECON_AUTH_APIKEY, or RECON_AUTH_HEADERS "
                "to enable authenticated scanning")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        endpoints = self._collect_endpoints(target, ctx)
        if not endpoints:
            res = self._ok([], "no endpoints discovered to test with auth")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        n_tested = 0
        for url in endpoints[:MAX_ENDPOINTS]:
            # Global time guard: leave headroom under the 30s plugin cap.
            if time.monotonic() - t0 > 24:
                break
            try:
                result = await self._probe(url, auth_headers, ctx)
            except Exception:
                continue
            n_tested += 1
            if result is not None:
                findings.append(result)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"tested {n_tested} endpoints with provided credentials, "
            f"{len(findings)} auth-relevant findings")
        res.duration_ms = dur
        return res

    def _collect_endpoints(self, target: Target, ctx: Ctx) -> List[str]:
        seen: List[str] = []
        for kind in ("endpoints", "api_endpoints", "js_endpoints",
                     "hidden_paths", "forms"):
            for item in ctx.consume(kind):
                url = item if isinstance(item, str) else str(item.get("url", ""))
                if url.startswith("http") and url not in seen:
                    seen.append(url)
        # Always include the base target itself.
        base = target.normalized
        if not base.startswith("http"):
            base = f"https://{base}"
        if base not in seen:
            seen.insert(0, base)
        return seen

    async def _probe(self, url: str, auth_headers: Dict[str, str],
                     ctx: Ctx):
        """Probe one URL with and without auth. Returns a Finding or None."""
        try:
            r_open = await fetch(ctx.http, ctx.limiter, "GET", url,
                                 timeout=10, max_retries=0)
        except Exception:
            return None
        open_status = r_open.status_code
        open_body = r_open.content or b""

        # Skip obvious misses - nothing to compare.
        if open_status == 404:
            return None

        try:
            r_auth = await fetch(ctx.http, ctx.limiter, "GET", url,
                                 timeout=10, max_retries=0,
                                 headers=auth_headers)
        except Exception:
            return None
        auth_status = r_auth.status_code
        auth_body = r_auth.content or b""

        host = urlparse(url).netloc
        # Never include credential values anywhere.
        if open_status in DENIED and auth_status == 200:
            title = _sniff_title(auth_body[:20000].decode("utf-8", "ignore"))
            ev = {
                "severity": "low",
                "url": url,
                "host": host,
                "open_status": open_status,
                "auth_status": auth_status,
                "auth_body_bytes": len(auth_body),
                "auth_body_fingerprint": _fingerprint(auth_body),
                "page_title": title,
                "exploitability": "unknown",
                "remediation": REMEDIATION_AUTH_OK,
            }
            return self._f(
                "api", "auth_required_endpoint",
                f"Auth-gated endpoint: {url} "
                f"({open_status} without auth, 200 with your credentials)",
                source="authscan: credential comparison",
                source_url=url, confidence=90, passive=False,
                evidence=ev, bounty_value="low")

        if open_status == 200 and auth_status == 200:
            # Auth not enforced - flag only if it looks non-public.
            path = urlparse(url).lower()
            sensitive_hint = any(
                s in path for s in ("admin", "api", "account", "user",
                                    "dashboard", "settings", "private",
                                    "internal", "profile", "order",
                                    "payment", "billing"))
            fp_open = _fingerprint(open_body)
            fp_auth = _fingerprint(auth_body)
            if sensitive_hint or fp_open != fp_auth:
                sev = "medium" if sensitive_hint else "low"
                ev = {
                    "severity": sev,
                    "url": url,
                    "host": host,
                    "open_status": open_status,
                    "auth_status": auth_status,
                    "responses_differ": fp_open != fp_auth,
                    "sensitive_path_hint": sensitive_hint,
                    "exploitability": "theoretical",
                    "remediation": REMEDIATION_OPEN,
                }
                return self._f(
                    "api", "endpoint_not_auth_enforced",
                    f"Endpoint reachable WITHOUT auth: {url} "
                    f"(200 both with and without your credentials)",
                    source="authscan: credential comparison",
                    source_url=url, confidence=75, passive=False,
                    evidence=ev,
                    bounty_value="medium" if sensitive_hint else "low")
        return None
