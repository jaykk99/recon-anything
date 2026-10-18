"""Multi-Account State Comparator (IDOR/BOLA differential tester).

Two-account IDOR/BOLA testing framework. Jay provides two token sets via
environment variables:

    RECON_ACCT_A_TOKENS  - JSON string of HIGH-priv account auth headers
    RECON_ACCT_B_TOKENS  - JSON string of LOW-priv account auth headers

Format of each env var (JSON object of HTTP headers to send):

    {"Authorization": "Bearer <token>", "X-Session": "<id>"}

A raw token string (no JSON) is also accepted and is sent as an
Authorization: Bearer header.

For each endpoint taken from the scan's discovery bus (GET only,
read-only), the plugin:
  1. Requests it with Account A's tokens (the authorized baseline).
  2. Requests it with Account B's tokens (A's tokens stripped first -
     a fresh header set is built from B only, nothing from A leaks in).
  3. Compares. A BOLA/IDOR signal is flagged when B receives 200 OK with
     data instead of the expected 403/401/404 denial.

TOKEN SAFETY:
- Tokens are read only from the environment, never from args/files.
- Tokens are NEVER stored in findings, NEVER logged, NEVER echoed in
  error messages. Evidence carries status codes and body fingerprints
  only.
- If either token set is missing, the plugin skips gracefully with a
  note explaining the env vars.

Authorized testing only: only run against assets Jay owns or that are
in an approved bounty scope.
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

ENV_A = "RECON_ACCT_A_TOKENS"
ENV_B = "RECON_ACCT_B_TOKENS"
MAX_ENDPOINTS = 20
DENIED = (401, 403, 404)
DATA_MIN_BYTES = 32

REMEDIATION = ("Enforce object-level authorization on every API endpoint: "
               "the server must check that the calling user owns or is "
               "allowed to access the requested object ID, not just that "
               "they are logged in. Use OWASP API Security Top 10 "
               "guidance for BOLA (API1:2023).")


def _load_tokens(var: str) -> Optional[Dict[str, str]]:
    """Read one token set from the environment. Never logs values."""
    raw = os.environ.get(var, "").strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Raw token string -> Authorization: Bearer header.
        data = {"Authorization": f"Bearer {raw}"}
    if not isinstance(data, dict):
        return None
    headers = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, str) and k and v:
            headers[k] = v
    return headers or None


def _fingerprint(body: bytes) -> Tuple[str, int]:
    return hashlib.sha256(body).hexdigest()[:16], len(body)


ID_LIKE = re.compile(r"/(\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}|[A-Za-z0-9_-]{12,})", re.IGNORECASE)
OBJECT_PATH = re.compile(
    r"/(?:api|v\d+|graphql|rest)/(?:users?|accounts?|profiles?|orders?|"
    r"invoices?|payments?|admin|internal|private)/", re.IGNORECASE)


def _object_specific(url: str) -> bool:
    """Heuristic: does the URL look like it addresses a specific object?"""
    path = urlparse(url).path or ""
    return bool(ID_LIKE.search(path) or OBJECT_PATH.search(path))


class IdorComparatorPlugin(Plugin):
    id = "idor_comparator"
    label = "Multi-Account IDOR Comparator"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "api"
    phase = 2  # consumes endpoints found by phase-1 discovery
    timeout_s = 120
    description = "Two-account IDOR/BOLA differential test (env tokens, never stored)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends authenticated probe requests)")

        tok_a = _load_tokens(ENV_A)
        tok_b = _load_tokens(ENV_B)
        if tok_a is None or tok_b is None:
            missing = [v for v, t in ((ENV_A, tok_a), (ENV_B, tok_b)) if t is None]
            return self._skipped(
                "no account tokens provided. Set " + " and ".join(missing) +
                " (JSON object of auth headers, e.g. "
                "'{\"Authorization\": \"Bearer <token>\"}') to enable "
                "two-account IDOR/BOLA comparison. Tokens are read only "
                "from the environment and are never stored or logged.")

        findings: List = []
        endpoints = [str(u) for u in ctx.consume("endpoints") if isinstance(u, str)]
        same_domain = [u for u in endpoints if domain in urlparse(u).netloc][:MAX_ENDPOINTS]
        if target.type == "url" and target.normalized not in same_domain:
            same_domain.insert(0, target.normalized)

        tested = 0
        for url in same_domain:
            if tested >= MAX_ENDPOINTS:
                break
            tested += 1
            # Account A first: the authorized baseline. Tokens go only in
            # this request's headers; nothing is cached or persisted.
            try:
                ra = await fetch(ctx.http, ctx.limiter, "GET", url,
                                 headers=tok_a, timeout=15,
                                 follow_redirects=True, max_retries=1)
                a_hash, a_len = _fingerprint(ra.content)
            except Exception:
                continue
            if ra.status_code != 200 or a_len < DATA_MIN_BYTES:
                continue  # no authorized data to compare against

            # Account B: strip A's tokens first - a fresh header set built
            # ONLY from B's token set. A's headers are never merged in.
            b_headers = dict(tok_b)
            try:
                rb = await fetch(ctx.http, ctx.limiter, "GET", url,
                                 headers=b_headers, timeout=15,
                                 follow_redirects=True, max_retries=1)
                b_hash, b_len = _fingerprint(rb.content)
            except Exception:
                continue

            if rb.status_code in DENIED:
                continue  # correctly denied for the low-priv account
            if rb.status_code == 200 and b_len >= DATA_MIN_BYTES:
                if not _object_specific(url):
                    # Public-looking page (A and B both get it): not an
                    # IDOR signal. Only object-specific URLs are flagged,
                    # so public pages don't produce noise.
                    continue
                same_data = (b_hash == a_hash)
                findings.append(self._f(
                    "api", "idor_confirmed",
                    f"HIGH: low-priv account got 200 OK with data on "
                    f"'{urlparse(url).path or '/'}' "
                    f"({'identical' if same_data else 'different'} data vs "
                    f"high-priv account, {b_len} bytes). Possible "
                    f"BOLA/IDOR: missing object-level authorization.",
                    source="two-account comparator", source_url=url,
                    confidence=85 if same_data else 70, passive=False,
                    evidence={"severity": "high",
                              "account_a_status": ra.status_code,
                              "account_b_status": rb.status_code,
                              "account_b_bytes": b_len,
                              "identical_to_a": same_data,
                              "tokens_redacted": True,
                              "remediation": REMEDIATION,
                              "scope_note": "Authorized testing only. "
                                            "Confirm on an owned asset or "
                                            "approved bounty scope."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{tested} endpoints compared, {len(findings)} IDOR signals")
        res.duration_ms = dur
        return res
