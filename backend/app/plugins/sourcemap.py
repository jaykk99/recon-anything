"""Source Map Tree Reconstructor.

For every JavaScript file found during the scan (discovery bus
"js_files"), tries fetching "<file>.map". If it returns a valid JSON
source map, it is parsed locally and reconstructed:

  - original source paths (webpack://, sources[])
  - embedded sourcesContent, if present
  - internal URLs: localhost, staging/dev/internal hostnames
  - hardcoded tokens/keys (redacted per the secretutils convention)
  - internal API routes, debug flags, comments with credentials

Secret handling follows the repo convention: findings never carry a
full secret in `value` (redacted prefix...suffix); the full match goes
in evidence["match"] for owner verification/rotation.

If a key/secret is found, a safe READ-ONLY verification call is made
where a provider offers one (Stripe balance, GitHub user, Slack
auth.test). Verified live keys are marked confirmed; everything else is
explicitly marked unverified.

Read-only: only GETs public .map files. Authorized testing only.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..ratelimit import fetch, fetch_many
from .base import Cost, Ctx, Plugin, PluginResult, Target
from .secretutils import PLACEHOLDERS, evidence_block, is_placeholder, redact

MAX_JS = 25
MAP_BODY_LIMIT = 5_000_000

# Focused secret patterns for source maps (not the full secrets.py list -
# source maps carry app code, so provider keys + generic secrets + creds).
SECRET_PATTERNS = [
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}", "critical"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36}", "critical"),
    ("stripe_secret", r"sk_(live|test)_[0-9A-Za-z]{16,}", "critical"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}", "critical"),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}", "high"),
    ("generic_api_key", r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']", "high"),
    ("hardcoded_password", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"']{6,})[\"']", "high"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "medium"),
]

INTERNAL_URL_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[^/\s\"']*\b(?:staging|stg|dev|"
    r"development|internal|intranet|test|qa|uat|sandbox|localhost)\b[^/\s\"']*)"
    r"(?::\d+)?(?:/[^\s\"']*)?",
    re.IGNORECASE)
API_ROUTE_RE = re.compile(r"['\"`](/(?:api|v\d|graphql|internal|admin|private)[^'\"`\s]*)['\"`]")
DEBUG_FLAG_RE = re.compile(r"(?i)\b(debug|verbose|trace|__DEV__|enableDebug|showDebug)\b\s*[:=]\s*(true|1)")
CRED_COMMENT_RE = re.compile(r"(?i)(?://|/\*|#)\s*(?:todo|fixme|hack|note)?\s*:?\s*[^\n]*(?:password|secret|token|key)\s*[:=]\s*[^\n]{4,80}")

REMEDIATION_MAP = ("Do not ship source maps to production, or ship them "
                   "without sourcesContent. Strip secrets from client code, "
                   "rotate anything that leaked, and serve .map files only "
                   "to authenticated staff if needed at all.")


async def _verify_secret(kind: str, match: str, ctx: Ctx) -> Optional[bool]:
    """Safe read-only liveness check. True=confirmed, False=dead, None=cannot verify."""
    try:
        if kind == "stripe_secret":
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            "https://api.stripe.com/v1/balance",
                            headers={"Authorization": f"Bearer {match}"},
                            timeout=10, max_retries=1)
            return r.status_code == 200
        if kind == "github_token":
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            "https://api.github.com/user",
                            headers={"Authorization": f"Bearer {match}",
                                       "Accept": "application/vnd.github+json"},
                            timeout=10, max_retries=1)
            return r.status_code == 200
        if kind == "slack_token":
            r = await fetch(ctx.http, ctx.limiter, "POST",
                            "https://slack.com/api/auth.test",
                            headers={"Authorization": f"Bearer {match}"},
                            timeout=10, max_retries=1)
            try:
                return bool(r.json().get("ok"))
            except Exception:
                return None
    except Exception:
        return None
    return None


class SourcemapPlugin(Plugin):
    id = "sourcemap"
    label = "Source Map Reconstructor"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    phase = 2  # consumes js_files from phase-1 crawlers
    timeout_s = 120
    description = "Reconstruct source maps; extract secrets, internal URLs, debug flags."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List = []
        js_files = [str(u) for u in ctx.consume("js_files") if isinstance(u, str)][:MAX_JS]
        if not js_files:
            return self._skipped("no JS files found by discovery (nothing to map)")

        seen_urls = set()
        targets = []
        for js in js_files:
            map_url = js.split("#")[0].split("?")[0] + ".map"
            if map_url in seen_urls:
                continue
            seen_urls.add(map_url)
            targets.append((js, map_url))
        # Fetch all candidate .map URLs in parallel (independent probes)
        responses = await fetch_many(
            ctx.http, ctx.limiter,
            [("GET", mu, {"timeout": 12, "follow_redirects": True})
             for _, mu in targets],
            concurrency=8, max_retries=1)
        for (js, map_url), r in zip(targets, responses):
            if r is None or r.status_code != 200:
                continue
            body = r.text[:MAP_BODY_LIMIT]
            try:
                sm = json.loads(body)
            except Exception:
                continue
            if not isinstance(sm, dict) or "mappings" not in sm or "sources" not in sm:
                continue

            sources = [s for s in sm.get("sources", []) if isinstance(s, str)]
            contents = sm.get("sourcesContent") or []
            corpus = "\n".join(c for c in contents if isinstance(c, str))
            if not corpus:
                corpus = " ".join(sources)

            base_evidence = {
                "map_url": map_url,
                "js_file": js,
                "source_count": len(sources),
                "has_sources_content": bool(contents),
            }

            # Chain: publish the recovered map so jsdeep (phase 2) can run
            # deep analysis over the original sources
            # (sourcemap_chain in backend/app/chains.py).
            ctx.publish("recovered_sources", map_url)
            ctx.publish("js", {"url": map_url, "recovered": True,
                               "js_file": js})

            # 1) Source tree summary.
            interesting = [s for s in sources
                           if not s.startswith("webpack://") or "/src/" in s or "/app/" in s][:20]
            findings.append(self._f(
                "leak", "sourcemap_exposed",
                f"Source map exposed for {urlparse(js).path or js} "
                f"({len(sources)} original sources"
                f"{', embedded content included' if contents else ''}).",
                source="source map reconstructor", source_url=map_url,
                confidence=95, passive=True,
                evidence={"severity": "medium",
                          **base_evidence,
                          "sample_sources": interesting,
                          "remediation": REMEDIATION_MAP,
                          "scope_note": "Authorized testing only."}))

            # 2) Internal / staging URLs.
            for m in set(INTERNAL_URL_RE.findall(corpus)):
                url = m if isinstance(m, str) else m[0]
                if len(url) > 200:
                    continue
                findings.append(self._f(
                    "leak", "sourcemap_internal_url",
                    f"Internal/staging URL in source map: {url[:120]}",
                    source="source map reconstructor", source_url=map_url,
                    confidence=80, passive=True,
                    evidence={"severity": "medium", **base_evidence,
                              "url": url[:200],
                              "remediation": REMEDIATION_MAP}))

            # 3) Internal API routes.
            for route in list(set(API_ROUTE_RE.findall(corpus)))[:25]:
                if len(route) > 160 or ".." in route:
                    continue
                findings.append(self._f(
                    "api", "sourcemap_api_route",
                    f"Internal API route in source map: {route}",
                    source="source map reconstructor", source_url=map_url,
                    confidence=85, passive=True,
                    evidence={"severity": "medium", **base_evidence,
                              "route": route,
                              "remediation": "Audit this route for auth; "
                                             "source maps make hidden API "
                                             "surface visible to attackers."}))

            # 4) Debug flags.
            for flag, val in set(DEBUG_FLAG_RE.findall(corpus)):
                findings.append(self._f(
                    "web", "sourcemap_debug_flag",
                    f"Debug flag enabled in source: {flag}={val}",
                    source="source map reconstructor", source_url=map_url,
                    confidence=85, passive=True,
                    evidence={"severity": "low", **base_evidence,
                              "flag": flag,
                              "remediation": "Disable debug/verbose flags in "
                                             "production builds."}))

            # 5) Secrets + credential comments (redacted; verified where possible).
            for kind, pat, sev in SECRET_PATTERNS:
                for m in re.finditer(pat, corpus):
                    secret = m.group(1) if m.lastindex else m.group(0)
                    if not secret or is_placeholder(secret):
                        continue
                    if kind == "generic_api_key" and secret.lower() in PLACEHOLDERS:
                        continue
                    verified = await _verify_secret(kind, secret, ctx)
                    status_word = ("CONFIRMED LIVE" if verified is True
                                   else "DEAD/INVALID" if verified is False
                                   else "UNVERIFIED")
                    findings.append(self._f(
                        "leak", "sourcemap_secret",
                        f"{status_word}: {kind} {redact(secret)} in source map "
                        f"for {urlparse(js).path or js}",
                        source="source map reconstructor", source_url=map_url,
                        confidence=95 if verified is True else 75,
                        passive=True,
                        evidence=evidence_block(
                            secret, kind,
                            "api_key" if "key" in kind or "token" in kind else "credential",
                            sev if verified is not False else "low",
                            {"map_url": map_url, "js_file": js,
                             "verified": verified,
                             "verification": status_word,
                             "scope_note": "Authorized testing only: rotate "
                                           "immediately if this is your asset."})))
                    break  # one finding per pattern kind per map
            for m in list(set(CRED_COMMENT_RE.findall(corpus)))[:10]:
                comment = m if isinstance(m, str) else m[0]
                findings.append(self._f(
                    "leak", "sourcemap_cred_comment",
                    f"Credential-looking comment in source map: {comment.strip()[:100]}",
                    source="source map reconstructor", source_url=map_url,
                    confidence=65, passive=True,
                    evidence={"severity": "medium", **base_evidence,
                              "comment": comment.strip()[:200],
                              "remediation": REMEDIATION_MAP}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(js_files)} JS files checked, {len(findings)} map findings")
        res.duration_ms = dur
        return res
