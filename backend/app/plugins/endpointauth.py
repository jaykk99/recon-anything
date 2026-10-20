"""Endpoint Auth Probe (native, keyless).

Detection only: takes API-looking URLs from the "endpoints" discovery
bus (published by jsdeep/apidiscover) and sends ONE plain GET per
endpoint with no credentials, no cookies, no auth headers, no
parameters. Records the status code and classifies:

- 401/403            -> auth_required (properly guarded; cataloged low)
- 200 with JSON      -> unauthenticated_api (HIGH: an API answering
                       without auth is exactly what bounty hunters
                       want flagged)
- 404/405            -> dead
- 5xx                -> server_error (error-leak candidate, medium)

Never retries failures. Never attempts auth. Bounded at 25s total.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   gather_capped)

MAX_ENDPOINTS = 60
CONCURRENCY = 8
TIME_BUDGET = 25
PER_REQUEST_TIMEOUT = 8

API_HINTS = ("/api/", "/v1/", "/v2/", "/rest/", "/graphql",
             "/admin/", "/internal/")


def _is_api_looking(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(h in path for h in API_HINTS)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _looks_like_json(resp) -> bool:
    ctype = resp.headers.get("content-type", "").lower()
    if "json" in ctype:
        try:
            data = resp.json()
            return isinstance(data, (dict, list))
        except Exception:
            return False
    try:
        text = (resp.text or "").lstrip()[:1]
        return text in ("{", "[")
    except Exception:
        return False


class EndpointAuthPlugin(Plugin):
    id = "endpointauth"
    label = "Endpoint Auth Probe"
    accepts = ["domain", "url"]
    passive = False  # sends unauthenticated GETs (read-only probes)
    cost = Cost.FREE
    group = "api"
    phase = 2
    timeout_s = 30
    description = ("Probe API-looking endpoints with one clean GET to "
                   "classify auth requirements. Detection only: no "
                   "parameters, no credentials, no auth attempts.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        seen: set = set()
        urls: List[str] = []
        for item in ctx.consume("endpoints"):
            if not isinstance(item, str) or not item.startswith(
                    ("http://", "https://")):
                continue
            if item in seen or not _is_api_looking(item):
                continue
            seen.add(item)
            urls.append(item)
            if len(urls) >= MAX_ENDPOINTS:
                break

        if not urls:
            return self._ok([], "no API-looking endpoints on the bus")

        # Guarantee a credential-free probe: drop any cookies the shared
        # client picked up from this host so this is a clean,
        # unauthenticated request. No auth headers are ever sent.
        for h in {_host(u) for u in urls if _host(u)}:
            try:
                ctx.http.cookies.clear(domain=h)
            except Exception:
                pass

        sem = asyncio.Semaphore(CONCURRENCY)

        async def probe(url: str) -> Tuple[str, int, Any] | None:
            if (time.monotonic() - t0) > TIME_BUDGET:
                return None
            async with sem:
                try:
                    host = _host(url)
                    limiter = getattr(ctx, "limiter", None)
                    if limiter is not None:
                        await limiter.wait(host)
                    resp = await ctx.http.request(
                        "GET", url, timeout=PER_REQUEST_TIMEOUT,
                        headers={"Accept": "*/*"})
                    # feed the shared rate limiter / WAF accounting
                    # manually since we bypassed the fetch wrapper
                    try:
                        from ..ratelimit import classify_response
                        if limiter is not None:
                            limiter.note_result(host,
                                                classify_response(resp))
                    except Exception:
                        pass
                    return url, resp.status_code, resp
                except Exception:
                    return None

        results = await gather_capped(
            [probe(u) for u in urls],
            max(1.0, TIME_BUDGET - (time.monotonic() - t0)))

        probed: List[Dict] = []
        for res in results:
            if not res:
                continue
            url, status, resp = res
            if status in (401, 403):
                verdict = "auth_required"
            elif status == 200 and _looks_like_json(resp):
                verdict = "unauthenticated_api"
            elif status in (404, 405):
                verdict = "dead"
            elif status >= 500:
                verdict = "server_error"
            else:
                verdict = "other"
            entry = {"url": url, "status": status, "verdict": verdict}
            probed.append(entry)
            ctx.publish("endpoint_auth", entry)

        if not probed:
            return self._ok([], "probes failed or timed out")

        findings: List[Finding] = []
        for e in probed:
            url, status, verdict = e["url"], e["status"], e["verdict"]
            if verdict == "unauthenticated_api":
                findings.append(self._f(
                    "api", "unauthenticated_api",
                    f"API responds without auth: HTTP {status} {url}",
                    "endpointauth", source_url=url, confidence=80,
                    passive=False,
                    evidence={
                        "severity": "high", "status": status,
                        "remediation": "This endpoint answers "
                                       "unauthenticated requests with API "
                                       "data. Require authentication and "
                                       "enforce object-level authorization; "
                                       "test with a second account."}))
            elif verdict == "auth_required":
                findings.append(self._f(
                    "api", "auth_required_endpoint",
                    f"HTTP {status}: {url}", "endpointauth",
                    source_url=url, confidence=85, passive=False,
                    evidence={
                        "severity": "low", "status": status,
                        "remediation": "Auth-gated as expected. Confirm the "
                                       "gate holds for all HTTP methods and "
                                       "parameter variants."}))
            elif verdict == "server_error":
                findings.append(self._f(
                    "api", "endpoint_error_leak",
                    f"HTTP {status} on {url} (possible error/stack-trace "
                    f"leak)", "endpointauth", source_url=url,
                    confidence=70, passive=False,
                    evidence={
                        "severity": "medium", "status": status,
                        "remediation": "5xx responses can leak stack "
                                       "traces, paths, or versions. Return "
                                       "a generic error and log details "
                                       "server-side."}))

        counts: Dict[str, int] = {}
        for e in probed:
            counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
        count_str = ", ".join(f"{k}:{v}" for k, v in
                              sorted(counts.items()))
        reason = f"probed {len(probed)} endpoints ({count_str})"
        return self._ok(findings, reason)
