"""Response-Diff Parameter Fuzzer.

GET-only differential fuzzer. For each endpoint from the discovery bus:

  1. Baseline: GET the endpoint, record status code, response body hash,
     body length, and response time.
  2. Fuzz: append each parameter from a curated wordlist (~50 entries)
     as `?<param>=1` and re-request.
  3. Flag when vs baseline: status code changes, body length changes
     by more than 20%, new JSON keys appear, or response time changes
     by more than 3x.

Signals a hidden/debug parameter changing server behavior - a classic
precursor to auth bypass, verbose errors, or hidden functionality.

GET ONLY. POST/PUT/DELETE endpoints are never fuzzed (state-changing).
Endpoints whose URL pattern suggests a non-GET action (logout, delete,
submit, etc.) are skipped gracefully.

Read-only and rate-limited via the shared limiter. Authorized testing
only.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Plugin, PluginResult, Target

MAX_ENDPOINTS = 5
LENGTH_DELTA = 0.20   # flag when body length changes > 20%
TIME_FACTOR = 3.0     # flag when response time changes > 3x
MIN_BODY = 16         # ignore trivially small bodies for length diffs

# Curated wordlist: debug/admin/feature-flag style params (~50).
FUZZ_PARAMS = [
    "debug", "admin", "role", "test", "bypass", "internal", "dev",
    "staging", "verbose", "all", "show", "edit", "delete", "true",
    "1", "view", "mode", "preview", "beta", "flag", "override",
    "superuser", "isadmin", "is_admin", "user", "uid", "id", "key",
    "token", "auth", "login", "root", "sys", "maintenance", "console",
    "trace", "log", "dump", "export", "raw", "format", "json", "xml",
    "pretty", "full", "details", "info", "status", "health", "ping",
    "version",
]

# URL path hints of state-changing actions: never fuzz these, even via GET.
STATE_CHANGING_HINTS = (
    "logout", "signout", "delete", "remove", "destroy", "submit",
    "purchase", "checkout", "payment", "pay", "order", "register",
    "signup", "unsubscribe", "reset", "revoke", "cancel", "refund",
    "transfer", "send", "post", "create", "update", "edit",
)

REMEDIATION = ("Unknown parameters should not change server behavior. "
               "Ignore or reject unrecognized query params, keep debug "
               "flags behind auth and environment gates, and make sure "
               "error/verbose output never leaks internals.")


def _body_fingerprint(text: str) -> Tuple[str, int]:
    b = text.encode("utf-8", "replace")
    return hashlib.sha256(b).hexdigest()[:16], len(b)


def _json_keys(text: str) -> Optional[set]:
    try:
        data = json.loads(text)
    except Exception:
        return None
    keys = set()

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                keys.add(str(k))
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(data)
    return keys


def _with_param(url: str, param: str) -> str:
    parts = urlparse(url)
    params = parse_qsl(parts.query)
    params.append((param, "1"))
    return urlunparse(parts._replace(query=urlencode(params)))


class ParamFuzzerPlugin(Plugin):
    id = "param_fuzzer"
    label = "Response-Diff Parameter Fuzzer"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    phase = 2  # consumes endpoints from phase-1 discovery
    timeout_s = 180
    description = "GET-only param fuzzer; flags behavior-changing params via response diff."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends fuzzed GET requests)")

        endpoints: List[str] = []
        for eu in ctx.consume("endpoints"):
            u = str(eu)
            p = urlparse(u)
            if domain not in p.netloc:
                continue
            low = (p.path + "?" + p.query).lower()
            if any(h in low for h in STATE_CHANGING_HINTS):
                continue  # never fuzz likely state-changing endpoints
            if u not in endpoints:
                endpoints.append(u)
            if len(endpoints) >= MAX_ENDPOINTS:
                break

        findings: List = []
        tested = 0
        for url in endpoints:
            # Baseline.
            try:
                t_start = time.monotonic()
                rb = await fetch(ctx.http, ctx.limiter, "GET", url,
                                 timeout=15, follow_redirects=True, max_retries=1)
                t_base = max(time.monotonic() - t_start, 0.001)
                base_hash, base_len = _body_fingerprint(rb.text)
                base_keys = _json_keys(rb.text)
            except Exception:
                continue
            tested += 1

            for param in FUZZ_PARAMS:
                furl = _with_param(url, param)
                try:
                    t_start = time.monotonic()
                    rf = await fetch(ctx.http, ctx.limiter, "GET", furl,
                                     timeout=15, follow_redirects=True, max_retries=1)
                    t_f = max(time.monotonic() - t_start, 0.001)
                    f_hash, f_len = _body_fingerprint(rf.text)
                    f_keys = _json_keys(rf.text)
                except Exception:
                    continue

                signals = []
                if rf.status_code != rb.status_code:
                    signals.append(f"status {rb.status_code}->{rf.status_code}")
                if base_len >= MIN_BODY and f_len >= MIN_BODY:
                    delta = abs(f_len - base_len) / base_len
                    if delta > LENGTH_DELTA:
                        signals.append(f"body length {base_len}->{f_len} ({delta:.0%})")
                if base_keys is not None and f_keys is not None:
                    new_keys = f_keys - base_keys
                    if new_keys:
                        signals.append("new JSON keys: " + ", ".join(sorted(new_keys)[:8]))
                slow = t_f > t_base * TIME_FACTOR and t_f - t_base > 0.5
                if slow:
                    # Timing is noisy (proxies, GC pauses): confirm by
                    # re-requesting once. Flag only if it is slow twice.
                    try:
                        t2 = time.monotonic()
                        await fetch(ctx.http, ctx.limiter, "GET", furl,
                                    timeout=15, follow_redirects=True, max_retries=1)
                        t_f2 = max(time.monotonic() - t2, 0.001)
                    except Exception:
                        t_f2 = 0.0
                    if t_f2 > t_base * TIME_FACTOR and t_f2 - t_base > 0.5:
                        signals.append(f"response time {t_base:.2f}s->{t_f:.2f}s (confirmed x2)")
                    # else: single slow sample, dropped as noise

                if signals:
                    findings.append(self._f(
                        "web", "fuzz_param_anomaly",
                        f"Parameter '{param}' changes behavior at "
                        f"'{urlparse(url).path or '/'}': " + "; ".join(signals),
                        source="param fuzzer", source_url=furl,
                        confidence=70, passive=False,
                        evidence={"severity": "medium",
                                  "parameter": param,
                                  "endpoint": url,
                                  "baseline_status": rb.status_code,
                                  "fuzzed_status": rf.status_code,
                                  "signals": signals,
                                  "remediation": REMEDIATION,
                                  "scope_note": "GET-only differential test. "
                                                "Authorized testing only."}))

            # Checkpoint after each endpoint's full param pass (up to 50
            # sequential requests, each with its own baseline + possible
            # timing-confirmation re-request). timeout_s=180 is clamped
            # to MAX_PLUGIN_TIMEOUT_S=120 by the runner, and can be
            # clamped further by the scan's remaining budget - a slow
            # target can blow that well before all MAX_ENDPOINTS finish.
            # Without this, a kill mid-fuzz discarded every anomaly
            # already found on earlier endpoints.
            self._checkpoint(findings)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{tested} endpoints fuzzed ({len(FUZZ_PARAMS)} params each), {len(findings)} anomalies")
        res.duration_ms = dur
        return res
