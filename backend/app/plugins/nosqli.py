"""NoSQL injection detector (high findings).

Non-destructive: operator probes with Mongo/NoSQL error-text
detection, plus a $where sleep canary (delay > 4s = signal).
No data extraction. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Tuple
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url

REMEDIATION = ("Use typed query builders / ODMs, never pass raw request "
               "objects into queries. Cast inputs to expected types, "
               "disable server-side $where, and hide DB error details.")

NOSQL_ERRORS = [
    (r"MongoError", "MongoDB error"),
    (r"MongoServerError", "MongoDB server error"),
    (r"ObjectId(.*?failed|.*?invalid)", "ObjectId cast error"),
    (r"BSON.*?error", "BSON error"),
    (r"Cast to .*? failed", "Mongoose cast error"),
    (r"SyntaxError.*?Unexpected token", "JS query syntax error"),
    (r"MongoParseError", "Mongo parse error"),
    (r"document must be a valid JSON", "invalid document error"),
    (r"CouchDB.*?error", "CouchDB error"),
    (r"Redis.*?ERR", "Redis error"),
]

# Safe operator payloads (detection only; appended as plain GET params)
NOSQL_ERROR_PAYLOADS = [
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$where":"1"}',
    '{"$regex":".*"}',
    "[$ne]",
]

# $where sleep canary, harmless timing probe
NOSQL_TIME_PAYLOADS: List[Tuple[str, str]] = [
    ('{"$where":"sleep(5000)"}', "mongodb-where"),
    ('{"$where":"function(){sleep(5000);return true}"}', "mongodb-where"),
]


class NosqlInjectionPlugin(Plugin):
    id = "nosqli"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "NoSQL Injection"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "NoSQL injection: operator, error and timing probes."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []

        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        tested = 0
        for u in list(urls)[:8]:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            for name, val in params[:3]:
                found = False

                # --- Method 1: error-based operator probes ---
                for payload in NOSQL_ERROR_PAYLOADS:
                    tested += 1
                    purl = probe_url(parts, params, name, payload)
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                         timeout=15)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    for pat, label in NOSQL_ERRORS:
                        if re.search(pat, body, re.I | re.S):
                            findings.append(self._f(
                                "leak", "nosqli_error_based",
                                f"HIGH: NoSQL injection signal in parameter "
                                f"'{name}' at {parts.path or '/'} "
                                f"({label}).",
                                source="nosql probe", source_url=purl,
                                confidence=80, passive=False,
                                evidence={"severity": "high",
                                          "method": "error-based",
                                          "parameter": name,
                                          "error_label": label,
                                          "payload": payload,
                                          "remediation": REMEDIATION,
                                          "scope_note": "Authorized testing only. "
                                                        "No data extracted."}))
                            found = True
                            break
                    if found:
                        break
                if found:
                    continue

                # --- Method 2: $where timing probe ---
                for payload, label in NOSQL_TIME_PAYLOADS:
                    tested += 1
                    purl = probe_url(parts, params, name, payload)
                    try:
                        p0 = time.monotonic()
                        await fetch(ctx.http, ctx.limiter, "GET", purl,
                                    timeout=20)
                        delta = time.monotonic() - p0
                    except Exception:
                        continue
                    if delta >= 4.0:
                        findings.append(self._f(
                            "leak", "nosqli_time_based",
                            f"HIGH: time-based NoSQL injection in "
                            f"parameter '{name}' (~{delta:.1f}s delay) at "
                            f"{parts.path or '/'} ({label}).",
                            source="nosql probe", source_url=purl,
                            confidence=75, passive=False,
                            evidence={"severity": "high",
                                      "method": "time-based",
                                      "parameter": name,
                                      "delay_s": round(delta, 1),
                                      "payload": payload,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Authorized testing only. "
                                                    "Sleep canary only."}))
                        found = True
                        break

        res = self._ok(findings, f"probed {tested} payloads across "
                                 f"{len(urls)} URLs, {len(findings)} NoSQL signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
