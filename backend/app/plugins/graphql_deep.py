"""GraphQL deep introspection (phase-2 chain consumer).

Consumes the "graphql_endpoints" bus published by graphql.py (phase 1)
plus "graphql:" chain signals, and goes deeper - still strictly
read-only, detection only:

  - Full schema introspection: enumerate Query / Mutation /
    Subscription field NAMES only. Dangerous-sounding operation names
    (deleteUser, admin*, *password*) are flagged by name; they are never
    executed.
  - Batching probe: one POST carrying an array of two tiny read-only
    queries. If both are answered, query batching is enabled (cheap
    brute-force / DoS amplifier).
  - GET-query probe: ?query={__typename} over GET. If it works, queries
    can ride GET requests (CSRF-able when auth is cookie-based).
  - Error verbosity: one malformed query; verbose errors that leak
    schema hints are flagged.

No mutations are ever executed. No auth bypass is attempted. Keyless.
"""
from __future__ import annotations

import json
import time
from typing import Dict, List
from urllib.parse import urlencode

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

FULL_INTROSPECTION = """{__schema{queryType{name fields{name}}}mutationType{name fields{name}}subscriptionType{name fields{name}}}}"""

# operation-name fragments that deserve a closer look (names only)
RISKY_OP_FRAGMENTS = (
    "delete", "remove", "drop", "admin", "password", "passwd", "secret",
    "token", "apikey", "api_key", "payment", "charge", "refund", "transfer",
    "withdraw", "impersonate", "elevate", "grant", "revoke", "exec",
    "eval", "shell", "command", "debug", "internal",
)


def _risky(name: str) -> bool:
    low = name.lower()
    return any(f in low for f in RISKY_OP_FRAGMENTS)


class GraphqlDeepPlugin(Plugin):
    id = "graphql_deep"
    label = "GraphQL Deep Analysis"
    accepts = ["domain", "url"]
    passive = False  # sends read-only probes
    cost = Cost.FREE
    group = "api"
    phase = 2  # chain consumer: runs after graphql.py (phase 1)
    timeout_s = 30
    description = ("Deep read-only GraphQL analysis: schema field "
                   "enumeration, batching and GET-query probes. No "
                   "mutations executed.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        endpoints: List[str] = []
        for u in ctx.consume("graphql_endpoints"):
            if isinstance(u, str) and u not in endpoints:
                endpoints.append(u)
        try:
            from ..chains import chain_signals
            for u in chain_signals(ctx, "graphql"):
                if u not in endpoints:
                    endpoints.append(u)
        except Exception:
            pass
        if not endpoints:
            return self._ok([], "no GraphQL endpoints on bus (chain not "
                                "triggered)")

        findings: List[Finding] = []
        for url in endpoints[:4]:
            if (time.monotonic() - t0) > 24:
                break
            await self._analyze(url, ctx, findings)

        res = self._ok(findings, f"deep analysis of {len(endpoints[:4])} "
                                 f"GraphQL endpoint(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _post(self, ctx: Ctx, url: str, payload) -> Dict:
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url, timeout=12,
                            max_retries=1, json=payload,
                            headers={"Content-Type": "application/json"})
            if r.status_code != 200:
                return {}
            return json.loads(r.text[:500000])
        except Exception:
            return {}

    async def _analyze(self, url: str, ctx: Ctx, findings: List[Finding]):
        # 1) Full schema: enumerate operation names (read-only __schema).
        data = await self._post(ctx, url, {"query": FULL_INTROSPECTION})
        schema = (data.get("data") or {}).get("__schema") or {}
        ops: Dict[str, List[str]] = {}
        for kind in ("queryType", "mutationType", "subscriptionType"):
            node = schema.get(kind) or {}
            fields = [f.get("name", "") for f in (node.get("fields") or [])
                      if isinstance(f, dict) and f.get("name")]
            if fields:
                ops[kind.replace("Type", "")] = fields
        if ops:
            risky = sorted({f for fs in ops.values() for f in fs
                            if _risky(f)})
            sev = "high" if risky else "medium"
            findings.append(self._f(
                "api", "graphql_schema_enum",
                f"GraphQL schema enumerated at {url}: " +
                ", ".join(f"{k}({len(v)})" for k, v in ops.items()) +
                (f" - RISKY operation names present: "
                 f"{', '.join(risky[:10])}" if risky else ""),
                source="GraphQL deep analysis", source_url=url,
                confidence=92, passive=False,
                exploitability="public_poc" if risky else "theoretical",
                evidence={
                    "severity": sev,
                    "operations": {k: v[:50] for k, v in ops.items()},
                    "risky_operations": risky[:20],
                    "remediation": ("Disable introspection in production or "
                                    "gate it behind auth. Review every "
                                    "flagged operation for authorization - "
                                    "names like delete*/admin* are prime "
                                    "targets. This check only READ names; "
                                    "no operation was executed."),
                }))

        # 2) Batching probe: two tiny read-only queries in one POST array.
        batch = await self._post(
            ctx, url, [{"query": "{__typename}"}, {"query": "{__typename}"}])
        if isinstance(batch, list) and len(batch) == 2 and all(
                isinstance(b, dict) and "data" in b for b in batch):
            findings.append(self._f(
                "api", "graphql_batching",
                f"GraphQL at {url} answered a batched request (2 queries, "
                "1 HTTP call) - query batching is enabled",
                source="GraphQL deep analysis", source_url=url,
                confidence=88, passive=False,
                exploitability="theoretical",
                evidence={
                    "severity": "medium",
                    "remediation": ("Batching multiplies brute-force and "
                                    "DoS efficiency. Cap batch size, enforce "
                                    "query cost/complexity limits, and rate "
                                    "limit the endpoint."),
                }))

        # 3) GET-query probe: read-only query over GET (CSRF-able).
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            url + ("&" if "?" in url else "?") +
                            urlencode({"query": "{__typename}"}),
                            timeout=10, max_retries=1)
            if r.status_code == 200 and "__typename" in r.text[:20000] \
                    and "Query" in r.text[:20000]:
                findings.append(self._f(
                    "api", "graphql_get_queries",
                    f"GraphQL at {url} executes queries over GET - "
                    "CSRF-able when auth is cookie-based",
                    source="GraphQL deep analysis", source_url=url,
                    confidence=85, passive=False,
                    exploitability="theoretical",
                    evidence={
                        "severity": "medium",
                        "remediation": ("Disallow GET for queries carrying "
                                        "auth cookies, or require a "
                                        "CSRF token on the endpoint."),
                    }))
        except Exception:
            pass

        # 4) Error verbosity: malformed query, look for schema leakage.
        bad = await self._post(ctx, url, {"query": "{__nope__"})
        err_txt = json.dumps(bad)[:4000].lower()
        if any(h in err_txt for h in ("did you mean", "suggestion",
                                      "possible types", "fields:")):
            findings.append(self._f(
                "api", "graphql_verbose_errors",
                f"GraphQL at {url} returns verbose errors with schema "
                "suggestions - aids schema reconstruction",
                source="GraphQL deep analysis", source_url=url,
                confidence=80, passive=False,
                exploitability="theoretical",
                evidence={
                    "severity": "low",
                    "remediation": ("Return generic error messages in "
                                    "production; keep verbose errors on dev "
                                    "only."),
                }))
