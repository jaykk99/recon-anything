"""GraphQL endpoint discovery and introspection analysis plugin.

Discovers GraphQL endpoints (/graphql, /graphiql, /query, /api/graphql),
sends a single safe read-only introspection POST
(query { __schema { types { name } } }), and reports schema exposure
plus a naive query-depth allowance check. Detection only - no mutations,
no destructive operations.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

INTROSPECTION_QUERY = "query { __schema { types { name } } }"


class GraphqlPlugin(Plugin):
    id = "graphql"
    label = "GraphQL Analyzer"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Finds GraphQL endpoints, runs one safe introspection "
                   "query, and flags schema exposure and deep-query risk.")
    phase = 1

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

        findings: List[Finding] = []
        endpoints = ["/graphql", "/graphiql", "/query", "/api/graphql"]

        async def probe(path: str):
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                                max_retries=1, follow_redirects=True)
                return r, url
            except Exception:
                return None, url

        for path in endpoints:
            r, url = await probe(path)
            if r is None:
                continue
            txt = ""
            try:
                txt = r.text[:20000]
            except Exception:
                pass
            low = txt.lower()

            is_gql = (
                "graphql" in low or "graphiql" in low
                or '"data"' in low or '"errors"' in low
            )
            if r.status_code == 200 and is_gql:
                findings.append(self._f(
                    "api", "graphql_endpoint",
                    f"GraphQL endpoint discovered at {path} (HTTP 200, "
                    "GraphQL content markers)",
                    source="GraphQL analyzer", source_url=url,
                    confidence=80, passive=True,
                    evidence={"severity": "low", "exploitability": "theoretical",
                              "remediation": "Inventory this endpoint, enforce "
                              "authentication and rate limiting on it, and "
                              "decide whether it needs to be public."}))
                # Chain: publish the live endpoint so graphql_deep (phase 2)
                # runs deeper read-only introspection on it
                # (graphql_chain in backend/app/chains.py).
                ctx.publish("graphql_endpoints", url)

                # Single safe introspection POST (read-only, no mutations).
                try:
                    ir = await fetch(
                        ctx.http, ctx.limiter, "POST", url, timeout=12,
                        max_retries=1,
                        json={"query": INTROSPECTION_QUERY},
                        headers={"Content-Type": "application/json"})
                except Exception:
                    ir = None

                introspected = False
                if ir is not None and ir.status_code == 200:
                    try:
                        itxt = ir.text[:100000]
                    except Exception:
                        itxt = ""
                    if '"__schema"' in itxt and '"types"' in itxt:
                        introspected = True
                        type_count = itxt.count('"name"')
                        findings.append(self._f(
                            "api", "graphql_introspection",
                            f"GraphQL introspection ENABLED at {path}: full "
                            f"schema exposed (~{type_count} named types) via a "
                            "read-only __schema query",
                            source="GraphQL analyzer", source_url=url,
                            confidence=95, passive=False,
                            evidence={"severity": "medium",
                                      "exploitability": "public_poc",
                                      "remediation": "Disable introspection in "
                                      "production (introspection: false) or "
                                      "gate it behind authentication, and "
                                      "re-scan to verify."}))
                if not introspected and ir is not None and ir.status_code == 200:
                    # Introspection off or POST unsupported - note quietly.
                    pass

                # Query-depth allowance: a single nested introspection-free
                # probe that only asks for __typename at depth.
                depth = 12
                nested = "{" * depth + "__typename" + "}" * depth
                try:
                    dr = await fetch(
                        ctx.http, ctx.limiter, "POST", url, timeout=12,
                        max_retries=1,
                        json={"query": f"query {{ __typename {nested} }}"},
                        headers={"Content-Type": "application/json"})
                    if dr is not None and dr.status_code == 200:
                        try:
                            dtxt = dr.text[:20000]
                        except Exception:
                            dtxt = ""
                        if "__typename" in dtxt and "Query" in dtxt:
                            findings.append(self._f(
                                "api", "graphql_deep_query",
                                f"GraphQL at {path} accepted a {depth}-level "
                                "nested query - no depth limiting detected "
                                "(DoS / resource-exhaustion risk)",
                                source="GraphQL analyzer", source_url=url,
                                confidence=75, passive=False,
                                evidence={"severity": "medium",
                                          "exploitability": "theoretical",
                                          "remediation": "Enforce max query "
                                          "depth (e.g. 7-10) and query "
                                          "complexity scoring, plus rate "
                                          "limiting, on this endpoint."}))
                except Exception:
                    pass
            elif "graphiql" in path and r is not None and r.status_code == 200 and "graphiql" in low:
                findings.append(self._f(
                    "api", "graphiql_ui",
                    f"GraphiQL interactive explorer exposed at {path} - "
                    "lets anyone browse and run queries",
                    source="GraphQL analyzer", source_url=url,
                    confidence=90, passive=True,
                    evidence={"severity": "medium", "exploitability": "public_poc",
                              "remediation": "Disable the GraphiQL UI in "
                              "production; keep it on authenticated dev "
                              "environments only."}))

        if not findings:
            findings.append(self._f(
                "api", "graphql_clean",
                "No GraphQL endpoints found at /graphql, /graphiql, /query, "
                "/api/graphql",
                source="GraphQL analyzer", source_url=base,
                confidence=70, passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {len(endpoints)} GraphQL paths")
        res.duration_ms = dur
        return res
