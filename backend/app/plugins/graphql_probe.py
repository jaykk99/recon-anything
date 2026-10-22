"""GraphQL endpoint + introspection detection plugin.

Probes the conventional GraphQL paths (/graphql, /api/graphql,
/graphql/console, /playground) with a harmless __typename query and
checks whether full introspection (__schema) is enabled. An exposed
introspection schema hands an attacker the complete API map; an
exposed GraphiQL console is worse.

Detection only: read-only introspection queries, no mutations, no
auth bypass attempts. The introspection query is the standard
diagnostic the schema itself advertises.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target, safe_json_dict

PATHS = ["graphql", "api/graphql", "v1/graphql", "graphql/console",
         "playground", "graphiql", "api/graphiql"]
TYPENAME_Q = {"query": "{__typename}"}
INTROSPECTION_Q = {"query": "{__schema{queryType{name}}}"}


class GraphqlProbePlugin(Plugin):
    id = "graphql_probe"
    label = "GraphQL Exposure"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = ("Detect GraphQL endpoints and whether introspection / "
                   "GraphiQL consoles are exposed.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        # Phase 1: harmless __typename probe on each conventional path.
        reqs = [("POST", f"{base}/{p}") for p in PATHS]
        kwargs = {"json": TYPENAME_Q, "timeout": 10, "max_retries": 0}
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=4, **kwargs)
        endpoints: List[str] = []
        for (_m, url), resp in zip(reqs, resps):
            if resp is None:
                continue
            data = safe_json_dict(resp)
            if (isinstance(data.get("data"), dict)
                    and "__typename" in data["data"]):
                endpoints.append(url)
            elif "graphql" in (resp.text or "")[:2000].lower() and resp.status_code < 500:
                # Endpoint answered but rejected our query shape; still
                # evidence of a GraphQL handler. Low confidence.
                endpoints.append(url + " (unconfirmed)")
        findings: List = []
        for url in endpoints:
            confirmed = not url.endswith("(unconfirmed)")
            findings.append(self._f(
                "api", "graphql_endpoint",
                f"GraphQL endpoint detected at {url}",
                source="GraphQL probe", source_url=url.split(" ")[0],
                confidence=90 if confirmed else 60, passive=True,
                evidence={"severity": "low",
                          "remediation": (
                              "If this endpoint is intentional, ensure it "
                              "requires authentication and rate limiting; "
                              "disable public introspection.")}))
        # Phase 2: introspection check on confirmed endpoints only.
        for url in [u for u in endpoints if not u.endswith("(unconfirmed)")]:
            try:
                r = await fetch(ctx.http, ctx.limiter, "POST", url,
                                json=INTROSPECTION_Q, timeout=10,
                                max_retries=0)
                data = safe_json_dict(r)
                schema = (data.get("data") or {}).get("__schema")
                if schema:
                    qname = ((schema.get("queryType") or {}).get("name")
                             or "Query")
                    findings.append(self._f(
                        "api", "graphql_introspection_enabled",
                        f"GraphQL introspection ENABLED at {url} - full "
                        f"schema exposed (query root: {qname})",
                        source="GraphQL probe", source_url=url,
                        confidence=95, passive=True,
                        evidence={"severity": "medium",
                                  "query_root": qname,
                                  "remediation": (
                                      "Disable introspection in production "
                                      "(most frameworks: introspection: False "
                                      "in prod config); keep GraphiQL/playground "
                                      "off public networks.")}))
            except Exception:
                pass
        for url in [u.split(" ")[0] for u in endpoints
                    if not u.endswith("(unconfirmed)")]:
            ctx.publish("endpoints", url)
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"probed {len(PATHS)} paths, {len(endpoints)} endpoints, "
                   f"{len(findings)} findings")
