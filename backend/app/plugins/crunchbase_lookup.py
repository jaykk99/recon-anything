"""Crunchbase organization lookup (Tier-1 OSINT, keyed wrapper).

Looks a target domain up in Crunchbase (company profile: name,
short description, founded date, employee range, funding total,
headquarters) via the Crunchbase API v4 entities endpoint.
Crunchbase is a paid SaaS: without CRUNCHBASE_API_KEY (run key vault
or process environment) this plugin returns a clean SKIPPED result -
"needs key" - and never fabricates data. The full query path sits
behind that key check. No sign-up, no scraping of crunchbase.com.
"""
from __future__ import annotations

import os
import time
from typing import List, Optional
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, \
    safe_json_dict

CB_SEARCH_URL = "https://api.crunchbase.com/api/v4/searches/organizations"
CB_ENTITY_URL = "https://api.crunchbase.com/api/v4/entities/organizations"


def crunchbase_key(ctx: Ctx) -> str:
    return (ctx.keys.get("CRUNCHBASE_API_KEY")
            or os.environ.get("CRUNCHBASE_API_KEY") or "").strip()


def parse_org(entity: dict) -> dict:
    """Crunchbase v4 entity payload -> flat org facts."""
    props = (entity or {}).get("properties") or {}
    out = {}
    for key in ("name", "short_description", "founded_on",
                "num_employees_enum", "website_url", "linkedin_url"):
        if props.get(key):
            out[key] = str(props[key])
    funding = props.get("funding_total") or {}
    if isinstance(funding, dict) and funding.get("value_usd"):
        out["funding_total_usd"] = str(funding["value_usd"])
    hq = props.get("location_identifiers") or []
    cities = [str(x.get("value")) for x in hq
              if isinstance(x, dict) and x.get("value")]
    if cities:
        out["headquarters"] = ", ".join(cities[:3])
    return out


class CrunchbaseLookupPlugin(Plugin):
    timeout_s = 60
    id = "crunchbase_lookup"
    label = "Crunchbase Organization Lookup"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.PAID
    group = "graph"
    description = ("Crunchbase company profile for the target domain "
                   "(founded, size, funding, HQ). Needs "
                   "CRUNCHBASE_API_KEY; skipped cleanly without one.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = crunchbase_key(ctx)
        if not key:
            res = self._skipped(
                "needs key: set CRUNCHBASE_API_KEY to enable "
                "Crunchbase organization lookup")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        try:
            resp = await fetch(
                ctx.http, ctx.limiter, "POST", CB_SEARCH_URL,
                timeout=25, max_retries=1,
                headers={"X-cb-user-key": key,
                         "Content-Type": "application/json"},
                json={"field_ids": ["name", "website_url"],
                      "query": [{"type": "predicate",
                                 "field_id": "website_url",
                                 "operator_id": "domain_eq",
                                 "values": [domain]}],
                      "limit": 5})
            if resp.status_code in (401, 403):
                return self._skipped("needs key: Crunchbase rejected "
                                     "the configured API key")
            if resp.status_code != 200:
                return self._degraded(f"Crunchbase search HTTP "
                                      f"{resp.status_code}")
            data = safe_json_dict(resp)
            entities = data.get("entities") or []
            for ent in entities[:3]:
                if not isinstance(ent, dict):
                    continue
                facts = parse_org(ent)
                if not facts.get("name"):
                    continue
                findings.append(self._f(
                    "graph", "organization",
                    f"{facts['name']} ({domain})",
                    source="Crunchbase API", source_url=CB_SEARCH_URL,
                    confidence=85, passive=True,
                    evidence={**facts, "severity": "low"}))
                self._checkpoint(findings)
        except Exception as e:
            return self._degraded(f"Crunchbase lookup failed: "
                                  f"{type(e).__name__}")
        res = self._ok(findings, f"{len(findings)} Crunchbase org match(es)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
