"""BBRF-style recon data store (Tier-5 orchestration).

BBRF (Bug Bounty Recon Framework) is a STORE, not a scanner:
programs contain domains, IPs and URLs, every tool writes its output
into the one store, and every later tool queries the store instead
of re-discovering assets. The schema - programs / domains / ips /
urls - is the interface.

This plugin is that store as a native meta-plugin. It writes the
current run's discovered assets (target domain as the program, plus
subdomains / IPs / endpoints+URLs from the discovery bus) into a
BBRF-style structured store carried in ctx.shared["bbrf_store"]
({"programs": {program: {"domains": [...], "ips": [...],
"urls": [...]}}}), merging with whatever a previous plugin or run
already stored there - the store dict is updated in place, so later
plugins in the same run see the merged state. It then supports
query-back: ctx.shared["bbrf_query"] ({"kind": "domains"|"ips"|
"urls", "contains": substring}) returns stored assets as findings.

Emits one store summary (per-kind counts, what was newly added this
run) when the run actually contributed or holds assets, plus one
finding per query hit. An empty run with an empty store is silent.
No filesystem or network: the store lives in the run context, in
exactly the JSON shape an external BBRF server would exchange.
"""
from __future__ import annotations

import time
from typing import Dict, List

from ..classifier import domain_from_target
from ._orchestration import consume, shared_get
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_KINDS = ("domains", "ips", "urls")


def _merge(program: Dict, kind: str, values) -> List[str]:
    bucket = program.setdefault(kind, [])
    added = []
    for value in values or []:
        if isinstance(value, str) and value.strip() \
                and value not in bucket:
            bucket.append(value)
            added.append(value)
    return added


class BbrfReconStorePlugin(Plugin):
    id = "bbrf_recon_store"
    label = "BBRF Recon Data Store"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 30
    description = ("Writes the run's findings into a BBRF-style "
                   "structured store (programs/domains/ips/urls as "
                   "JSON via ctx) and queries stored assets back.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        shared = getattr(ctx, "shared", None)
        store = shared_get(ctx, "bbrf_store")
        if not isinstance(store, dict):
            store = {}
        programs = store.setdefault("programs", {})
        if not isinstance(programs, dict):
            programs = {}
            store["programs"] = programs
        program = programs.setdefault(
            domain, {"domains": [], "ips": [], "urls": []})
        if not isinstance(program, dict):
            program = {"domains": [], "ips": [], "urls": []}
            programs[domain] = program

        domains = [s for s in consume(ctx, "subdomains")
                   if isinstance(s, str)]
        if domain not in domains:
            domains.append(domain)
        ips = [i for i in consume(ctx, "ips") if isinstance(i, str)]
        urls = []
        for kind in ("endpoints", "urls"):
            for item in consume(ctx, kind):
                if isinstance(item, str) and item not in urls:
                    urls.append(item)
        added = {
            "domains": _merge(program, "domains", domains),
            "ips": _merge(program, "ips", ips),
            "urls": _merge(program, "urls", urls),
        }
        if isinstance(shared, dict):
            shared["bbrf_store"] = store

        total_assets = sum(len(program.get(k) or []) for k in _KINDS)
        contributed = sum(len(v) for v in added.values())
        findings: List[Finding] = []
        query = shared_get(ctx, "bbrf_query")
        hits: List = []
        if isinstance(query, dict):
            kind = str(query.get("kind") or "domains")
            needle = str(query.get("contains") or "").lower()
            if kind in _KINDS:
                hits = [v for v in program.get(kind) or []
                        if needle in str(v).lower()]
                for hit in hits[:50]:
                    findings.append(self._f(
                        "graph", "bbrf_query_hit",
                        f"BBRF store query hit: {kind} '{hit}' "
                        f"(program {domain})",
                        source="bbrf_recon_store", confidence=90,
                        evidence={"severity": "low", "kind": kind,
                                  "asset": hit, "program": domain,
                                  "remediation": "Stored assets are "
                                                 "the team's shared "
                                                 "truth: keep the "
                                                 "store deduped and "
                                                 "current."}))
        # The lone program domain on its own is not a contribution:
        # a run that discovered nothing beyond the target itself
        # stays silent.
        if total_assets > 1:
            findings.append(self._f(
                "graph", "bbrf_store_summary",
                f"BBRF store program '{domain}': "
                f"{len(program.get('domains') or [])} domains, "
                f"{len(program.get('ips') or [])} IPs, "
                f"{len(program.get('urls') or [])} URLs "
                f"(+{contributed} new this run)",
                source="bbrf_recon_store", confidence=95,
                evidence={"severity": "low", "program": domain,
                          "counts": {k: len(program.get(k) or [])
                                     for k in _KINDS},
                          "added_this_run": added,
                          "store": {domain: program},
                          "remediation": "Query the store before "
                                         "re-running discovery; assets "
                                         "already stored do not need "
                                         "to be found twice."}))
        res = self._ok(findings, f"bbrf store '{domain}': "
                                 f"{total_assets} assets, "
                                 f"+{contributed} new, "
                                 f"{len(hits)} query hits")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
