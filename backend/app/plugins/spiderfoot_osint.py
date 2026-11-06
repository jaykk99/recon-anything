"""SpiderFoot-style OSINT correlation graph (Tier-5 orchestration).

SpiderFoot's signature move is CORRELATION: run many passive OSINT
modules, then connect what they found into an entity graph - this
domain resolves to that IP, that IP serves this certificate, that
certificate names this organisation - so an investigator sees
relationships, not lists.

This plugin runs passive OSINT plugins already in the registry
(defaults: passive_subdomains, emails, rdap - overridable via
ctx.shared["spiderfoot_modules"]) and builds the correlation graph
from the discovery bus plus caller-supplied facts
(ctx.shared["spiderfoot_facts"]: {"ips": [...], "certs":
[{"names": [...], "issuer": ..., "org": ...}], "org": ...}).
Each correlation is emitted as its own graph finding
(domain->IP, domain->cert, cert->org, IP->org, domain->email) and the
whole graph ships as one entity-graph finding with nodes/edges in
evidence.

Distinct from assetgraph (on master): assetgraph renders a generic
attack-surface map from every bus kind and reports pivot points.
This plugin is narrower and evidence-shaped: only OSINT entity
correlations, one finding per edge, sourced from passive modules it
actually executed plus declared facts. Silent when there is nothing
to correlate - no facts and no module output means no graph noise.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Set, Tuple

from ..classifier import domain_from_target
from ._orchestration import consume, override_for, run_downstream, \
    shared_get
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DEFAULT_MODULES = ["passive_subdomains", "emails", "rdap"]
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class SpiderfootOsintGraphPlugin(Plugin):
    id = "spiderfoot_osint_graph"
    label = "SpiderFoot OSINT Correlation"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 90
    description = ("Runs passive OSINT modules and builds an entity "
                   "correlation graph (domain->IP->cert->org edges) "
                   "as graph findings.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        modules = override_for(ctx, "spiderfoot_modules")
        if not (isinstance(modules, (list, tuple)) and modules):
            modules = list(DEFAULT_MODULES)
        records = await run_downstream(
            ctx, target, [str(m) for m in modules], cap=6)

        facts = shared_get(ctx, "spiderfoot_facts")
        if not isinstance(facts, dict):
            facts = {}
        ips: Set[str] = set()
        for raw in facts.get("ips") or []:
            if _IP_RE.match(str(raw).strip()):
                ips.add(str(raw).strip())
        for item in consume(ctx, "ips"):
            if isinstance(item, str) and _IP_RE.match(item.strip()):
                ips.add(item.strip())
        # IPs surfaced by downstream findings join the graph too.
        for rec in records:
            for f in rec.get("findings") or []:
                val = str(getattr(f, "value", "") or "")
                for token in re.split(r"[\s,;]+", val):
                    if _IP_RE.match(token):
                        ips.add(token)
        certs: List[Dict[str, Any]] = []
        for cert in facts.get("certs") or []:
            if isinstance(cert, dict):
                certs.append(cert)
        for san in consume(ctx, "cert_sans"):
            if isinstance(san, str) and san.strip():
                certs.append({"names": [san.strip()]})
        org = str(facts.get("org") or "").strip()
        emails = {e for e in consume(ctx, "emails")
                  if isinstance(e, str) and "@" in e}
        subdomains = {s for s in consume(ctx, "subdomains")
                      if isinstance(s, str) and s}

        edges: List[Tuple[str, str, str]] = []

        def edge(frm: str, rel: str, to: str) -> None:
            item = (frm, rel, to)
            if to and frm != to and item not in edges:
                edges.append(item)

        for ip in sorted(ips):
            edge(domain, "resolves_to", ip)
            if org:
                edge(ip, "attributed_to", org)
        for cert in certs:
            names = cert.get("names") or []
            label = (str(names[0]) if names else
                     str(cert.get("issuer") or "certificate"))
            edge(domain, "cert_covers", label)
            cert_org = str(cert.get("org") or cert.get("issuer") or "")
            if cert_org:
                edge(label, "issued_by", cert_org)
        if org:
            edge(domain, "operated_by", org)
        for email in sorted(emails):
            edge(domain, "publishes_email", email)
        for sub in sorted(subdomains):
            edge(domain, "has_subdomain", sub)

        if not edges:
            res = self._ok([], "spiderfoot: modules ran, nothing to "
                               "correlate")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        for frm, rel, to in edges[:60]:
            findings.append(self._f(
                "graph", "osint_correlation_edge",
                f"{frm} -{rel}-> {to}",
                source="spiderfoot_osint_graph", confidence=80,
                evidence={"severity": "low", "from": frm, "rel": rel,
                          "to": to,
                          "remediation": "Review this correlation for "
                                         "unintended exposure: assets "
                                         "an investigator can connect "
                                         "to this domain from public "
                                         "data alone."}))
        nodes = sorted({domain} | {e[0] for e in edges}
                       | {e[2] for e in edges})
        findings.append(self._f(
            "graph", "osint_entity_graph",
            f"SpiderFoot entity graph for {domain}: {len(nodes)} "
            f"entities, {len(edges)} correlations from "
            f"{len(modules)} passive modules",
            source="spiderfoot_osint_graph", confidence=85,
            evidence={"severity": "low",
                      "nodes": nodes,
                      "edges": [{"from": a, "rel": r, "to": b}
                                for a, r, b in edges],
                      "modules": [str(m) for m in modules],
                      "module_statuses": {r["id"]: r["status"]
                                          for r in records},
                      "remediation": "Use the graph to find the "
                                     "weakest connected asset; "
                                     "correlations an OSINT tool can "
                                     "build are available to any "
                                     "attacker for free."}))
        res = self._ok(findings, f"spiderfoot graph: {len(edges)} "
                                 f"correlations, {len(nodes)} entities")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
