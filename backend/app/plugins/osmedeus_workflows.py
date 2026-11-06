"""Osmedeus-style workflow module runner (Tier-5 orchestration).

Osmedeus organises recon as named WORKFLOWS: a module chain where
each step runs with its own parameters and the chain is invoked by
name ("run the web-baseline workflow on this target"). The workflow
library - not any single check - is the reusable asset.

This plugin ships a small built-in workflow library, resolves a
workflow by name (ctx.shared["osmedeus_workflow"]: a name string, or
{"name": ..., "params": {...}}), and executes its steps in order
through the shared orchestration engine. Per-step params can narrow
a step to a subset of its default plugins ("only": [...]) or skip it
("skip": true). Step outcomes are accounted individually, composed
findings are deduped across steps, and one workflow-run summary
reports the chain.

Unknown workflow names degrade to an explanatory ok(0) - never a
crash, never a guessed chain. Silent when the chain produced no
findings: a clean target gets no workflow noise.
"""
from __future__ import annotations

import time
from typing import Dict, List

from ..classifier import domain_from_target
from ._orchestration import collect_findings, dedupe_findings, \
    override_for, run_downstream
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# name -> ordered steps; each step: {"name", "plugins": [...]}
WORKFLOW_LIBRARY: Dict[str, List[Dict]] = {
    "quick-recon": [
        {"name": "passive-enum", "plugins": ["passive_subdomains"]},
        {"name": "headers", "plugins": ["headers"]},
    ],
    "web-baseline": [
        {"name": "surface", "plugins": ["headers", "robots"]},
        {"name": "browser-policy", "plugins": ["cors", "clickjack"]},
        {"name": "tls", "plugins": ["tls"]},
    ],
    "osint-sweep": [
        {"name": "subdomains", "plugins": ["passive_subdomains"]},
        {"name": "contacts", "plugins": ["emails"]},
        {"name": "registration", "plugins": ["rdap"]},
    ],
    "api-review": [
        {"name": "discovery", "plugins": ["apidiscover"]},
        {"name": "policy", "plugins": ["cors"]},
        {"name": "graphql", "plugins": ["graphql"]},
    ],
}


class OsmedeusWorkflowPlugin(Plugin):
    id = "osmedeus_workflow"
    label = "Osmedeus Workflow Runner"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 120
    description = ("Executes a named multi-step workflow (module "
                   "chain with per-step params) from a built-in "
                   "workflow library over existing plugins.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        raw = override_for(ctx, "osmedeus_workflow")
        name = "quick-recon"
        params: Dict = {}
        if isinstance(raw, str) and raw.strip():
            name = raw.strip()
        elif isinstance(raw, dict):
            name = str(raw.get("name") or name).strip() or name
            if isinstance(raw.get("params"), dict):
                params = raw["params"]
        steps = WORKFLOW_LIBRARY.get(name)
        if steps is None:
            return self._ok([], f"unknown workflow '{name}'; library: "
                                f"{', '.join(sorted(WORKFLOW_LIBRARY))}")
        composed: List[Finding] = []
        step_stats: List[Dict] = []
        for step in steps:
            step_params = params.get(step["name"]) or {}
            if not isinstance(step_params, dict):
                step_params = {}
            if step_params.get("skip"):
                step_stats.append({"step": step["name"],
                                   "status": "skipped-param",
                                   "findings": 0})
                continue
            ids = step["plugins"]
            only = step_params.get("only")
            if isinstance(only, list) and only:
                ids = [i for i in ids if i in only] or ids
            records = await run_downstream(ctx, target, ids, cap=6)
            found = collect_findings(records)
            composed.extend(found)
            step_stats.append({
                "step": step["name"], "plugins": ids,
                "statuses": {r["id"]: r["status"] for r in records},
                "findings": len(found)})
            self._checkpoint(composed)
        composed = dedupe_findings(composed)
        if not composed:
            res = self._ok([], f"workflow '{name}' ran "
                               f"{len(steps)} steps, no findings")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = list(composed)
        steps_str = ", ".join(
            f"{s['step']}={s['findings']}" for s in step_stats)
        findings.append(self._f(
            "graph", "workflow_run",
            f"Osmedeus workflow '{name}' on {domain}: "
            f"{len(step_stats)} steps, {len(composed)} deduped "
            f"findings ({steps_str})",
            source="osmedeus_workflow", confidence=90,
            evidence={"severity": "low", "workflow": name,
                      "steps": step_stats,
                      "total_findings": len(composed),
                      "remediation": "Work the workflow's findings in "
                                     "step order; re-run the same "
                                     "named workflow after fixes to "
                                     "verify the chain is clean."}))
        res = self._ok(findings, f"workflow '{name}': "
                                 f"{len(composed)} findings")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
