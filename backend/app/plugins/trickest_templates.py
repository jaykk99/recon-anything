"""Trickest-style workflow template library (Tier-5 orchestration).

Trickest's asset is a TEMPLATE LIBRARY: parameterized workflow
templates ("new-domain-onboarding", "weekly-diff") that expand into
a concrete run plan once the operator fills in the parameters. The
template guarantees the same steps, in the same order, every time -
and parameter validation catches a half-filled template before it
runs, not halfway through it.

This plugin ships the library, validates template parameters, and
expands a requested template into a concrete plugin run plan
(step order, plugin ids, per-step purpose, the validated params it
was expanded with). Expansion is a plan, not an execution - the
plan finding is the deliverable, ready to hand to the pipeline /
workflow runners in this tier or to a human.

Input: ctx.shared["trickest_template"] as a template name string or
{"name": ..., "params": {...}}. A valid expansion fires exactly one
plan finding; a template with missing/invalid params fires one
validation finding naming every problem; no template requested (or
an unknown name) is silent - templates only speak when invoked.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List

from ..classifier import domain_from_target
from ._orchestration import override_for
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.I)

TEMPLATES: Dict[str, Dict] = {
    "new-domain-onboarding": {
        "description": "First-look plan for a domain the team just "
                       "acquired or launched.",
        "required": ["domain"],
        "steps": [
            {"plugin": "passive_subdomains", "purpose": "enumerate"},
            {"plugin": "dns", "purpose": "records and infra"},
            {"plugin": "headers", "purpose": "baseline headers"},
            {"plugin": "tls", "purpose": "certificate posture"},
            {"plugin": "assetgraph", "purpose": "surface map"},
        ],
    },
    "weekly-diff": {
        "description": "Weekly change-detection plan against the "
                       "stored baseline snapshot.",
        "required": ["domain"],
        "steps": [
            {"plugin": "passive_subdomains", "purpose": "fresh enum"},
            {"plugin": "amass_asset_tracker", "purpose": "diff vs "
                                                          "baseline"},
            {"plugin": "flyover_surface_summary",
             "purpose": "ranked overview"},
        ],
    },
    "api-surface-review": {
        "description": "API-first review plan for a web property.",
        "required": ["domain"],
        "steps": [
            {"plugin": "apidiscover", "purpose": "endpoint discovery"},
            {"plugin": "cors", "purpose": "cross-origin policy"},
            {"plugin": "graphql", "purpose": "graphql surface"},
            {"plugin": "headers", "purpose": "baseline headers"},
        ],
    },
}


def validate_params(template: Dict, params: Dict) -> List[str]:
    problems: List[str] = []
    for name in template.get("required") or []:
        value = params.get(name)
        if value is None or (isinstance(value, str)
                             and not value.strip()):
            problems.append(f"missing required param: {name}")
        elif name == "domain" and not _DOMAIN_RE.match(str(value)):
            problems.append(f"param 'domain' is not a domain: "
                            f"{value!r}")
    return problems


def expand_template(name: str, params: Dict) -> Dict:
    template = TEMPLATES[name]
    steps = []
    for idx, step in enumerate(template["steps"], start=1):
        steps.append({"order": idx, "plugin": step["plugin"],
                      "purpose": step["purpose"],
                      "params": dict(params)})
    return {"template": name, "description": template["description"],
            "params": dict(params), "steps": steps}


class TrickestWorkflowTemplatesPlugin(Plugin):
    id = "trickest_workflow_templates"
    label = "Trickest Workflow Templates"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 1
    timeout_s = 30
    description = ("Parameterized workflow template library: "
                   "validates template params and expands templates "
                   "into concrete plugin run plans.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        raw = override_for(ctx, "trickest_template")
        if raw is None:
            return self._ok([], "no workflow template requested")
        name = ""
        params: Dict = {}
        if isinstance(raw, str):
            name = raw.strip()
        elif isinstance(raw, dict):
            name = str(raw.get("name") or "").strip()
            if isinstance(raw.get("params"), dict):
                params = dict(raw["params"])
        if not name:
            return self._ok([], "template request had no name")
        template = TEMPLATES.get(name)
        if template is None:
            return self._ok([], f"unknown template '{name}'; library: "
                                f"{', '.join(sorted(TEMPLATES))}")
        if "domain" not in params:
            domain = domain_from_target(target.type, target.normalized)
            if domain:
                params["domain"] = domain
        problems = validate_params(template, params)
        findings: List[Finding] = []
        if problems:
            findings.append(self._f(
                "graph", "template_validation_error",
                f"Template '{name}' cannot expand: "
                + "; ".join(problems),
                source="trickest_workflow_templates", confidence=95,
                evidence={"severity": "medium", "template": name,
                          "problems": problems,
                          "params_supplied": sorted(params),
                          "remediation": "Fix the template parameters "
                                         "and re-expand; a half-filled "
                                         "template must never start a "
                                         "run."}))
        else:
            plan = expand_template(name, params)
            steps_str = " -> ".join(
                f"{s['order']}.{s['plugin']}" for s in plan["steps"])
            findings.append(self._f(
                "graph", "workflow_template_expansion",
                f"Template '{name}' expanded for "
                f"{params.get('domain')}: {steps_str}",
                source="trickest_workflow_templates", confidence=95,
                evidence={"severity": "low", "plan": plan,
                          "remediation": "Run the expanded plan in "
                                         "order (pipeline or workflow "
                                         "runner), or save it as the "
                                         "standing plan for this "
                                         "template."}))
        res = self._ok(findings, f"template '{name}': "
                                 f"{'validation failed' if problems else 'expanded'}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
