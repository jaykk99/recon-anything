"""reNgine-style scan-engine plugin (Tier-5 orchestration).

reNgine lets an operator save a scan ENGINE: a YAML file naming which
checks to run and at what intensity, reused across targets. The
engine file is the product - the compliance question "does what the
engine asks for match what this scanner can actually run?" is where
engines silently rot (renamed checks, checks that need a key, checks
that do not exist).

This plugin parses a reNgine-style engine config (YAML subset or
JSON, from ctx.shared["rengine_config"] / the module override),
executes the matching existing plugins through the shared
orchestration engine, and reports engine compliance: configured vs
runnable vs unknown vs excluded, per check. Unknown or excluded
checks are findings in their own right - an engine that asks for a
check this scanner cannot run is a real defect, reported, not
silently dropped.

Distinct from lifecycle_orchestrator (PR #118): that plugin has no
config file, no parsing and no compliance accounting; the word
"reNgine" in its docstring is an analogy for chaining, not an engine.

With no explicit config, a built-in light engine (headers only) runs
and only its downstream findings pass through - silent on a clean
target. The compliance report fires when a config was supplied.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ._orchestration import classify_ids, collect_findings, \
    engine_check_ids, override_for, parse_engine_config, run_downstream
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DEFAULT_ENGINE = {"name": "builtin-light", "intensity": "light",
                  "checks": ["headers"]}


class RengineScanEnginePlugin(Plugin):
    id = "rengine_scan_engine"
    label = "reNgine Scan Engine"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 120
    description = ("Parses a reNgine-style YAML scan-engine config, "
                   "executes the matching existing plugins, and "
                   "reports configured-vs-runnable engine compliance.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        raw = override_for(ctx, "rengine_config")
        explicit = raw is not None
        config, error = parse_engine_config(raw)
        if error:
            return self._ok([], f"engine config unusable: {error}")
        if not config:
            config = dict(DEFAULT_ENGINE)
            explicit = False
        ids = engine_check_ids(config)
        if not ids:
            return self._ok([], "engine config names no checks")
        intensity = str(config.get("intensity") or "light").lower()
        cap = 3 if intensity in ("light", "passive") else \
            6 if intensity in ("normal", "medium") else 10

        records = await run_downstream(ctx, target, ids, cap=cap)
        composed = collect_findings(records)
        findings: List[Finding] = list(composed)
        if explicit:
            groups = classify_ids(ctx, ids)
            for pid in groups["unknown"]:
                findings.append(self._f(
                    "graph", "engine_unknown_check",
                    f"Engine '{config.get('name', 'unnamed')}' configures "
                    f"check '{pid}', which does not exist in this "
                    f"scanner - the engine silently loses that coverage",
                    source="rengine_scan_engine", confidence=95,
                    evidence={"severity": "medium", "check": pid,
                              "remediation": "Rename the check to a "
                                             "plugin id this scanner "
                                             "provides, or remove it "
                                             "from the engine file."}))
            for pid in groups["excluded"]:
                findings.append(self._f(
                    "graph", "engine_excluded_check",
                    f"Engine configures '{pid}', an orchestration "
                    f"plugin - engines may not dispatch orchestrators",
                    source="rengine_scan_engine", confidence=95,
                    evidence={"severity": "low", "check": pid,
                              "remediation": "Remove orchestration "
                                             "plugins from engine check "
                                             "lists; configure leaf "
                                             "checks instead."}))
            findings.append(self._f(
                "graph", "engine_compliance",
                f"Engine '{config.get('name', 'unnamed')}' "
                f"(intensity {intensity}) for {domain}: "
                f"{len(groups['runnable'])} runnable / "
                f"{len(groups['unknown'])} unknown / "
                f"{len(groups['excluded'])} excluded of "
                f"{len(ids)} configured checks; "
                f"{len(composed)} findings from executed checks",
                source="rengine_scan_engine", confidence=95,
                evidence={"severity": "low",
                          "engine_name": str(config.get("name", "")),
                          "intensity": intensity,
                          "configured": ids,
                          "runnable": groups["runnable"],
                          "unknown": groups["unknown"],
                          "excluded": groups["excluded"],
                          "statuses": {r["id"]: r["status"]
                                       for r in records},
                          "remediation": "Keep engine files honest: "
                                         "every configured check should "
                                         "be runnable, or the scan "
                                         "report overstates coverage."}))
        res = self._ok(findings, f"engine '{config.get('name', '')}': "
                                 f"{len(ids)} checks configured, "
                                 f"{len(composed)} findings")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
