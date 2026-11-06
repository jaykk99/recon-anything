"""reconFTW-style staged pipeline runner (Tier-5 orchestration).

reconFTW's value is not a new check: it is a STAGED pipeline -
subdomain enumeration feeds live-host discovery, which feeds content
discovery, which feeds vulnerability checks - with one unified,
deduped output instead of four separate tool dumps.

This plugin is that pipeline as a native meta-plugin. It executes
EXISTING ReconAnything plugins stage by stage through the shared
orchestration engine (registry-resolved, timeout-capped, one bad
stage never kills the run), threads each stage's discoveries through
the shared discovery bus for the next stage, and re-emits the
composed findings deduped on (plugin_id, key, value), plus one
pipeline summary finding.

Distinct from lifecycle_orchestrator (PR #118, not on master): that
plugin scores and risk-ranks bus assets and probes candidates - it
never executes other plugins and has no stage configuration. This
plugin's job is execution: a configurable stage list, per-stage
status accounting, and composed output.

Stage configuration: ctx.shared["reconftw_stages"] (or the
module override) as {stage_name: [plugin_id, ...]}; the default is a
light four-stage plan using only keyless plugins already on master.
Silent when the composed run produced nothing - a clean target gets
no pipeline noise.
"""
from __future__ import annotations

import time
from typing import Dict, List

from ..classifier import domain_from_target
from ._orchestration import collect_findings, dedupe_findings, \
    override_for, run_downstream
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DEFAULT_STAGES: Dict[str, List[str]] = {
    "subdomain_enum": ["passive_subdomains"],
    "live_hosts": ["headers"],
    "content": ["robots"],
    "vuln_checks": ["cors", "clickjack"],
}

# Bus kinds a stage's findings can feed forward, keyed by finding key.
_FEED_FORWARD = {"subdomain": "subdomains", "endpoint": "endpoints",
                 "url": "urls", "tech": "tech"}


class ReconftwPipelinePlugin(Plugin):
    id = "reconftw_pipeline"
    label = "reconFTW Staged Pipeline"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 120
    description = ("Staged pipeline runner (enum -> live hosts -> "
                   "content -> vuln checks) executing existing plugins "
                   "via the registry with unified deduped output.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        raw_stages = override_for(ctx, "reconftw_stages")
        stages: Dict[str, List[str]] = {}
        if isinstance(raw_stages, dict) and raw_stages:
            for name, ids in raw_stages.items():
                if isinstance(ids, (list, tuple)):
                    stages[str(name)] = [str(i) for i in ids]
                elif isinstance(ids, str) and ids:
                    stages[str(name)] = [ids]
        if not stages:
            stages = dict(DEFAULT_STAGES)

        composed: List[Finding] = []
        stage_stats: Dict[str, Dict] = {}
        for stage_name, ids in stages.items():
            if not ids:
                stage_stats[stage_name] = {"requested": [], "ran": 0,
                                           "findings": 0}
                continue
            records = await run_downstream(ctx, target, ids, cap=8)
            found = collect_findings(records)
            for f in found:
                kind = _FEED_FORWARD.get(getattr(f, "key", ""))
                if kind:
                    try:
                        ctx.publish(kind, f.value)
                    except Exception:
                        pass
            composed.extend(found)
            stage_stats[stage_name] = {
                "requested": [r["id"] for r in records],
                "ran": sum(1 for r in records
                           if r["status"] not in ("unknown", "excluded")),
                "statuses": {r["id"]: r["status"] for r in records},
                "findings": len(found),
            }
            self._checkpoint(composed)
        composed = dedupe_findings(composed)
        if not composed:
            res = self._ok([], "reconFTW pipeline ran "
                               f"{len(stages)} stages, no findings")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = list(composed)
        findings.append(self._f(
            "graph", "pipeline_summary",
            f"reconFTW pipeline for {domain}: {len(stages)} stages, "
            f"{len(composed)} deduped findings "
            f"({', '.join(f'{k}={v['findings']}' for k, v in stage_stats.items())})",
            source="reconftw_pipeline", confidence=90, passive=True,
            evidence={"severity": "low", "stages": stage_stats,
                      "total_findings": len(composed),
                      "remediation": "Work the composed findings stage "
                                     "by stage; the pipeline already "
                                     "deduped repeats across stages."}))
        res = self._ok(findings, f"pipeline: {len(composed)} findings "
                                 f"across {len(stages)} stages")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
