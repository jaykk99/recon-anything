"""Git checkpoint / rollback audit (read-only, over supplied git state).

Audits SUPPLIED git state (HEAD, branch, dirty-file fingerprints,
recorded checkpoints). It never runs git and never mutates anything.
Findings: work sitting uncommitted with no checkpoint, drift since
the last checkpoint (naming the exact rollback target commit), and a
large dirty tree at risk of loss. Pure analysis, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DIRTY_LIMIT = 10


def analyze_git_state(state: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(state, dict):
        return rows
    head = str(state.get("head") or "")
    dirty = state.get("dirty_files") if isinstance(state.get("dirty_files"), list) else []
    checkpoints = state.get("checkpoints") if isinstance(state.get("checkpoints"), list) else []
    if dirty and not checkpoints:
        rows.append({"key": "git_no_checkpoint_dirty_tree",
                     "value": f"{len(dirty)} uncommitted file(s) and no "
                              f"recorded checkpoint: work can be lost with "
                              f"no rollback target",
                     "severity": "high",
                     "evidence": {"head": head, "dirty_count": len(dirty)}})
    if len(dirty) >= DIRTY_LIMIT:
        rows.append({"key": "git_large_dirty_tree",
                     "value": f"Dirty tree holds {len(dirty)} files: split "
                              f"and checkpoint before continuing",
                     "severity": "medium",
                     "evidence": {"head": head, "dirty_count": len(dirty)}})
    if checkpoints and head:
        last = checkpoints[-1] if isinstance(checkpoints[-1], dict) else {}
        last_head = str(last.get("head") or "")
        if last_head and last_head != head:
            rows.append({"key": "git_drift_since_checkpoint",
                         "value": f"HEAD {head[:12]} has drifted from the "
                                  f"last checkpoint '{last.get('label', '')}' "
                                  f"at {last_head[:12]}: rollback target is "
                                  f"{last_head[:12]}",
                         "severity": "medium" if dirty else "low",
                         "evidence": {"head": head,
                                      "rollback_target": last_head}})
    return rows


class GitCheckpointRollbackPlugin(Plugin):
    id = "git_checkpoint_rollback"
    label = "Git Checkpoint Rollback"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Read-only audit of supplied git state: uncheckpointed "
                   "dirty work, drift since checkpoint, rollback target.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            state = ctx.consume("git_state")
            rows = analyze_git_state(state[0] if state else None)
        except Exception as exc:
            return self._degraded(f"git audit failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Git checkpoint audit",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Record a checkpoint (commit) "
                                             "now, or roll back to the named "
                                             "target commit.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"git rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
