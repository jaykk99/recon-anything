"""Multi-step agent plan built on the checkpointed engine.

Chains the pieces that already exist, each behind its own gate, into one
resumable plan:

  gate -> rank -> investigate -> terminal_probe -> remediate -> verify -> report

  gate            refuse the whole plan if the objective trips a hard
                  boundary (app/agent/refusal.py); authorization is
                  resolved here and recorded.
  rank            neural-engine score + queue (app/nn_engine, remediation)
  investigate     ACTIVE live verification via the existing detection-only
                  layer (app/agent/service.investigate_run: browser fetch +
                  allowlisted terminal, SSRF-checked). Gated.
  terminal_probe  extra allowlisted detection commands (app/agent/terminal,
                  no shell/writes/installs, SSRF-checked). Gated.
  remediate       draft a fix + regression test per top finding
                  (app/remediation). Coding step; nothing is applied.
  verify          compile-check the drafted tests. Never executed.
  report          report.md + the engine's audit log.

Boundaries, enforced in code (not just prose):
  * The objective is checked against the hard-boundary list before any
    step runs; a trip refuses the whole plan.
  * ACTIVE steps (investigate, terminal_probe) run only when the caller
    passed authorized=True AND every target is authorized
    (app/agent/allowlist). Otherwise they skip with a recorded reason.
  * This plan never executes drafted proof-of-concept / exploit code
    against a target. It drafts fixes and tests and stops there.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .. import remediation
from . import allowlist, refusal, service, terminal
from .orchestrator import Engine, Step


class PlanRefused(RuntimeError):
    """The objective tripped a hard boundary; no step runs."""


def _active_skip(e: Engine) -> Optional[str]:
    """Skip reason for an ACTIVE step, or None to run it."""
    gate = e.out("gate") or {}
    if not gate.get("authorized"):
        return gate.get("reason") or "not authorized (pass authorized=True)"
    return None


# ------------------------------------------------------------------ steps

def step_gate(e: Engine) -> Dict[str, Any]:
    """Resolve refusal + target authorization once, up front."""
    objective = e.params.get("objective", "")
    reason = refusal.hard_block_reason(objective)
    if reason:
        raise PlanRefused(f"objective refused: {reason}")
    targets: List[str] = e.params.get("targets") or []
    unauthorized = []
    for t in targets:
        ok, why = allowlist.is_authorized(t)
        if not ok:
            unauthorized.append({"target": t, "reason": why})
    authorized = bool(e.params.get("authorized")) and not unauthorized
    out = {"authorized": authorized, "targets": targets,
           "unauthorized": unauthorized}
    if not e.params.get("authorized"):
        out["reason"] = "passive plan: active steps need authorized=True"
    elif unauthorized:
        out["reason"] = ("not all targets authorized: "
                         + ", ".join(u["target"] for u in unauthorized))
    e.audit("gate", authorized=authorized,
            unauthorized=[u["target"] for u in unauthorized])
    return out


def step_rank(e: Engine) -> Dict[str, Any]:
    rows = [r for r in e.context.get("findings", [])
            if not remediation.is_plugin_error(r)]
    try:
        from ..nn_engine import score_run
        overall = score_run(rows)
    except Exception:
        overall = None
    queue = remediation.select_queue(rows, e.params.get("min_score", 40),
                                     e.params.get("limit", 5))
    e.audit("rank", findings=len(rows), queued=len(queue))
    return {"findings": len(rows), "run_score": overall,
            "queued": [q.get("key") for q in queue]}


def step_investigate(e: Engine) -> Dict[str, Any]:
    run_id = e.params.get("run_id")
    if not run_id:
        return {"skipped": "no run_id to investigate"}
    fn: Callable = e.context.get("investigate", service.investigate_run)
    res = fn(run_id, verify_limit=e.params.get("verify_limit", 20),
             target_limit=e.params.get("target_limit", 3))
    added = res.get("added_findings") or []
    verified = res.get("verified") or []
    e.audit("investigate", verified=len(verified), added=len(added))
    return {"verified": len(verified), "added_findings": len(added),
            "probed_targets": res.get("probed_targets", [])}


def step_terminal_probe(e: Engine) -> Dict[str, Any]:
    """Run the caller's allowlisted detection commands, each gated."""
    commands: List[str] = e.params.get("commands") or []
    run_cmd: Callable = e.context.get("terminal", terminal.run_terminal)
    results = []
    for cmd in commands[:10]:
        res = run_cmd(cmd)
        ok = res.get("returncode") == 0 and not res.get("error")
        e.audit("terminal", command=cmd, ok=ok,
                error=res.get("error"))
        results.append({"command": cmd, "ok": ok,
                        "error": res.get("error"),
                        "returncode": res.get("returncode")})
    return {"ran": len(results), "results": results}


def step_remediate(e: Engine) -> Dict[str, Any]:
    if not e.params.get("use_llm", True):
        return {"drafted": 0, "note": "drafting skipped (use_llm=False)"}
    rows = [r for r in e.context.get("findings", [])
            if not remediation.is_plugin_error(r)]
    try:
        complete = e.context.get("complete") or remediation.get_completer()
    except RuntimeError as exc:
        return {"drafted": 0, "note": f"no LLM provider: {exc}"}
    drafts = remediation.run_pipeline(rows, complete,
                                      e.params.get("min_score", 40),
                                      e.params.get("limit", 5))
    e.audit("remediate", drafted=len(drafts))
    return {"drafted": len(drafts), "results": drafts}


def step_verify(e: Engine) -> Dict[str, Any]:
    drafts = (e.out("remediate") or {}).get("results") or []
    ok = 0
    for d in drafts:
        if not d.get("test"):
            d["test_check"] = "missing"
            continue
        try:
            compile(d["test"], f"<draft {d.get('key')}>", "exec")
            d["test_check"] = "compiles"
            ok += 1
        except SyntaxError as exc:
            d["test_check"] = f"syntax error line {exc.lineno}"
    e.audit("verify", drafts=len(drafts), compiles=ok)
    return {"drafts": len(drafts), "tests_compile": ok}


def step_report(e: Engine) -> Dict[str, Any]:
    dest = e.workdir
    gate = e.out("gate") or {}
    lines = [f"# Agent plan report", "",
             f"- Objective: {e.params.get('objective', '(none)')}",
             f"- Authorized (active steps): {gate.get('authorized')}",
             f"- Steps: {e.summary()['done']} done, "
             f"{len(e.summary()['failed'])} failed, "
             f"{len(e.summary()['blocked'])} blocked", ""]
    for name in e.order:
        rec = e.state["steps"].get(name, {})
        lines.append(f"## {name} - {rec.get('status', 'pending')}")
        out = e.out(name)
        if isinstance(out, dict):
            for k, v in out.items():
                if k == "results":
                    continue
                lines.append(f"- {k}: {v}")
        lines.append("")
    lines.append("Drafts are suggestions for human review. No code was "
                 "applied, and no exploit code was run against any target.")
    (dest / "report.md").write_text("\n".join(lines) + "\n")
    import json as _json
    (dest / "audit.json").write_text(
        _json.dumps(e.state["audit"], indent=2, default=str))
    return {"report": str(dest / "report.md"),
            "audit": str(dest / "audit.json")}


def build_steps() -> List[Step]:
    return [
        Step("gate", step_gate),
        Step("rank", step_rank, deps=["gate"]),
        Step("investigate", step_investigate, deps=["gate"],
             when=_active_skip, retries=1),
        Step("terminal_probe", step_terminal_probe, deps=["gate"],
             when=_active_skip),
        Step("remediate", step_remediate, deps=["rank"]),
        Step("verify", step_verify, deps=["remediate"]),
        Step("report", step_report,
             deps=["rank", "investigate", "terminal_probe", "verify"]),
    ]


def run_plan(workdir: Path, *, objective: str = "", run_id: str = "",
             targets: Optional[List[str]] = None, authorized: bool = False,
             findings: Optional[List[Dict[str, Any]]] = None,
             commands: Optional[List[str]] = None, use_llm: bool = True,
             min_score: int = 40, limit: int = 5,
             complete: Optional[remediation.Completer] = None,
             investigate: Optional[Callable] = None,
             terminal_fn: Optional[Callable] = None,
             log: Callable[[str], None] = print) -> Dict[str, Any]:
    """Build and run the plan. Refusal is checked before any step runs."""
    reason = refusal.hard_block_reason(objective)
    if reason:
        raise PlanRefused(f"objective refused: {reason}")
    params = {"objective": objective, "run_id": run_id,
              "targets": targets or [], "authorized": authorized,
              "commands": commands or [], "use_llm": use_llm,
              "min_score": min_score, "limit": limit}
    context: Dict[str, Any] = {"findings": findings or []}
    if complete is not None:
        context["complete"] = complete
    if investigate is not None:
        context["investigate"] = investigate
    if terminal_fn is not None:
        context["terminal"] = terminal_fn
    e = Engine(build_steps(), workdir, params=params, log=log,
               context=context)
    e.run()
    return {"summary": e.summary(), "report": (e.out("report") or {}),
            "workdir": str(workdir)}
