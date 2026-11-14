"""End-to-end workflow: recon -> rank -> remediate -> verify -> report.

One command runs the whole pipeline against a running ReconAnything API:

  1. recon      start a scan (POST /api/runs) or resume an existing run,
                and wait for it to finish
  2. rank       pull the findings; each already carries the neural engine's
                score (evidence.nn), and the run gets an overall score
  3. remediate  for the top-ranked findings, draft a fix + regression test
                with the configured LLM provider (app/remediation_llm.py);
                skipped cleanly when no provider is configured
  4. verify     syntax-check every drafted test (compile only - generated
                code is never executed by this workflow)
  5. report     write report.md, summary.json, findings.json and the drafts
                to <out>/<run_id>/ for human review

Passive mode is the default. Active mode (direct probing) requires
--authorized, your explicit statement that you own the target or have
written permission to test it.

  python -m app.workflow example.com
  python -m app.workflow example.com --mode active --authorized
  python -m app.workflow --run-id abc123def456        # resume a run
  python -m app.workflow example.com --no-llm          # skip drafting

Env: RECON_API (default http://localhost:8000), RECON_ACCESS_CODE, plus
the RECON_LLM_* / ANTHROPIC_API_KEY variables used by app.remediation_llm.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from . import remediation_llm as remediation

TERMINAL = {"done", "failed"}


class WorkflowError(RuntimeError):
    pass


class Api:
    """Thin client for the ReconAnything HTTP API."""

    def __init__(self, base: str, access_code: str = "",
                 client: Optional[httpx.Client] = None):
        headers = {"X-Access-Code": access_code} if access_code else {}
        self.c = client or httpx.Client(base_url=base.rstrip("/"),
                                        headers=headers, timeout=60)

    def _json(self, r: httpx.Response) -> Dict[str, Any]:
        if r.status_code == 401:
            raise WorkflowError("API refused the request (401): set "
                                "RECON_ACCESS_CODE / --access-code")
        if r.status_code >= 400:
            raise WorkflowError(f"API {r.status_code}: {r.text[:300]}")
        return r.json()

    def start(self, targets: str, mode: str) -> str:
        return self._json(self.c.post("/api/runs", json={
            "targets": targets, "mode": mode}))["run_id"]

    def detail(self, run_id: str) -> Dict[str, Any]:
        return self._json(self.c.get(f"/api/runs/{run_id}"))


def wait_for_run(api: Api, run_id: str, timeout_s: float = 3600,
                 poll_s: float = 5, log: Callable[[str], None] = print,
                 sleep: Callable[[float], None] = time.sleep
                 ) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        d = api.detail(run_id)
        status = d["run"]["status"]
        prog = d.get("progress") or {}
        line = f"  [{status}] {prog.get('done', '?')}/{prog.get('total', '?')} jobs"
        if line != last:
            log(line)
            last = line
        if status in TERMINAL:
            return d
        if time.monotonic() > deadline:
            raise WorkflowError(f"run {run_id} still {status} after "
                                f"{int(timeout_s)}s; resume with --run-id")
        sleep(poll_s)


def run_score(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    try:
        from .nn_engine import score_run
        return score_run(rows)
    except Exception:
        return None


def verify_drafts(results: List[Dict[str, Any]]) -> None:
    """Compile-check drafted tests in place. Never executes them."""
    for r in results:
        if not r.get("test"):
            r["test_check"] = "missing"
            continue
        try:
            compile(r["test"], f"<draft {r.get('key')}>", "exec")
            r["test_check"] = "compiles"
        except SyntaxError as e:
            r["test_check"] = f"syntax error line {e.lineno}: {e.msg}"


def _sev(row: Dict[str, Any]) -> str:
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    return str(ev.get("severity") or "info").lower()


def render_report(detail: Dict[str, Any], rows: List[Dict[str, Any]],
                  overall: Optional[Dict[str, Any]],
                  drafts: List[Dict[str, Any]], llm_note: str) -> str:
    run = detail["run"]
    tl = [t["raw"] for t in detail.get("targets", [])]
    targets = (tl[0] + (f" (+{len(tl) - 1} discovered)" if len(tl) > 1
                        else "")) if tl else "?"
    noise = [r for r in rows if remediation.is_plugin_error(r)]
    rows = [r for r in rows if not remediation.is_plugin_error(r)]
    by_sev: Dict[str, int] = {}
    for r in rows:
        by_sev[_sev(r)] = by_sev.get(_sev(r), 0) + 1
    L = [f"# Recon workflow report - {targets}", "",
         f"- Run: `{run['id']}` ({run['mode']}, {run['status']})",
         f"- Findings: {len(rows)} ("
         + ", ".join(f"{k} {v}" for k, v in sorted(by_sev.items())) + ")"
         + (f"; {len(noise)} plugin errors left out of the ranking"
            if noise else "")]
    if overall:
        L.append(f"- Neural run score: {overall.get('score', '?')} "
                 f"({overall.get('band', '')})")
    L += ["", "## Top findings (neural rank)", "",
          "| Score | Severity | Plugin | Finding |", "|---|---|---|---|"]
    for r in rows[:15]:
        v = str(r.get("value", "")).replace("|", "\\|")[:90]
        L.append(f"| {remediation.nn_score(r)} | {_sev(r)} | "
                 f"{r.get('plugin')} | `{r.get('key')}` {v} |")
    L += ["", "## Drafted fixes + regression tests", ""]
    if not drafts:
        L.append(llm_note or "No findings met the score threshold.")
    for d in drafts:
        L.append(f"### {d['key']} (score {d['score']}) - {d['status']}, "
                 f"test {d.get('test_check', 'n/a')}")
        L.append("")
        L.append(d.get("fix") or d.get("error") or "(no fix drafted)")
        L.append("")
    L += ["", "Drafts are suggestions for human review. Nothing was "
          "applied to any code or executed against any target."]
    return "\n".join(L) + "\n"


def run_workflow(api: Api, *, targets: str = "", run_id: str = "",
                 mode: str = "passive", authorized: bool = False,
                 out: Path = Path("workflow_out"), use_llm: bool = True,
                 min_score: int = 40, limit: int = 5,
                 timeout_s: float = 3600, poll_s: float = 5,
                 complete: Optional[remediation.Completer] = None,
                 log: Callable[[str], None] = print,
                 sleep: Callable[[float], None] = time.sleep
                 ) -> Dict[str, Any]:
    if mode not in ("passive", "active"):
        raise WorkflowError("mode must be passive or active")
    if mode == "active" and not authorized:
        raise WorkflowError("active mode probes the target directly: pass "
                            "--authorized to confirm you own it or have "
                            "written permission to test it")
    if not (targets or run_id):
        raise WorkflowError("give a target or --run-id")

    log("1/5 recon")
    if not run_id:
        run_id = api.start(targets, mode)
        log(f"  started run {run_id} ({mode})")
    detail = wait_for_run(api, run_id, timeout_s, poll_s, log, sleep)

    log("2/5 rank")
    rows = detail.get("findings") or []
    overall = run_score(rows)
    log(f"  {len(rows)} findings, {len(remediation.select_queue(rows, min_score, limit))}"
        f" queued for drafting (score >= {min_score})")

    log("3/5 remediate")
    drafts: List[Dict[str, Any]] = []
    llm_note = ""
    if not use_llm:
        llm_note = "Drafting skipped (--no-llm)."
    else:
        try:
            drafts = remediation.run_pipeline(
                rows, complete=complete or remediation.get_completer(),
                min_score=min_score, limit=limit)
        except RuntimeError as e:  # provider not configured
            llm_note = f"Drafting skipped: {e}."
    log("  " + (llm_note or f"{len(drafts)} drafted"))

    log("4/5 verify")
    verify_drafts(drafts)
    ok = sum(1 for d in drafts if d.get("test_check") == "compiles")
    log(f"  {ok}/{len(drafts)} drafted tests compile")

    log("5/5 report")
    dest = out / run_id
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "findings.json").write_text(json.dumps(rows, indent=2, default=str))
    if drafts:
        remediation.write_results(drafts, dest / "drafts")
    (dest / "report.md").write_text(
        render_report(detail, rows, overall, drafts, llm_note))
    summary = {"run_id": run_id, "status": detail["run"]["status"],
               "findings": len(rows), "run_score": overall,
               "drafted": len(drafts), "tests_compile": ok,
               "note": llm_note, "out": str(dest)}
    (dest / "summary.json").write_text(json.dumps(summary, indent=2,
                                                  default=str))
    log(f"  wrote {dest}/report.md")
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="recon -> rank -> remediate -> verify -> report")
    ap.add_argument("targets", nargs="?", default="",
                    help="target(s), as you would type them in the UI")
    ap.add_argument("--run-id", default="", help="resume an existing run")
    ap.add_argument("--mode", default="passive", choices=["passive", "active"])
    ap.add_argument("--authorized", action="store_true",
                    help="required for active mode: you own the target "
                         "or have written permission to test it")
    ap.add_argument("--api", default=os.environ.get("RECON_API",
                                                   "http://localhost:8000"))
    ap.add_argument("--access-code",
                    default=os.environ.get("RECON_ACCESS_CODE", ""))
    ap.add_argument("--out", default="workflow_out")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--min-score", type=int, default=40)
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=3600)
    a = ap.parse_args(argv)
    try:
        s = run_workflow(Api(a.api, a.access_code), targets=a.targets,
                         run_id=a.run_id, mode=a.mode,
                         authorized=a.authorized, out=Path(a.out),
                         use_llm=not a.no_llm, min_score=a.min_score,
                         limit=a.limit, timeout_s=a.timeout)
    except (WorkflowError, httpx.HTTPError) as e:
        print(f"workflow failed: {e}", file=sys.stderr)
        return 1
    return 0 if s["status"] == "done" else 2


if __name__ == "__main__":
    raise SystemExit(main())
