"""CLI for the multi-step agent plan (app/agent/plan.py).

    cd backend
    python -m app.agent.plan_cli <run_id> --objective "assess my site"
    python -m app.agent.plan_cli <run_id> --authorized \
        --command "dig example.com" --command "curl -sI https://example.com"

Loads the run's findings and targets from the database (DATABASE_URL),
then runs the plan. Active steps run only with --authorized and allowlisted
targets. Resumable: re-running the same run_id + objective continues the
stored plan under RECON_AGENT_PLAN_DIR (default evidence/plans).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import List, Optional

from .. import config
from . import plan as plan_mod


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.agent.plan_cli",
                                 description=__doc__.split("\n")[0])
    ap.add_argument("run_id")
    ap.add_argument("--objective", default="")
    ap.add_argument("--authorized", action="store_true",
                    help="allow active steps (needs allowlisted targets)")
    ap.add_argument("--command", action="append", dest="commands",
                    default=[], help="allowlisted terminal command (repeatable)")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--min-score", type=int, default=40)
    ap.add_argument("--limit", type=int, default=5)
    a = ap.parse_args(argv)

    from ..models import Target, get_session
    from ..reporting import findings_dump
    session = get_session()
    try:
        rows = findings_dump(session, a.run_id, show_secrets=False)
        targets = [t.normalized or t.raw for t in
                   session.query(Target).filter_by(run_id=a.run_id).all()]
    finally:
        session.close()
    if not rows and not targets:
        print(f"run {a.run_id} has no data (check DATABASE_URL)", file=sys.stderr)
        return 1

    key = hashlib.sha1(f"{a.run_id}:{a.objective}".encode()).hexdigest()[:10]
    base = os.environ.get("RECON_AGENT_PLAN_DIR") or os.path.join(
        getattr(config, "EVIDENCE_DIR", "evidence") or "evidence", "plans")
    workdir = Path(base) / f"{a.run_id}-{key}"
    try:
        result = plan_mod.run_plan(
            workdir, objective=a.objective, run_id=a.run_id, targets=targets,
            authorized=a.authorized, findings=rows, commands=a.commands,
            use_llm=not a.no_llm, min_score=a.min_score, limit=a.limit)
    except plan_mod.PlanRefused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    s = result["summary"]
    for name, status in s["steps"].items():
        print(f"  {status:<8} {name}")
    print(f"{s['done']} steps done; report at {workdir}/report.md")
    return 0 if not s["failed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
