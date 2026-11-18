"""Checkpointed, resumable step engine for agent workflows.

Generic orchestration only — no security logic lives here. Steps declare
their dependencies, an optional skip condition, and a retry budget. State
(step status, outputs, an append-only audit log) is written to disk after
every step, so an interrupted plan resumes exactly where it stopped
instead of re-running finished work. A failed step blocks only the steps
that depend on it; independent branches still run.

The concrete, security-gated steps live in app/agent/plan.py; this module
just runs whatever steps it is handed, in dependency order, and records
what happened.
"""
from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

Log = Callable[[str], None]


@dataclass
class Step:
    name: str
    fn: Callable[["Engine"], Any]
    deps: List[str] = field(default_factory=list)
    when: Optional[Callable[["Engine"], Optional[str]]] = None  # -> skip reason
    retries: int = 0
    backoff_s: float = 2.0


class Engine:
    def __init__(self, steps: List[Step], workdir: Path,
                 params: Optional[Dict[str, Any]] = None, log: Log = print,
                 sleep: Callable[[float], None] = time.sleep,
                 context: Optional[Dict[str, Any]] = None):
        self.steps = {s.name: s for s in steps}
        self.order = self._toposort(steps)
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.log = log
        self.sleep = sleep
        # Not persisted: live handles (api clients, callables) the steps need.
        self.context: Dict[str, Any] = context or {}
        self.state_path = self.workdir / "state.json"
        if self.state_path.exists():
            self.state = json.loads(self.state_path.read_text())
        else:
            self.state = {"params": params or {}, "steps": {}, "outputs": {},
                          "audit": [], "created": time.time()}
        if params:
            self.state["params"].update(params)
        self.save()

    @staticmethod
    def _toposort(steps: List[Step]) -> List[str]:
        names = {s.name for s in steps}
        deps = {s.name: list(s.deps) for s in steps}
        for n, ds in deps.items():
            for d in ds:
                if d not in names:
                    raise ValueError(f"step {n!r} depends on unknown {d!r}")
        order: List[str] = []
        seen: set = set()
        temp: set = set()

        def visit(n: str) -> None:
            if n in seen:
                return
            if n in temp:
                raise ValueError(f"dependency cycle at {n!r}")
            temp.add(n)
            for d in deps[n]:
                visit(d)
            temp.discard(n)
            seen.add(n)
            order.append(n)

        for s in steps:
            visit(s.name)
        return order

    # -- state helpers ----------------------------------------------------
    @property
    def params(self) -> Dict[str, Any]:
        return self.state["params"]

    def out(self, name: str, default: Any = None) -> Any:
        return self.state["outputs"].get(name, default)

    def audit(self, event: str, **fields: Any) -> None:
        """Append one record to the plan's audit log and persist it."""
        rec = {"t": round(time.time(), 3), "event": event, **fields}
        self.state["audit"].append(rec)
        self.save()

    def save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=2, default=str))
        tmp.replace(self.state_path)

    # -- execution --------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        total = len(self.order)
        for i, name in enumerate(self.order, 1):
            step = self.steps[name]
            rec = self.state["steps"].setdefault(
                name, {"status": "pending", "attempts": 0})
            if rec["status"] in ("done", "skipped"):
                self.log(f"[{i}/{total}] {name}: {rec['status']} (resumed)")
                continue
            blocked_by = [d for d in step.deps
                          if self.state["steps"].get(d, {}).get("status")
                          not in ("done", "skipped")]
            if blocked_by:
                rec.update(status="blocked",
                           reason=f"needs {', '.join(blocked_by)}")
                self.log(f"[{i}/{total}] {name}: blocked ({rec['reason']})")
                self.audit("step_blocked", step=name, needs=blocked_by)
                self.save()
                continue
            skip = step.when(self) if step.when else None
            if skip:
                rec.update(status="skipped", reason=skip)
                self.log(f"[{i}/{total}] {name}: skipped ({skip})")
                self.audit("step_skipped", step=name, reason=skip)
                self.save()
                continue
            self.log(f"[{i}/{total}] {name}")
            self._run_one(step, rec)
        return self.state

    def _run_one(self, step: Step, rec: Dict[str, Any]) -> None:
        while True:
            rec["attempts"] += 1
            rec["status"] = "running"
            self.audit("step_start", step=step.name, attempt=rec["attempts"])
            t0 = time.monotonic()
            try:
                result = step.fn(self)
            except Exception as e:  # recorded, never hidden
                rec.update(status="failed", error=str(e)[:500],
                           trace=traceback.format_exc()[-2000:],
                           seconds=round(time.monotonic() - t0, 2))
                self.audit("step_failed", step=step.name, error=str(e)[:300])
                if rec["attempts"] <= step.retries:
                    wait = step.backoff_s * (2 ** (rec["attempts"] - 1))
                    self.log(f"    failed ({e}); retry in {wait:.0f}s")
                    self.sleep(wait)
                    continue
                self.log(f"    failed: {e}")
                return
            self.state["outputs"][step.name] = result
            rec.update(status="done", error=None,
                       seconds=round(time.monotonic() - t0, 2))
            rec.pop("trace", None)
            self.audit("step_done", step=step.name,
                       seconds=rec["seconds"])
            self.save()
            return

    def summary(self) -> Dict[str, Any]:
        st = {k: v.get("status") for k, v in self.state["steps"].items()}
        return {"steps": st,
                "done": sum(1 for v in st.values() if v == "done"),
                "failed": [k for k, v in st.items() if v == "failed"],
                "blocked": [k for k, v in st.items() if v == "blocked"],
                "audit_events": len(self.state["audit"])}
