"""Checkpointed step engine (app/agent/orchestrator.py)."""
import json

import pytest

from app.agent.orchestrator import Engine, Step


def _engine(steps, tmp_path, **kw):
    return Engine(steps, tmp_path / "wf", log=lambda m: None,
                  sleep=lambda s: None, **kw)


def test_runs_in_dependency_order(tmp_path):
    seen = []
    steps = [
        Step("c", lambda e: seen.append("c"), deps=["a", "b"]),
        Step("a", lambda e: seen.append("a")),
        Step("b", lambda e: seen.append("b"), deps=["a"]),
    ]
    _engine(steps, tmp_path).run()
    assert seen.index("a") < seen.index("b") < seen.index("c")


def test_cycle_is_rejected(tmp_path):
    steps = [Step("a", lambda e: 1, deps=["b"]),
             Step("b", lambda e: 1, deps=["a"])]
    with pytest.raises(ValueError, match="cycle"):
        _engine(steps, tmp_path)


def test_unknown_dep_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown"):
        _engine([Step("a", lambda e: 1, deps=["ghost"])], tmp_path)


def test_outputs_flow_between_steps(tmp_path):
    steps = [
        Step("make", lambda e: {"n": 21}),
        Step("use", lambda e: e.out("make")["n"] * 2, deps=["make"]),
    ]
    e = _engine(steps, tmp_path)
    e.run()
    assert e.out("use") == 42


def test_resume_skips_finished_steps(tmp_path):
    calls = {"a": 0, "b": 0}

    def mk():
        return [Step("a", lambda e: calls.__setitem__("a", calls["a"] + 1) or "A"),
                Step("b", lambda e: calls.__setitem__("b", calls["b"] + 1) or 1 / 0,
                     deps=["a"])]

    _engine(mk(), tmp_path).run()  # b divides by zero -> failed
    assert calls == {"a": 1, "b": 1}
    # resume: a is done (not re-run), b is retried
    _engine(mk(), tmp_path).run()
    assert calls == {"a": 1, "b": 2}


def test_failed_step_blocks_only_its_dependents(tmp_path):
    ran = []
    steps = [
        Step("bad", lambda e: 1 / 0),
        Step("needs_bad", lambda e: ran.append("needs_bad"), deps=["bad"]),
        Step("independent", lambda e: ran.append("independent")),
    ]
    e = _engine(steps, tmp_path)
    e.run()
    s = e.summary()
    assert s["failed"] == ["bad"] and s["blocked"] == ["needs_bad"]
    assert ran == ["independent"]  # independent branch still ran


def test_retries_then_succeeds(tmp_path):
    n = {"i": 0}

    def flaky(e):
        n["i"] += 1
        if n["i"] < 3:
            raise RuntimeError("not yet")
        return "ok"

    e = _engine([Step("f", flaky, retries=5)], tmp_path)
    e.run()
    assert e.out("f") == "ok" and n["i"] == 3


def test_when_skips_with_reason(tmp_path):
    ran = []
    steps = [Step("s", lambda e: ran.append("s"),
                  when=lambda e: "not authorized")]
    e = _engine(steps, tmp_path)
    e.run()
    assert ran == [] and e.summary()["steps"]["s"] == "skipped"


def test_audit_log_records_every_step_and_persists(tmp_path):
    e = _engine([Step("a", lambda e: e.audit("custom", detail="x") or "A")],
                tmp_path)
    e.run()
    events = [r["event"] for r in e.state["audit"]]
    assert "step_start" in events and "step_done" in events and "custom" in events
    # persisted to disk
    on_disk = json.loads((tmp_path / "wf" / "state.json").read_text())
    assert any(r["event"] == "custom" for r in on_disk["audit"])


def test_context_is_not_persisted(tmp_path):
    e = _engine([Step("a", lambda e: str(type(e.context["handle"])))],
                tmp_path, context={"handle": object()})
    e.run()
    assert "object" in e.out("a")
    assert "context" not in json.loads((tmp_path / "wf" / "state.json").read_text())
