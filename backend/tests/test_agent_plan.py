"""Multi-step agent plan (app/agent/plan.py): offline, stubbed tools."""
import json

import pytest

from app.agent import plan


def _row(key, score, sev="high", plugin_error=False):
    k = key + ("_error" if plugin_error else "")
    return {"id": 1, "plugin": "headers", "category": "web", "key": k,
            "value": "v", "source": "s", "confidence": 90,
            "evidence": {"severity": sev, "nn": {"score": score}}}


GOOD = "```fix\nSet HSTS.\n```\n```python\ndef test_h():\n    assert True\n```"


def _run(tmp_path, **kw):
    kw.setdefault("objective", "assess my site's headers")
    kw.setdefault("complete", lambda s, u: GOOD)
    kw.setdefault("log", lambda m: None)
    return plan.run_plan(tmp_path / "wf", **kw)


def test_harmful_objective_is_refused_before_any_step(tmp_path):
    with pytest.raises(plan.PlanRefused, match="theft"):
        _run(tmp_path, objective="steal the admin password from the login")
    assert not (tmp_path / "wf" / "state.json").exists()


def test_passive_plan_skips_active_steps_but_still_codes(tmp_path):
    called = {"inv": 0, "term": 0}
    r = _run(tmp_path, run_id="r1", findings=[_row("hsts_missing", 90)],
             commands=["curl https://x"], authorized=False,
             investigate=lambda *a, **k: called.__setitem__("inv", 1),
             terminal_fn=lambda c: called.__setitem__("term", 1))
    s = r["summary"]["steps"]
    assert s["investigate"] == "skipped" and s["terminal_probe"] == "skipped"
    assert called == {"inv": 0, "term": 0}  # active tools never called
    assert s["rank"] == "done" and s["remediate"] == "done"
    assert s["report"] == "done"


def test_authorized_plan_runs_active_steps(tmp_path):
    seen = {}
    def inv(rid, **k):
        seen["inv"] = rid
        return {"verified": [1], "added_findings": [], "probed_targets": [rid]}

    def term(cmd):
        seen["cmd"] = cmd
        return {"returncode": 0, "stdout": "ok"}

    r = _run(tmp_path, run_id="r1",
             targets=["https://recon-anything.onrender.com"],
             authorized=True, findings=[_row("hsts_missing", 90)],
             commands=["dig recon-anything.onrender.com"],
             investigate=inv, terminal_fn=term)
    s = r["summary"]["steps"]
    assert s["investigate"] == "done" and s["terminal_probe"] == "done"
    assert seen["inv"] == "r1" and seen["cmd"].startswith("dig")


def test_unauthorized_target_blocks_active_even_if_flag_set(tmp_path):
    r = _run(tmp_path, targets=["https://example.com"], authorized=True,
             findings=[_row("k", 90)], commands=["dig example.com"],
             investigate=lambda *a, **k: 1 / 0,  # must never run
             terminal_fn=lambda c: 1 / 0)
    gate = _load(tmp_path)["outputs"]["gate"]
    assert gate["authorized"] is False
    assert r["summary"]["steps"]["terminal_probe"] == "skipped"
    assert "example.com" in gate["reason"]


def test_plugin_errors_are_excluded_from_rank_and_remediate(tmp_path):
    rows = [_row("keyleak_paste", 99, plugin_error=True),
            _row("hsts_missing", 80)]
    r = _run(tmp_path, findings=rows)
    assert _load(tmp_path)["outputs"]["rank"]["findings"] == 1
    assert _load(tmp_path)["outputs"]["remediate"]["drafted"] == 1


def test_no_llm_still_reports(tmp_path):
    r = _run(tmp_path, findings=[_row("k", 90)], use_llm=False)
    assert _load(tmp_path)["outputs"]["remediate"]["drafted"] == 0
    assert r["summary"]["steps"]["report"] == "done"


def test_broken_test_is_flagged_not_trusted(tmp_path):
    bad = "```fix\nF\n```\n```python\ndef broken(:\n```"
    _run(tmp_path, findings=[_row("k", 90)], complete=lambda s, u: bad)
    assert _load(tmp_path)["outputs"]["verify"]["tests_compile"] == 0


def test_report_and_audit_written_and_note_present(tmp_path):
    _run(tmp_path, findings=[_row("hsts_missing", 90)],
         commands=["dig x"], authorized=False)
    report = (tmp_path / "wf" / "report.md").read_text()
    assert "no exploit code was run" in report
    audit = json.loads((tmp_path / "wf" / "audit.json").read_text())
    assert any(a["event"] == "rank" for a in audit)


def test_resume_does_not_redraft(tmp_path):
    calls = {"n": 0}

    def once(s, u):
        calls["n"] += 1
        return GOOD

    _run(tmp_path, findings=[_row("k", 90)], complete=once)
    assert calls["n"] == 1
    _run(tmp_path, findings=[_row("k", 90)], complete=once)  # resume
    assert calls["n"] == 1  # remediate was already done


def _load(tmp_path):
    return json.loads((tmp_path / "wf" / "state.json").read_text())
