"""scripts/run_profile.py: per-run time accounting from plugin_jobs."""
import datetime as dt
import importlib.util
import os
import uuid

from app.models import PluginJob, Run, get_session, init_db

_spec = importlib.util.spec_from_file_location(
    "run_profile", os.path.join(os.path.dirname(__file__), "..", "scripts",
                                "run_profile.py"))
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)


def _seed():
    init_db()
    rid = "prof-" + uuid.uuid4().hex[:8]
    t0 = dt.datetime(2026, 1, 1, 12, 0, 0)
    s = get_session()
    try:
        s.add(Run(id=rid, mode="passive", status="done", summary={}))
        for pid, start, dur, reason in [
            ("fast", 0, 1, "ok"),
            ("fast", 1, 1, "ok"),
            ("slow", 0, 90, "skipped: timeout after 90s - findings may be incomplete"),
            ("mid", 5, 10, "ok"),
        ]:
            s.add(PluginJob(run_id=rid, target_id="t", plugin_id=pid,
                            status="done", result={"reason": reason},
                            started_at=t0 + dt.timedelta(seconds=start),
                            finished_at=t0 + dt.timedelta(seconds=start + dur)))
        s.commit()
    finally:
        s.close()
    return rid


def test_profile_accounts_time_and_timeouts():
    r = rp.profile(_seed(), top=2)
    assert r["jobs"] == 4 and r["wall_s"] == 90.0
    assert r["plugin_time_s"] == 102.0
    assert r["timeouts"] == 1 and r["timeout_time_s"] == 90.0
    assert r["timeout_start_buckets_s"] == {0: 1}
    assert [p["plugin"] for p in r["slowest"]] == ["slow", "mid"]
    assert r["slowest"][0]["timeouts"] == 1


def test_unknown_run_reports_nothing(capsys):
    assert rp.profile("no-such-run") is None
    assert rp.main(["no-such-run"]) == 1
    assert "no finished jobs" in capsys.readouterr().err
