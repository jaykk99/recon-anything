"""End-to-end workflow (app/workflow.py): offline, fake API + fake LLM."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import json

import httpx
import pytest

from app import workflow as wf


def _row(i, score, key=None, sev="high"):
    return {"id": i, "plugin": "headers", "category": "web",
            "key": key or f"k{i}", "value": f"v{i}", "source": "s",
            "confidence": 90,
            "evidence": {"severity": sev, "nn": {"score": score}}}


class FakeApi:
    def __init__(self, rows, statuses=("running", "running", "done")):
        self.rows = rows
        self.statuses = list(statuses)
        self.started = []

    def start(self, targets, mode):
        self.started.append((targets, mode))
        return "run123"

    def detail(self, run_id):
        status = self.statuses.pop(0) if len(self.statuses) > 1 \
            else self.statuses[0]
        return {"run": {"id": run_id, "mode": "passive", "status": status},
                "targets": [{"raw": "example.com"}],
                "progress": {"done": 1, "total": 2},
                "findings": self.rows}


GOOD = ("```fix\nSet Strict-Transport-Security.\n```\n"
        "```python\ndef test_hsts():\n    assert True\n```")


def _run(api, tmp_path, **kw):
    kw.setdefault("complete", lambda s, u: GOOD)
    return wf.run_workflow(api, out=tmp_path, poll_s=0, log=lambda m: None,
                           sleep=lambda s: None, **kw)


def test_full_pipeline_writes_report_and_drafts(tmp_path):
    api = FakeApi([_row(1, 90, "hsts_missing"), _row(2, 10)])
    s = _run(api, tmp_path, targets="example.com")
    assert api.started == [("example.com", "passive")]
    assert s["status"] == "done" and s["findings"] == 2
    assert s["drafted"] == 1 and s["tests_compile"] == 1
    d = tmp_path / "run123"
    report = (d / "report.md").read_text()
    assert "hsts_missing" in report and "Set Strict-Transport-Security" in report
    assert "Nothing was applied" in report
    assert json.loads((d / "summary.json").read_text())["drafted"] == 1
    assert len(json.loads((d / "findings.json").read_text())) == 2
    assert (d / "drafts" / "index.json").exists()


def test_plugin_errors_are_not_ranked_or_drafted(tmp_path):
    rows = [_row(1, 99, "keyleak_paste_error"), _row(2, 80, "hsts_missing")]
    s = _run(FakeApi(rows, statuses=("done",)), tmp_path, targets="x.com")
    assert s["drafted"] == 1
    report = (tmp_path / "run123" / "report.md").read_text()
    assert "keyleak_paste_error" not in report
    assert "1 plugin errors left out" in report


def test_resume_does_not_start_a_new_scan(tmp_path):
    api = FakeApi([_row(1, 90)], statuses=("done",))
    _run(api, tmp_path, run_id="run123")
    assert api.started == []


def test_active_mode_requires_authorization(tmp_path):
    with pytest.raises(wf.WorkflowError, match="authorized"):
        _run(FakeApi([]), tmp_path, targets="x.com", mode="active")
    s = _run(FakeApi([], statuses=("done",)), tmp_path, targets="x.com",
             mode="active", authorized=True)
    assert s["status"] == "done"


def test_no_llm_and_unconfigured_provider_still_report(tmp_path, monkeypatch):
    s = _run(FakeApi([_row(1, 90)], statuses=("done",)), tmp_path,
             targets="x.com", use_llm=False)
    assert s["drafted"] == 0 and "no-llm" in s["note"]
    monkeypatch.setenv("RECON_LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    s = wf.run_workflow(FakeApi([_row(1, 90)], statuses=("done",)),
                        targets="x.com", out=tmp_path, poll_s=0,
                        log=lambda m: None, sleep=lambda s: None)
    assert s["drafted"] == 1  # provider error is per-finding, recorded
    assert (tmp_path / "run123" / "report.md").exists()


def test_broken_drafted_test_is_flagged_not_trusted(tmp_path):
    bad = "```fix\nF\n```\n```python\ndef broken(:\n```"
    s = _run(FakeApi([_row(1, 90)], statuses=("done",)), tmp_path,
             targets="x.com", complete=lambda s, u: bad)
    assert s["tests_compile"] == 0
    assert "syntax error" in (tmp_path / "run123" / "report.md").read_text()


def test_timeout_says_how_to_resume(tmp_path):
    with pytest.raises(wf.WorkflowError, match="--run-id"):
        _run(FakeApi([], statuses=("running",)), tmp_path,
             targets="x.com", timeout_s=-1)


def test_api_client_sends_access_code_and_explains_401():
    seen = {}

    def handler(req):
        seen["code"] = req.headers.get("x-access-code")
        if req.url.path == "/api/runs":
            return httpx.Response(200, json={"run_id": "r1"})
        return httpx.Response(401, json={"detail": "bad access code"})

    client = httpx.Client(base_url="http://t", transport=httpx.MockTransport(handler),
                          headers={"X-Access-Code": "sekrit"})
    api = wf.Api("http://t", client=client)
    assert api.start("x.com", "passive") == "r1"
    assert seen["code"] == "sekrit"
    with pytest.raises(wf.WorkflowError, match="RECON_ACCESS_CODE"):
        api.detail("r1")
