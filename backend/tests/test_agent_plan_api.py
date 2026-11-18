"""POST /api/agent/plan: owner-gated multi-step plan over a run."""
import os
import sys
import tempfile
import uuid

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp.name}")
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config, remediation_llm as remediation  # noqa: E402
from app.agent import plan as plan_mod  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, Target, get_session, init_db  # noqa: E402

GOOD = "```fix\nSet HSTS.\n```\n```python\ndef test_h():\n    assert True\n```"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ACCESS_CODE", "")
    for k in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("RECON_AGENT_PLAN_DIR", str(tmp_path / "plans"))
    monkeypatch.setattr(remediation, "get_completer", lambda: (lambda s, u: GOOD))
    init_db()
    with TestClient(app) as c:
        yield c


def _seed(with_finding=True):
    rid = "plan-" + uuid.uuid4().hex[:8]
    s = get_session()
    try:
        s.add(Run(id=rid, mode="passive", status="done",
                  source_type="website", summary={}))
        s.add(Target(id=uuid.uuid4().hex[:12], run_id=rid, raw="http://x",
                     type="url", normalized="http://x"))
        if with_finding:
            s.add(Finding(run_id=rid, target_id="t", plugin_id="headers",
                          category="web", key="hsts_missing", value="no HSTS",
                          source="s", confidence=90,
                          evidence={"severity": "high",
                                    "exploitability": "public_poc"}))
        s.commit()
    finally:
        s.close()
    return rid


def test_passive_plan_runs_and_reports(client):
    rid = _seed()
    r = client.post("/api/agent/plan",
                    json={"run_id": rid, "objective": "assess headers"})
    assert r.status_code == 200, r.text
    body = r.json()
    steps = body["summary"]["steps"]
    assert steps["rank"] == "done" and steps["remediate"] == "done"
    assert steps["investigate"] == "skipped"  # not authorized
    assert "no exploit code was run" in body["report_markdown"]


def test_harmful_objective_is_422(client):
    rid = _seed()
    r = client.post("/api/agent/plan",
                    json={"run_id": rid,
                          "objective": "steal the admin password"})
    assert r.status_code == 422 and "refused" in r.text


def test_requires_run_id(client):
    assert client.post("/api/agent/plan", json={"objective": "x"}).status_code == 400


def test_unknown_run_is_404(client):
    r = client.post("/api/agent/plan", json={"run_id": "ghost-run"})
    assert r.status_code == 404


def test_customer_is_forbidden(client, monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "resolve_actor",
                        lambda req, code: {"kind": "user",
                                           "user": type("U", (), {"id": 9})()})
    assert client.post("/api/agent/plan",
                       json={"run_id": _seed()}).status_code == 403


def test_resume_is_idempotent_on_steps(client):
    rid = _seed()
    a = client.post("/api/agent/plan", json={"run_id": rid}).json()
    b = client.post("/api/agent/plan", json={"run_id": rid}).json()
    assert a["summary"]["done"] == b["summary"]["done"]
