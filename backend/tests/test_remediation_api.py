"""GET/POST /api/runs/{id}/remediation: drafts stored on the run.

Network-free: temp SQLite via TestClient, fake LLM provider."""
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

from app import config, remediation  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, get_session, init_db  # noqa: E402

GOOD = "```fix\nEnable HSTS.\n```\n```python\ndef test_h():\n    assert True\n```"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(config, "ACCESS_CODE", "")
    for k in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    init_db()
    with TestClient(app) as c:
        yield c


def _seed():
    rid = "rem-" + uuid.uuid4().hex[:8]
    s = get_session()
    try:
        s.add(Run(id=rid, mode="passive", status="done",
                  source_type="website", summary={"keep": "me"}))
        s.add(Finding(run_id=rid, target_id="t", plugin_id="headers",
                      category="web", key="hsts_missing", value="no HSTS",
                      source="header check", confidence=95,
                      evidence={"severity": "high",
                                "exploitability": "public_poc"}))
        s.commit()
    finally:
        s.close()
    return rid


def test_get_is_empty_before_generation(client):
    rid = _seed()
    r = client.get(f"/api/runs/{rid}/remediation")
    assert r.status_code == 200 and r.json() == {"results": []}


def test_generate_stores_drafts_and_keeps_summary(client, monkeypatch):
    monkeypatch.setattr(remediation, "get_completer", lambda: (lambda s, u: GOOD))
    rid = _seed()
    r = client.post(f"/api/runs/{rid}/remediation?min_score=0&limit=3")
    assert r.status_code == 200, r.text
    res = r.json()["results"]
    assert len(res) == 1 and res[0]["key"] == "hsts_missing"
    assert res[0]["fix"] == "Enable HSTS." and res[0]["test_check"] == "compiles"
    stored = client.get(f"/api/runs/{rid}/remediation").json()
    assert stored["results"][0]["status"] == "drafted"
    s = get_session()
    try:
        summary = s.query(Run).filter_by(id=rid).first().summary
    finally:
        s.close()
    assert summary["keep"] == "me"  # existing summary keys survive


def test_generate_without_provider_is_503(client, monkeypatch):
    def none():
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    monkeypatch.setattr(remediation, "get_completer", none)
    r = client.post(f"/api/runs/{_seed()}/remediation")
    assert r.status_code == 503 and "ANTHROPIC_API_KEY" in r.text


def test_unknown_run_is_404(client):
    assert client.get("/api/runs/nope-nope/remediation").status_code == 404
