"""Tests for GET /api/runs (list endpoint perf + shape).

Regression coverage for the 2026-10-20 perf fix: the list endpoint used
to deserialize every run's full summary JSON blob (~6s idle). Now it
loads light columns only, adds one GROUP BY for findings counts, and
only includes summaries on ?summary=1.

Network-free: runs against a temp SQLite DB via FastAPI TestClient.
"""
import os
import sys
import tempfile
import time

# Env must be set before app.main is imported (engine binds at import).
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.models import Finding, Run, get_session, init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def _seed(n_runs=30, summary_kb=50, findings_per_run=7):
    """Seed runs with heavy summaries (the old perf killer)."""
    session = get_session()
    try:
        session.query(Finding).delete()
        session.query(Run).delete()
        big = {"blob": "x" * (summary_kb * 1024), "findings": findings_per_run}
        for i in range(n_runs):
            r = Run(id=f"test-run-{i:03d}", mode="passive", status="done",
                    source_type="website", summary=dict(big))
            session.add(r)
            for j in range(findings_per_run):
                session.add(Finding(run_id=r.id, target_id="t",
                                    plugin_id="p", category="web",
                                    key="k", value="v", source="s"))
        session.commit()
    finally:
        session.close()


def test_list_omits_summary_by_default(client):
    _seed()
    r = client.get("/api/runs?limit=30")
    assert r.status_code == 200
    runs = r.json()["runs"]
    assert len(runs) == 30
    for row in runs:
        assert "summary" not in row, "heavy summary leaked into list"
        assert row["findings_count"] == 7
        assert set(row) >= {"id", "mode", "status", "source_type",
                            "created_at", "findings_count"}


def test_list_summary_opt_in(client):
    _seed(n_runs=3)
    r = client.get("/api/runs?limit=3&summary=1")
    assert r.status_code == 200
    runs = r.json()["runs"]
    assert len(runs) == 3
    for row in runs:
        assert row["summary"]["findings"] == 7
        assert len(row["summary"]["blob"]) == 50 * 1024


def test_list_respects_limit(client):
    _seed(n_runs=10)
    r = client.get("/api/runs?limit=5")
    assert r.status_code == 200
    assert len(r.json()["runs"]) == 5


def test_list_empty_db(client):
    session = get_session()
    try:
        session.query(Finding).delete()
        session.query(Run).delete()
        session.commit()
    finally:
        session.close()
    r = client.get("/api/runs")
    assert r.status_code == 200
    assert r.json() == {"runs": []}


def test_list_fast_with_heavy_summaries(client):
    # The regression that matters: 30 runs x 50KB summaries must list fast
    # now that summaries are deferred. Measured at the endpoint function
    # (not through TestClient, whose ASGI spin-up dominates in CI).
    # Budget 5s (old behavior: ~6s+ of JSON deserialization).
    from app.main import api_list_runs
    _seed(n_runs=30, summary_kb=50)
    t0 = time.monotonic()
    out = api_list_runs(limit=30, summary=False)
    dt = time.monotonic() - t0
    assert len(out["runs"]) == 30
    assert dt < 5.0, f"list took {dt:.1f}s, perf regression"
    assert all("summary" not in row for row in out["runs"])
