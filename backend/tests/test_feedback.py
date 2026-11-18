"""Finding feedback -> neural-engine labels (app/feedback.py + API).

Network-free: temp SQLite via TestClient."""
import json
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

from app import config, feedback  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, FindingFeedback, Run, get_session, init_db  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(config, "ACCESS_CODE", "")
    for k in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    init_db()
    s = get_session()
    try:  # each test sees only its own labels
        s.query(FindingFeedback).delete()
        s.commit()
    finally:
        s.close()
    with TestClient(app) as c:
        yield c


def _seed(findings):
    rid = "fb-" + uuid.uuid4().hex[:8]
    ids = []
    s = get_session()
    try:
        s.add(Run(id=rid, mode="passive", status="done", summary={}))
        for key, sev, val in findings:
            f = Finding(run_id=rid, target_id="t", plugin_id="headers",
                        category="web", key=key, value=val, source="s",
                        confidence=90,
                        evidence={"severity": sev, "nn": {"score": 50}})
            s.add(f)
            s.flush()
            ids.append(f.id)
        s.commit()
    finally:
        s.close()
    return rid, ids


def test_set_update_list_and_clear(client):
    rid, (fid,) = _seed([("hsts_missing", "medium", "no HSTS")])
    url = f"/api/runs/{rid}/findings/{fid}/feedback"
    assert client.put(url, json={"verdict": "confirmed"}).status_code == 200
    r = client.put(url, json={"verdict": "false_positive", "note": "CDN adds it"})
    assert r.json() == {"finding_id": fid, "verdict": "false_positive",
                        "note": "CDN adds it"}
    got = client.get(f"/api/runs/{rid}/feedback").json()["verdicts"]
    assert got[str(fid)]["verdict"] == "false_positive"  # one row, updated
    assert client.delete(url).json() == {"cleared": True}
    assert client.get(f"/api/runs/{rid}/feedback").json()["verdicts"] == {}


def test_bad_verdict_and_wrong_run_are_rejected(client):
    rid, (fid,) = _seed([("k", "low", "v")])
    other, _ = _seed([("k", "low", "v")])
    assert client.put(f"/api/runs/{rid}/findings/{fid}/feedback",
                      json={"verdict": "maybe"}).status_code == 400
    assert client.put(f"/api/runs/{other}/findings/{fid}/feedback",
                      json={"verdict": "confirmed"}).status_code == 404
    assert client.put(f"/api/runs/nope-run/findings/{fid}/feedback",
                      json={"verdict": "confirmed"}).status_code == 404


def test_snapshot_masks_secrets_and_drops_model_score(client):
    secret = "AKIAIOSFODNN7EXAMPLE"
    rid, (fid,) = _seed([("aws_access_key", "critical", secret)])
    client.put(f"/api/runs/{rid}/findings/{fid}/feedback",
               json={"verdict": "confirmed"})
    s = get_session()
    try:
        snap = s.query(FindingFeedback).filter_by(finding_id=fid).one().snapshot
    finally:
        s.close()
    assert secret not in json.dumps(snap)
    assert "nn" not in snap["evidence"]


def test_export_is_nn_train_jsonl_and_skips_unsure(client):
    rid, ids = _seed([("a", "high", "1"), ("b", "low", "2"), ("c", "low", "3")])
    for fid, v in zip(ids, ("confirmed", "false_positive", "unsure")):
        client.put(f"/api/runs/{rid}/findings/{fid}/feedback", json={"verdict": v})
    r = client.get("/api/feedback/export")
    assert r.status_code == 200
    recs = [json.loads(line) for line in r.text.splitlines()]
    assert sorted(x["label"] for x in recs) == [0.0, 1.0]
    assert all({"finding", "label"} <= set(x) for x in recs)


def test_stats_counts_and_scores_current_model(client):
    rid, ids = _seed([("rce_confirmed", "critical", "x"),
                      ("missing_hsts", "low", "y")])
    client.put(f"/api/runs/{rid}/findings/{ids[0]}/feedback", json={"verdict": "confirmed"})
    client.put(f"/api/runs/{rid}/findings/{ids[1]}/feedback", json={"verdict": "false_positive"})
    st = client.get("/api/feedback/stats").json()
    assert st["counts"]["confirmed"] == 1 and st["counts"]["false_positive"] == 1
    assert st["labelled"] == 2
    assert st["model"]["records"] == 2 and "spearman" in st["model"]


def test_stats_without_both_classes_has_no_model_block(client):
    rid, (fid,) = _seed([("k", "low", "v")])
    client.put(f"/api/runs/{rid}/findings/{fid}/feedback", json={"verdict": "confirmed"})
    assert client.get("/api/feedback/stats").json()["model"] is None


def test_export_is_owner_only(client, monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "resolve_actor",
                        lambda req, code: {"kind": "user", "user": type("U", (), {"id": 7})()})
    assert client.get("/api/feedback/export").status_code == 403


def test_label_mapping_is_what_nn_train_expects():
    assert feedback.LABEL_FOR == {"confirmed": 1.0, "not_actionable": 0.3,
                                  "false_positive": 0.0}
    recs = [{"finding": {"plugin": "p"}, "label": 1.0}]
    assert feedback.as_corpus(recs) == [({"plugin": "p"}, 1.0, "p")]
