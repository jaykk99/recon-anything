"""Tests for app/presets.py + the /api/presets and preset-run wiring.

One-click scan presets (anti-Amass): quick / standard / deep resolve
against the live registry, set mode + plugins + hunter depth, and an
unknown preset is a hard 400, never a silent full scan.
"""
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Run, get_session, init_db  # noqa: E402
from app.presets import (DEEP_ONLY_PLUGIN_IDS, QUICK_PLUGIN_IDS,  # noqa: E402
                         list_presets, resolve_preset)
from app.plugins.registry import discover  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


# -- pure resolution -------------------------------------------------------

def test_three_presets_listed():
    ids = [p["id"] for p in list_presets()]
    assert ids == ["quick", "standard", "deep"]


def test_quick_is_passive_shallow_and_fast_set_only():
    r = resolve_preset("quick")
    assert r["mode"] == "passive"
    assert r["max_depth"] == 0
    assert r["plugins"], "quick set must resolve to real plugins"
    known = set(discover())
    assert set(r["plugins"]) <= known
    assert "dns" in r["plugins"]
    # none of the deep/crawl set leaks into a triage scan
    assert not (set(r["plugins"]) & set(DEEP_ONLY_PLUGIN_IDS))


def test_standard_is_active_depth1_without_deep_only():
    r = resolve_preset("standard")
    assert r["mode"] == "active"
    assert r["max_depth"] == 1
    assert r["plugins"]
    assert "dns" in r["plugins"]
    assert not (set(r["plugins"]) & set(DEEP_ONLY_PLUGIN_IDS))


def test_deep_is_full_default_set_full_depth():
    r = resolve_preset("deep")
    assert r["mode"] == "active"
    assert r["plugins"] is None  # runner default-set semantics
    assert r["max_depth"] is None  # engine global cap


def test_unknown_preset_raises():
    with pytest.raises(KeyError):
        resolve_preset("bogus")


def test_resolution_drops_ids_missing_from_registry():
    r = resolve_preset("quick", registry_ids=["dns", "tls"])
    assert r["plugins"] == ["dns", "tls"]


def test_quick_ids_all_exist_in_registry():
    # Guard against preset rot: a renamed plugin must fail loudly here
    # rather than silently shrinking the triage set.
    known = set(discover())
    missing = [pid for pid in QUICK_PLUGIN_IDS if pid not in known]
    assert missing == []


# -- API -------------------------------------------------------------------

def test_presets_endpoint(client):
    r = client.get("/api/presets")
    assert r.status_code == 200
    presets = {p["id"]: p for p in r.json()["presets"]}
    assert set(presets) == {"quick", "standard", "deep"}
    assert presets["quick"]["plugin_count"] > 0
    assert presets["quick"]["mode"] == "passive"
    assert presets["deep"]["plugin_count"] is None


def _capture_launch(monkeypatch):
    calls = {}

    async def fake_launch(run_id, targets, mode, plugins=None,
                          overrides=None, keys=None, **kw):
        calls.update(run_id=run_id, mode=mode, plugins=plugins, **kw)

    monkeypatch.setattr(main, "launch_run", fake_launch)
    return calls


def _run_row(run_id):
    s = get_session()
    try:
        return s.query(Run).filter_by(id=run_id).first()
    finally:
        s.close()


def test_run_with_quick_preset(client, monkeypatch):
    calls = _capture_launch(monkeypatch)
    r = client.post("/api/runs", json={"targets": "example.com",
                                       "preset": "quick"})
    assert r.status_code == 200
    run_id = r.json()["run_id"]
    assert calls["run_id"] == run_id
    assert calls["mode"] == "passive"
    assert calls["plugins"] and "deepcrawl" not in calls["plugins"]
    run = _run_row(run_id)
    assert run.summary["preset"] == "quick"
    # Depth rides the durable enqueue intent; execute_run reads it
    # from there (see app/runner.py), so recovery honors it too.
    intent = run.summary["pending_enqueue"]
    assert intent["max_depth"] == 0
    assert intent["mode"] == "passive"
    assert intent["plugins"] == calls["plugins"]


def test_run_with_deep_preset(client, monkeypatch):
    calls = _capture_launch(monkeypatch)
    r = client.post("/api/runs", json={"targets": "example.com",
                                       "preset": "deep"})
    assert r.status_code == 200
    assert calls["mode"] == "active"
    assert calls["plugins"] is None
    run = _run_row(r.json()["run_id"])
    assert run.summary["pending_enqueue"]["max_depth"] is None


def test_run_with_unknown_preset_is_400(client, monkeypatch):
    _capture_launch(monkeypatch)
    r = client.post("/api/runs", json={"targets": "example.com",
                                       "preset": "bogus"})
    assert r.status_code == 400


def test_run_without_preset_unchanged(client, monkeypatch):
    calls = _capture_launch(monkeypatch)
    r = client.post("/api/runs", json={"targets": "example.com",
                                       "mode": "active",
                                       "plugins": ["dns"]})
    assert r.status_code == 200
    assert calls["plugins"] == ["dns"]
    run = _run_row(r.json()["run_id"])
    assert run.summary["preset"] is None
    assert run.summary["pending_enqueue"]["max_depth"] is None
