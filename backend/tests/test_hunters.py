"""Hunter layer tests: known-set extraction, dedupe, expansion bounds,
hunt memory, the agent data service, and the no-chat rule.

Network-free and DB-isolated: the module points DATABASE_URL at a
throwaway SQLite file before importing the app.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TMPDB = os.path.join(tempfile.mkdtemp(prefix="ra-hunters-"), "test.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMPDB}"
os.environ.pop("RECON_ACCESS_CODE", None)

import pytest  # noqa: E402

from app import models  # noqa: E402
from app.agentdata import packs, resources, store  # noqa: E402
from app.hunters import engine  # noqa: E402
from app.hunters.roles import HUNTERS  # noqa: E402
from app.models import Finding as FindingRow  # noqa: E402
from app.models import PluginJob, Run, Target as TargetRow  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _db():
    models.init_db()
    yield


@pytest.fixture()
def session():
    s = models.get_session()
    yield s
    s.close()


def _finding(key, value, plugin="dns", category="dns", source_url=None):
    return FindingRow(run_id="r-x", target_id="t1", plugin_id=plugin,
                      category=category, key=key, value=value,
                      source="test", source_url=source_url)


# ---------------------------------------------------------------------------
# Roles + packs + registry
# ---------------------------------------------------------------------------

def test_twenty_hunters_defined():
    assert len(HUNTERS) == 20
    names = [h["name"] for h in HUNTERS]
    assert len(set(names)) == 20
    for h in HUNTERS:
        assert h["specialty"] and h["consumes"] and h["produces"]


def test_knowledge_packs_have_entries():
    inv = {p["name"]: p for p in packs.pack_inventory()}
    for name in ("subdomain_wordlist", "sensitive_paths", "secret_patterns",
                 "tech_fingerprints", "cloud_patterns"):
        assert inv[name]["entries"] >= 10, name
    assert len(packs.pack_entries("subdomain_wordlist")) >= 100


def test_resource_registry_shape():
    cat = resources.catalog()
    assert len(cat) >= 12
    ids = {r["id"] for r in cat}
    for expected in ("seclists-discovery", "payloadsallthethings",
                     "hacktricks", "owasp-wstg", "crtsh", "wayback-cdx",
                     "xposedornot", "nuclei-templates"):
        assert expected in ids
    for r in cat:
        assert r["url"].startswith("http") and r["attribution"] and r["used_by"]


def test_resource_fetch_caches_with_attribution(session):
    class FakeResp:
        status_code = 200
        text = "www\napi\ndev\n"

    result = resources.fetch_resource(
        session, "seclists-subdomains", http_get=lambda url: FakeResp())
    assert result["ok"] and result["source_url"].startswith("https://")
    assert "SecLists" in result["attribution"]
    assert resources.cached_lines(session, "seclists-subdomains") == [
        "www", "api", "dev"]
    entry = [r for r in resources.catalog(session)
             if r["id"] == "seclists-subdomains"][0]
    assert entry["cached"] is True
    # reference-only resources are never fetched
    ref = resources.fetch_resource(session, "hacktricks",
                                   http_get=lambda url: FakeResp())
    assert ref["ok"] is False


def test_hunter_wordlist_merges_bundled_and_cached(session):
    words = engine.hunter_wordlist(session)
    assert "www" in words and len(words) >= 100


# ---------------------------------------------------------------------------
# Extraction (pivot candidates from findings)
# ---------------------------------------------------------------------------

def test_extract_assets_from_findings():
    target = TargetRow(id="t1", run_id="r-x", raw="example.com",
                       type="domain", normalized="example.com")
    findings = [
        _finding("subdomain", "api.example.com"),
        _finding("subdomain", "api.example.com"),  # duplicate
        _finding("tls_san", "mail.example.com"),
        _finding("a", "93.184.216.34"),
        _finding("email", "admin@example.com"),
        _finding("crypto_eth_address", "0x" + "a" * 40, plugin="wallets"),
        _finding("endpoint", "https://example.com/api/v1/users",
                 plugin="apidiscover", category="api"),
        _finding("page", "see https://cdn.example.com/app.js",
                 plugin="crawler", category="web",
                 source_url="https://cdn.example.com/app.js"),
        _finding("link", "code at https://github.com/example/widgets",
                 plugin="github", category="web"),
    ]
    assets = engine.extract_assets(findings, [target])
    pairs = {(a["type"], a["value"]) for a in assets}
    assert ("domain", "example.com") in pairs
    assert ("subdomain", "api.example.com") in pairs
    assert ("subdomain", "mail.example.com") in pairs
    assert ("ip", "93.184.216.34") in pairs
    assert ("email", "admin@example.com") in pairs
    assert ("wallet", "0x" + "a" * 40) in pairs
    assert ("endpoint", "https://example.com/api/v1/users") in pairs
    assert ("js_file", "https://cdn.example.com/app.js") in pairs
    assert ("repo", "https://github.com/example/widgets") in pairs
    # dedupe: the repeated subdomain appears once
    assert sum(1 for a in assets if a["value"] == "api.example.com") == 1
    # attribution rides along
    sub = [a for a in assets if a["value"] == "api.example.com"][0]
    assert sub["found_by"] == "subdomain_hunter"
    san = [a for a in assets if a["value"] == "mail.example.com"][0]
    assert san["found_by"] == "cert_hunter"


# ---------------------------------------------------------------------------
# Store: known set, memory, dead ends
# ---------------------------------------------------------------------------

def test_known_set_add_is_idempotent(session):
    _row, created = store.add_known_asset(
        session, "recon", "dedup.test", "subdomain", "a.dedup.test",
        found_by="subdomain_hunter", run_id="r1")
    assert created is True
    _row2, created2 = store.add_known_asset(
        session, "recon", "dedup.test", "subdomain", "a.dedup.test",
        found_by="subdomain_hunter", run_id="r2")
    assert created2 is False
    assert store.known_total(session, "recon", "dedup.test") == 1
    # namespacing: another agent system keeps its own set
    assert store.known_total(session, "other-system", "dedup.test") == 0


def test_hunt_memory_roundtrip(session):
    store.add_known_asset(session, "recon", "mem.test", "domain",
                          "mem.test", found_by="seed", run_id="r1")
    assert store.add_dead_end(session, "recon", "mem.test", "subdomain",
                              "dead.mem.test", run_id="r1",
                              reason="no findings") is True
    assert store.add_dead_end(session, "recon", "mem.test", "subdomain",
                              "dead.mem.test", run_id="r1") is False
    store.record_run_summary(session, "recon", "mem.test", "r1",
                             known_before=0, known_after=1,
                             finding_counts={"dns": 3})
    mem = store.get_memory(session, "recon", "mem.test")
    assert mem["assets_by_type"] == {"domain": 1}
    assert mem["finding_counts"] == {"dns": 3}
    assert mem["dead_ends"][0]["value"] == "dead.mem.test"
    assert mem["runs"][0]["known_before"] == 0
    assert mem["runs"][0]["known_after"] == 1
    assert "dead.mem.test" in store.dead_end_values(
        session, "recon", "mem.test")


# ---------------------------------------------------------------------------
# Expansion: jobs, dedupe, bounds, persistence across runs
# ---------------------------------------------------------------------------

def _mk_run(session, run_id, target_value="expand.test"):
    run = Run(id=run_id, mode="passive", status="running",
              source_type="website", summary={})
    session.add(run)
    session.add(TargetRow(id=f"{run_id}-t", run_id=run_id, raw=target_value,
                          type="domain", normalized=target_value))
    session.commit()
    return run


def test_expand_enqueues_verification_jobs(session):
    run = _mk_run(session, "run-expand-1")
    r = _finding("subdomain", "api.expand.test")
    r.run_id = "run-expand-1"
    session.add(r)
    session.commit()
    accum = engine.new_accum()
    enqueued = engine.hunter_expand(session, run, accum)
    assert enqueued > 0
    jobs = session.query(PluginJob).filter_by(run_id="run-expand-1").all()
    assert len(jobs) == enqueued
    # the new subdomain became a target and got detection plugins
    targets = session.query(TargetRow).filter_by(run_id="run-expand-1").all()
    assert any(t.normalized == "api.expand.test" for t in targets)
    assert store.known_total(session, "recon", "expand.test") >= 2
    # second pass on the same findings: dedupe means no new jobs for the
    # already-expanded frontier
    enqueued2 = engine.hunter_expand(session, run, accum)
    assert enqueued2 == 0


def test_expand_respects_task_budget(session, monkeypatch):
    monkeypatch.setattr(engine, "MAX_TASKS", 3)
    run = _mk_run(session, "run-budget-1", "budget.test")
    for i in range(6):
        r = _finding("subdomain", f"s{i}.budget.test")
        r.run_id = "run-budget-1"
        session.add(r)
    session.commit()
    accum = engine.new_accum()
    engine.hunter_expand(session, run, accum)
    assert accum["tasks_used"] <= 3


def test_expand_skips_dead_ends(session):
    store.add_dead_end(session, "recon", "deadend.test", "subdomain",
                       "gone.deadend.test", run_id="r0", reason="nothing")
    run = _mk_run(session, "run-dead-1", "deadend.test")
    r = _finding("subdomain", "gone.deadend.test")
    r.run_id = "run-dead-1"
    session.add(r)
    session.commit()
    accum = engine.new_accum()
    engine.hunter_expand(session, run, accum)
    assert "gone.deadend.test" not in store.known_values(
        session, "recon", "deadend.test")


def test_known_set_persists_across_runs(session):
    run1 = _mk_run(session, "run-persist-1", "persist.test")
    r = _finding("subdomain", "api.persist.test")
    r.run_id = "run-persist-1"
    session.add(r)
    session.commit()
    a1 = engine.new_accum()
    engine.hunter_expand(session, run1, a1)
    total_after_1 = store.known_total(session, "recon", "persist.test")
    assert total_after_1 >= 2
    # a second run on the same target starts from the persisted set:
    # the same finding produces no new assets
    run2 = _mk_run(session, "run-persist-2", "persist.test")
    r2 = _finding("subdomain", "api.persist.test")
    r2.run_id = "run-persist-2"
    session.add(r2)
    session.commit()
    a2 = engine.new_accum()
    engine.hunter_expand(session, run2, a2)
    assert a2["known_before"]["persist.test"] == total_after_1
    assert store.known_total(session, "recon", "persist.test") == total_after_1


def test_finalize_hunt_records_memory_and_dead_ends(session):
    run = _mk_run(session, "run-fin-1", "fin.test")
    accum = engine.new_accum()
    accum["known_before"] = {"fin.test": 0}
    # a hunter target that produced nothing becomes a dead end
    session.add(TargetRow(id="fin-dead-t", run_id="run-fin-1",
                          raw="nope.fin.test", type="domain",
                          normalized="nope.fin.test"))
    session.commit()
    accum["hunter_targets"] = ["fin-dead-t"]
    section = engine.finalize_hunt(session, run, accum)
    assert "known_before" in section and "known_after" in section
    assert "nope.fin.test" in store.dead_end_values(
        session, "recon", "fin.test")
    mem = store.get_memory(session, "recon", "fin.test")
    assert mem["runs"] and mem["runs"][-1]["run_id"] == "run-fin-1"


# ---------------------------------------------------------------------------
# HTTP surface: hunters endpoints, agent data, and the no-chat rule
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_hunters_endpoint_shape(client):
    resp = client.get("/api/hunters")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 20
    h = data["hunters"][0]
    assert {"name", "specialty", "consumes", "produces", "stats"} <= set(h)
    assert "assets_discovered" in h["stats"]


def test_hunters_endpoints_empty_data_shapes(client):
    mem = client.get("/api/hunters/memory", params={"target": "none.test"})
    assert mem.status_code == 200
    body = mem.json()
    assert body["known_set_total"] == 0 and body["runs"] == []
    ks = client.get("/api/hunters/known-set", params={"target": "none.test"})
    assert ks.status_code == 200 and ks.json()["total"] == 0
    know = client.get("/api/hunters/knowledge")
    assert know.status_code == 200 and len(know.json()["packs"]) == 5
    res = client.get("/api/hunters/resources")
    assert res.status_code == 200 and len(res.json()["resources"]) >= 12


def test_agentdata_endpoints_roundtrip(client):
    resp = client.post("/api/agentdata/known", json={
        "target": "api.test", "asset_type": "ip", "value": "10.0.0.9",
        "found_by": "dns_hunter"})
    assert resp.status_code == 200 and resp.json()["created"] is True
    got = client.get("/api/agentdata/known", params={"target": "api.test"})
    assert got.status_code == 200 and got.json()["count"] == 1
    finds = client.get("/api/agentdata/finds")
    assert finds.status_code == 200 and "finds" in finds.json()


def test_assistant_routes_are_gone(client):
    assert client.post("/api/assistant/chat",
                       json={"messages": []}).status_code == 404
    assert client.post("/api/assistant/agent",
                       json={"run_id": "x", "instruction": "y"}
                       ).status_code == 404
    assert client.post("/api/assistant/deep-run",
                       json={"run_id": "x", "plugin_ids": ["dns"]}
                       ).status_code == 404


def test_gate_protects_hunter_endpoints(client, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "ACCESS_CODE", "sekrit")
    try:
        assert client.get("/api/hunters").status_code == 401
        ok = client.get("/api/hunters",
                        headers={"X-Access-Code": "sekrit"})
        assert ok.status_code == 200
        assert client.get("/api/agentdata/packs").status_code == 401
    finally:
        monkeypatch.setattr(config, "ACCESS_CODE", "")
