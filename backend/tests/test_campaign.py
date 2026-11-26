"""Unit gate for the autonomous campaign engine (app/campaign/).

Pure stdlib + the project's own FetchResponse, so it runs without
fastapi/sqlalchemy and with no network access. Run directly
(`python tests/test_campaign.py`) or under pytest.

Checks the ARTEX-shaped contract:
  * scope is a hard filter (foreign host, never-target, active mode),
  * the dual graph is deterministic and idempotent,
  * the planner surfaces a target before probing it and never repeats,
  * the loop proves a goal from a captured receipt, not from an attempt,
  * impact enumeration is gated behind an explicit approval,
  * the budget stops the campaign, and
  * every confirmed finding ships the request that decided it.
"""
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.campaign import (  # noqa: E402
    Attempt, CampaignStore, Graph, Scope, goals_for, next_intents, render,
    resume_campaign, run_campaign,
)
from app.campaign.evidence import EvidenceRecorder, to_har  # noqa: E402
from app.campaign.graph import import_findings  # noqa: E402
from app.campaign.llm_planner import propose_intents  # noqa: E402
from app.campaign.models import finding  # noqa: E402
from app.campaign.retest import retest_finding  # noqa: E402
from app.exploit_probes import FetchResponse  # noqa: E402


# ---------------------------------------------------------------------------
# A tiny fake target: routes by path, records every request.
# ---------------------------------------------------------------------------
class FakeTarget:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url, method="GET", **kw):
        self.calls.append((method, url))
        p = urlparse(url)
        body = self.routes.get(p.path or "/")
        if body is None:
            return FetchResponse(url=url, method=method, status=404,
                                 headers={"content-type": "text/html"},
                                 text="not found")
        status, headers, text = body
        return FetchResponse(url=url, method=method, status=status,
                             headers=dict(headers), text=text)


LAB_HTML = (
    "<html><head><title>Lab app</title></head><body>"
    "<a href='/app?q=1'>app</a><form><input name='user'></form>"
    "</body></html>"
)

DOCKER_ROUTES = {
    "/": (200, {"server": "nginx"}, LAB_HTML),
    "/version": (200, {"content-type": "application/json"},
                 '{"ApiVersion": "1.43", "Version": "24.0.7"}'),
    "/containers/json": (200, {"content-type": "application/json"},
                         '[{"Names": ["/web"], "Id": "abc123def456"}]'),
}


def _scope(**kw):
    base = dict(roots=("lab.test",), allow_active=True,
                max_requests=40, max_intents=20, max_rounds=3,
                max_seconds=30, per_host_rps=0)
    base.update(kw)
    return Scope(**base)


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
def test_scope_allows_root_and_subdomain_but_not_foreign():
    s = _scope(roots=("example.com",))
    assert s.allows("example.com")[0]
    assert s.allows("https://api.example.com/x")[0]
    denied, reason = s.allows("evil.test")
    assert not denied and "outside" in reason


def test_scope_never_targets_crypto_com():
    s = _scope(roots=("crypto.com", "example.com"))
    ok, reason = s.allows("crypto.com")
    assert not ok and "never" in reason


def test_scope_gates_active_and_impact_actions():
    passive = _scope(allow_active=False)
    # Build intents directly so the check is about scope, not planning.
    from app.campaign.models import Intent
    p = Intent(kind="probe", action="docker-api", target="https://lab.test")
    ok, reason = passive.allows_intent(p)
    assert not ok and "active" in reason
    v = Intent(kind="verify", action="bucket-list", target="https://lab.test")
    assert not passive.allows_intent(v)[0]

    active = _scope(allow_active=True, allow_exploit_confirm=False)
    ok, reason = active.allows_intent(p)
    assert ok
    impact = Intent(kind="impact", action="enumerate:docker",
                    target="https://lab.test")
    ok, reason = active.allows_intent(impact)
    assert not ok and "allow_exploit_confirm" in reason
    assert active.needs_approval(impact)


def test_scope_exclusions_win():
    s = _scope(roots=("example.com",), exclude=("admin.example.com",))
    assert not s.allows("admin.example.com")[0]
    assert s.allows("www.example.com")[0]


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------
def _graph_with_host():
    g = Graph()
    g.add_asset("host", "lab.test")
    return g


def test_graph_is_idempotent_and_deterministic():
    g = Graph()
    a1 = g.add_asset("host", "Lab.Test.")
    a2 = g.add_asset("host", "lab.test", source="seed")
    assert a1 == a2 and len(g.assets) == 1
    assert g.assets[a1]["sources"] == ["seed"]
    f = finding("probe", "unauth docker", "https://lab.test",
                tags=["exposed_console"])
    assert g.add_finding(f) == g.add_finding(dict(f))
    assert len(g.findings) == 1
    assert g.findings[f["id"]]["meta"]["observations"] == 2
    assert g.link(a1, f["id"], "about") == g.link(a1, f["id"], "about")
    assert len(g.edges) == 1


def test_imported_findings_are_leads_not_verdicts():
    g = Graph()
    import_findings(g, [{
        "plugin": "keyharvest", "key": "exposed_api_key",
        "value": "sk_live_example", "source_url": "https://lab.test/app",
        "confidence": 80, "evidence": {"severity": "high"},
    }])
    imported = list(g.findings.values())
    assert imported and imported[0]["confirmed"] is False
    assert "secret" in imported[0]["tags"]


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------
def test_planner_surfaces_before_probing_and_never_repeats():
    g = _graph_with_host()
    s = _scope()
    first = next_intents(g, s, ["secrets"])
    assert [i.kind for i in first] == ["recon"]
    assert first[0].action == "surface"

    g.record_attempt(Attempt(key=first[0].key, kind="recon",
                             action="surface", target=first[0].target))
    anon = next_intents(g, s, ["secrets"])
    assert anon and all(i.kind == "probe" for i in anon)
    assert "git-exposed" in [i.action for i in anon]

    # The planner drips probes a bounded batch at a time so each round's
    # observations shape the next; drain it and check nothing repeats.
    seen = set()
    for _ in range(40):
        batch = next_intents(g, s, ["secrets"], limit=50)
        if not batch:
            break
        for i in batch:
            assert i.key not in seen, f"duplicate intent {i.key}"
            seen.add(i.key)
            g.record_attempt(Attempt(key=i.key, kind=i.kind,
                                     action=i.action, target=i.target,
                                     status="ok"))
    assert "git-exposed" in {k.split(":")[1] for k in seen}
    assert next_intents(g, s, ["secrets"], limit=50) == []


def test_objective_maps_to_goals():
    assert "secrets" in goals_for("hunt for leaked secrets")
    assert "injection" in goals_for("test for SQL injection")
    assert goals_for("do whatever") == ["full"]
    # "exploit" must resolve to a provable goal class; the old contract
    # goal had no worker, so it could never be satisfied.
    assert goals_for("exploit the app") == ["full"]


# ---------------------------------------------------------------------------
# End-to-end campaign
# ---------------------------------------------------------------------------
def test_campaign_proves_goal_from_a_receipt():
    fake = FakeTarget(DOCKER_ROUTES)
    result = run_campaign(
        "find an exposed docker console", _scope(), seeds=["https://lab.test"],
        fetch=fake, sleep=lambda _s: None)

    assert result["status"] == "proven"
    findings = [f for f in result["graph"]["findings"].values()
                if f["confirmed"]]
    docker = [f for f in findings if "Docker" in f["title"]]
    assert docker, [f["title"] for f in findings]
    receipt = docker[0]["evidence"]
    assert receipt["status"] == 200
    assert receipt["request"].startswith("GET ")
    assert len(receipt["body_sha256"]) == 64
    assert result["summary"]["evidence_receipts"] >= 1
    # The surface fetch recorded the discovered parameter for later probes.
    assert any(a["type"] == "param" and a["value"] == "user"
               for a in result["graph"]["assets"].values())
    assert "impact" in [s["stage"] for s in result["kill_chain"]]


def test_impact_enumeration_waits_for_approval_then_resumes():
    fake = FakeTarget(DOCKER_ROUTES)
    scope = _scope(allow_exploit_confirm=True, max_rounds=3)
    first = run_campaign("find an exposed docker console", scope,
                         seeds=["https://lab.test"], fetch=fake,
                         sleep=lambda _s: None)
    assert first["pending_approval"], first["status"]
    pending = first["pending_approval"][0]
    assert pending["action"] == "enumerate:docker"
    before = first["summary"]["confirmed_findings"]
    assert not any(a["action"] == "enumerate:docker"
                   for a in first["graph"]["attempts"].values()
                   if a["status"] == "ok")

    resumed = resume_campaign(first, approve=[pending["key"]],
                              fetch=fake, sleep=lambda _s: None)
    assert resumed["status"] == "proven"
    assert resumed["summary"]["confirmed_findings"] > before
    impact = [a for a in resumed["graph"]["attempts"].values()
              if a["action"] == "enumerate:docker" and a["status"] == "ok"]
    assert impact, resumed["pending_approval"]
    assert impact[0]["findings"][0]["tags"][0] == "exposed_console"


def test_budget_stops_the_campaign():
    fake = FakeTarget(DOCKER_ROUTES)
    result = run_campaign("find an exposed docker console",
                          _scope(max_intents=1), seeds=["https://lab.test"],
                          fetch=fake, sleep=lambda _s: None)
    assert result["status"] == "budget_exhausted"
    assert result["summary"]["attempts"] == 1
    assert result["budget"]["stop_reason"]


def test_out_of_scope_seed_is_refused_before_any_request():
    fake = FakeTarget(DOCKER_ROUTES)
    result = run_campaign("find anything", _scope(),
                          seeds=["https://evil.test"], fetch=fake,
                          sleep=lambda _s: None)
    assert all("evil.test" not in call[1] for call in fake.calls)
    assert any(r["target"] == "https://evil.test"
               for r in result["refused_seeds"])
    assert set(result["graph"]["assets"])  # the in-scope root was seeded


def test_report_contains_kill_chain_and_receipts():
    fake = FakeTarget(DOCKER_ROUTES)
    result = run_campaign("exposed docker console", _scope(),
                          seeds=["https://lab.test"], fetch=fake,
                          sleep=lambda _s: None)
    text = render(result)
    assert "Campaign report" in text
    assert "## Kill chain" in text
    assert "sha256" in text
    assert "Read-only by construction" in text


# ---------------------------------------------------------------------------
# Engine-first additions: parallel waves, evidence, model plan, retest
# ---------------------------------------------------------------------------
def test_parallel_waves_run_intents_concurrently():
    from app.campaign import engine
    from app.campaign.models import Budget, Intent
    from app.campaign.workers import WorkerContext

    barrier = threading.Barrier(2, timeout=1.0)

    def fake_execute(intent, workers, ctx):
        try:
            barrier.wait()
            return Attempt(key=intent.key, kind=intent.kind,
                           action=intent.action, target=intent.target)
        except threading.BrokenBarrierError:
            return Attempt(key=intent.key, kind=intent.kind,
                           action=intent.action, target=intent.target,
                           status="failed", error="not concurrent")

    original = engine._execute
    engine._execute = fake_execute
    try:
        graph = Graph()
        scope = _scope(max_parallel=2, max_requests=10, max_intents=10)
        budget = Budget(max_requests=10, max_intents=10, max_seconds=30)
        ctx = WorkerContext(scope=scope, budget=budget, graph=graph,
                            fetch=lambda *a, **k: None)
        intents = [
            Intent(kind="recon", action="surface",
                   target="https://a.lab.test"),
            Intent(kind="recon", action="surface",
                   target="https://b.lab.test"),
        ]
        ran = engine._run_wave(intents, {}, ctx, scope, graph, time.time)
    finally:
        engine._execute = original
    assert ran == 2
    attempts = list(graph.attempts.values())
    assert len(attempts) == 2
    assert all(a["status"] == "ok" for a in attempts), attempts


def test_per_host_pacing_spaces_parallel_waves():
    """per_host_rps is a request boundary, not a wave boundary.

    The last-hit map used to be local to one wave, so the first request of
    the next round went out immediately after the previous round's last
    one: a burst past 1 rps at every round boundary, even at
    max_parallel 3. The fake clock only advances when the pacer sleeps, so
    the recorded request times are exactly the enforced intervals.
    """
    now = [1000.0]

    def clock():
        return now[0]

    def sleep(seconds):
        now[0] += max(0.0, float(seconds))

    hits = []

    def fetch(url, method="GET", **_kw):
        hits.append((now[0], url))
        path = urlparse(url).path or "/"
        body = DOCKER_ROUTES.get(path)
        if body is None:
            return FetchResponse(url=url, method=method, status=404,
                                 headers={}, text="not found")
        status, headers, text = body
        return FetchResponse(url=url, method=method, status=status,
                             headers=dict(headers), text=text)

    result = run_campaign(
        "find an exposed docker console",
        _scope(max_parallel=3, per_host_rps=1.0, max_seconds=120),
        seeds=["https://lab.test"], fetch=fetch, clock=clock, sleep=sleep)

    assert result["scope"]["max_parallel"] == 3
    assert result["scope"]["per_host_rps"] == 1.0
    # Several rounds ran (surface first, then probes): the wave boundary
    # is exactly where the old pacer reset.
    assert len(hits) >= 3, hits
    assert len({urlparse(u).hostname for _t, u in hits}) == 1
    stamps = [t for t, _u in hits]
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    assert min(gaps) >= 1.0 - 1e-9, gaps
    assert max(gaps) <= 1.0 + 1e-9, gaps


def test_evidence_archive_redacts_and_exports_har():
    rec = EvidenceRecorder()
    resp = FetchResponse(
        url="https://lab.test/private", status=200,
        headers={"set-cookie": "sid=abc", "server": "lab",
                 "content-type": "text/plain"},
        text="hello")
    rec.record("https://lab.test/private", resp,
               {"method": "GET",
                "headers": {"Authorization": "Bearer top-secret",
                            "Accept": "*/*"}})
    entry = rec.entries[0]
    assert entry["request"]["headers"]["Authorization"] == "[redacted]"
    assert entry["response"]["headers"]["set-cookie"] == "[redacted]"
    assert entry["response"]["body"] == "hello"
    assert len(entry["response"]["body_sha256"]) == 64

    har = to_har(rec.entries, campaign_id="cmp_test")
    har_entry = har["log"]["entries"][0]
    assert har_entry["request"]["url"] == "https://lab.test/private"
    assert har_entry["response"]["content"]["text"] == "hello"
    assert har["log"]["creator"]["comment"] == "cmp_test"

    fake = FakeTarget(DOCKER_ROUTES)
    result = run_campaign("exposed docker console", _scope(),
                          seeds=["https://lab.test"], fetch=fake,
                          evidence=rec, sleep=lambda _s: None)
    assert result["evidence"]["entries"] >= 1
    with tempfile.TemporaryDirectory() as tmp:
        store = CampaignStore(Path(tmp))
        store.save(result)
        store.save_evidence(result["id"], rec)
        rows = store.load_evidence(result["id"])
        assert len(rows) == len(rec.entries)
        assert store.load_evidence("../../etc/passwd") == []


def test_llm_planner_validates_and_falls_back():
    graph = _graph_with_host()
    scope = _scope(allow_exploit_confirm=True)

    def llm(_prompt):
        return json.dumps({"intents": [
            {"kind": "probe", "action": "docker-api",
             "target": "https://lab.test"},
            {"kind": "probe", "action": "metasploit",
             "target": "https://lab.test"},
            {"kind": "probe", "action": "docker-api",
             "target": "https://evil.test"},
            {"kind": "impact", "action": "enumerate:docker",
             "target": "https://lab.test"},
        ]})

    intents, meta = propose_intents(llm, graph, scope, ["secrets"])
    assert [i.action for i in intents] == ["docker-api", "enumerate:docker"]
    assert intents[1].requires_approval is True
    assert meta["accepted"] == 2 and len(meta["dropped"]) == 2

    def broken(_prompt):
        raise RuntimeError("model offline")

    intents, meta = propose_intents(broken, graph, scope, ["secrets"])
    assert intents == [] and "model offline" in meta["error"]

    intents, meta = propose_intents(lambda _p: "not json", graph, scope,
                                    ["secrets"])
    assert intents == [] and "invalid JSON" in meta["error"]


def test_campaign_reports_model_rounds():
    fake = FakeTarget(DOCKER_ROUTES)
    prompts = []

    def llm(prompt):
        prompts.append(prompt)
        return json.dumps({"intents": [
            {"kind": "probe", "action": "metasploit",
             "target": "https://lab.test"}]})

    result = run_campaign("find an exposed docker console",
                          _scope(max_rounds=1), seeds=["https://lab.test"],
                          fetch=fake, llm=llm, sleep=lambda _s: None)
    assert prompts and "allowed_actions" in prompts[0]
    assert result["llm"]["enabled"] is True
    assert result["llm"]["rounds"][0]["accepted"] == 0
    assert result["llm"]["rounds"][0]["dropped"]


def test_retest_reproducible_then_fixed():
    fake = FakeTarget(DOCKER_ROUTES)
    result = run_campaign("find an exposed docker console", _scope(),
                          seeds=["https://lab.test"], fetch=fake,
                          sleep=lambda _s: None)
    docker = next(f for f in result["graph"]["findings"].values()
                  if "Docker" in f["title"])

    rec = retest_finding(result, docker["id"], fetch=fake)
    assert rec["verdict"] == "reproducible"
    assert result["retests"][-1]["verdict"] == "reproducible"

    closed = FakeTarget({"/": (200, {}, LAB_HTML),
                         "/version": (401, {}, "unauthorized")})
    rec = retest_finding(result, docker["id"], fetch=closed)
    assert rec["verdict"] == "fixed"

    def unreachable(_url, **_kw):
        raise OSError("dns failure")

    rec = retest_finding(result, docker["id"], fetch=unreachable)
    assert rec["verdict"] == "unconfirmed", rec
    assert "dns failure" in rec["reason"]

    try:
        retest_finding(result, "nope")
    except KeyError:
        pass
    else:
        raise AssertionError("unknown finding must raise")


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
def test_store_roundtrip_and_approval():
    fake = FakeTarget(DOCKER_ROUTES)
    result = run_campaign("exposed docker console", _scope(),
                          seeds=["https://lab.test"], fetch=fake,
                          sleep=lambda _s: None)
    with tempfile.TemporaryDirectory() as tmp:
        store = CampaignStore(Path(tmp))
        store.save(result)
        loaded = store.load(result["id"])
        assert loaded and loaded["id"] == result["id"]
        listed = store.list()
        assert listed and listed[0]["id"] == result["id"]
        key = "impact:enumerate:docker:https://lab.test"
        store.approve(result["id"], key)
        assert key in store.load(result["id"])["approved"]
        assert store.load("../../etc/passwd") is None
        assert store.delete(result["id"]) is True
        assert store.load(result["id"]) is None


def main():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print(f"ok   {name}")
        except Exception as exc:  # noqa: BLE001 - test harness
            failed += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
