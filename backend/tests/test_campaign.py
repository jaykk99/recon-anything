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
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.campaign import (  # noqa: E402
    Attempt, CampaignStore, Graph, Scope, goals_for, next_intents, render,
    resume_campaign, run_campaign,
)
from app.campaign.graph import import_findings  # noqa: E402
from app.campaign.models import finding  # noqa: E402
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
