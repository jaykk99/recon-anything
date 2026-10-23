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
    # DB isolation (fixed 2026-10-23): app.models binds its engine ONCE
    # at import time from DATABASE_URL. Standalone, this module is
    # imported first, so the engine is this module's throwaway DB and
    # all 34 tests pass. In a full-suite run, an earlier-collected
    # module imports app.models first (binding the shared default DB),
    # the env assignment above becomes a no-op, and these tests run
    # against a database full of foreign + leftover rows: known-set
    # adds collide on unique keys (IntegrityError), counts include
    # other modules' assets, and 16 tests fail. Rebind the engine to
    # this module's own DB for the module's tests and restore the
    # original binding afterwards, so the module behaves exactly as it
    # does standalone without disturbing any other module.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    orig_engine = models.engine
    orig_sessionlocal = models.SessionLocal
    orig_url = str(orig_engine.url)
    want_url = f"sqlite:///{_TMPDB}"
    if orig_url != want_url:
        new_engine = create_engine(
            want_url, connect_args={"check_same_thread": False},
            pool_pre_ping=True)
        models.engine = new_engine
        models.SessionLocal = sessionmaker(
            bind=new_engine, autoflush=False, autocommit=False)
    else:
        new_engine = None
    models.init_db()
    yield
    if new_engine is not None:
        models.engine = orig_engine
        models.SessionLocal = orig_sessionlocal
        new_engine.dispose()


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

def test_hunters_defined():
    assert len(HUNTERS) == 23
    names = [h["name"] for h in HUNTERS]
    assert len(set(names)) == 23
    for expected in ("neighbor_hunter", "passive_dns_hunter",
                     "rapiddns_hunter"):
        assert expected in names
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
# Canonicalization: one node, one asset, however it was spelled
# ---------------------------------------------------------------------------

def test_extract_canonicalizes_duplicate_spellings():
    target = TargetRow(id="t1", run_id="r-x", raw="Example.COM.",
                       type="domain", normalized="Example.COM.")
    findings = [
        _finding("subdomain", "API.Example.com."),
        _finding("subdomain", "api.example.com"),
        _finding("a", "2606:4700:0:0:0:0:6813:DF11"),
        _finding("aaaa", "2606:4700::6813:df11"),
        _finding("endpoint", "https://EXAMPLE.com:443/api/v1/#frag",
                 plugin="apidiscover", category="api"),
        _finding("endpoint", "https://example.com/api/v1",
                 plugin="apidiscover", category="api"),
    ]
    assets = engine.extract_assets(findings, [target])
    pairs = [(a["type"], a["value"]) for a in assets]
    assert pairs.count(("subdomain", "api.example.com")) == 1
    assert sum(1 for t, v in pairs if t == "ip") == 1
    assert ("ip", "2606:4700::6813:df11") in pairs
    assert sum(1 for t, v in pairs if t == "endpoint") == 1
    assert ("endpoint", "https://example.com/api/v1") in pairs


def test_extract_mx_ns_cname_and_archive_keys():
    target = TargetRow(id="t1", run_id="r-x", raw="pivots.test",
                       type="domain", normalized="pivots.test")
    findings = [
        _finding("mx", "10 mail.pivots.test."),
        _finding("ns", "ns1.otherdns.test."),
        _finding("cname", "pivots.test.hosting.test."),
        _finding("archived_url", "https://pivots.test/old-login",
                 plugin="gau", category="web"),
        _finding("graphql_endpoint", "https://pivots.test/graphql",
                 plugin="graphql", category="api"),
        _finding("passive_ip", "198.51.100.23", plugin="passive_dns"),
        _finding("cohosted_domain", "sibling.test",
                 plugin="reverse_ip", category="graph"),
    ]
    pairs = {(a["type"], a["value"])
             for a in engine.extract_assets(findings, [target])}
    assert ("domain", "mail.pivots.test") in pairs
    assert ("domain", "ns1.otherdns.test") in pairs
    assert ("subdomain", "pivots.test.hosting.test") in pairs
    assert ("url", "https://pivots.test/old-login") in pairs
    assert ("endpoint", "https://pivots.test/graphql") in pairs
    assert ("ip", "198.51.100.23") in pairs
    assert ("domain", "sibling.test") in pairs


def test_extract_cross_root_san_promoted_to_domain():
    target = TargetRow(id="t1", run_id="r-x", raw="main.test",
                       type="domain", normalized="main.test")
    findings = [
        _finding("tls_san", "www.main.test", plugin="tls"),
        _finding("tls_san", "sibling-other.test", plugin="tls"),
    ]
    assets = engine.extract_assets(findings, [target])
    by_value = {a["value"]: a for a in assets}
    assert by_value["www.main.test"]["type"] == "subdomain"
    assert by_value["sibling-other.test"]["type"] == "domain"
    assert by_value["sibling-other.test"]["found_by"] == "neighbor_hunter"


# ---------------------------------------------------------------------------
# Compounding: the persisted known set re-seeds the next run
# ---------------------------------------------------------------------------

def test_known_set_reseeds_next_run(session):
    run1 = _mk_run(session, "run-reseed-1", "reseed.test")
    r = _finding("subdomain", "api.reseed.test")
    r.run_id = "run-reseed-1"
    session.add(r)
    session.commit()
    a1 = engine.new_accum()
    assert engine.hunter_expand(session, run1, a1) > 0
    # second run, NO new findings at all: the persisted known set
    # alone must produce re-verification jobs for the known node
    run2 = _mk_run(session, "run-reseed-2", "reseed.test")
    a2 = engine.new_accum()
    enqueued = engine.hunter_expand(session, run2, a2)
    assert enqueued > 0
    assert a2["tasks_reexpand"] > 0
    jobs = session.query(PluginJob).filter_by(run_id="run-reseed-2").all()
    targets = {t.id: t for t in
               session.query(TargetRow).filter_by(
                   run_id="run-reseed-2").all()}
    assert any(targets[j.target_id].normalized == "api.reseed.test"
               for j in jobs)


def test_reseed_respects_reexpand_budget(session, monkeypatch):
    run1 = _mk_run(session, "run-reseed-b1", "rbudget.test")
    r = _finding("subdomain", "api.rbudget.test")
    r.run_id = "run-reseed-b1"
    session.add(r)
    session.commit()
    engine.hunter_expand(session, run1, engine.new_accum())
    monkeypatch.setattr(engine, "REEXPAND_FRACTION", 0.0)
    run2 = _mk_run(session, "run-reseed-b2", "rbudget.test")
    a2 = engine.new_accum()
    engine.hunter_expand(session, run2, a2)
    # with a zero re-expansion share, NO job may target the known
    # node (the seed target's own depth-0 expansion is unaffected)
    assert a2["tasks_reexpand"] == 0
    jobs = session.query(PluginJob).filter_by(run_id="run-reseed-b2").all()
    targets = {t.id: t for t in
               session.query(TargetRow).filter_by(
                   run_id="run-reseed-b2").all()}
    assert jobs and all(
        targets[j.target_id].normalized == "rbudget.test" for j in jobs)


def test_frontier_prioritizes_new_surface_over_identity(session,
                                                        monkeypatch):
    monkeypatch.setattr(engine, "MAX_TASKS", 3)
    run = Run(id="run-prio-1", mode="passive", status="running",
              source_type="website", summary={})
    session.add(run)
    session.add(TargetRow(id="run-prio-1-t", run_id="run-prio-1",
                          raw="owner@prio.test", type="email",
                          normalized="owner@prio.test"))
    r = _finding("a", "203.0.113.7")
    r.run_id = "run-prio-1"
    session.add(r)
    session.commit()
    accum = engine.new_accum()
    engine.hunter_expand(session, run, accum)
    jobs = session.query(PluginJob).filter_by(run_id="run-prio-1").all()
    assert jobs
    targets = {t.id: t for t in
               session.query(TargetRow).filter_by(
                   run_id="run-prio-1").all()}
    # the whole (tiny) budget went to the new IP node, none to the
    # seed email's own expansion rules
    assert all(targets[j.target_id].normalized == "203.0.113.7"
               for j in jobs)


def test_dead_end_ttl_expires(session):
    store.add_dead_end(session, "recon", "ttl.test", "subdomain",
                       "old.ttl.test", run_id="r0", reason="nothing")
    assert "old.ttl.test" in store.dead_end_values(
        session, "recon", "ttl.test")
    # backdate the entry 30 days: past the 7-day TTL it no longer
    # blocks re-hunting
    from app.models import HuntMemory
    row = (session.query(HuntMemory)
           .filter_by(system="recon", target_key="ttl.test").first())
    import datetime as _dt
    stale = (_dt.datetime.now(_dt.timezone.utc)
             - _dt.timedelta(days=30)).isoformat()
    row.dead_ends = [dict(d, at=stale) for d in row.dead_ends]
    session.commit()
    assert "old.ttl.test" not in store.dead_end_values(
        session, "recon", "ttl.test")


# ---------------------------------------------------------------------------
# Finding-driven chaining
# ---------------------------------------------------------------------------

def test_chaining_wordpress_finding_queues_cms_plugins(session):
    run = _mk_run(session, "run-chain-1", "chain.test")
    tid = "run-chain-1-t"
    f = _finding("tech", "WordPress 6.4.2", plugin="webtech",
                 category="web")
    f.run_id = "run-chain-1"
    f.target_id = tid
    session.add(f)
    session.commit()
    accum = engine.new_accum()
    engine.hunter_expand(session, run, accum)
    assert accum["chained_jobs"] >= 2
    jobs = session.query(PluginJob).filter_by(
        run_id="run-chain-1", target_id=tid).all()
    chained = {j.plugin_id for j in jobs} & {"cms_probes", "cves"}
    assert chained == {"cms_probes", "cves"}
    from app.models import HuntAction
    actions = (session.query(HuntAction)
               .filter_by(run_id="run-chain-1",
                          hunter="chain_engine").all())
    assert actions and all(a.action == "job_enqueued" for a in actions)


def test_chaining_findingless_target_queues_nothing(session):
    run = _mk_run(session, "run-chain-2", "plain.test")
    accum = engine.new_accum()
    engine.hunter_expand(session, run, accum)
    assert accum["chained_jobs"] == 0
    from app.models import HuntAction
    assert (session.query(HuntAction)
            .filter_by(run_id="run-chain-2",
                       hunter="chain_engine").count()) == 0


def test_chaining_graphql_and_jwt(session):
    from app.hunters.chaining import plan_chains
    target = TargetRow(id="tt", run_id="r-x", raw="api.test",
                       type="domain", normalized="api.test")
    f1 = _finding("graphql_endpoint", "https://api.test/graphql",
                  plugin="graphql", category="api")
    f1.target_id = "tt"
    f2 = _finding("jwt_header", "alg none", plugin="jwt", category="api")
    f2.target_id = "tt"
    plan, hot, signals = plan_chains([f1, f2], [target])
    assert "graphql" in plan["tt"] and "jwt" in plan["tt"]
    assert "graphql" in signals["tt"]


# ---------------------------------------------------------------------------
# New hunter source plugins: parsers (network-free)
# ---------------------------------------------------------------------------

def test_new_plugins_registered():
    from app.plugins.registry import discover
    reg = discover()
    for pid in ("reverse_ip", "passive_dns", "rapiddns"):
        assert pid in reg
        assert reg[pid]().passive is True


def test_reverse_ip_parsers():
    from app.plugins.reverse_ip import (parse_hackertarget_reverse,
                                        parse_otx_ip_passive,
                                        parse_rapiddns_sameip)
    assert parse_hackertarget_reverse(
        "a.example.com\nb.example.org\nerror invalid\n") == {
        "a.example.com", "b.example.org"}
    assert parse_otx_ip_passive({"passive_dns": [
        {"hostname": "mail.example.com"},
        {"hostname": "bad host!"},
        {"hostname": "x.example.net"}]}) == {
        "mail.example.com", "x.example.net"}
    html = ('<a href="https://rapiddns.io/subdomain/shop.example.com">x</a>'
            "<td>api.example.com</td><td>rapiddns.io</td>")
    assert parse_rapiddns_sameip(html) == {
        "shop.example.com", "api.example.com"}


def test_passive_dns_parsers():
    from app.plugins.passive_dns import (parse_otx_domain_passive,
                                         parse_threatcrowd_domain)
    out = parse_otx_domain_passive({"passive_dns": [
        {"hostname": "www.example.com", "address": "192.0.2.5",
         "record_type": "A"},
        {"hostname": "old.example.com", "address": "192.0.2.9",
         "record_type": "A"},
        {"hostname": "example.com", "address": "cdn.hosting.net",
         "record_type": "CNAME"},
        {"hostname": "v6.example.com", "address": "2001:db8:0:0:0:0:0:1",
         "record_type": "AAAA"}]}, "example.com")
    assert "192.0.2.5" in out["ips"] and "2001:db8::1" in out["ips"]
    assert out["hosts"] == ["old.example.com", "v6.example.com",
                            "www.example.com"]
    assert out["cname_targets"] == ["cdn.hosting.net"]
    tc = parse_threatcrowd_domain({
        "resolutions": [{"ip_address": "198.51.100.7"}],
        "subdomains": ["mail.example.com"]})
    assert tc["ips"] == ["198.51.100.7"]
    assert tc["hosts"] == ["mail.example.com"]


def test_rapiddns_parser():
    from app.plugins.rapiddns import parse_rapiddns_subdomains
    html = ("<td>api.example.com</td> <td>WWW.Example.COM.</td> "
            "junk other.org example.com <td>dev.example.com</td>")
    assert parse_rapiddns_subdomains(html, "example.com") == [
        "api.example.com", "dev.example.com", "www.example.com"]


# ---------------------------------------------------------------------------
# Agent activity feed: order, attribution, plain language
# ---------------------------------------------------------------------------

def test_agent_activity_feed(session):
    run = _mk_run(session, "run-feed-1", "feed.test")
    r = _finding("subdomain", "api.feed.test")
    r.run_id = "run-feed-1"
    session.add(r)
    session.commit()
    engine.hunter_expand(session, run, engine.new_accum())
    data = store.run_agent_activity(session, "recon", "run-feed-1")
    assert data["run_id"] == "run-feed-1"
    assert data["total_actions"] > 0
    ids = [a["id"] for a in data["actions"]]
    assert ids == sorted(ids)  # chronological order
    found = [a for a in data["actions"] if a["action"] == "asset_found"]
    api_found = [a for a in found if "api.feed.test" in a["description"]]
    assert api_found and api_found[0]["agent"] == "subdomain_hunter"
    rollup = {a["name"]: a for a in data["agents"]}
    assert rollup["subdomain_hunter"]["assets_found"] >= 1
    assert rollup["subdomain_hunter"]["jobs_enqueued"] >= 1
    assert rollup["subdomain_hunter"]["status"] in (
        "working", "done", "idle", "abandoned")


def test_agent_activity_endpoint(client, session):
    run = _mk_run(session, "run-feed-2", "feed2.test")
    r = _finding("subdomain", "api.feed2.test")
    r.run_id = "run-feed-2"
    session.add(r)
    session.commit()
    engine.hunter_expand(session, run, engine.new_accum())
    resp = client.get("/api/runs/run-feed-2/agent-activity")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_actions"] > 0 and body["agents"]
    assert all("description" in a for a in body["actions"])
    missing = client.get("/api/runs/no-such-run/agent-activity")
    assert missing.status_code == 404


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
    assert data["count"] == 23
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
