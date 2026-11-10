"""Tier-5 orchestration plugins (100-plugin expansion, 2026-11-05).

Meta-plugins compose / dispatch / track OTHER plugins, so the
fixture pattern here is: deterministic FAKE downstream plugins
registered through the orchestration override seam
(ctx.shared["orchestration_plugins"]), exactly the seam production
code resolves first, plus shared-fixture tests (plugin_fixtures)
for the bus-driven plugins and the one real-registry execution
path (headers). Per plugin: fires on the VULN fixture, silent on
the CLEAN fixture, no crash on malformed input.

Base: built against origin/master bed5824, discover() 847 -> 857
with this tier; then merged onto master dee4763 after PR #118
landed (master 853, incl. lifecycle_orchestrator), for a final
registry of 863. These plugins are built distinct from
lifecycle_orchestrator (execution / config / sharding / tracking,
not bus scoring + live probing) and never dispatch it.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.plugins.base import Ctx, Finding, PluginResult, PluginStatus, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = ["reconftw_pipeline", "rengine_scan_engine", "osmedeus_workflow",
       "axiom_fleet_dispatch", "purpleteam_test_plan",
       "spiderfoot_osint_graph", "amass_asset_tracker",
       "trickest_workflow_templates", "bbrf_recon_store",
       "flyover_surface_summary"]

VULN = "vuln.test"
CLEAN = "clean.test"


# ---------------------------------------------------------------------------
# Fake downstream plugins + fake ctx
# ---------------------------------------------------------------------------

def _finding(pid, key, value, severity="low"):
    return Finding(plugin_id=pid, category="web", key=key, value=value,
                   source="fake-downstream", confidence=80,
                   evidence={"severity": severity})


class FakeVulnPlugin:
    """Downstream stub that always reports a high-severity issue."""
    id = "fake_vuln"
    accepts = ["domain", "url"]

    async def run(self, target, ctx):
        return PluginResult(
            plugin_id="fake_vuln", status=PluginStatus.OK,
            findings=[_finding("fake_vuln", "csp_missing",
                               f"CSP missing on {target.normalized}",
                               "high")])


class FakeCleanPlugin:
    id = "fake_clean"
    accepts = ["domain", "url"]

    async def run(self, target, ctx):
        return PluginResult(plugin_id="fake_clean",
                            status=PluginStatus.OK, findings=[])


class FakeSubdomainPlugin:
    id = "fake_subs"
    accepts = ["domain", "url"]

    async def run(self, target, ctx):
        subs = ["www.vuln.test", "dev.vuln.test"]
        return PluginResult(
            plugin_id="fake_subs", status=PluginStatus.OK,
            findings=[_finding("fake_subs", "subdomain", s)
                      for s in subs])


class FakeCtx:
    """Duck-typed Ctx: shared bus + overrides, no network."""

    def __init__(self, shared=None, overrides=None):
        self.run_id = "tier5-test"
        self.mode = "passive"
        self.http = None
        self.cache = None
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = overrides or {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = dict(shared or {})

    def publish(self, kind, item):
        bucket = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in bucket:
                bucket.append(item)
        else:
            bucket.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []) or [])


def run_plugin(pid, target, ctx):
    plugin = discover()[pid]()
    return asyncio.run(plugin.run(target, ctx))


def domain(name):
    return Target(raw=name, type="domain", normalized=name)


def url(name):
    return Target(raw=f"https://{name}/", type="url",
                  normalized=f"https://{name}/")


def vuln_ctx(shared=None, overrides=None):
    base = {"orchestration_plugins": {
        "headers": FakeVulnPlugin, "cors": FakeVulnPlugin,
        "clickjack": FakeCleanPlugin, "robots": FakeCleanPlugin,
        "tls": FakeCleanPlugin, "passive_subdomains": FakeSubdomainPlugin,
        "emails": FakeCleanPlugin, "rdap": FakeCleanPlugin,
        "apidiscover": FakeVulnPlugin, "graphql": FakeCleanPlugin,
        "dns": FakeCleanPlugin}}
    base.update(shared or {})
    return FakeCtx(shared=base, overrides=overrides)


def clean_ctx(shared=None, overrides=None):
    base = {"orchestration_plugins": {
        "headers": FakeCleanPlugin, "cors": FakeCleanPlugin,
        "clickjack": FakeCleanPlugin, "robots": FakeCleanPlugin,
        "tls": FakeCleanPlugin, "passive_subdomains": FakeCleanPlugin,
        "emails": FakeCleanPlugin, "rdap": FakeCleanPlugin,
        "apidiscover": FakeCleanPlugin, "graphql": FakeCleanPlugin,
        "dns": FakeCleanPlugin}}
    base.update(shared or {})
    return FakeCtx(shared=base, overrides=overrides)


def keys_of(res):
    return [f.key for f in res.findings]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_all_ten_registered_and_count_863():
    reg = discover()
    assert len(reg) == 1341, f"registry size {len(reg)}, expected 1341"
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_orchestration_never_dispatches_orchestrators():
    from app.plugins._orchestration import ORCHESTRATION_IDS, classify_ids
    ctx = vuln_ctx()
    groups = classify_ids(ctx, ["headers", "lifecycle_orchestrator",
                                "reconftw_pipeline", "no_such_plugin"])
    assert groups["runnable"] == ["headers"]
    assert "lifecycle_orchestrator" in groups["excluded"]
    assert "reconftw_pipeline" in groups["excluded"]
    assert groups["unknown"] == ["no_such_plugin"]


# ---------------------------------------------------------------------------
# 1. reconftw_pipeline
# ---------------------------------------------------------------------------

def test_reconftw_fires_on_vuln():
    res = run_plugin("reconftw_pipeline", domain(VULN), vuln_ctx())
    assert "pipeline_summary" in keys_of(res)
    assert "csp_missing" in keys_of(res)  # composed downstream finding
    # deduped: headers (live_hosts) + cors (vuln_checks) report the
    # same fake finding shape but with distinct plugin ids... the fake
    # uses one plugin_id, so the composed set must dedupe to one.
    assert keys_of(res).count("csp_missing") == 1


def test_reconftw_custom_stages():
    ctx = vuln_ctx({"reconftw_stages": {"only_stage": ["headers"]}})
    res = run_plugin("reconftw_pipeline", domain(VULN), ctx)
    summary = [f for f in res.findings if f.key == "pipeline_summary"][0]
    assert list(summary.evidence["stages"]) == ["only_stage"]


def test_reconftw_silent_on_clean():
    res = run_plugin("reconftw_pipeline", domain(CLEAN), clean_ctx())
    assert res.findings == []


def test_reconftw_malformed_no_crash():
    res = run_plugin("reconftw_pipeline", domain(""), vuln_ctx())
    assert res.findings == []
    ctx = vuln_ctx({"reconftw_stages": {"bad": "not-a-list",
                                        "ok": ["headers"]}})
    res = run_plugin("reconftw_pipeline", domain(VULN), ctx)
    assert "pipeline_summary" in keys_of(res)


def test_reconftw_real_headers_on_shared_fixture():
    import plugin_fixtures as fx

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        ctx.shared["reconftw_stages"] = {"live_hosts": ["headers"]}
        try:
            return await discover()["reconftw_pipeline"]().run(
                fx.url_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    assert "pipeline_summary" in keys_of(res)
    assert len(res.findings) > 2  # headers fires hard on the fixture


# ---------------------------------------------------------------------------
# 2. rengine_scan_engine
# ---------------------------------------------------------------------------

ENGINE_YAML = """# light engine
name: fixture-engine
intensity: light
checks:
  - headers
  - no_such_check_xyz
  - lifecycle_orchestrator
"""


def test_rengine_fires_on_vuln_with_yaml_config():
    ctx = vuln_ctx({"rengine_config": ENGINE_YAML})
    res = run_plugin("rengine_scan_engine", domain(VULN), ctx)
    assert "engine_compliance" in keys_of(res)
    assert "engine_unknown_check" in keys_of(res)
    assert "engine_excluded_check" in keys_of(res)
    assert "csp_missing" in keys_of(res)
    comp = [f for f in res.findings if f.key == "engine_compliance"][0]
    assert comp.evidence["runnable"] == ["headers"]
    assert comp.evidence["unknown"] == ["no_such_check_xyz"]


def test_rengine_json_config():
    ctx = vuln_ctx({"rengine_config":
                    '{"name": "j", "checks": ["headers"]}'})
    res = run_plugin("rengine_scan_engine", domain(VULN), ctx)
    assert "engine_compliance" in keys_of(res)


def test_rengine_silent_on_clean_default_engine():
    res = run_plugin("rengine_scan_engine", domain(CLEAN), clean_ctx())
    assert res.findings == []


def test_rengine_malformed_no_crash():
    ctx = vuln_ctx({"rengine_config": "{{{ not a config"})
    res = run_plugin("rengine_scan_engine", domain(VULN), ctx)
    assert res.findings == []
    res = run_plugin("rengine_scan_engine", domain(""), vuln_ctx())
    assert res.findings == []


def test_engine_config_parser_stages():
    from app.plugins._orchestration import engine_check_ids, \
        parse_engine_config
    cfg, err = parse_engine_config(
        "name: x\nstages:\n  discovery:\n    - passive_subdomains\n"
        "  checks:\n    - headers\n")
    assert not err
    assert engine_check_ids(cfg) == ["passive_subdomains", "headers"]


# ---------------------------------------------------------------------------
# 3. osmedeus_workflow
# ---------------------------------------------------------------------------

def test_osmedeus_fires_on_vuln():
    res = run_plugin("osmedeus_workflow", domain(VULN), vuln_ctx())
    assert "workflow_run" in keys_of(res)
    run_f = [f for f in res.findings if f.key == "workflow_run"][0]
    assert run_f.evidence["workflow"] == "quick-recon"


def test_osmedeus_named_workflow_with_params():
    ctx = vuln_ctx({"osmedeus_workflow": {
        "name": "web-baseline",
        "params": {"tls": {"skip": True}}}})
    res = run_plugin("osmedeus_workflow", domain(VULN), ctx)
    run_f = [f for f in res.findings if f.key == "workflow_run"][0]
    tls_step = [s for s in run_f.evidence["steps"]
                if s["step"] == "tls"][0]
    assert tls_step["status"] == "skipped-param"


def test_osmedeus_silent_on_clean():
    res = run_plugin("osmedeus_workflow", domain(CLEAN), clean_ctx())
    assert res.findings == []


def test_osmedeus_malformed_no_crash():
    ctx = vuln_ctx({"osmedeus_workflow": "no-such-workflow"})
    res = run_plugin("osmedeus_workflow", domain(VULN), ctx)
    assert res.findings == []
    res = run_plugin("osmedeus_workflow", domain(""), vuln_ctx())
    assert res.findings == []


# ---------------------------------------------------------------------------
# 4. axiom_fleet_dispatch
# ---------------------------------------------------------------------------

def test_axiom_shard_plan_and_validation():
    from app.plugins.axiom_fleet import build_shards, validate_shards
    shards = build_shards(["b.test", "a.test", "c.test", "a.test"],
                          [80, 443], 2)
    validation = validate_shards(shards, ["a.test", "b.test", "c.test"])
    assert validation["complete"] and validation["no_duplicates"]
    assert validation["targets_assigned"] == 3


def test_axiom_fires_on_multi_target():
    ctx = vuln_ctx({"axiom_targets": ["a.vuln.test", "b.vuln.test",
                                      "c.vuln.test"],
                    "axiom_workers": 2})
    res = run_plugin("axiom_fleet_dispatch", domain(VULN), ctx)
    plans = [f for f in res.findings if f.key == "fleet_shard_plan"]
    assert len(plans) == 2
    assert plans[0].evidence["validation"]["complete"]


def test_axiom_merge_dedupes_shard_results():
    ctx = vuln_ctx({"axiom_shard_results": [
        {"key": "open_port", "value": "a.vuln.test:22"},
        {"key": "open_port", "value": "a.vuln.test:22"},
        {"key": "open_port", "value": "b.vuln.test:443"}]})
    res = run_plugin("axiom_fleet_dispatch", domain(VULN), ctx)
    assert "fleet_merge_summary" in keys_of(res)
    assert keys_of(res).count("fleet_merged_finding") == 2


def test_axiom_silent_on_single_clean_target():
    res = run_plugin("axiom_fleet_dispatch", domain(CLEAN), clean_ctx())
    assert res.findings == []


def test_axiom_malformed_no_crash():
    ctx = vuln_ctx({"axiom_ports": "not-a-range",
                    "axiom_workers": "lots",
                    "axiom_targets": [123, None, ""]})
    res = run_plugin("axiom_fleet_dispatch", domain(VULN), ctx)
    assert isinstance(res.findings, list)


# ---------------------------------------------------------------------------
# 5. purpleteam_test_plan
# ---------------------------------------------------------------------------

def test_purpleteam_fires_and_grades_fail():
    res = run_plugin("purpleteam_test_plan", domain(VULN), vuln_ctx())
    assert "purpleteam_posture_report" in keys_of(res)
    report = [f for f in res.findings
              if f.key == "purpleteam_posture_report"][0]
    # headers (frontend) and cors (api) fakes report high severity.
    assert report.evidence["posture"]["frontend"]["grade"] == "fail"
    assert report.evidence["posture"]["api"]["grade"] == "fail"
    assert report.evidence["posture"]["infra"]["grade"] == "pass"


def test_purpleteam_silent_on_clean():
    res = run_plugin("purpleteam_test_plan", domain(CLEAN), clean_ctx())
    assert res.findings == []


def test_purpleteam_malformed_no_crash():
    ctx = vuln_ctx({"purpleteam_plan": {"layer1": "not-a-list",
                                        "ok": ["headers"]}})
    res = run_plugin("purpleteam_test_plan", domain(VULN), ctx)
    assert "purpleteam_posture_report" in keys_of(res)
    res = run_plugin("purpleteam_test_plan", domain(""), vuln_ctx())
    assert res.findings == []


# ---------------------------------------------------------------------------
# 6. spiderfoot_osint_graph
# ---------------------------------------------------------------------------

def _spider_ctx(clean=False):
    ctx = (clean_ctx if clean else vuln_ctx)()
    ctx.shared["spiderfoot_facts"] = {} if clean else {
        "ips": ["192.0.2.10"],
        "certs": [{"names": ["www.vuln.test"],
                   "issuer": "Fixture CA", "org": "Fixture Corp"}],
        "org": "Fixture Corp"}
    if not clean:
        ctx.publish("emails", "admin@vuln.test")
    return ctx


def test_spiderfoot_fires_with_correlations():
    res = run_plugin("spiderfoot_osint_graph", domain(VULN),
                     _spider_ctx())
    assert "osint_entity_graph" in keys_of(res)
    rels = {(f.evidence["from"], f.evidence["rel"], f.evidence["to"])
            for f in res.findings if f.key == "osint_correlation_edge"}
    assert ("vuln.test", "resolves_to", "192.0.2.10") in rels
    assert ("vuln.test", "operated_by", "Fixture Corp") in rels
    assert ("vuln.test", "cert_covers", "www.vuln.test") in rels


def test_spiderfoot_silent_on_clean():
    res = run_plugin("spiderfoot_osint_graph", domain(CLEAN),
                     _spider_ctx(clean=True))
    assert res.findings == []


def test_spiderfoot_malformed_no_crash():
    ctx = _spider_ctx()
    ctx.shared["spiderfoot_facts"] = {"ips": "not-a-list", "certs": [42]}
    res = run_plugin("spiderfoot_osint_graph", domain(VULN), ctx)
    assert isinstance(res.findings, list)
    res = run_plugin("spiderfoot_osint_graph", domain(""), _spider_ctx())
    assert res.findings == []


# ---------------------------------------------------------------------------
# 7. amass_asset_tracker
# ---------------------------------------------------------------------------

def test_amass_tracker_reports_diff():
    ctx = vuln_ctx({"amass_previous_snapshot": {
        "subdomains": ["www.vuln.test", "api.vuln.test"],
        "ips": ["192.0.2.10"]}})
    res = run_plugin("amass_asset_tracker", domain(VULN), ctx)
    assert "asset_change_summary" in keys_of(res)
    added = [f for f in res.findings if f.key == "asset_added"]
    removed = [f for f in res.findings if f.key == "asset_removed"]
    assert any("dev.vuln.test" in f.value for f in added)
    assert any("api.vuln.test" in f.value for f in removed)
    assert any("192.0.2.10" in f.value for f in removed)


def test_amass_tracker_silent_when_unchanged():
    ctx = vuln_ctx({"amass_previous_snapshot": {
        "subdomains": ["www.vuln.test", "dev.vuln.test"], "ips": []},
        "amass_tracker_modules": []})
    # fresh bus matches the snapshot exactly: no downstream modules
    # configured via override seam to a clean stub returning the same.
    ctx.shared["orchestration_plugins"] = {
        "passive_subdomains": FakeCleanPlugin}
    ctx.shared["amass_tracker_modules"] = ["passive_subdomains"]
    ctx.publish("subdomains", "www.vuln.test")
    ctx.publish("subdomains", "dev.vuln.test")
    res = run_plugin("amass_asset_tracker", domain(VULN), ctx)
    assert res.findings == []


def test_amass_tracker_no_snapshot_is_silent():
    res = run_plugin("amass_asset_tracker", domain(VULN), vuln_ctx())
    assert res.findings == []


def test_amass_tracker_malformed_no_crash():
    ctx = vuln_ctx({"amass_previous_snapshot": "not-a-dict"})
    res = run_plugin("amass_asset_tracker", domain(VULN), ctx)
    assert res.findings == []
    ctx = vuln_ctx({"amass_previous_snapshot": {"other": [1, 2]}})
    res = run_plugin("amass_asset_tracker", domain(VULN), ctx)
    assert res.findings == []


# ---------------------------------------------------------------------------
# 8. trickest_workflow_templates
# ---------------------------------------------------------------------------

def test_trickest_expands_valid_template():
    ctx = vuln_ctx({"trickest_template": {
        "name": "new-domain-onboarding",
        "params": {"domain": "vuln.test"}}})
    res = run_plugin("trickest_workflow_templates", domain(VULN), ctx)
    assert "workflow_template_expansion" in keys_of(res)
    plan = res.findings[0].evidence["plan"]
    assert [s["plugin"] for s in plan["steps"]][:2] == [
        "passive_subdomains", "dns"]


def test_trickest_validation_fires_on_bad_params():
    ctx = vuln_ctx({"trickest_template": {
        "name": "new-domain-onboarding",
        "params": {"domain": "not a domain!!"}}})
    # target is an IP so no domain can be auto-filled over the bad one
    res = run_plugin("trickest_workflow_templates",
                     Target(raw="192.0.2.1", type="ip",
                            normalized="192.0.2.1"), ctx)
    assert "template_validation_error" in keys_of(res)


def test_trickest_silent_when_not_invoked():
    res = run_plugin("trickest_workflow_templates", domain(CLEAN),
                     clean_ctx())
    assert res.findings == []


def test_trickest_malformed_no_crash():
    ctx = vuln_ctx({"trickest_template": {"name": "nope"}})
    res = run_plugin("trickest_workflow_templates", domain(VULN), ctx)
    assert res.findings == []
    ctx = vuln_ctx({"trickest_template": 42})
    res = run_plugin("trickest_workflow_templates", domain(VULN), ctx)
    assert res.findings == []


# ---------------------------------------------------------------------------
# 9. bbrf_recon_store
# ---------------------------------------------------------------------------

def _bbrf_ctx(clean=False):
    ctx = (clean_ctx if clean else vuln_ctx)()
    if not clean:
        ctx.publish("subdomains", "www.vuln.test")
        ctx.publish("subdomains", "api.vuln.test")
        ctx.publish("endpoints", "https://vuln.test/api/v1/users")
    return ctx


def test_bbrf_stores_and_summarises():
    ctx = _bbrf_ctx()
    res = run_plugin("bbrf_recon_store", domain(VULN), ctx)
    assert "bbrf_store_summary" in keys_of(res)
    store = ctx.shared["bbrf_store"]
    program = store["programs"]["vuln.test"]
    assert "api.vuln.test" in program["domains"]
    assert "https://vuln.test/api/v1/users" in program["urls"]


def test_bbrf_query_back():
    ctx = _bbrf_ctx()
    run_plugin("bbrf_recon_store", domain(VULN), ctx)
    ctx.shared["bbrf_query"] = {"kind": "domains", "contains": "api."}
    res = run_plugin("bbrf_recon_store", domain(VULN), ctx)
    hits = [f for f in res.findings if f.key == "bbrf_query_hit"]
    assert len(hits) == 1 and "api.vuln.test" in hits[0].value


def test_bbrf_silent_on_clean_empty_bus():
    res = run_plugin("bbrf_recon_store", domain(CLEAN), _bbrf_ctx(True))
    assert res.findings == []


def test_bbrf_malformed_no_crash():
    ctx = _bbrf_ctx()
    ctx.shared["bbrf_store"] = "not-a-dict"
    res = run_plugin("bbrf_recon_store",
                     Target(raw="192.0.2.1", type="ip",
                            normalized="192.0.2.1"), ctx)
    assert res.findings == []


def test_bbrf_shared_fixture():
    import plugin_fixtures as fx

    async def _go():
        ctx = fx.make_fixture_ctx(seed=True)
        try:
            return await discover()["bbrf_recon_store"]().run(
                fx.domain_target(), ctx), ctx
        finally:
            await ctx.http.aclose()
    res, ctx = asyncio.run(_go())
    assert "bbrf_store_summary" in keys_of(res)
    program = ctx.shared["bbrf_store"]["programs"]["fixture.test"]
    assert "api.fixture.test" in program["domains"]


# ---------------------------------------------------------------------------
# 10. flyover_surface_summary
# ---------------------------------------------------------------------------

def _flyover_ctx(clean=False, previous=None):
    ctx = (clean_ctx if clean else vuln_ctx)()
    if not clean:
        for sub in ("www.vuln.test", "api.vuln.test"):
            ctx.publish("subdomains", sub)
        ctx.publish("endpoints", "https://vuln.test/admin/")
        ctx.publish("endpoints", "https://vuln.test/api/v1/users")
        ctx.publish("tech", "wordpress 6.4.2")
    if previous is not None:
        ctx.shared["flyover_previous_counts"] = previous
    return ctx


def test_flyover_fires_with_ranked_exposure():
    res = run_plugin("flyover_surface_summary", domain(VULN),
                     _flyover_ctx())
    assert "flyover_summary" in keys_of(res)
    tops = [f for f in res.findings if f.key == "top_exposure"]
    assert tops and "/admin/" in tops[0].value


def test_flyover_change_finding():
    ctx = _flyover_ctx(previous={"subdomains": 1, "endpoints": 2,
                                 "tech": 1})
    res = run_plugin("flyover_surface_summary", domain(VULN), ctx)
    assert "surface_change" in keys_of(res)


def test_flyover_silent_on_clean():
    res = run_plugin("flyover_surface_summary", domain(CLEAN),
                     _flyover_ctx(clean=True))
    assert res.findings == []


def test_flyover_malformed_no_crash():
    ctx = _flyover_ctx()
    ctx.shared["flyover_previous_counts"] = {"subdomains": "lots"}
    res = run_plugin("flyover_surface_summary", domain(VULN), ctx)
    assert "flyover_summary" in keys_of(res)
    res = run_plugin("flyover_surface_summary", domain(""),
                     _flyover_ctx())
    assert res.findings == []


def test_flyover_shared_fixture():
    import plugin_fixtures as fx

    async def _go():
        ctx = fx.make_fixture_ctx(seed=True)
        try:
            return await discover()["flyover_surface_summary"]().run(
                fx.domain_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    assert "flyover_summary" in keys_of(res)
