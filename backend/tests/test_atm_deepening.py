"""ATM deepening tests (plugin atm) - all inside the authorization gate.

Gate: without module_overrides atm=authorized (or an atm source type)
the plugin skips and probes nothing. Authorized: audit claim finding,
canonical vendor fingerprinting feeding the verified CVE matcher
(incl. the APTRA -> NCR mapping the old substring code missed), mgmt
interface observations. Healthy case: authorized but a plain site ->
only the audit claim + clean-footprint findings.
"""
import asyncio

from app.plugins.atm import AtmPlugin
from app.plugins.base import Target
from plugin_fixtures import make_fixture_ctx, url_target


def _auth_ctx(mode="passive"):
    ctx = make_fixture_ctx(mode=mode)
    ctx.module_overrides = {"atm": "authorized"}
    ctx.source_type = "atm"
    return ctx


def _run(plugin, target, ctx):
    return asyncio.run(plugin.run(target, ctx))


def test_gate_skips_without_authorization():
    plugin = AtmPlugin()
    ctx = make_fixture_ctx(mode="passive")  # website source, no override
    res = _run(plugin, url_target(), ctx)
    assert res.findings == []
    assert "not authorized" in (res.reason or "")


def test_authorized_run_records_audit_claim_and_clean_result():
    plugin = AtmPlugin()
    res = _run(plugin, url_target(), _auth_ctx())
    keys = [f.key for f in res.findings]
    assert keys[0] == "atm_authorization"
    # plain fixture site: no vendor, no CVEs, no mgmt surface. (The
    # sandbox resolver answers every name, so atm_subdomain observations
    # may appear - they are not vendor/CVE claims and are not asserted
    # against here.)
    assert "atm_vendor" not in keys
    assert "atm_cve" not in keys
    assert "atm_mgmt_interface" not in keys


def test_authorized_run_on_atm_portal_fixture():
    plugin = AtmPlugin()
    target = Target(type="url", raw="http://atm.fixture.test/",
                    normalized="http://atm.fixture.test/")
    res = _run(plugin, target, _auth_ctx())
    by_key = {}
    for f in res.findings:
        by_key.setdefault(f.key, []).append(f)
    assert "atm_authorization" in by_key
    vendors = {f.evidence.get("vendor")
               for f in by_key.get("atm_vendor", [])}
    assert "diebold" in vendors and "ncr" in vendors
    cve_ids = {f.value.split(":")[0] for f in by_key.get("atm_cve", [])}
    assert "CVE-2018-9094" in cve_ids          # Diebold
    assert "CVE-2020-10124" in cve_ids         # NCR via the APTRA hint
    assert any("/aptra" in f.value
               for f in by_key.get("atm_mgmt_interface", []))


def test_cve_matcher_uses_published_vendors_and_word_boundaries():
    plugin = AtmPlugin()
    ctx = make_fixture_ctx(mode="passive")
    ctx.publish("atm_vendors", "ncr")
    ids = {f.value.split(":")[0] for f in plugin._match_cves(ctx)}
    assert ids == {"CVE-2020-10124", "CVE-2020-10147", "CVE-2020-10123"}
    # Fallback scan: an APTRA mention maps to NCR...
    ctx2 = make_fixture_ctx(mode="passive")
    ctx2.publish("tech", "APTRA XFS terminal software")
    ids2 = {f.value.split(":")[0] for f in plugin._match_cves(ctx2)}
    assert "CVE-2020-10124" in ids2
    # ...but "ncr" inside another word must NOT match.
    ctx3 = make_fixture_ctx(mode="passive")
    ctx3.publish("tech", "encryption appliance")
    assert plugin._match_cves(ctx3) == []
