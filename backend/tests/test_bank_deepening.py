"""Bank deepening tests (plugin bank) - inside the authorization gate.

Gate: without module_overrides bank=authorized (or a bank source type)
the plugin skips. Authorized: audit claim, platform fingerprinting,
structured login-posture evidence, mobile/API host surface, header
audit - and NO CVE from the letters "f5" appearing inside a hex token
(the old substring matcher fired on exactly that).
Healthy case: authorized run on a plain non-bank site: authorization
recorded, no platform/CVE/mobile findings.
"""
import asyncio

from app.plugins.bank import BankPlugin
from app.plugins.base import Target
from plugin_fixtures import make_fixture_ctx, url_target


def _auth_ctx(mode="passive"):
    ctx = make_fixture_ctx(mode=mode)
    ctx.module_overrides = {"bank": "authorized"}
    ctx.source_type = "bank"
    return ctx


def test_gate_skips_without_authorization():
    ctx = make_fixture_ctx(mode="passive")
    res = asyncio.run(BankPlugin().run(url_target(), ctx))
    assert res.findings == []
    assert "not authorized" in (res.reason or "")


def test_authorized_bank_fixture_findings():
    target = Target(type="url", raw="http://bank.fixture.test/",
                    normalized="http://bank.fixture.test/")
    res = asyncio.run(BankPlugin().run(target, _auth_ctx()))
    by_key = {}
    for f in res.findings:
        by_key.setdefault(f.key, []).append(f)
    assert res.findings[0].key == "bank_authorization"
    assert any("Fiserv" in f.value
               for f in by_key.get("bank_platform", []))
    posture = by_key["bank_login_posture"][0]
    assert posture.evidence["login_forms"] == 1
    assert posture.evidence["mfa_hints"] == 0
    assert posture.evidence["password_autocomplete_off"] is False
    assert posture.evidence["cookies_seen"] == 1
    assert posture.evidence["cookie_httponly"] == "0/1"
    hosts = {f.evidence.get("host")
             for f in by_key.get("bank_mobile_api_host", [])}
    assert "mobile-api.bank.fixture.test" in hosts
    assert any("strict-transport-security" in (f.evidence or {}).get(
        "header", "") for f in by_key.get("bank_missing_header", []))
    # the hex token a1f5b2c3 contains "f5" inside a word: no F5 CVE.
    cves = {f.evidence.get("cve") for f in by_key.get("bank_cve", [])}
    assert "CVE-2022-1388" not in cves


def test_authorized_plain_site_has_no_bank_tech_claims():
    # The shared fixture site is deliberately vulnerable (it has /login,
    # /admin, API docs), so portal/admin/header findings are CORRECT
    # there. The healthy-case claim is narrower: no core-banking
    # platform, no CVE, no PCI flag gets asserted about a site with no
    # banking tech on it.
    res = asyncio.run(BankPlugin().run(url_target(), _auth_ctx()))
    keys = {f.key for f in res.findings}
    assert "bank_authorization" in keys
    assert "bank_platform" not in keys
    assert "bank_cve" not in keys
    assert "bank_pci_flag" not in keys
