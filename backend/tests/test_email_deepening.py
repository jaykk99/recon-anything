"""Email-posture deepening tests (plugin email_infra).

DNS is stubbed at the plugin's own seam (its module-level _txt/_mx/_a
helpers), so the parsing/grading/finding logic runs for real. HTTP
surface checks run against the fixture transport (webmail.fixture.test
serves a Roundcube login page).

Positive case: weak domain (SPF ?all + duplicate record, DMARC p=none
pct=50, no DKIM, resolving webmail subdomain with a Roundcube login).
Healthy case: strict domain (SPF -all, DMARC p=reject pct=100 strict
alignment, DKIM published, no mail subdomains) -> posture findings only,
no weakness findings.
"""
import asyncio

import pytest

from app.plugins import email_infra
from app.plugins.base import Target
from plugin_fixtures import make_fixture_ctx

WEAK_TXT = {
    "weak.test": [
        "v=spf1 include:_spf.example.net ?all",
        "v=spf1 -all",
    ],
    "_dmarc.weak.test": ["v=DMARC1; p=none; pct=50; "
                         "rua=mailto:dmarc@weak.test"],
}
STRONG_TXT = {
    "strong.test": ["v=spf1 include:_spf.example.net -all"],
    "_dmarc.strong.test": ["v=DMARC1; p=reject; pct=100; adkim=s; "
                           "aspf=s; sp=reject; rua=mailto:d@strong.test"],
    "selector1._domainkey.strong.test": ['v=DKIM1; k=rsa; p=MIGfMA0...'],
}


def _install(monkeypatch, txt_map, mx_map, a_names):
    async def fake_txt(name):
        return list(txt_map.get(name, []))

    async def fake_mx(domain):
        return list(mx_map.get(domain, []))

    async def fake_a(name):
        return name in a_names

    monkeypatch.setattr(email_infra, "_txt", fake_txt)
    monkeypatch.setattr(email_infra, "_mx", fake_mx)
    monkeypatch.setattr(email_infra, "_a", fake_a)


def _run(domain):
    plugin = email_infra.EmailInfraPlugin()
    ctx = make_fixture_ctx(mode="passive")
    target = Target(type="domain", raw=domain, normalized=domain)
    res = asyncio.run(plugin.run(target, ctx))
    return {f.key: f for f in res.findings}


def test_weak_domain_email_findings(monkeypatch):
    _install(monkeypatch, WEAK_TXT,
             {"weak.test": [(10, "mail.weak.test")]},
             {"webmail.fixture.test", "mail.weak.test"})
    # the surface check probes <sub>.<domain>; for the weak domain the
    # resolving webmail host is webmail.weak.test, which has no fixture
    # route - point the domain at the fixture webmail host instead:
    got = _run("weak.test")
    assert "spf_multiple_records" in got
    assert "dmarc_partial_enforcement" in got
    assert got["dmarc_partial_enforcement"].evidence["severity"] == "medium"
    assert "dkim_missing" in got
    assert "mail_subdomains" in got
    assert "mail.weak.test" in got["mail_subdomains"].value
    assert got["email_spoofing_risk"].evidence["severity"] in (
        "medium", "high")


def test_webmail_surface_identified(monkeypatch):
    # Domain whose webmail subdomain IS the fixture Roundcube host.
    txt = {"fixture.test": ["v=spf1 -all"],
           "_dmarc.fixture.test": ["v=DMARC1; p=reject"]}
    _install(monkeypatch, txt,
             {"fixture.test": [(10, "mx.fixture.test")]},
             {"webmail.fixture.test"})
    got = _run("fixture.test")
    assert "mail_login_surface" in got
    f = got["mail_login_surface"]
    assert "Roundcube" in f.value
    assert f.evidence["product"] == "Roundcube Webmail"


def test_strong_domain_has_no_weakness_findings(monkeypatch):
    _install(monkeypatch, STRONG_TXT,
             {"strong.test": [(10, "aspmx.l.google.com")]},
             set())
    got = _run("strong.test")
    for bad in ("spf_missing", "spf_multiple_records", "dmarc_missing",
                "dmarc_partial_enforcement", "dkim_missing",
                "mail_login_surface", "mx_missing"):
        assert bad not in got, bad
    assert got["email_spoofing_risk"].evidence["severity"] == "low"
    assert got["dmarc_record"].evidence["dkim_alignment"] == "strict"
    assert got["dmarc_record"].evidence["pct"] == 100
