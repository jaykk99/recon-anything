"""WAF detection coverage: passive vendor fingerprinting, active-block
recording, and the finalize hook that turns blocks seen by ANY plugin
into findings (so a WAF-filtered scan never looks like a silent zero).
"""
from types import SimpleNamespace

import pytest

from app import runner
from app.models import Base, Finding, Run, Target, get_session
from app.waf import classify_response, detect_vendors

from plugin_fixtures import run_plugin_fixture


# -- classifier / registry unit checks ---------------------------------------

class _Resp:
    def __init__(self, status, headers, text=""):
        self.status_code = status
        self.headers = headers
        self.text = text


def test_registry_covers_the_named_vendors():
    cf = detect_vendors({"cf-ray": "x", "server": "cloudflare"},
                        "__cf_bm=1")
    assert "Cloudflare" in cf
    ak = detect_vendors({"x-akamai-transformed": "v"}, "_abck=1")
    assert "Akamai" in ak
    imp = detect_vendors({"x-iinfo": "1"}, "incap_ses_123=1")
    assert "Imperva" in imp
    aws = detect_vendors({"x-amz-cf-id": "1"}, "aws-waf-token=1")
    assert "AWS WAF / CloudFront" in aws or "AWS WAF" in aws
    suc = detect_vendors({"x-sucuri-id": "1"}, "")
    assert "Sucuri" in suc
    mod = detect_vendors({"x-mod-security": "1"}, "")
    assert "ModSecurity" in mod


def test_classify_block_page_attributes_vendor():
    from app.waf import BLOCK_KINDS
    r = _Resp(403, {"server": "cloudflare"},
              "<title>Attention Required! | Cloudflare</title>")
    v = classify_response(r)
    # Cloudflare's "Attention Required" page classifies as a challenge
    # block; what matters is block-kind + vendor attribution.
    assert v.kind in BLOCK_KINDS and v.vendor == "Cloudflare"


# -- plugin against the protected fixture host --------------------------------

def test_waf_plugin_fingerprints_and_records_block():
    import asyncio
    from app.plugins.base import Target as T
    from app.plugins.waf import WafPlugin
    target = T(type="url", raw="http://waf.fixture.test/",
               normalized="http://waf.fixture.test/")
    status, findings, err = asyncio.run(run_plugin_fixture(
        WafPlugin, target, "passive"))
    assert status == "ok", err
    keys = {(f.key, (f.evidence or {}).get("vendor")) for f in findings}
    assert ("waf_detected", "Cloudflare") in keys
    assert any(k == "waf_blocking" for k, _ in keys)


def test_waf_plugin_clean_host_reports_none():
    import asyncio
    from app.plugins.waf import WafPlugin
    from plugin_fixtures import url_target
    status, findings, err = asyncio.run(run_plugin_fixture(
        WafPlugin, url_target(), "passive"))
    assert status == "ok", err
    assert [f.key for f in findings] == ["waf_none"]


# -- finalize hook: blocks seen by other plugins become findings --------------

class _Limiter:
    def __init__(self, stats):
        self._stats = stats

    def waf_stats(self, host):
        return dict(self._stats.get(host, {}))


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.models as models
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine(f"sqlite:///{tmp_path}/waf.db")
    Base.metadata.create_all(bind=eng)
    TestSession = sessionmaker(bind=eng, autoflush=False, autocommit=False)
    monkeypatch.setattr(models, "SessionLocal", TestSession)
    s = TestSession()
    s.add(Run(id="wafrun", mode="active", status="running",
              source_type="website", summary={}))
    s.add(Target(id="wafrun:1", run_id="wafrun", raw="fixture.test",
                 type="domain", normalized="fixture.test"))
    s.commit()
    s.close()
    return TestSession


def test_record_waf_blocks_creates_finding_once(db):
    ctx = SimpleNamespace(
        shared={"_waf_base": {"fixture.test": {
            "blocked": 1, "succeeded": 10, "vendor": "Cloudflare"}}},
        limiter=_Limiter({"fixture.test": {
            "blocked": 5, "succeeded": 40, "vendor": "Cloudflare"}}))
    s = get_session()
    try:
        assert runner._record_waf_blocks(s, "wafrun", ctx) == 1
        rows = s.query(Finding).filter_by(run_id="wafrun").all()
        assert len(rows) == 1
        f = rows[0]
        assert f.key == "waf_blocked_requests" and f.plugin_id == "waf"
        assert f.evidence["blocked"] == 4  # delta only, not the raw total
        assert f.evidence["vendor"] == "Cloudflare"
        # second pass (finalize can retry): no duplicate
        assert runner._record_waf_blocks(s, "wafrun", ctx) == 0
    finally:
        s.close()


def test_record_waf_blocks_no_delta_no_finding(db):
    ctx = SimpleNamespace(
        shared={"_waf_base": {"fixture.test": {"blocked": 2,
                                               "succeeded": 3}}},
        limiter=_Limiter({"fixture.test": {"blocked": 2, "succeeded": 9}}))
    s = get_session()
    try:
        assert runner._record_waf_blocks(s, "wafrun", ctx) == 0
        assert s.query(Finding).filter_by(run_id="wafrun").count() == 0
    finally:
        s.close()
