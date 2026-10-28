"""Behavior tests for the openid_discovery plugin (2026-10-28 quota).

Canned HTTP responses, network-free. Covers: full discovery doc with
weak configuration, clean doc, missing doc, malformed doc, and unit
tests for the pure discovery_issues() helper.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.plugins import base  # noqa: E402
from app.plugins.openid_discovery import discovery_issues  # noqa: E402
from app.plugins.registry import discover  # noqa: E402


def _resp(url, status=200, text=""):
    req = httpx.Request("GET", url)
    return httpx.Response(status, headers={}, text=text, request=req)


class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None


class CtxStub:
    def __init__(self):
        self.run_id = "test"
        self.mode = "passive"
        self.http = None
        self.cache = _FakeCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = {}

    def publish(self, kind, item):
        b = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in b:
                b.append(item)
        else:
            b.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        return None

    async def probe(self, url, timeout=8):
        return {"status": 0, "headers": {}, "text": "", "url": url}


def _patch_http(monkeypatch, mapping):
    import app.ratelimit as _rl
    import app.plugins.openid_discovery as mod
    discover()

    async def fake_fetch(client, limiter, method, url, **kw):
        r = mapping.get(url)
        if r is None:
            raise ConnectionError(f"no canned response for {url}")
        return r

    monkeypatch.setattr(mod, "fetch", fake_fetch, raising=False)
    monkeypatch.setattr(_rl, "fetch", fake_fetch, raising=False)


def _run(target, ctx):
    cls = discover()["openid_discovery"]
    return asyncio.run(cls().run(target, ctx))


def _url_target(url="https://example.com"):
    return base.Target(raw=url, type="url", normalized=url)


def _keys(res):
    return {f.key for f in res.findings}


FULL_DOC = {
    "issuer": "https://auth.other.test",
    "authorization_endpoint": "https://auth.other.test/authorize",
    "token_endpoint": "https://auth.other.test/token",
    "userinfo_endpoint": "https://auth.other.test/userinfo",
    "jwks_uri": "https://auth.other.test/.well-known/jwks.json",
    "response_types_supported": ["code", "id_token token"],
    "grant_types_supported": ["authorization_code", "password"],
    "code_challenge_methods_supported": ["plain"],
    "scopes_supported": ["openid", "profile"],
}

CLEAN_DOC = {
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code"],
    "code_challenge_methods_supported": ["S256"],
}


def test_full_doc_flags_weak_config(monkeypatch):
    url = "https://example.com/.well-known/openid-configuration"
    _patch_http(monkeypatch, {url: _resp(url, text=json.dumps(FULL_DOC))})
    ctx = CtxStub()
    res = _run(_url_target(), ctx)
    assert res.status == base.PluginStatus.OK
    keys = _keys(res)
    assert "oidc_discovery" in keys
    assert "oidc_endpoint" in keys
    assert "oidc_issuer_mismatch" in keys
    assert "oidc_implicit_flow" in keys
    assert "oidc_password_grant" in keys
    assert "oidc_no_pkce_s256" in keys
    assert len([f for f in res.findings if f.key == "oidc_endpoint"]) == 4
    assert "https://auth.other.test/token" in ctx.consume("endpoints")


def test_clean_doc_no_weak_findings(monkeypatch):
    url = "https://example.com/.well-known/openid-configuration"
    _patch_http(monkeypatch, {url: _resp(url, text=json.dumps(CLEAN_DOC))})
    res = _run(_url_target(), CtxStub())
    assert res.status == base.PluginStatus.OK
    keys = _keys(res)
    assert "oidc_discovery" in keys
    assert "oidc_endpoint" in keys
    assert "oidc_issuer_mismatch" not in keys
    assert "oidc_implicit_flow" not in keys
    assert "oidc_password_grant" not in keys
    assert "oidc_no_pkce_s256" not in keys


def test_missing_doc_degrades(monkeypatch):
    url = "https://example.com/.well-known/openid-configuration"
    _patch_http(monkeypatch, {url: _resp(url, status=404, text="nope")})
    res = _run(_url_target(), CtxStub())
    assert res.status == base.PluginStatus.OK
    assert not res.findings


def test_malformed_doc_degrades(monkeypatch):
    url = "https://example.com/.well-known/openid-configuration"
    _patch_http(monkeypatch, {url: _resp(url, text="<html>not json</html>")})
    res = _run(_url_target(), CtxStub())
    assert res.status == base.PluginStatus.OK
    assert not res.findings


def test_issuer_mismatch_unit():
    issues = discovery_issues({"issuer": "https://login.other.test"},
                              "example.com")
    assert [i["key"] for i in issues] == ["oidc_issuer_mismatch"]


def test_hybrid_flow_not_implicit():
    issues = discovery_issues(
        {"response_types_supported": ["code id_token", "code token"]},
        "example.com")
    assert not any(i["key"] == "oidc_implicit_flow" for i in issues)


def test_pkce_s256_ok():
    issues = discovery_issues(
        {"code_challenge_methods_supported": ["S256"]}, "example.com")
    assert not any(i["key"] == "oidc_no_pkce_s256" for i in issues)
