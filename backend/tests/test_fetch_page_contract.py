"""Regression tests for the Ctx.fetch_page payload contract.

Production bug (first seen live 2026-10-21, run 8867a7fe2d46): the
real fetch_page returns a lightweight dict payload, but ten plugins
(hsts, csp_audit, cookie_security, cdn_detect, rate_limit_audit,
sri_audit, mixed_content, html_comments, trackers, exposed_debug)
were written against its documented "returns the response" contract
and crashed with AttributeError ('dict' object has no attribute
'text'/'headers') on every successful homepage fetch. The existing
suite never caught it because plugin tests stub fetch_page with
response objects. These tests use the REAL Ctx/fetch_page with only
the network layer (app.ratelimit.fetch) stubbed.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/test_recon_fp.db")
os.environ.setdefault("ACCESS_CODE", "")

import app.ratelimit as ratelimit  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins import base  # noqa: E402
from app.plugins.base import Ctx, PageData, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402


class _FakeResponse:
    def __init__(self, url, status_code=200, headers=None, text=""):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


_HOMEPAGE = _FakeResponse(
    "https://example.com/",
    headers={"Strict-Transport-Security": "max-age=300",
             "Content-Type": "text/html; charset=utf-8",
             "Set-Cookie": "sid=abc; Path=/"},
    text=("<html><head><script src=\"http://example.com/app.js\">"
          "</script></head><body><!-- secret comment -->"
          "<script src=\"https://www.google-analytics.com/ga.js\">"
          "</script></body></html>"))


def _install_fake_fetch(monkeypatch):
    calls = {"n": 0}

    async def fake_fetch(client, limiter, method, url, **kw):
        calls["n"] += 1
        if "example.com" in url:
            return _HOMEPAGE
        raise ConnectionError(f"no canned response for {url}")

    # Import every plugin module BEFORE patching anything: modules
    # bind `fetch` at import time (from ..ratelimit import fetch), so a
    # module first imported while ratelimit.fetch is patched captures
    # the fake as its permanent binding - and monkeypatch's undo never
    # restores it, silently breaking that plugin for every later test
    # in the process (found by tests/test_plugin_fixtures.py, which saw
    # headers/cors/forms/git/secrets/waybackurls/webtech return zero
    # findings only when run after this file).
    registry = discover()
    monkeypatch.setattr(ratelimit, "fetch", fake_fetch)
    # Plugins that imported fetch at module level need their own binding
    # patched too (same approach as tests/test_new_plugins._patch_http).
    for pid in ("hsts", "csp_audit", "cookie_security", "cdn_detect",
                "rate_limit_audit", "sri_audit", "mixed_content",
                "html_comments", "trackers", "exposed_debug"):
        mod = sys.modules[registry[pid].__module__]
        if hasattr(mod, "fetch"):
            monkeypatch.setattr(mod, "fetch", fake_fetch)
    return calls


def _real_ctx() -> Ctx:
    return Ctx(run_id="test-fp", mode="passive", http=None,
               cache=Cache(), keys={}, limiter=None)


def test_fetch_page_dual_access(monkeypatch):
    _install_fake_fetch(monkeypatch)
    ctx = _real_ctx()
    page = asyncio.run(ctx.fetch_page("https://example.com/"))
    assert isinstance(page, PageData)
    # dict-style consumers (the majority convention)
    assert page["status_code"] == 200
    assert "google-analytics" in page["text"]
    assert page.get("url") == "https://example.com/"
    # attribute-style consumers (the crashed plugin family)
    assert "google-analytics" in page.text
    assert page.status_code == 200
    # header lookup must ignore the server's casing
    assert page.headers.get("strict-transport-security") == "max-age=300"
    assert page["headers"].get("content-type").startswith("text/html")


def test_fetch_page_cached_second_call(monkeypatch):
    calls = _install_fake_fetch(monkeypatch)
    ctx = _real_ctx()
    first = asyncio.run(ctx.fetch_page("https://example.com/"))
    second = asyncio.run(ctx.fetch_page("https://example.com"))
    assert calls["n"] == 1  # singleflight + cache: one network fetch
    assert second.text == first.text
    assert second.headers.get("STRICT-TRANSPORT-SECURITY") == "max-age=300"


def test_previously_crashing_plugins_run_clean(monkeypatch):
    _install_fake_fetch(monkeypatch)
    registry = discover()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    for pid in ("hsts", "csp_audit", "cookie_security", "cdn_detect",
                "rate_limit_audit", "sri_audit", "mixed_content",
                "html_comments", "trackers", "exposed_debug"):
        ctx = _real_ctx()
        res = asyncio.run(registry[pid]().run(target, ctx))
        assert res.status.value != "error", (
            f"{pid} errored: {getattr(res, 'reason', res)}")
