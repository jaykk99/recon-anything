"""Unit gate for the Alt-Svc header audit plugin (altsvc_audit).

Every Alt-Svc shape must produce exactly its own finding class, the
clean site must stay silent, and the parser must handle multi-entry
values, quoted commas, persist flags and malformed fragments without
ever fetching anything but the target's own homepage.
"""
import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import altsvc_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.altsvc_audit import parse_alt_svc  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    alt_svc = samples.HOST_HEADERS.get(host)
    headers = {"Content-Type": "text/html"}
    if alt_svc is not None:
        headers["Alt-Svc"] = alt_svc
    return httpx.Response(200, content=samples.CLEAN_HTML,
                          headers=headers, request=request)


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="altsvc-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run(host: str, scheme: str = "https"):
    cls = discover()["altsvc_audit"]
    ctx = _ctx()
    target = Target(raw=f"{scheme}://{host}/", type="url",
                    normalized=f"{scheme}://{host}/")
    try:
        return asyncio.run(cls().run(target, ctx))
    finally:
        asyncio.run(ctx.http.aclose())


def _keys(result) -> set:
    return {f.key for f in result.findings}


# --- parser unit tests -------------------------------------------------

def test_parse_single_entry():
    entries, clear = parse_alt_svc(['h3=":443"; ma=86400'])
    assert not clear
    assert len(entries) == 1
    e = entries[0]
    assert e.protocol == "h3"
    assert e.host == "" and e.port == "443" and e.ma == 86400
    assert not e.malformed and not e.is_legacy_h3


def test_parse_multi_entry_and_persist():
    entries, clear = parse_alt_svc(
        ['h3="example.com:443"; ma=86400; persist=1, h2=":443"; ma=3600'])
    assert not clear
    assert len(entries) == 2
    assert entries[0].persist is True
    assert entries[0].host == "example.com"
    assert entries[1].protocol == "h2" and entries[1].ma == 3600


def test_parse_clear_and_legacy_and_malformed():
    entries, clear = parse_alt_svc(["clear"])
    assert clear and entries == []
    entries, _ = parse_alt_svc(['h3-Q050=":443"; ma=86400'])
    assert entries[0].is_legacy_h3
    entries, _ = parse_alt_svc(['h3=broken;;'])
    assert entries[0].malformed
    entries, _ = parse_alt_svc(['h3=":443"; ma=notanumber'])
    assert entries[0].malformed


def test_parse_quoted_comma_not_a_split():
    # A comma inside quotes must not split the entry.
    entries, _ = parse_alt_svc(['h3=":443"; ma=86400'])
    assert len(entries) == 1
    entries, _ = parse_alt_svc(['h2="a.test:443"; ma=1, h3=":443"; ma=2'])
    assert len(entries) == 2


# --- plugin behaviour tests --------------------------------------------

def test_clean_site_silent():
    result = _run("clean.test")
    assert result.status.value == "ok"
    assert result.findings == []


def test_h3_advertised():
    result = _run("canary-h3.test")
    assert _keys(result) == {"altsvc_h3_advertised"}


def test_legacy_draft_only():
    result = _run("canary-legacy.test")
    assert _keys(result) == {"altsvc_legacy_draft"}


def test_cross_origin_h2_only():
    result = _run("canary-xorigin.test")
    assert _keys(result) == {"altsvc_cross_origin"}


def test_cross_origin_h3_both_facts():
    # A cross-origin h3 entry is both facts: h3 advertised AND the
    # advertisement points at another host.
    result = _run("canary-xorigin-h3.test")
    assert _keys(result) == {"altsvc_cross_origin", "altsvc_h3_advertised"}


def test_malformed_only():
    result = _run("canary-malformed.test")
    assert _keys(result) == {"altsvc_malformed"}


def test_clear_token():
    result = _run("canary-clear.test")
    assert _keys(result) == {"altsvc_clear"}


def test_ma_zero_withdrawal():
    result = _run("canary-mazero.test")
    assert _keys(result) == {"altsvc_ma_zero"}


def test_cleartext_h2c():
    result = _run("canary-cleartext.test")
    assert _keys(result) == {"altsvc_cleartext"}


def test_multi_entry_no_dupe_noise():
    result = _run("canary-multi.test")
    assert _keys(result) == {"altsvc_h3_advertised"}


def test_http_origin_ignored():
    result = _run("canary-http.test", scheme="http")
    assert _keys(result) == {"altsvc_ignored_http"}


def test_plugin_registered_with_valid_metadata():
    cls = discover()["altsvc_audit"]
    plugin = cls()
    assert plugin.group == "web"
    assert plugin.passive is True
    assert plugin.description
    assert "url" in plugin.accepts and "domain" in plugin.accepts
