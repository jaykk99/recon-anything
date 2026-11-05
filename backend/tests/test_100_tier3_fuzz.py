"""Tier-3 Fuzzing & Parameter Discovery plugins (100-plugin expansion).

Per shipped plugin: fires on the VULN fixture, silent on the CLEAN
fixture, no crash on malformed input - all over httpx MockTransport.
Duplicate-of tools (Arjun, Katana, Gau, LinkFinder) get a presence +
behavior check against the EXISTING plugin they duplicate.

Shipped: ffuf_fuzz (vhost remainder of FFUF), paramspider,
kiterunner, wfuzz, burp_collaborator, waymore (status-history
remainder of Waymore).
Duplicates: arjun -> param_fuzzer (+param_discovery),
katana -> katana, gau -> gau, linkfinder -> js_endpoints.
"""
import asyncio
import json
import os
import sys
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

NEW_IDS = ["ffuf_fuzz", "paramspider", "kiterunner", "wfuzz",
           "burp_collaborator", "waymore"]
DUP_IDS = ["param_fuzzer", "param_discovery", "katana", "gau",
           "js_endpoints"]

VULN = "vuln.test"
CLEAN = "clean.test"

NOT_FOUND = ("<html><head><title>404</title></head><body>"
             "not found</body></html>")
HOME = ("<html><head><title>home</title>"
        '<script src="/static/app.js"></script></head>'
        "<body>home page</body></html>")
SPA_SHELL = ("<html><head><title>app</title></head><body>"
             "<div id=root>spa shell</div></body></html>")


def _cdx_rows_for(domain, fl):
    """Wayback CDX rows shaped by the requested field list."""
    if domain.startswith("clean") or not domain:
        rows = [["timestamp", "original", "statuscode"],
                ["20230101000000", f"https://{domain}/", "200"],
                ["20230601000000", f"https://{domain}/about", "200"]]
        if "statuscode" in fl:
            return rows
        return [[r[1]] if "original" in fl else r for r in rows]
    param_urls = [
        f"https://{domain}/search?q=shoes&id=4",
        f"https://{domain}/item?id=9&debug=1",
        f"https://{domain}/search?q=hats&page=2",
        f"https://{domain}/plain",
    ]
    if "statuscode" in fl:
        return [
            ["timestamp", "original", "statuscode"],
            ["20230101000000", f"https://{domain}/old-page", "200"],
            ["20230601000000", f"https://{domain}/old-page", "404"],
            ["20240101000000", f"https://{domain}/old-page", "200"],
            ["20230105000000", f"https://{domain}/stable", "200"],
            ["20240105000000", f"https://{domain}/stable", "200"],
        ] + [["20230202000000", u, "200"] for u in param_urls]
    return [["original"]] + [[u] for u in param_urls]


def _handler(request: httpx.Request) -> httpx.Response:
    url = urlparse(str(request.url))
    host, path = url.hostname or "", url.path or "/"
    q = parse_qs(url.query)
    host_header = (request.headers.get("host") or "").lower()

    if host == "web.archive.org":
        target_domain = ""
        raw_q = parse_qs(url.query)
        target_domain = (raw_q.get("url") or [""])[0].strip("/*")
        fl = (raw_q.get("fl") or [""])[0]
        rows = _cdx_rows_for(target_domain, fl)
        return httpx.Response(200, json=rows, request=request)
    if host == "index.commoncrawl.org":
        if path == "/collinfo.json":
            return httpx.Response(200, json=[{
                "id": "CC-TEST-2024",
                "cdx-index": "https://index.commoncrawl.org/"
                             "CC-TEST-2024-index"}], request=request)
        if VULN in str(request.url):
            nd = "\n".join(json.dumps({"url": u}) for u in (
                f"https://{VULN}/search?q=x&id=1",
                f"https://{VULN}/legacy.zip"))
            return httpx.Response(200, text=nd, request=request)
        return httpx.Response(200, text="", request=request)
    if host == "otx.alienvault.com":
        if VULN in str(request.url):
            return httpx.Response(200, json={"url_list": [
                {"url": f"https://{VULN}/search?q=x&id=1"}]},
                request=request)
        return httpx.Response(200, json={"url_list": []},
                              request=request)
    if host == "collab.test":
        if path == "/poll":
            return httpx.Response(200, json={"interactions": [{
                "protocol": "http", "from_ip": "192.0.2.55",
                "time": "2026-01-01T00:00:00Z",
                "payload_id": "smoke-token"}]}, request=request)
        return httpx.Response(200, text="ok", request=request)

    if host == VULN:
        # --- ffuf vhost behaviour (Host header decides) ---
        if host_header.startswith("dev."):
            return httpx.Response(200, headers={
                "Content-Type": "text/html"}, request=request,
                content="<html><title>dev portal</title>dev</html>")
        if host_header.startswith("staging."):
            return httpx.Response(403, headers={
                "Content-Type": "text/html"}, request=request,
                content="<html><title>staging</title>denied</html>")
        # --- kiterunner real API routes ---
        if path in ("/api/v1/users", "/api/v1/orders"):
            return httpx.Response(200, headers={
                "Content-Type": "application/json"}, request=request,
                content=json.dumps([{"id": 1}, {"id": 2}]))
        if path == "/api/v1/health":
            return httpx.Response(200, headers={
                "Content-Type": "application/json"}, request=request,
                content=json.dumps({"status": "ok", "uptime": 42}))
        if path == "/openapi.json":
            return httpx.Response(200, headers={
                "Content-Type": "application/json"}, request=request,
                content=json.dumps({"openapi": "3.0.0", "paths": {}}))
        if path == "/api/data":
            if "debug" in q:
                return httpx.Response(200, headers={
                    "Content-Type": "application/json"}, request=request,
                    content=json.dumps({"a": 1, "debug": True,
                                        "trace": "x" * 200}))
            return httpx.Response(200, headers={
                "Content-Type": "application/json"}, request=request,
                content=json.dumps({"a": 1}))
        if path.startswith("/api/") or path.startswith("/v1/") \
                or path.startswith("/rest/"):
            return httpx.Response(404, headers={
                "Content-Type": "text/html"}, request=request,
                content=NOT_FOUND)
        # --- wfuzz path/query behaviour ---
        if path == "/admin":
            return httpx.Response(200, headers={
                "Content-Type": "text/html"}, request=request,
                content="<html><title>Admin Panel</title>admin</html>")
        if path == "/":
            if "q" in q:
                return httpx.Response(200, headers={
                    "Content-Type": "text/html"}, request=request,
                    content=f"<html>results for {q['q'][0]}</html>")
            return httpx.Response(200, headers={
                "Content-Type": "text/html"}, request=request,
                content=HOME)
        if path == "/static/app.js":
            return httpx.Response(200, headers={
                "Content-Type": "application/javascript"},
                request=request,
                content="fetch('/api/v1/users');"
                        "const x='/api/internal/metrics';")
        return httpx.Response(404, headers={
            "Content-Type": "text/html"}, request=request,
            content=NOT_FOUND)
    if host == CLEAN:
        # SPA catch-all: every route serves the same shell.
        return httpx.Response(200, headers={"Content-Type": "text/html"},
                              request=request, content=SPA_SHELL)
    return httpx.Response(404, content="", request=request)


def make_ctx(mode="active", transport=None, shared=None):
    client = httpx.AsyncClient(
        transport=transport or httpx.MockTransport(_handler),
        follow_redirects=True, trust_env=False,
        headers={"User-Agent": "ReconAnything-Test/1.0"})
    ctx = Ctx(run_id="tier3-test", mode=mode, http=client,
              cache=Cache(), keys={},
              limiter=RateLimiter(default_rps=10000.0),
              evidence_dir="/tmp", source_type="website")
    if shared:
        for kind, items in shared.items():
            for item in items:
                ctx.publish(kind, item)
    return ctx


def run(cls, target, mode="active", transport=None, shared=None):
    async def _go():
        ctx = make_ctx(mode=mode, transport=transport, shared=shared)
        try:
            return await cls().run(target, ctx)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def domain(name):
    return Target(raw=name, type="domain", normalized=name)


def url_of(name):
    return Target(raw=f"https://{name}/", type="url",
                  normalized=f"https://{name}/")


@pytest.fixture(autouse=True)
def _no_collab_env(monkeypatch):
    monkeypatch.delenv("COLLABORATOR_DOMAIN", raising=False)
    monkeypatch.delenv("COLLABORATOR_POLL_URL", raising=False)


# ---------------------------------------------------------------------------
# Registry count (re-baselined at install time)
# ---------------------------------------------------------------------------

def test_registry_count_tier3():
    reg = discover()
    for pid in NEW_IDS + DUP_IDS:
        assert pid in reg, f"{pid} missing from registry"


# ---------------------------------------------------------------------------
# ffuf_fuzz (FFUF vhost remainder)
# ---------------------------------------------------------------------------

def test_ffuf_vhost_fires_on_vuln():
    from app.plugins.ffuf_fuzz import FfufFuzzPlugin
    res = run(FfufFuzzPlugin, domain(VULN))
    vhosts = {f.value for f in res.findings if f.key == "virtual_host"}
    assert f"dev.{VULN}" in vhosts
    assert f"staging.{VULN}" in vhosts


def test_ffuf_vhost_silent_on_clean():
    from app.plugins.ffuf_fuzz import FfufFuzzPlugin
    res = run(FfufFuzzPlugin, domain(CLEAN))
    assert res.findings == []


def test_ffuf_malformed_no_crash():
    from app.plugins.ffuf_fuzz import FfufFuzzPlugin
    res = run(FfufFuzzPlugin, Target(raw="192.0.2.1", type="ip",
                                     normalized="192.0.2.1"))
    assert res.findings == []
    res = run(FfufFuzzPlugin, domain(""))
    assert res.findings == []


def test_ffuf_passive_mode_skips():
    from app.plugins.ffuf_fuzz import FfufFuzzPlugin
    res = run(FfufFuzzPlugin, domain(VULN), mode="passive")
    assert res.findings == []


# ---------------------------------------------------------------------------
# paramspider
# ---------------------------------------------------------------------------

def test_paramspider_fires_on_vuln():
    from app.plugins.paramspider import ParamSpiderPlugin, mine_params
    mined = mine_params(["https://x.test/a?id=1&q=2",
                         "https://x.test/b?id=3"])
    assert set(mined["params"]) == {"id", "q"}
    res = run(ParamSpiderPlugin, domain(VULN), mode="passive")
    names = {f.value for f in res.findings if f.key == "archived_param"}
    assert {"q", "id", "debug", "page"} <= names
    assert any(f.key == "parameterized_endpoint" for f in res.findings)


def test_paramspider_silent_on_clean():
    from app.plugins.paramspider import ParamSpiderPlugin
    res = run(ParamSpiderPlugin, domain(CLEAN), mode="passive")
    assert res.findings == []


def test_paramspider_malformed_no_crash():
    from app.plugins.paramspider import ParamSpiderPlugin
    res = run(ParamSpiderPlugin, domain(""), mode="passive")
    assert res.findings == []


def test_paramspider_shared_fixture_no_params():
    import plugin_fixtures as fx
    from app.plugins.paramspider import ParamSpiderPlugin

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        try:
            return await ParamSpiderPlugin().run(fx.domain_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    # Shared-fixture CDX rows carry no query strings: silent, no crash.
    assert [f for f in res.findings if f.key == "archived_param"] == []


# ---------------------------------------------------------------------------
# kiterunner
# ---------------------------------------------------------------------------

def test_kiterunner_shape_logic():
    from app.plugins.kiterunner import is_route_hit
    baseline = {"status": 200, "ctype": "text/html", "is_json": False,
                "is_html": True, "length": 500, "hash": "aaa"}
    spa = dict(baseline)
    assert not is_route_hit(spa, baseline)
    api = {"status": 200, "ctype": "application/json", "is_json": True,
           "is_html": False, "length": 120, "hash": "bbb"}
    assert is_route_hit(api, baseline)
    assert not is_route_hit({"status": 404, "ctype": "text/html",
                             "is_json": False, "is_html": True,
                             "length": 90, "hash": "ccc"}, baseline)


def test_kiterunner_fires_on_vuln():
    from app.plugins.kiterunner import KiterunnerPlugin
    res = run(KiterunnerPlugin, domain(VULN))
    hits = {f.value for f in res.findings if f.key == "api_route"}
    assert any("/api/v1/users" in h for h in hits)
    assert any("/openapi.json" in h for h in hits)


def test_kiterunner_silent_on_spa_clean():
    from app.plugins.kiterunner import KiterunnerPlugin
    res = run(KiterunnerPlugin, domain(CLEAN))
    assert res.findings == []


def test_kiterunner_malformed_no_crash():
    from app.plugins.kiterunner import KiterunnerPlugin
    res = run(KiterunnerPlugin, Target(raw="192.0.2.1", type="ip",
                                       normalized="192.0.2.1"))
    assert res.findings == []


# ---------------------------------------------------------------------------
# wfuzz
# ---------------------------------------------------------------------------

def test_wfuzz_fires_on_vuln():
    from app.plugins.wfuzz import WfuzzPlugin
    res = run(WfuzzPlugin, url_of(VULN))
    keys = {f.key for f in res.findings}
    assert "fuzz_hit" in keys  # /admin differs from path baseline
    assert "fuzz_reflection" in keys  # ?q= marker reflected


def test_wfuzz_silent_on_clean():
    from app.plugins.wfuzz import WfuzzPlugin
    res = run(WfuzzPlugin, url_of(CLEAN))
    assert res.findings == []


def test_wfuzz_malformed_no_crash():
    from app.plugins.wfuzz import WfuzzPlugin
    res = run(WfuzzPlugin, Target(raw="192.0.2.1", type="ip",
                                  normalized="192.0.2.1"))
    assert res.findings == []


# ---------------------------------------------------------------------------
# burp_collaborator
# ---------------------------------------------------------------------------

def test_collaborator_needs_config_cleanly():
    from app.plugins.burp_collaborator import BurpCollaboratorPlugin
    res = run(BurpCollaboratorPlugin, domain(VULN))
    assert res.findings == []
    assert "needs config" in (res.reason or "")


def test_collaborator_payload_generation():
    from app.plugins.burp_collaborator import generate_payloads
    p = generate_payloads("collab.test", "tok123")
    assert p["host"] == "tok123.collab.test"
    assert "tok123.collab.test" in p["url"]
    body = json.loads(p["json_body"])
    assert body["url"] == p["url"]


def test_collaborator_parse_interactions():
    from app.plugins.burp_collaborator import parse_interactions
    hits = parse_interactions({"interactions": [
        {"protocol": "dns", "remote_ip": "192.0.2.1",
         "timestamp": "2026-01-01T00:00:00Z", "id": "abc"},
        {"bad": "shape"}, "junk", 42]})
    assert len(hits) == 2  # junk entries dropped, never raised on
    assert hits[0]["protocol"] == "dns"
    assert hits[0]["from_ip"] == "192.0.2.1"
    assert parse_interactions(None) == []
    assert parse_interactions({"nope": 1}) == []


def test_collaborator_with_config_sends_and_polls(monkeypatch):
    monkeypatch.setenv("COLLABORATOR_DOMAIN", "collab.test")
    monkeypatch.setenv("COLLABORATOR_POLL_URL", "https://collab.test/poll")
    from app.plugins.burp_collaborator import BurpCollaboratorPlugin
    res = run(BurpCollaboratorPlugin, domain(VULN), shared={
        "endpoints": [f"https://{VULN}/api/data?id=1"]})
    keys = {f.key for f in res.findings}
    assert "collaborator_payload" in keys
    assert "collaborator_interaction" in keys


def test_collaborator_malformed_no_crash(monkeypatch):
    monkeypatch.setenv("COLLABORATOR_DOMAIN", "collab.test")
    from app.plugins.burp_collaborator import BurpCollaboratorPlugin
    res = run(BurpCollaboratorPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# waymore (status-history remainder)
# ---------------------------------------------------------------------------

def test_waymore_history_helpers():
    from app.plugins.waymore import build_history, classify_history
    rows = [["timestamp", "original", "statuscode"],
            ["20230101000000", "https://x.test/a", "200"],
            ["20230601000000", "https://x.test/a", "404"],
            ["20230101000000", "https://x.test/b", "200"]]
    hist = build_history(rows)
    classes = classify_history(hist)
    assert [u for u, _t, _c in classes["flips"]] == ["https://x.test/a"]
    assert build_history([]) == {}
    assert build_history([["only-header"]]) == {}


def test_waymore_fires_on_vuln():
    from app.plugins.waymore import WaymorePlugin
    res = run(WaymorePlugin, domain(VULN), mode="passive")
    flips = [f for f in res.findings if f.key == "archived_status_flip"]
    assert flips and "old-page" in flips[0].value


def test_waymore_silent_on_clean():
    from app.plugins.waymore import WaymorePlugin
    res = run(WaymorePlugin, domain(CLEAN), mode="passive")
    assert res.findings == []


def test_waymore_malformed_no_crash():
    from app.plugins.waymore import WaymorePlugin
    res = run(WaymorePlugin, domain(""), mode="passive")
    assert res.findings == []


# ---------------------------------------------------------------------------
# Duplicate-of evidence: the existing plugins work
# ---------------------------------------------------------------------------

def test_duplicate_arjun_param_fuzzer_differential_fires():
    from app.plugins.param_fuzzer import ParamFuzzerPlugin
    res = run(ParamFuzzerPlugin, domain(VULN), shared={
        "endpoints": [f"https://{VULN}/api/data"]})
    assert any(f.key == "fuzz_param_anomaly" for f in res.findings)


def test_duplicate_katana_crawls_shared_fixture():
    import plugin_fixtures as fx
    from app.plugins.katana import KatanaPlugin

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        try:
            return await KatanaPlugin().run(fx.url_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    assert any(f.key == "endpoint" for f in res.findings)


def test_duplicate_gau_aggregates_archives():
    from app.plugins.gau import GauPlugin
    res = run(GauPlugin, domain(VULN), mode="passive")
    assert any(f.key == "archived_url" for f in res.findings)


def test_duplicate_linkfinder_js_endpoints_shared_fixture():
    import plugin_fixtures as fx
    from app.plugins.js_endpoints import JsEndpointsPlugin

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        try:
            return await JsEndpointsPlugin().run(fx.url_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    assert any(f.key == "hidden_api_endpoint" for f in res.findings)
