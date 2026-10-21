"""Behavior tests for the 25 quota-batch plugins (2026-10-20).

Each plugin is exercised with canned HTTP/DNS/socket responses -
network-free. Covers: expected findings on positive input, graceful
skip/degrade on empty input, and unit tests for the pure helpers.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.resolver  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402

from app.plugins import base  # noqa: E402
from app.plugins.registry import discover  # noqa: E402


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

def _resp(url, status=200, headers=None, text="", json_data=None):
    req = httpx.Request("GET", url)
    if json_data is not None:
        import json as _json
        return httpx.Response(status, headers=headers or {},
                              text=_json.dumps(json_data), request=req)
    return httpx.Response(status, headers=headers or {}, text=text,
                          request=req)


class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None

    async def cached(self, source, target, fn, ttl=None):
        return await fn(), False


class CtxStub:
    def __init__(self, pages=None):
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
        self.pages = pages or {}

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
        return self.pages.get(url) or self.pages.get(url.rstrip("/"))

    async def probe(self, url, timeout=8):
        return {"status": 0, "headers": {}, "text": "", "url": url}


def _mod(pid):
    return sys.modules[discover()[pid].__module__]


def _patch_http(monkeypatch, pid, mapping):
    """Stub module-level fetch/fetch_many with canned URL -> Response.

    Also stubs app.ratelimit.fetch/fetch_many: net.web_base() imports
    fetch from ratelimit at call time for its scheme probe, so
    domain-target plugins need the ratelimit-level patch too.
    """
    import app.ratelimit as _rl
    mod = _mod(pid)

    async def fake_fetch(client, limiter, method, url, **kw):
        r = mapping.get(url)
        if r is None:
            raise ConnectionError(f"no canned response for {url}")
        return r

    async def fake_fetch_many(client, limiter, requests, **kw):
        out = []
        for req in requests:
            out.append(mapping.get(req[1]))
        return out

    monkeypatch.setattr(mod, "fetch", fake_fetch, raising=False)
    if hasattr(mod, "fetch_many"):
        monkeypatch.setattr(mod, "fetch_many", fake_fetch_many,
                            raising=False)
    monkeypatch.setattr(_rl, "fetch", fake_fetch, raising=False)
    monkeypatch.setattr(_rl, "fetch_many", fake_fetch_many, raising=False)


def _run(pid, target, ctx):
    cls = discover()[pid]
    return asyncio.run(cls().run(target, ctx))


def _url_target(url="https://example.com"):
    return base.Target(raw=url, type="url", normalized=url)


def _domain_target(d="example.com"):
    return base.Target(raw=d, type="domain", normalized=d)


def _keys(res):
    return {f.key for f in res.findings}


# ---------------------------------------------------------------------------
# cookie_security
# ---------------------------------------------------------------------------

def test_cookie_flags_missing():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers=[("set-cookie", "sess=abc; Path=/"),
                 ("set-cookie", "_ga=1; Path=/; Domain=example.com")],
        text="<html></html>")}
    res = _run("cookie_security", _url_target(), CtxStub(pages))
    assert res.status == base.PluginStatus.OK
    assert "cookie_flags_missing" in _keys(res)
    sess = [f for f in res.findings if f.key == "cookie_flags_missing"
            and "sess" in f.value][0]
    assert "Secure" in sess.value and "HttpOnly" in sess.value
    assert (sess.evidence or {}).get("severity") == "medium"


def test_cookie_secure_prefix_violation():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers=[("set-cookie", "__Secure-id=1; Path=/")],
        text="<html></html>")}
    res = _run("cookie_security", _url_target(), CtxStub(pages))
    assert "cookie_secure_prefix_violation" in _keys(res)


def test_cookie_host_prefix_ok():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers=[("set-cookie", "__Host-id=1; Path=/; Secure")],
        text="<html></html>")}
    res = _run("cookie_security", _url_target(), CtxStub(pages))
    assert "cookie_host_prefix_violation" not in _keys(res)


def test_cookie_no_cookies_skipped():
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html></html>")}
    res = _run("cookie_security", _url_target(), CtxStub(pages))
    assert res.status == base.PluginStatus.OK
    assert not res.findings


# ---------------------------------------------------------------------------
# csp_audit
# ---------------------------------------------------------------------------

def test_csp_weaknesses():
    csp = ("script-src 'unsafe-inline' https: data:; "
           "style-src 'self'")
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers={"content-security-policy": csp}, text="<html></html>")}
    res = _run("csp_audit", _url_target(), CtxStub(pages))
    keys = _keys(res)
    assert "csp_unsafe_inline" in keys
    assert "csp_data_script_src" in keys
    assert "csp_no_object_src" in keys
    assert "csp_no_base_uri" in keys


def test_csp_missing_skipped():
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html></html>")}
    res = _run("csp_audit", _url_target(), CtxStub(pages))
    assert not res.findings  # headers.py owns the missing-header finding


def test_csp_parse_unit():
    from app.plugins.csp_audit import _parse_csp, _grade_csp
    p = _parse_csp("default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'")
    assert p["default-src"] == ["'self'"]
    weak = _grade_csp(p, True)
    assert not [w for w in weak if w["key"] == "csp_unsafe_inline"]


# ---------------------------------------------------------------------------
# hsts
# ---------------------------------------------------------------------------

def test_hsts_weaknesses(monkeypatch):
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers={"strict-transport-security": "max-age=86400"},
        text="<html></html>")}
    _patch_http(monkeypatch, "hsts",
                {"https://example.com": _resp("https://example.com",
                                              status=200, text="hi"),
                 "http://example.com/": _resp("http://example.com/",
                                              status=200, text="hi")})
    res = _run("hsts", _domain_target(), CtxStub(pages))
    keys = _keys(res)
    assert "hsts_short_max_age" in keys
    assert "hsts_no_includesubdomains" in keys
    assert "hsts_no_preload" in keys
    assert "hsts_bare_domain_downgrade" in keys


def test_hsts_strong():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers={"strict-transport-security":
                 "max-age=31536000; includeSubDomains; preload"},
        text="<html></html>")}
    res = _run("hsts", _url_target(), CtxStub(pages))
    assert not res.findings


def test_hsts_parse_unit():
    from app.plugins.hsts import _parse_hsts
    h = _parse_hsts("max-age=31536000; includeSubDomains; preload")
    assert h["max-age"] == "31536000"
    assert "includesubdomains" in h and "preload" in h


# ---------------------------------------------------------------------------
# http_methods
# ---------------------------------------------------------------------------

def test_http_trace_enabled(monkeypatch):
    _patch_http(monkeypatch, "http_methods",
                {"https://example.com/": _resp(
                    "https://example.com/",
                    headers={"allow": "GET, HEAD, POST, OPTIONS, TRACE"},
                    text="")})
    res = _run("http_methods", _url_target(), CtxStub())
    assert "http_trace_enabled" in _keys(res)
    f = [x for x in res.findings if x.key == "http_trace_enabled"][0]
    assert (f.evidence or {}).get("severity") == "medium"


def test_http_methods_clean(monkeypatch):
    _patch_http(monkeypatch, "http_methods",
                {"https://example.com/": _resp(
                    "https://example.com/",
                    headers={"allow": "GET, HEAD, POST, OPTIONS"},
                    text="")})
    res = _run("http_methods", _url_target(), CtxStub())
    assert not res.findings


# ---------------------------------------------------------------------------
# error_pages
# ---------------------------------------------------------------------------

def test_error_stack_trace(monkeypatch):
    body = ("<html><body><h1>500</h1><pre>Traceback (most recent call last):"
            "  File \"/var/www/app.py\", line 10</pre></body></html>")
    mod = _mod("error_pages")

    async def fake_fetch_many(client, limiter, requests, **kw):
        return [_resp(req[1], status=500, text=body) for req in requests]

    monkeypatch.setattr(mod, "fetch_many", fake_fetch_many, raising=False)
    res = _run("error_pages", _url_target(), CtxStub())
    keys = _keys(res)
    assert "error_stack_trace" in keys
    assert "error_path_disclosure" in keys  # /var/www/app.py


def test_error_clean_404(monkeypatch):
    mod = _mod("error_pages")

    async def fake_fetch_many(client, limiter, requests, **kw):
        return [_resp(req[1], status=404, text="<h1>Not found</h1>")
                for req in requests]

    monkeypatch.setattr(mod, "fetch_many", fake_fetch_many, raising=False)
    res = _run("error_pages", _url_target(), CtxStub())
    assert not res.findings


# ---------------------------------------------------------------------------
# exposed_debug
# ---------------------------------------------------------------------------

def test_django_toolbar_exposed():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        text='<html><div id="djdt">debug</div></html>')}
    res = _run("exposed_debug", _url_target(), CtxStub(pages))
    assert "debug_django_toolbar" in _keys(res)
    f = res.findings[0]
    assert (f.evidence or {}).get("severity") == "high"


def test_no_toolbar_clean():
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html><body>hi</body></html>")}
    res = _run("exposed_debug", _url_target(), CtxStub(pages))
    assert not res.findings


# ---------------------------------------------------------------------------
# phpinfo
# ---------------------------------------------------------------------------

def test_phpinfo_exposed(monkeypatch):
    mod = _mod("phpinfo")
    body = ("<html><head><title>phpinfo()</title></head><body>"
            "<h1>PHP Version 8.1.2</h1>Zend Engine</body></html>")

    async def fake_fetch_many(client, limiter, requests, **kw):
        out = []
        for req in requests:
            if req[1].endswith("/phpinfo.php"):
                out.append(_resp(req[1], status=200, text=body))
            else:
                out.append(_resp(req[1], status=404, text="no"))
        return out

    monkeypatch.setattr(mod, "fetch_many", fake_fetch_many, raising=False)
    res = _run("phpinfo", _url_target(), CtxStub())
    assert "phpinfo_exposed" in _keys(res)
    assert res.findings[0].confidence >= 95


def test_phpinfo_absent(monkeypatch):
    mod = _mod("phpinfo")

    async def fake_fetch_many(client, limiter, requests, **kw):
        return [_resp(req[1], status=404, text="no") for req in requests]

    monkeypatch.setattr(mod, "fetch_many", fake_fetch_many, raising=False)
    res = _run("phpinfo", _url_target(), CtxStub())
    assert not res.findings


# ---------------------------------------------------------------------------
# mixed_content
# ---------------------------------------------------------------------------

def test_mixed_content_active():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        text='<html><head><script src="http://cdn.evil/x.js"></script>'
             '<img src="http://cdn.evil/p.png"></head></html>')}
    res = _run("mixed_content", _url_target("https://example.com"),
               CtxStub(pages))
    keys = _keys(res)
    assert "mixed_content_active" in keys
    assert "mixed_content_passive" in keys
    active = [f for f in res.findings
              if f.key == "mixed_content_active"][0]
    assert (active.evidence or {}).get("severity") == "medium"


def test_mixed_content_http_page_skipped():
    pages = {"http://example.com/": _resp("http://example.com/",
                                          text="<html></html>")}
    res = _run("mixed_content", _url_target("http://example.com"),
               CtxStub(pages))
    assert not res.findings


# ---------------------------------------------------------------------------
# http2_check
# ---------------------------------------------------------------------------

def test_http2_only_http1(monkeypatch):
    mod = _mod("http2_check")
    monkeypatch.setattr(mod, "_alpn_probe",
                        lambda host, port=443, timeout=8.0: "http/1.1")
    res = _run("http2_check", _domain_target(), CtxStub())
    assert "http1_only" in _keys(res)


def test_http2_h2_ok(monkeypatch):
    mod = _mod("http2_check")
    monkeypatch.setattr(mod, "_alpn_probe",
                        lambda host, port=443, timeout=8.0: "h2")
    res = _run("http2_check", _domain_target(), CtxStub())
    assert "http_version" in _keys(res)


def test_http2_no_tls_degraded(monkeypatch):
    mod = _mod("http2_check")
    monkeypatch.setattr(mod, "_alpn_probe",
                        lambda host, port=443, timeout=8.0: None)
    res = _run("http2_check", _domain_target(), CtxStub())
    assert not res.findings


# ---------------------------------------------------------------------------
# graphql_probe
# ---------------------------------------------------------------------------

def test_graphql_introspection(monkeypatch):
    mod = _mod("graphql_probe")
    typename = {"data": {"__typename": "Query"}}
    schema = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    mapping = {}
    for p in ["graphql", "api/graphql"]:
        mapping[f"https://example.com/{p}"] = _resp(
            f"https://example.com/{p}", json_data=typename)
    _patch_http(monkeypatch, "graphql_probe", mapping)

    async def fake_fetch(client, limiter, method, url, **kw):
        return _resp(url, json_data=schema)

    monkeypatch.setattr(mod, "fetch", fake_fetch, raising=False)
    res = _run("graphql_probe", _url_target(), CtxStub())
    keys = _keys(res)
    assert "graphql_endpoint" in keys
    assert "graphql_introspection_enabled" in keys
    intro = [f for f in res.findings
             if f.key == "graphql_introspection_enabled"][0]
    assert (intro.evidence or {}).get("severity") == "medium"


def test_graphql_absent(monkeypatch):
    _patch_http(monkeypatch, "graphql_probe", {})
    res = _run("graphql_probe", _url_target(), CtxStub())
    assert not res.findings


# ---------------------------------------------------------------------------
# rate_limit_audit
# ---------------------------------------------------------------------------

def test_rate_limit_documented():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers={"x-ratelimit-limit": "100",
                 "x-ratelimit-remaining": "99"},
        text="<html></html>")}
    res = _run("rate_limit_audit", _url_target(), CtxStub(pages))
    assert "rate_limit_documented" in _keys(res)


def test_rate_limit_no_signals():
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html></html>")}
    res = _run("rate_limit_audit", _url_target(), CtxStub(pages))
    assert "rate_limit_no_signals" in _keys(res)


# ---------------------------------------------------------------------------
# web_manifest
# ---------------------------------------------------------------------------

def test_manifest_no_icons(monkeypatch):
    manifest = {"name": "Shop", "start_url": "/",
                "icons": []}
    mapping = {"https://example.com/manifest.json": _resp(
        "https://example.com/manifest.json", json_data=manifest)}
    _patch_http(monkeypatch, "web_manifest", mapping)
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html></html>")}
    res = _run("web_manifest", _url_target(), CtxStub(pages))
    assert "manifest_no_icons" in _keys(res)


def test_manifest_absent(monkeypatch):
    _patch_http(monkeypatch, "web_manifest", {})
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html></html>")}
    res = _run("web_manifest", _url_target(), CtxStub(pages))
    assert not res.findings


# ---------------------------------------------------------------------------
# sri_audit
# ---------------------------------------------------------------------------

def test_sri_missing():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        text='<html><head><script src="https://cdn.other/x.js"></script>'
             '<link rel="stylesheet" href="https://cdn.other/y.css">'
             '<script src="/local.js"></script></head></html>')}
    res = _run("sri_audit", _url_target(), CtxStub(pages))
    assert "sri_missing" in _keys(res)
    assert len(res.findings) == 2  # local.js is same-origin, skipped


def test_sri_present_ok():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        text='<html><head><script src="https://cdn.other/x.js" '
             'integrity="sha384-abc" crossorigin="anonymous"></script>'
             '</head></html>')}
    res = _run("sri_audit", _url_target(), CtxStub(pages))
    assert not res.findings


# ---------------------------------------------------------------------------
# html_comments
# ---------------------------------------------------------------------------

def test_html_comments_intel():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        text="<!-- TODO: fix the auth bypass -->\n"
             "<!-- api_key = \"sk-live-1234567890abcdef\" -->\n"
             "<!-- staging host: db.internal -->\n"
             "<!-- /admin/backup.zip -->\n"
             "<html></html>")}
    res = _run("html_comments", _url_target(), CtxStub(pages))
    keys = _keys(res)
    assert "comment_credential" in keys
    assert "comment_todos" in keys
    assert "comment_internal_host" in keys
    assert "comment_endpoints" in keys
    cred = [f for f in res.findings if f.key == "comment_credential"][0]
    assert (cred.evidence or {}).get("severity") == "high"


# ---------------------------------------------------------------------------
# trackers
# ---------------------------------------------------------------------------

def test_trackers_found():
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        text='<html><script src="https://connect.facebook.net/en_US/'
             'fbevents.js"></script>'
             '<script src="https://www.google-analytics.com/analytics.js">'
             '</script></html>')}
    res = _run("trackers", _url_target(), CtxStub(pages))
    assert "third_party_trackers" in _keys(res)
    assert "Meta Pixel" in res.findings[0].value


def test_trackers_none():
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html></html>")}
    res = _run("trackers", _url_target(), CtxStub(pages))
    assert not res.findings


# ---------------------------------------------------------------------------
# well_known_audit
# ---------------------------------------------------------------------------

def test_well_known_security_txt(monkeypatch):
    mapping = {
        "https://example.com/.well-known/security.txt": _resp(
            "https://example.com/.well-known/security.txt",
            text="Contact: mailto:security@example.com\nExpires: 2027-01-01\n"),
        "https://example.com/.well-known/change-password": _resp(
            "https://example.com/.well-known/change-password",
            text="redirect"),
    }
    _patch_http(monkeypatch, "well_known_audit", mapping)
    res = _run("well_known_audit", _url_target(), CtxStub())
    keys = _keys(res)
    assert "security_txt_present" in keys
    assert "well_known_change_password" in keys
    assert "security_txt_missing" not in keys


def test_well_known_no_security_txt(monkeypatch):
    _patch_http(monkeypatch, "well_known_audit", {})
    res = _run("well_known_audit", _url_target(), CtxStub())
    assert "security_txt_missing" in _keys(res)


# ---------------------------------------------------------------------------
# redirect_chain
# ---------------------------------------------------------------------------

def test_redirect_off_domain(monkeypatch):
    mapping = {
        "https://example.com/": _resp(
            "https://example.com/", status=301,
            headers={"location": "https://other.net/"}),
        "https://other.net/": _resp("https://other.net/", status=200,
                                    text="hi"),
    }
    _patch_http(monkeypatch, "redirect_chain", mapping)
    res = _run("redirect_chain", _url_target("https://example.com/"),
               CtxStub())
    assert "redirect_off_domain" in _keys(res)


def test_redirect_plaintext_first_hop(monkeypatch):
    mapping = {
        "http://example.com/": _resp("http://example.com/", status=301,
                                     headers={"location":
                                              "https://example.com/"}),
        "https://example.com/": _resp("https://example.com/", status=200,
                                      text="hi"),
    }
    _patch_http(monkeypatch, "redirect_chain", mapping)
    res = _run("redirect_chain", _url_target("http://example.com/"),
               CtxStub())
    assert "redirect_plaintext_first_hop" in _keys(res)


# ---------------------------------------------------------------------------
# Canned DNS
# ---------------------------------------------------------------------------

class _FakeAnswer(list):
    """List of RR strings with a .response.flags like dnspython."""
    def __init__(self, rrs, aa=True):
        super().__init__(rrs)
        import dns.flags
        self.response = type("R", (), {
            "flags": dns.flags.AA if aa else 0})()


class _FakeMX:
    def __init__(self, exchange):
        self.exchange = exchange


class CannedResolver:
    """answers: {(name, rdtype): [rr strings] | 'NXDOMAIN' | _FakeMX list}."""
    answers = {}

    def __init__(self, *a, **k):
        pass

    async def resolve(self, name, rdtype):
        key = (str(name).rstrip(".").lower(), rdtype)
        if key not in CannedResolver.answers:
            raise dns.resolver.NXDOMAIN()
        val = CannedResolver.answers[key]
        if val == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        return _FakeAnswer(val)


@pytest.fixture()
def canned_dns(monkeypatch):
    import dns.asyncresolver
    CannedResolver.answers = {}
    monkeypatch.setattr(dns.asyncresolver, "Resolver", CannedResolver)
    yield CannedResolver
    CannedResolver.answers = {}


# ---------------------------------------------------------------------------
# dns_infra
# ---------------------------------------------------------------------------

def test_dns_infra_single_ns(canned_dns):
    canned_dns.answers = {
        ("example.com", "NS"): ["ns1.example.com."],
        ("example.com", "SOA"): ["ns1.example.com. hostmaster.example.com. "
                                 "1 86400 7200 1209600 3600"],
        ("ns1.example.com", "A"): ["93.184.216.34"],
    }
    res = _run("dns_infra", _domain_target(), CtxStub())
    assert "dns_single_ns" in _keys(res)


def test_dns_infra_no_ns_degraded(canned_dns):
    res = _run("dns_infra", _domain_target(), CtxStub())
    assert not res.findings  # degraded, no NS resolvable


def test_dns_infra_soa_expire(canned_dns):
    canned_dns.answers = {
        ("example.com", "NS"): ["ns1.example.com.", "ns2.example.com."],
        ("example.com", "SOA"): ["ns1.example.com. hostmaster.example.com. "
                                 "1 86400 172800 3600 300"],
        ("ns1.example.com", "A"): ["93.184.216.34"],
        ("ns2.example.com", "A"): ["93.184.216.35"],
    }
    res = _run("dns_infra", _domain_target(), CtxStub())
    keys = _keys(res)
    # expire=3600 < 7d -> short; retry(172800) >= refresh(86400) -> bad
    assert "soa_expire_short" in keys
    assert "soa_retry_gte_refresh" in keys


# ---------------------------------------------------------------------------
# ipv6_check
# ---------------------------------------------------------------------------

def test_ipv6_no_aaaa(canned_dns):
    res = _run("ipv6_check", _domain_target(), CtxStub())
    assert "ipv6_no_aaaa" in _keys(res)


def test_ipv6_ready(canned_dns, monkeypatch):
    canned_dns.answers = {("example.com", "AAAA"): ["2606:2800:220:1::1"]}
    mod = _mod("ipv6_check")
    monkeypatch.setattr(mod, "_probe", lambda ip: True)
    res = _run("ipv6_check", _domain_target(), CtxStub())
    assert "ipv6_ready" in _keys(res)


def test_ipv6_broken(canned_dns, monkeypatch):
    canned_dns.answers = {("example.com", "AAAA"): ["2606:2800:220:1::1"]}
    mod = _mod("ipv6_check")
    monkeypatch.setattr(mod, "_probe", lambda ip: False)
    res = _run("ipv6_check", _domain_target(), CtxStub())
    assert "ipv6_broken" in _keys(res)


# ---------------------------------------------------------------------------
# ip_reputation
# ---------------------------------------------------------------------------

def test_ip_reputation_clean(canned_dns):
    canned_dns.answers = {("example.com", "A"): ["93.184.216.34"]}
    res = _run("ip_reputation", _domain_target(), CtxStub())
    assert "ip_reputation_clean" in _keys(res)


def test_ip_reputation_listed(canned_dns):
    canned_dns.answers = {
        ("example.com", "A"): ["93.184.216.34"],
        ("34.216.184.93.zen.spamhaus.org", "A"): ["127.0.0.2"],
        ("34.216.184.93.zen.spamhaus.org", "TXT"): ["listed test"],
    }
    res = _run("ip_reputation", _domain_target(), CtxStub())
    assert "ip_blocklisted" in _keys(res)
    f = [x for x in res.findings if x.key == "ip_blocklisted"][0]
    assert (f.evidence or {}).get("severity") == "medium"


# ---------------------------------------------------------------------------
# smtp_tls
# ---------------------------------------------------------------------------

def test_smtp_no_starttls(canned_dns, monkeypatch):
    canned_dns.answers = {
        ("example.com", "MX"): [_FakeMX("mail.example.com.")],
    }
    mod = _mod("smtp_tls")
    monkeypatch.setattr(mod, "_smtp_audit", lambda host, timeout=10.0: {
        "host": host, "banner": "220 mail ESMTP", "starttls": False,
        "tls_ok": False, "tls_version": "", "auth_plain": False, "error": ""})
    res = _run("smtp_tls", _domain_target(), CtxStub())
    assert "smtp_no_starttls" in _keys(res)


def test_smtp_no_mx_skipped(canned_dns):
    res = _run("smtp_tls", _domain_target(), CtxStub())
    assert not res.findings


# ---------------------------------------------------------------------------
# cdn_detect
# ---------------------------------------------------------------------------

def test_cdn_cloudflare(canned_dns):
    pages = {"https://example.com/": _resp(
        "https://example.com/",
        headers={"cf-ray": "abc123", "server": "cloudflare"},
        text="<html></html>")}
    res = _run("cdn_detect", _url_target(), CtxStub(pages))
    assert "cdn_detected" in _keys(res)
    assert "Cloudflare" in res.findings[0].value


def test_cdn_none(canned_dns):
    pages = {"https://example.com/": _resp("https://example.com/",
                                           text="<html></html>")}
    res = _run("cdn_detect", _url_target(), CtxStub(pages))
    assert not res.findings


# ---------------------------------------------------------------------------
# typosquat
# ---------------------------------------------------------------------------

def test_typosquat_registered(canned_dns):
    # "example" omission variant "exampl" is generated; NXDOMAIN the rest.
    canned_dns.answers = {("exampl.com", "A"): ["93.184.216.99"]}
    res = _run("typosquat", _domain_target(), CtxStub())
    keys = _keys(res)
    assert "typosquat_registered" in keys
    hit = [f for f in res.findings
           if (f.evidence or {}).get("domain") == "exampl.com"]
    assert hit and hit[0].confidence == 95


def test_typosquat_none_registered(canned_dns):
    res = _run("typosquat", _domain_target(), CtxStub())
    assert not res.findings


def test_typosquat_variants_unit():
    from app.plugins.typosquat import _variants
    vs = _variants("example")
    assert "exampl" in vs          # omission
    assert "exmaple" in vs         # adjacent swap
    assert "examplee" in vs        # doubling
    assert "example" not in vs
    assert len(vs) <= 120


# ---------------------------------------------------------------------------
# tls_config
# ---------------------------------------------------------------------------

def test_tls_deprecated_version(monkeypatch):
    import ssl as _ssl
    mod = _mod("tls_config")

    def fake_probe(host, versions):
        if _ssl.TLSVersion.TLSv1 in versions:
            return ("TLSv1", "DES-CBC3-SHA", False)
        if _ssl.TLSVersion.TLSv1_2 in versions:
            return ("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", False)
        return (None, "", False)

    monkeypatch.setattr(mod, "_probe", fake_probe)
    res = _run("tls_config", _domain_target(), CtxStub())
    assert "tls_deprecated_version" in _keys(res)


def test_tls_modern_ok(monkeypatch):
    import ssl as _ssl
    mod = _mod("tls_config")

    def fake_probe(host, versions):
        if _ssl.TLSVersion.TLSv1_3 in versions:
            return ("TLSv1.3", "TLS_AES_256_GCM_SHA384", False)
        return (None, "", False)

    monkeypatch.setattr(mod, "_probe", fake_probe)
    res = _run("tls_config", _domain_target(), CtxStub())
    assert "tls_deprecated_version" not in _keys(res)
    assert "tls_no_forward_secrecy" not in _keys(res)


# ---------------------------------------------------------------------------
# caa_audit
# ---------------------------------------------------------------------------

def test_caa_missing(canned_dns):
    res = _run("caa_audit", _domain_target(), CtxStub())
    assert "caa_missing" in _keys(res)


def test_caa_no_issuewild(canned_dns):
    canned_dns.answers = {
        ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
    }
    res = _run("caa_audit", _domain_target(), CtxStub())
    assert "caa_no_issuewild" in _keys(res)
    assert "caa_missing" not in _keys(res)


# ---------------------------------------------------------------------------
# fastmode: new inline checks reuse the audit helpers
# ---------------------------------------------------------------------------

def test_fastmode_cookie_csp_hsts(monkeypatch):
    from app.plugins import fastmode as fm
    home = _resp(
        "https://example.com/",
        headers=[("set-cookie", "sessid=abc; Path=/"),
                 ("content-security-policy",
                  "script-src 'unsafe-inline' 'self'"),
                 ("strict-transport-security", "max-age=1000")],
        text="<html></html>")
    # stub the network-heavy parts; we only exercise the homepage checks
    async def fake_fetch_many(client, limiter, requests, **kw):
        return [home] + [None] * (len(requests) - 1)

    async def fake_fetch(client, limiter, method, url, **kw):
        raise ConnectionError("stubbed")

    monkeypatch.setattr(fm, "fetch_many", fake_fetch_many, raising=False)
    monkeypatch.setattr(fm, "fetch", fake_fetch, raising=False)
    monkeypatch.setattr(fm.socket, "gethostbyname",
                        lambda h: (_ for _ in ()).throw(
                            OSError("stubbed")))
    import dns.asyncresolver
    monkeypatch.setattr(dns.asyncresolver, "Resolver", CannedResolver)
    CannedResolver.answers = {}
    p = fm.FastmodePlugin()
    res = asyncio.run(p.run(_url_target("https://example.com"), CtxStub()))
    keys = {f.key for f in res.findings}
    assert "fast_cookie_flags" in keys
    assert "fast_csp_unsafe_inline" in keys
    assert "fast_hsts_weak" in keys
