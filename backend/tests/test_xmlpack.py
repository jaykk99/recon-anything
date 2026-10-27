"""Unit gate for the xml_* reader pack (5 detectors).

Every xml plugin runs through the REAL Ctx against a canary served
via httpx MockTransport (tests/xmlpack_samples.py): each extraction
class must fire on the canary, every plugin must stay silent on the
clean site, and no full planted secret may appear in any finding
(masked + fingerprint only).
"""
import asyncio
import hashlib
import json
import os
import sys
from urllib.parse import urlsplit

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import xmlpack_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.plugins.xmlpack import XML_IDS, _parse  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "canary.test"
CLEAN = "clean.test"
REQUESTED: list = []


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path or "/"
    REQUESTED.append(path)
    if host == CLEAN:
        if path in ("/", "/index.html"):
            return httpx.Response(200, content=samples.CLEAN_HTML,
                                  headers={"Content-Type": "text/html"},
                                  request=request)
        if path == "/robots.txt":
            return httpx.Response(200, content=samples.CLEAN_ROBOTS,
                                  headers={"Content-Type": "text/plain"},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)
    if host == CANARY:
        if path == "/maps/pages.xml":
            pass  # fall through to ROUTES (query-free)
        route = samples.ROUTES.get(path)
        if route is not None:
            ctype, body = route
            return httpx.Response(200, content=body,
                                  headers={"Content-Type": ctype},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)
    return httpx.Response(404, content="", request=request)


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="xmlpack-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run(pid: str, host: str):
    cls = discover()[pid]
    ctx = _ctx()
    target = Target(raw=f"https://{host}/", type="url",
                    normalized=f"https://{host}/")
    try:
        return asyncio.run(cls().run(target, ctx))
    finally:
        asyncio.run(ctx.http.aclose())


def _run_with_ctx(pid: str, host: str):
    cls = discover()[pid]
    ctx = _ctx()
    target = Target(raw=f"https://{host}/", type="url",
                    normalized=f"https://{host}/")
    try:
        return asyncio.run(cls().run(target, ctx)), ctx
    finally:
        asyncio.run(ctx.http.aclose())


def _by_key(result, key):
    return [f for f in result.findings if f.key == key]


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _blob(result) -> str:
    return json.dumps([f.value for f in result.findings]) + json.dumps(
        [f.evidence for f in result.findings], default=str)


# ---------------------------------------------------------------------------

def test_exactly_5_new_detectors_registered():
    xml = sorted(k for k in discover() if k.startswith("xml_"))
    assert xml == sorted(XML_IDS)
    assert len(xml) == 5
    # 592 when the xml pack landed; +10 da_* (deep-artifacts pack);
    # +5 ai_* (AI-crawler surface pack)
    assert len(discover()) == 616  # 615 + 1 altsvc_audit (Alt-Svc header audit, 2026-10-27)


def test_connstr_password_masked_with_fingerprint():
    r = _run("xml_secrets", CANARY)
    hits = _by_key(r, "xml_connection_string")
    assert hits, r.reason
    assert hits[0].evidence["fingerprint_sha256"] == _fp(samples.CONN_PWD)
    assert samples.CONN_PWD not in _blob(r)


def test_credential_attribute_masked():
    r = _run("xml_secrets", CANARY)
    hits = _by_key(r, "xml_credential_attribute")
    assert hits, r.reason
    assert hits[0].evidence["fingerprint_sha256"] == _fp(samples.ATTR_PWD)
    assert samples.ATTR_PWD not in _blob(r)


def test_api_key_element_masked():
    r = _run("xml_secrets", CANARY)
    fps = {f.evidence.get("fingerprint_sha256") for f in r.findings}
    assert _fp(samples.STRIPE_KEY) in fps
    assert samples.STRIPE_KEY not in _blob(r)


def test_js_discovered_xml_is_mined():
    # /static/endpoints.xml is only reachable via the homepage's JS
    r = _run("xml_secrets", CANARY)
    fps = {f.evidence.get("fingerprint_sha256") for f in r.findings}
    assert _fp(samples.GH_TOKEN) in fps
    assert samples.GH_TOKEN not in _blob(r)
    hosts = {f.evidence.get("host")
             for f in _by_key(r, "xml_internal_reference")}
    assert "billing.internal" in hosts


def test_internal_refs_and_service_endpoint():
    r = _run("xml_secrets", CANARY)
    hosts = {f.evidence.get("host")
             for f in _by_key(r, "xml_internal_reference")}
    assert "10.20.30.40" in hosts
    assert "db.internal" in hosts
    eps = {f.evidence.get("host")
           for f in _by_key(r, "xml_service_endpoint")}
    assert "api.partner-example.com" in eps


def test_pii_validated_and_masked():
    r = _run("xml_secrets", CANARY)
    assert _by_key(r, "xml_pii_ssn"), r.reason
    assert _by_key(r, "xml_pii_iban"), r.reason
    blob = _blob(r)
    assert "123-45-6789" not in blob
    assert "GB29NWBK60161331926819" not in blob
    assert "GB29 NWBK" not in blob


def test_sitemap_sensitive_paths_incl_index_children():
    r = _run("xml_sitemap_paths", CANARY)
    vals = " ".join(f.value for f in
                    _by_key(r, "xml_sitemap_sensitive_url"))
    for needle in ("/admin/panel", "/.git/config", "/backup/full.sql",
                   "/login", "/config/settings"):
        assert needle in vals, needle


def test_sitemap_internal_url():
    r = _run("xml_sitemap_paths", CANARY)
    hits = _by_key(r, "xml_sitemap_internal_url")
    assert hits and hits[0].evidence["host"] == "intranet.corp"


def test_sitemap_feeds_hunter_bus():
    r, ctx = _run_with_ctx("xml_sitemap_paths", CANARY)
    endpoints = ctx.consume("endpoints") \
        if hasattr(ctx, "consume") else ctx.shared.get("endpoints", [])
    urls = [e if isinstance(e, str) else str(e) for e in endpoints]
    assert any("/admin/panel" in u for u in urls), urls[:5]


def test_xxe_surface_external_entities():
    REQUESTED.clear()
    r = _run("xml_xxe_surface", CANARY)
    hits = _by_key(r, "xml_external_entity")
    assert len(hits) >= 2, r.reason
    by_name = {h.evidence["entity"]: h for h in hits}
    assert by_name["xxe"].evidence["system_id"] == "file:///etc/passwd"
    assert by_name["pe"].evidence["parameter_entity"] is True
    # the declared entity URI must never be fetched
    assert "/pe.dtd" not in REQUESTED


def test_policy_wildcard_and_site_control():
    r = _run("xml_policy", CANARY)
    wild = _by_key(r, "xml_crossdomain_wildcard")
    assert wild and wild[0].evidence["domain"] == "*"
    assert _by_key(r, "xml_policy_site_control_all")
    # the restrictive clientaccesspolicy.xml stays silent
    assert not _by_key(r, "xml_clientaccess_wildcard")


def test_wsdl_surface():
    r = _run("xml_wsdl", CANARY)
    svc = _by_key(r, "xml_wsdl_service")
    assert svc, r.reason
    assert "GetAccount" in svc[0].evidence["operations"]
    assert "TransferFunds" in svc[0].evidence["operations"]
    internal = _by_key(r, "xml_wsdl_internal_endpoint")
    assert internal and "10.20.30.41" in internal[0].evidence["location"]
    assert _by_key(r, "xml_wsdl_endpoint")
    assert _by_key(r, "xml_wsdl_import")


def test_parser_never_expands_entities():
    root = _parse(samples.LEGACY_XML)
    assert root is not None and root.tag == "legacy"
    # billion-laughs shape: parses (DTD stripped) without expansion
    laughs = ('<?xml version="1.0"?><!DOCTYPE lolz ['
              '<!ENTITY a "xxxxxxxxxx">'
              '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">'
              '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">]>'
              '<lolz>&c;</lolz>')
    assert _parse(laughs) is not None
    assert _parse("<configuration><unclosed>") is None
    assert _parse("") is None


def test_malformed_xml_degrades_gracefully():
    for pid in XML_IDS:
        r = _run(pid, CANARY)
        assert r.status.value == "ok", f"{pid}: {r.status} {r.reason}"


@pytest.mark.parametrize("pid", XML_IDS)
def test_clean_site_silence(pid):
    r = _run(pid, CLEAN)
    assert r.status.value == "ok", f"{pid}: {r.status} {r.reason}"
    assert not r.findings, f"{pid} fired on the clean site: " \
                           f"{[f.key for f in r.findings]}"


def test_no_planted_secret_anywhere():
    for pid in XML_IDS:
        r = _run(pid, CANARY)
        blob = _blob(r)
        for secret in samples.PLANTED_SECRETS:
            assert secret not in blob, f"{pid} leaked {secret[:6]}..."
