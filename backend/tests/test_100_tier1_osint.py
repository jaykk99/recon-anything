"""Tier-1 OSINT plugins (100-plugin expansion, 2026-11-05).

Per plugin: fires on the VULN fixture, silent on the CLEAN fixture,
no crash on malformed/empty targets. Deterministic: everything runs
over httpx MockTransport - the shared plugin_fixtures transport
where it already models the service (crt.sh, hackertarget, the
Cloudflare-fronted host, the tech-laden home page) and a local
transport below for the services it does not (AnubisDB, RapidDNS,
Common Crawl, DoH per-name answers, RDAP, InternetDB, Censys,
Crunchbase, WhoisXML).

Keyed wrappers (censys_search, crunchbase_lookup): with no key they
must return a clean "needs key" skip and zero findings; the real
query path is exercised with a dummy key against the mock.
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

IDS = ["subfinder", "amass", "assetfinder", "censys_search",
       "shodan_lookup", "crunchbase_lookup", "builtwith_scan",
       "cloudflare_detect", "whoisxml_lookup", "dnstwist"]

VULN = "vuln.test"
CLEAN = "clean.test"


# ---------------------------------------------------------------------------
# Local deterministic transport
# ---------------------------------------------------------------------------

def _domain_of(request) -> str:
    """Best-effort target domain referenced by an API request."""
    q = parse_qs(urlparse(str(request.url)).query)
    for key in ("q", "name", "url", "domainName"):
        for val in q.get(key, []):
            v = val.strip("%*.").split("/")[0].split(":")[0]
            if v.endswith(".test"):
                return v
    path = urlparse(str(request.url)).path
    for part in path.split("/"):
        if part.endswith(".test"):
            return part
    try:
        body = json.loads(request.content or b"{}")
        vals = body.get("query", [{}])[0].get("values", [])
        if vals:
            return str(vals[0])
    except Exception:
        pass
    return ""


def _subs(domain):
    return [f"www.{domain}", f"api.{domain}", f"mail.{domain}"]


def _handler(request: httpx.Request) -> httpx.Response:
    url = urlparse(str(request.url))
    host, path = url.hostname or "", url.path or "/"
    domain = _domain_of(request)
    is_clean = domain.startswith("clean") or host == CLEAN

    if host == "crt.sh":
        if is_clean or not domain:
            return httpx.Response(200, json=[], request=request)
        rows = [{"name_value": "\n".join(_subs(domain)),
                 "common_name": domain}]
        return httpx.Response(200, json=rows, request=request)
    if host == "api.hackertarget.com":
        if is_clean or not domain:
            return httpx.Response(200, text="error invalid host",
                                  request=request)
        return httpx.Response(
            200, text=f"api.{domain},192.0.2.10\nmail.{domain},192.0.2.10\n",
            request=request)
    if host == "anubisdb.com":
        if is_clean or not domain:
            return httpx.Response(200, json=[], request=request)
        return httpx.Response(
            200, json=[f"dev.{domain}", f"www.{domain}"], request=request)
    if host == "rapiddns.io":
        if is_clean or not domain:
            return httpx.Response(200, text="<html></html>",
                                  request=request)
        return httpx.Response(
            200, text=f"<html><td>staging.{domain}</td></html>",
            request=request)
    if host == "index.commoncrawl.org":
        if path == "/collinfo.json":
            return httpx.Response(200, json=[{
                "cdx-index": "https://index.commoncrawl.org/CC-TEST-index"
            }], request=request)
        if is_clean or not domain:
            return httpx.Response(200, text="", request=request)
        ndjson = "\n".join(
            json.dumps({"url": u}) for u in
            (f"https://blog.{domain}/a", f"https://www.{domain}/b"))
        return httpx.Response(200, text=ndjson, request=request)
    if host == "web.archive.org":
        if is_clean or not domain:
            return httpx.Response(200, json=[], request=request)
        return httpx.Response(200, json=[
            ["timestamp", "original"],
            ["20230101000000", f"https://shop.{domain}/"],
        ], request=request)
    if host == "dns.google":
        q = parse_qs(url.query)
        name = (q.get("name") or [""])[0]
        rtype = (q.get("type") or ["A"])[0]
        answers = []
        if name == "f1xture.test" and rtype == "A":
            answers = [{"name": name, "type": 1, "TTL": 60,
                        "data": "192.0.2.55"}]
        elif name.endswith("." + VULN) or name == VULN:
            if rtype == "A":
                ip = "203.0.113.99" if name.startswith(("mail.", "af-")) \
                    else "192.0.2.10"
                answers = [{"name": name, "type": 1, "TTL": 60,
                            "data": ip}]
        return httpx.Response(200, json={"Answer": answers},
                              request=request)
    if host == "rdap.org" and path.startswith("/domain/"):
        if is_clean:
            return httpx.Response(404, json={}, request=request)
        return httpx.Response(200, json={
            "ldhName": domain,
            "status": ["client transfer prohibited"],
            "events": [
                {"eventAction": "registration",
                 "eventDate": "2015-03-04T00:00:00Z"},
                {"eventAction": "expiration",
                 "eventDate": "2030-03-04T00:00:00Z"},
                {"eventAction": "last changed",
                 "eventDate": "2024-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "ns1.fixture-dns.test"},
                            {"ldhName": "ns2.fixture-dns.test"}],
            "entities": [
                {"roles": ["registrar"], "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Fixture Registrar LLC"]]]},
                {"roles": ["registrant"], "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Fixture Corp"]]]}],
        }, request=request)
    if host == "rdap.org" and path.startswith("/ip/"):
        return httpx.Response(200, json={
            "name": "FIXTURE-NET", "handle": "NET-192-0-2-0-1",
            "originAS": "AS64500",
            "entities": [{"roles": ["registrant"], "vcardArray": [
                "vcard", [["version", {}, "text", "4.0"],
                          ["fn", {}, "text", "Fixture Hosting Inc"]]]}],
        }, request=request)
    if host == "internetdb.shodan.io":
        ip = path.strip("/")
        if ip == "192.0.2.10":
            return httpx.Response(200, json={
                "ip": ip, "ports": [22, 443, 6379],
                "vulns": ["CVE-2021-41773"], "tags": ["cloud"],
                "hostnames": [VULN], "cpes": [],
            }, request=request)
        return httpx.Response(404, json={"detail": "No information"},
                              request=request)
    if host == "search.censys.io":
        return httpx.Response(200, json={"result": {"hits": [{
            "ip": "192.0.2.10",
            "services": [{"port": 443, "service_name": "HTTP",
                          "transport_protocol": "TCP"}],
            "location": {"country": "Canada"}}]}}, request=request)
    if host == "api.crunchbase.com":
        if is_clean:
            return httpx.Response(200, json={"entities": []},
                                  request=request)
        return httpx.Response(200, json={"entities": [{
            "properties": {
                "name": "Fixture Corp",
                "short_description": "Fixture company",
                "founded_on": "2015-03-04",
                "website_url": f"https://{domain}/",
                "funding_total": {"value_usd": 1200000},
                "location_identifiers": [{"value": "Winnipeg"}],
            }}]}, request=request)
    if host == "www.whoisxmlapi.com":
        return httpx.Response(200, json={"WhoisRecord": {
            "registrarName": "Fixture Registrar LLC",
            "registryData": {
                "createdDateNormalized": "2015-03-04 00:00:00 UTC"}}},
            request=request)
    if host == VULN:
        if path == "/cdn-cgi/trace":
            return httpx.Response(404, text="no", request=request)
        return httpx.Response(
            200, headers={
                "Content-Type": "text/html", "Server": "Apache/2.4.49",
                "X-Powered-By": "PHP/7.4.3"},
            content=("<html><head>"
                     '<meta name="generator" content="WordPress 6.4.2">'
                     '<script src="/wp-content/themes/x/style.css">'
                     "</script>"
                     '<script src="https://www.googletagmanager.com/'
                     'gtag/js?id=G-FIXTURE123"></script>'
                     '<script src="https://www.googletagmanager.com/'
                     'gtm.js?id=GTM-FIXTURE1"></script>'
                     '<script src="https://code.jquery.com/'
                     'jquery-3.7.1.min.js"></script>'
                     "</head><body>fixture</body></html>"),
            request=request)
    if host == "cf.test":
        cf = {"Server": "cloudflare", "CF-Ray": "8abc-fixture",
              "Set-Cookie": "__cf_bm=abc; path=/; HttpOnly"}
        if path == "/cdn-cgi/trace":
            return httpx.Response(
                200, headers=cf, request=request,
                content="fl=123\nh=cf.test\nip=192.0.2.1\n")
        return httpx.Response(
            200, headers=cf, request=request,
            content=('<html><head><title>cf</title></head><body>'
                     '<script src="/cdn-cgi/scripts/main.js"></script>'
                     "behind cloudflare</body></html>"))
    if host == CLEAN:
        return httpx.Response(
            200, headers={"Content-Type": "text/html",
                          "Server": "CustomServer/1.0"},
            content="<html><title>hi</title>plain page</html>",
            request=request)
    return httpx.Response(404, content="", request=request)


def make_ctx(keys=None, transport=None):
    client = httpx.AsyncClient(
        transport=transport or httpx.MockTransport(_handler),
        follow_redirects=True, trust_env=False,
        headers={"User-Agent": "ReconAnything-Test/1.0"})
    return Ctx(run_id="tier1-test", mode="passive", http=client,
               cache=Cache(), keys=keys or {}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def run(cls, target, keys=None, transport=None):
    async def _go():
        ctx = make_ctx(keys=keys, transport=transport)
        try:
            return await cls().run(target, ctx)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def domain(name):
    return Target(raw=name, type="domain", normalized=name)


@pytest.fixture(autouse=True)
def _no_real_keys(monkeypatch):
    for var in ("CENSYS_API_ID", "CENSYS_API_SECRET", "CRUNCHBASE_API_KEY",
                "WHOISXML_API_KEY", "SHODAN_API_KEY"):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_all_ten_registered_and_count_857():
    reg = discover()
    assert len(reg) == 927, f"registry size {len(reg)}, expected 927"
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

def test_subfinder_fires_on_vuln():
    from app.plugins.subfinder import SubfinderPlugin
    res = run(SubfinderPlugin, domain(VULN))
    subs = {f.value for f in res.findings if f.key == "subdomain"}
    assert {"www.vuln.test", "api.vuln.test", "mail.vuln.test",
            "dev.vuln.test", "staging.vuln.test"} <= subs


def test_subfinder_silent_on_clean():
    from app.plugins.subfinder import SubfinderPlugin
    res = run(SubfinderPlugin, domain(CLEAN))
    assert [f for f in res.findings if f.key == "subdomain"] == []


def test_subfinder_malformed_no_crash():
    from app.plugins.subfinder import SubfinderPlugin
    res = run(SubfinderPlugin, Target(raw="192.0.2.1", type="ip",
                                      normalized="192.0.2.1"))
    assert res.findings == []
    res = run(SubfinderPlugin, domain(""))
    assert res.findings == []


def test_subfinder_shared_fixture():
    import plugin_fixtures as fx
    from app.plugins.subfinder import SubfinderPlugin

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        try:
            return await SubfinderPlugin().run(fx.domain_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    subs = {f.value for f in res.findings if f.key == "subdomain"}
    assert {"www.fixture.test", "api.fixture.test",
            "mail.fixture.test"} <= subs


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------

def test_amass_fires_on_vuln():
    from app.plugins.amass import AmassPlugin
    res = run(AmassPlugin, domain(VULN))
    orgs = [f for f in res.findings if f.key == "asn_org"]
    assert orgs and "Fixture Hosting Inc" in orgs[0].value
    assert "AS64500" in orgs[0].value
    assert any(f.key == "subdomain" for f in res.findings)


def test_amass_silent_on_clean():
    from app.plugins.amass import AmassPlugin
    res = run(AmassPlugin, domain(CLEAN))
    assert res.findings == []


def test_amass_malformed_no_crash():
    from app.plugins.amass import AmassPlugin
    res = run(AmassPlugin, Target(raw="192.0.2.1", type="ip",
                                  normalized="192.0.2.1"))
    assert res.findings == []


# ---------------------------------------------------------------------------
# assetfinder
# ---------------------------------------------------------------------------

def test_assetfinder_fires_and_filters_wildcard():
    from app.plugins.assetfinder import AssetfinderPlugin
    res = run(AssetfinderPlugin, domain(VULN))
    subs = {f.value for f in res.findings if f.key == "subdomain"}
    assert {"www.vuln.test", "api.vuln.test", "blog.vuln.test",
            "shop.vuln.test"} <= subs
    # mail.vuln.test resolves only to the wildcard address: filtered.
    assert "mail.vuln.test" not in subs
    assert any(f.key == "wildcard_dns" for f in res.findings)


def test_assetfinder_silent_on_clean():
    from app.plugins.assetfinder import AssetfinderPlugin
    res = run(AssetfinderPlugin, domain(CLEAN))
    assert res.findings == []


def test_assetfinder_malformed_no_crash():
    from app.plugins.assetfinder import AssetfinderPlugin
    res = run(AssetfinderPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# censys_search (keyed)
# ---------------------------------------------------------------------------

def test_censys_needs_key_cleanly():
    from app.plugins.censys_search import CensysSearchPlugin
    res = run(CensysSearchPlugin, domain(VULN))
    assert res.findings == []
    assert "needs key" in (res.reason or "")


def test_censys_with_key_fires():
    from app.plugins.censys_search import CensysSearchPlugin
    res = run(CensysSearchPlugin, domain(VULN),
              keys={"CENSYS_API_ID": "dummy-id",
                    "CENSYS_API_SECRET": "dummy-secret"})
    hits = [f for f in res.findings if f.key == "censys_host"]
    assert hits and "192.0.2.10" in hits[0].value


def test_censys_malformed_no_crash():
    from app.plugins.censys_search import CensysSearchPlugin
    res = run(CensysSearchPlugin, Target(raw="AS64500", type="asn",
                                         normalized="AS64500"),
              keys={"CENSYS_API_ID": "d", "CENSYS_API_SECRET": "d"})
    assert res.findings == []


# ---------------------------------------------------------------------------
# shodan_lookup
# ---------------------------------------------------------------------------

def test_shodan_fires_on_vuln_ip():
    from app.plugins.shodan_lookup import ShodanLookupPlugin
    res = run(ShodanLookupPlugin,
              Target(raw="192.0.2.10", type="ip", normalized="192.0.2.10"))
    keys = {f.key for f in res.findings}
    assert "shodan_host" in keys
    assert "exposed_service_port" in keys
    cves = [f for f in res.findings if f.key == "known_cve"]
    assert cves and "CVE-2021-41773" in cves[0].value


def test_shodan_fires_on_vuln_domain():
    from app.plugins.shodan_lookup import ShodanLookupPlugin
    res = run(ShodanLookupPlugin, domain(VULN))
    assert any(f.key == "shodan_host" for f in res.findings)


def test_shodan_silent_on_clean_ip():
    from app.plugins.shodan_lookup import ShodanLookupPlugin
    res = run(ShodanLookupPlugin,
              Target(raw="192.0.2.99", type="ip", normalized="192.0.2.99"))
    assert res.findings == []


def test_shodan_malformed_no_crash():
    from app.plugins.shodan_lookup import ShodanLookupPlugin
    res = run(ShodanLookupPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# crunchbase_lookup (keyed)
# ---------------------------------------------------------------------------

def test_crunchbase_needs_key_cleanly():
    from app.plugins.crunchbase_lookup import CrunchbaseLookupPlugin
    res = run(CrunchbaseLookupPlugin, domain(VULN))
    assert res.findings == []
    assert "needs key" in (res.reason or "")


def test_crunchbase_with_key_fires():
    from app.plugins.crunchbase_lookup import CrunchbaseLookupPlugin
    res = run(CrunchbaseLookupPlugin, domain(VULN),
              keys={"CRUNCHBASE_API_KEY": "dummy-key"})
    orgs = [f for f in res.findings if f.key == "organization"]
    assert orgs and "Fixture Corp" in orgs[0].value


def test_crunchbase_with_key_clean_silent():
    from app.plugins.crunchbase_lookup import CrunchbaseLookupPlugin
    res = run(CrunchbaseLookupPlugin, domain(CLEAN),
              keys={"CRUNCHBASE_API_KEY": "dummy-key"})
    assert res.findings == []


# ---------------------------------------------------------------------------
# builtwith_scan
# ---------------------------------------------------------------------------

def test_builtwith_fires_on_shared_fixture():
    import plugin_fixtures as fx
    from app.plugins.builtwith_scan import BuiltwithScanPlugin

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        try:
            return await BuiltwithScanPlugin().run(fx.url_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    techs = {f.value for f in res.findings if f.key == "tech"}
    assert "WordPress" in techs
    assert "Apache" in techs
    assert "PHP" in techs


def test_builtwith_fires_on_vuln():
    from app.plugins.builtwith_scan import BuiltwithScanPlugin
    res = run(BuiltwithScanPlugin, domain(VULN))
    techs = {f.value for f in res.findings if f.key == "tech"}
    assert {"WordPress", "Google Tag Manager", "jQuery"} <= techs


def test_builtwith_silent_on_clean():
    from app.plugins.builtwith_scan import BuiltwithScanPlugin
    res = run(BuiltwithScanPlugin, domain(CLEAN))
    assert res.findings == []


def test_builtwith_malformed_no_crash():
    from app.plugins.builtwith_scan import BuiltwithScanPlugin
    res = run(BuiltwithScanPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# cloudflare_detect
# ---------------------------------------------------------------------------

def test_cloudflare_fires_on_shared_waf_fixture():
    import plugin_fixtures as fx
    from app.plugins.cloudflare_detect import CloudflareDetectPlugin

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        try:
            target = Target(raw="http://waf.fixture.test/", type="url",
                            normalized="http://waf.fixture.test/")
            return await CloudflareDetectPlugin().run(target, ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    assert any(f.key == "cloudflare_fronted" for f in res.findings)


def test_cloudflare_fires_on_cf_fixture():
    from app.plugins.cloudflare_detect import CloudflareDetectPlugin
    res = run(CloudflareDetectPlugin, domain("cf.test"))
    assert any(f.key == "cloudflare_fronted" for f in res.findings)


def test_cloudflare_silent_on_plain_fixture():
    import plugin_fixtures as fx
    from app.plugins.cloudflare_detect import CloudflareDetectPlugin

    async def _go():
        ctx = fx.make_fixture_ctx(seed=False)
        try:
            return await CloudflareDetectPlugin().run(
                fx.url_target(), ctx)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    assert [f for f in res.findings
            if f.key == "cloudflare_fronted"] == []


def test_cloudflare_malformed_no_crash():
    from app.plugins.cloudflare_detect import CloudflareDetectPlugin
    res = run(CloudflareDetectPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# whoisxml_lookup
# ---------------------------------------------------------------------------

def test_whoisxml_rdap_fires_on_vuln():
    from app.plugins.whoisxml_lookup import WhoisxmlLookupPlugin
    res = run(WhoisxmlLookupPlugin, domain(VULN))
    by_key = {f.key: f.value for f in res.findings}
    assert by_key.get("whois_registrar") == "Fixture Registrar LLC"
    assert by_key.get("whois_created") == "2015-03-04T00:00:00Z"
    assert "needs key" in (res.reason or "")


def test_whoisxml_with_key_adds_whoisxml_facts():
    from app.plugins.whoisxml_lookup import WhoisxmlLookupPlugin
    res = run(WhoisxmlLookupPlugin, domain(VULN),
              keys={"WHOISXML_API_KEY": "dummy-key"})
    assert any(f.key == "whoisxml_registrar" for f in res.findings)


def test_whoisxml_silent_on_clean():
    from app.plugins.whoisxml_lookup import WhoisxmlLookupPlugin
    res = run(WhoisxmlLookupPlugin, domain(CLEAN))
    assert res.findings == []


def test_whoisxml_malformed_no_crash():
    from app.plugins.whoisxml_lookup import WhoisxmlLookupPlugin
    res = run(WhoisxmlLookupPlugin,
              Target(raw="192.0.2.1", type="ip", normalized="192.0.2.1"))
    assert res.findings == []


# ---------------------------------------------------------------------------
# dnstwist
# ---------------------------------------------------------------------------

def test_dnstwist_permutation_generation():
    from app.plugins.dnstwist import generate_permutations
    perms = generate_permutations("fixture.test")
    assert perms["f1xture.test"] == "homoglyph"
    assert "fixtur.test" in perms  # omission
    assert "fixutre.test" in perms  # transposition
    assert "fixture.com" in perms  # tld swap
    assert "fixture.test" not in perms


def test_dnstwist_fires_on_registered_lookalike():
    from app.plugins.dnstwist import DnstwistPlugin
    res = run(DnstwistPlugin, domain("fixture.test"))
    hits = [f for f in res.findings if f.key == "typosquat_registered"]
    assert len(hits) == 1
    assert "f1xture.test" in hits[0].value


def test_dnstwist_silent_on_clean():
    from app.plugins.dnstwist import DnstwistPlugin
    res = run(DnstwistPlugin, domain(CLEAN))
    assert res.findings == []


def test_dnstwist_malformed_no_crash():
    from app.plugins.dnstwist import DnstwistPlugin
    res = run(DnstwistPlugin,
              Target(raw="192.0.2.1", type="ip", normalized="192.0.2.1"))
    assert res.findings == []
