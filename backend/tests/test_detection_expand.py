"""Gate for the 2026-10-27 detection-side expansion (all detection only).

1. Passive subdomain sources: CertSpotter CT, Wayback CDX, Bufferover
   passive DNS - deduped, same-target only, no brute force.
2. Exposed-file/database/backup sweep: new DIRECT_PATHS fire, and
   findings carry path/status/size + marker names only, never body
   content or a full secret.
3. Subdomain-takeover fingerprints: new provider fingerprints match.
4. CISA KEV: KEV CVEs badge (kev=True + label) and rank first at
   the same severity; non-KEV CVEs do not badge; a dead catalog
   fetch falls back to the fixture snapshot, never a fake match.

All proof runs through the real plugin code with an httpx
MockTransport - no live third-party scans.
"""
import asyncio
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.kev import (  # noqa: E402
    KEV_LABEL, annotate_finding, extract_cves, fixture_catalog,
    load_catalog, parse_kev_catalog,
)
from app.plugins import backup as backup_mod  # noqa: E402
from app.plugins import takeover as takeover_mod  # noqa: E402
from app.plugins.backup import BackupPlugin  # noqa: E402
from app.plugins.base import Ctx, Finding, Target  # noqa: E402
from app.plugins.cves import CvesPlugin  # noqa: E402
from app.plugins.passive_subdomains import (  # noqa: E402
    PassiveSubdomainsPlugin, clean_subdomain, dedupe_subdomains,
    parse_bufferover, parse_certspotter, parse_wayback_cdx,
)
from app.plugins.registry import discover  # noqa: E402
from app.prioritizer import prioritize  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

HOST = "fixture.test"


def _ctx(handler) -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="detection-expand-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _close(ctx):
    asyncio.run(ctx.http.aclose())


def _run(plugin_cls, ctx, raw):
    target = Target(raw=raw, type="url", normalized=raw)
    return asyncio.run(plugin_cls().run(target, ctx))


# --- 1. passive subdomain sources -------------------------------------

def test_clean_and_dedupe_same_target_only():
    assert clean_subdomain("*.api.fixture.test", HOST) == "api.fixture.test"
    assert clean_subdomain("evil.com", HOST) == ""
    assert clean_subdomain("fixture.test", HOST) == ""
    assert clean_subdomain("https://cdn.fixture.test:443/x", HOST) == "cdn.fixture.test"
    out = dedupe_subdomains(
        ["www.fixture.test", "www.fixture.test", "evil.com", "api.fixture.test"],
        HOST, existing=["www.fixture.test"])
    assert out == ["api.fixture.test"]


def test_parsers():
    cs = parse_certspotter([{"dns_names": ["a.fixture.test", "*.b.fixture.test"]}])
    assert "a.fixture.test" in cs and "*.b.fixture.test" in cs
    bo = parse_bufferover({"FDNS_A": ["1.2.3.4,api.fixture.test"],
                           "RDNS": [["9.9.9.9", "old.fixture.test"]]})
    assert "api.fixture.test" in bo and "old.fixture.test" in bo
    wb = parse_wayback_cdx(json.dumps([
        ["original"],
        ["https://blog.fixture.test/post", "20240101000000"],
    ]))
    assert wb == ["blog.fixture.test"]


def test_passive_subdomains_plugin_dedupes():
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "api.certspotter.com":
            return httpx.Response(200, content=json.dumps([
                {"dns_names": ["www.fixture.test", "api.fixture.test",
                               "api.fixture.test", "evil.com"]},
            ]), headers={"Content-Type": "application/json"}, request=request)
        if host == "dns.bufferover.run":
            return httpx.Response(200, content=json.dumps({
                "FDNS_A": ["1.2.3.4,api.fixture.test", "5.6.7.8,cdn.fixture.test"],
                "RDNS": [],
            }), headers={"Content-Type": "application/json"}, request=request)
        if host == "web.archive.org":
            return httpx.Response(200, content=json.dumps([
                ["original"],
                ["https://blog.fixture.test/post"],
            ]), headers={"Content-Type": "application/json"}, request=request)
        return httpx.Response(404, content="nope", request=request)

    ctx = _ctx(handler)
    try:
        res = _run(PassiveSubdomainsPlugin, ctx, f"https://{HOST}/")
    finally:
        _close(ctx)
    subs = sorted({f.value for f in res.findings if f.key == "subdomain"})
    # api appears in two sources but is reported once; evil.com dropped.
    assert subs == ["api.fixture.test", "blog.fixture.test",
                    "cdn.fixture.test", "www.fixture.test"]
    assert res.findings  # and no brute-force source involved (passive=True)
    assert all(f.passive for f in res.findings)


# --- 2. exposed-file / database / backup sweep -------------------------

def test_new_backup_paths_present_and_content_free():
    new_paths = {"/dump.sql", "/.git/logs/HEAD", "/secrets.yml",
                 "/.hg/hgrc", "/.svn/wc.db", "/site_backup.zip"}
    assert new_paths <= set(backup_mod.DIRECT_PATHS)
    assert backup_mod.EXPANDED_DIRECT_PATHS[0] == "/.git/logs/HEAD"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == HOST and path in new_paths:
            body = ("x" * 100 + " password=FixtureSecretValue1234567890 "
                    + "y" * 100)
            return httpx.Response(200, content=body,
                                  headers={"Content-Type": "text/plain"},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)

    ctx = _ctx(handler)
    try:
        res = _run(BackupPlugin, ctx, f"https://{HOST}/")
    finally:
        _close(ctx)
    hit_paths = {f.source_url.replace(f"https://{HOST}", "")
                 for f in res.findings if f.key == "backup_exposed"}
    assert new_paths <= hit_paths
    # Findings carry marker names only - never the secret value itself.
    blob = json.dumps([(f.value, f.evidence) for f in res.findings])
    assert "FixtureSecretValue1234567890" not in blob


# --- 3. takeover fingerprints ------------------------------------------

def test_new_takeover_fingerprints():
    assert len(takeover_mod.TAKEOVER_FINGERPRINTS) == 49  # was 33
    assert takeover_mod._match_service("x.storage.googleapis.com") == (
        "Google Cloud Storage", "NoSuchBucket")
    assert takeover_mod._match_service("x.squarespace.com") == (
        "Squarespace", "No Such Account")
    assert takeover_mod._match_service("x.list-manage.com") == (
        "Mailchimp", "404")
    assert takeover_mod._match_service("x.azureedge.net") == (
        "Azure CDN", "404")
    assert takeover_mod._match_service("x.example.com") is None


# --- 4. CISA KEV ---------------------------------------------------------

def test_kev_parsing_and_fixture_are_real_entries_only():
    catalog = fixture_catalog()
    assert "CVE-2021-44228" in catalog  # Log4Shell, genuinely KEV
    assert "CVE-2021-41773" in catalog
    assert parse_kev_catalog({"vulnerabilities": "nope"}) == {}
    assert parse_kev_catalog({"vulnerabilities": [{"cveID": "bogus"}]}) == {}
    assert extract_cves("see CVE-2021-44228 and cve-2024-3400") == [
        "CVE-2021-44228", "CVE-2024-3400"]


def test_kev_badge_and_rank_first_same_severity():
    catalog = fixture_catalog()
    kev_f = Finding(plugin_id="cves", category="web", key="cve_match",
                    value="HIGH: Apache - Log4Shell [CVE-2021-44228]",
                    source="CVE matcher",
                    evidence={"severity": "high", "cve": "CVE-2021-44228"})
    plain_f = Finding(plugin_id="cves", category="web", key="cve_match",
                      value="HIGH: nginx - resolver [CVE-2021-23017]",
                      source="CVE matcher",
                      evidence={"severity": "high", "cve": "CVE-2021-23017"})
    assert annotate_finding(kev_f, catalog) is True
    assert kev_f.evidence["kev"] is True
    assert kev_f.evidence["kev_label"] == KEV_LABEL
    assert KEV_LABEL in kev_f.value
    assert annotate_finding(plain_f, catalog) is False
    assert plain_f.evidence["kev"] is False
    # Same severity, non-KEV first in input -> KEV first after ranking.
    assert prioritize([plain_f, kev_f])[0] is kev_f


def test_kev_catalog_fallback_on_dead_fetch():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content="gone", request=request)

    ctx = _ctx(handler)
    try:
        catalog = asyncio.run(load_catalog(ctx))
    finally:
        _close(ctx)
    assert "CVE-2021-44228" in catalog  # fixture, not a fake match
    assert "CVE-2021-23017" not in catalog


def _cves_run(server_header: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == HOST:
            return httpx.Response(200, content="<html></html>",
                                  headers={"Server": server_header,
                                           "Content-Type": "text/html"},
                                  request=request)
        return httpx.Response(404, content="gone", request=request)

    ctx = _ctx(handler)
    try:
        return _run(CvesPlugin, ctx, f"https://{HOST}/")
    finally:
        _close(ctx)


def test_cves_plugin_badges_kev_and_not_non_kev():
    kev_res = _cves_run("Apache/2.4.49 (Unix)")
    kev_hits = [f for f in kev_res.findings
                if f.key == "cve_match" and "CVE-2021-41773" in f.value]
    assert len(kev_hits) == 1
    assert kev_hits[0].evidence["kev"] is True
    assert kev_hits[0].evidence["kev_label"] == KEV_LABEL

    plain_res = _cves_run("nginx/1.20.0")
    plain_hits = [f for f in plain_res.findings
                  if f.key == "cve_match" and "CVE-2021-23017" in f.value]
    assert len(plain_hits) == 1
    assert plain_hits[0].evidence["kev"] is False


def test_registry_grew_by_passive_subdomains():
    reg = discover()
    assert "passive_subdomains" in reg
    assert len(reg) == 626  # 624 master + 1 passive_subdomains
