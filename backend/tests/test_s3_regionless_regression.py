"""Regression tests: region-less S3 URLs in the ORIGINAL detectors.

The S3 URL patterns in app/plugins/s3.py (BUCKET_PATTERNS) and
app/plugins/cloud.py (CLOUD_PATTERNS) were copied from an upstream
style that requires a region segment:

    bucket.s3.<region>.amazonaws.com

That shape silently misses the most common S3 form, the region-less
one (bucket.s3.amazonaws.com, s3.amazonaws.com/bucket): after ".s3"
the pattern demanded "[.-]<region>" before ".amazonaws.com", so the
region-less host could never match. The gx_* pack made the region
optional in its own patterns; this file pins the same fix in the
original detectors.

Covered forms: region-less, dot region, dash region, dualstack, in
both virtual-hosted and path style. Negative control: a lookalike
host that merely ends with an S3-looking prefix
(bucket.s3.amazonaws.com.evil.com) must NOT match.
"""
import asyncio
import re

import httpx
import pytest

# NOTE: app.* imports are function-level on purpose (see
# test_falseneg_regressions.py: app.config snapshots DATABASE_URL at
# first import; module-level imports poison other test files).

HOST = "canary.test"

# One distinct bucket name per URL form, so each form's discovery is
# asserted independently.
FORM_URLS = [
    "https://rg-less-vh.s3.amazonaws.com/a.txt",
    "https://rg-dot.s3.us-east-1.amazonaws.com/a.txt",
    "https://rg-dash.s3-us-west-2.amazonaws.com/a.txt",
    "https://rg-dual.s3.dualstack.eu-west-1.amazonaws.com/a.txt",
    "https://s3.amazonaws.com/rg-less-path/a.txt",
    "https://s3.eu-central-1.amazonaws.com/rg-dot-path/a.txt",
    "https://s3-us-west-2.amazonaws.com/rg-dash-path/a.txt",
    "https://s3.dualstack.ap-south-1.amazonaws.com/rg-dual-path/a.txt",
]
EXPECTED_BUCKETS = {
    "rg-less-vh", "rg-dot", "rg-dash", "rg-dual",
    "rg-less-path", "rg-dot-path", "rg-dash-path", "rg-dual-path",
}

EVIL_URLS = [
    "https://rg-evil.s3.amazonaws.com.evil.com/a.txt",
    "https://rg-evil.s3.us-east-1.amazonaws.com.evil.com/a.txt",
    "https://s3.amazonaws.com.evil.com/rg-evil-path/a.txt",
]

HOME = ("<!DOCTYPE html><html><body><h1>Canary Test Co</h1>"
        + "".join(f'<a href="{u}">asset</a>' for u in FORM_URLS + EVIL_URLS)
        + "</body></html>")


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text=HOME,
                          headers={"Content-Type": "text/html"},
                          request=request)


def _run_plugin(plugin_cls):
    from app.cache import Cache
    from app.plugins.base import Ctx, Target
    from app.ratelimit import RateLimiter

    async def main():
        transport = httpx.MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport,
                                     follow_redirects=True,
                                     trust_env=False) as client:
            ctx = Ctx(run_id="s3-regionless-regression", mode="passive",
                      http=client, cache=Cache(), keys={},
                      limiter=RateLimiter(25))
            target = Target(raw=HOST, type="domain", normalized=HOST)
            return await plugin_cls().run(target, ctx)

    return asyncio.run(main())


# ---------------------------------------------------------------------------
# Pattern level: s3.py BUCKET_PATTERNS (bucket-name extraction)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", FORM_URLS)
def test_s3_patterns_extract_bucket_from_all_forms(url):
    from app.plugins.s3 import BUCKET_PATTERNS
    found = {m.group(1).lower()
             for pat, provider in BUCKET_PATTERNS if provider == "aws"
             for m in re.finditer(pat, url, re.I)}
    assert found & EXPECTED_BUCKETS, f"no bucket extracted from {url}"


@pytest.mark.parametrize("url", EVIL_URLS)
def test_s3_patterns_reject_lookalike_hosts(url):
    from app.plugins.s3 import BUCKET_PATTERNS
    for pat, provider in BUCKET_PATTERNS:
        assert not re.search(pat, url, re.I), \
            f"lookalike host matched {pat}: {url}"


# ---------------------------------------------------------------------------
# Pattern level: cloud.py CLOUD_PATTERNS (reference detection)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [u for u in FORM_URLS if ".s3" in u])
def test_cloud_patterns_match_virtual_hosted_forms(url):
    from app.plugins.cloud import CLOUD_PATTERNS
    aws = [pat for pat, _label, provider in CLOUD_PATTERNS
           if provider == "aws" and "s3" in pat]
    assert any(re.search(pat, url, re.I) for pat in aws), \
        f"cloud patterns missed {url}"


@pytest.mark.parametrize("url", EVIL_URLS[:2])
def test_cloud_patterns_reject_lookalike_hosts(url):
    from app.plugins.cloud import CLOUD_PATTERNS
    for pat, _label, _provider in CLOUD_PATTERNS:
        assert not re.search(pat, url, re.I), \
            f"lookalike host matched {pat}: {url}"


# ---------------------------------------------------------------------------
# End to end: the real plugins through a real Ctx (MockTransport)
# ---------------------------------------------------------------------------

def test_s3_plugin_discovers_buckets_from_all_forms():
    from app.plugins.s3 import S3Plugin
    res = _run_plugin(S3Plugin)
    buckets = {f.evidence.get("bucket") for f in res.findings
               if f.key == "cloud_bucket_ref"}
    assert EXPECTED_BUCKETS <= buckets, \
        f"missing buckets: {EXPECTED_BUCKETS - buckets}"
    assert "rg-evil" not in buckets
    assert "rg-evil-path" not in buckets


def test_cloud_plugin_references_regionless_bucket():
    from app.plugins.cloud import CloudPlugin
    res = _run_plugin(CloudPlugin)
    refs = [f.value for f in res.findings if f.key == "cloud_reference"]
    assert any("rg-less-vh.s3.amazonaws.com" in v for v in refs), refs
    assert not any("evil.com" in v for v in refs), refs
