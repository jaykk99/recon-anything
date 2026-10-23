"""Regression tests for the 2026-10-23 zero-findings diagnosis.

Two production bugs made whole finding categories silently return zero:

1. Classifier: `_looks_android_pkg` treated any dotted name whose last
   label was not in a small common-TLD list as an Android package id.
   Real domains on newer/cc TLDs (canary.test, victim.gg, mysite.lol,
   data.technology, site.museum, ...) classified as "play_store", so
   every domain/url plugin skipped them ("not applicable to target
   type 'play_store'") and the scan returned zero secrets, zero
   subdomains, zero ports - with every job reporting "ok".

2. Creds plugin: value extraction assumed regex group(1) is always the
   secret. For db_url_mongo the optional (\\+srv)? group is group(1),
   so a plain mongodb:// URL yielded None -> emit() crashed on
   None.strip() -> the runner marked the job errored and ALL credential
   findings for the target were lost. Same crash for a bare redis://
   URL (optional password group unmatched).

All secrets below are patterned fakes / published test vectors.
"""
import asyncio

import httpx

# NOTE: app.* imports are function-level on purpose (see
# test_falseneg_regressions.py: app.config snapshots DATABASE_URL at
# first import; module-level imports poison other test files).

HOST = "canary.test"

HOME = """<!DOCTYPE html><html><head>
<script src="/static/app.js"></script></head><body>
<h1>Canary Test Co</h1>
<!-- staging note: password = "CanaryPass123!" -->
</body></html>"""

APP_JS = """
var dbUrl = "mongodb://canaryuser:CanaryPass99@db.canary.test:27017/app";
var dbSrv = "mongodb+srv://srvuser:SrvPass88@cluster.canary.test/app";
var pgUrl = "postgres://pguser:PgPass77@db.canary.test:5432/app";
var redisAuth = "redis://:RedisPass66@cache.canary.test:6379/0";
var redisBare = "redis://localhost:6379";
"""


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/static/app.js":
        return httpx.Response(200, text=APP_JS, request=request)
    return httpx.Response(200, text=HOME,
                          headers={"Content-Type": "text/html"},
                          request=request)


def _run_creds():
    from app.cache import Cache
    from app.plugins.base import Ctx, Target
    from app.plugins.creds import CredsPlugin
    from app.ratelimit import RateLimiter

    async def main():
        transport = httpx.MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport,
                                     follow_redirects=True,
                                     trust_env=False) as client:
            ctx = Ctx(run_id="zero-regression", mode="active", http=client,
                      cache=Cache(), keys={}, limiter=RateLimiter(25))
            target = Target(raw=HOST, type="domain", normalized=HOST)
            return await CredsPlugin().run(target, ctx)

    return asyncio.run(main())


# ---------------------------------------------------------------------------
# 1. Classifier: real domains must not classify as Android packages
# ---------------------------------------------------------------------------

def test_domains_with_unusual_tlds_classify_as_domain():
    from app.classifier import classify
    for raw in ("canary.test", "victim.gg", "mysite.lol", "foo.bar",
                "shop.example", "data.technology", "site.museum",
                "www.example.technology", "example.com", "sub.example.co.uk"):
        result = classify(raw)
        assert result["type"] == "domain", f"{raw} -> {result['type']}"


def test_android_package_ids_still_classify_as_play_store():
    from app.classifier import classify
    for raw in ("com.whatsapp", "com.sec.android.app.samsungbrowser",
                "org.mozilla.firefox", "io.github.someapp"):
        result = classify(raw)
        assert result["type"] == "play_store", f"{raw} -> {result['type']}"


# ---------------------------------------------------------------------------
# 2. Creds plugin: DB URLs must produce findings, never crash the plugin
# ---------------------------------------------------------------------------

def test_creds_finds_db_url_credentials_without_crashing():
    res = _run_creds()
    assert res.status.value == "ok", f"status={res.status} reason={res.reason}"
    keys = {f.key for f in res.findings}
    assert "cred_db_url_mongo" in keys
    assert "cred_db_url_postgres" in keys
    assert "cred_db_url_redis" in keys
    assert "cred_password_assign" in keys
    # Both the plain and +srv mongo URLs are reported (user:pass pairs).
    mongo = [f for f in res.findings if f.key == "cred_db_url_mongo"]
    assert len(mongo) == 2, f"mongo findings: {[f.value for f in mongo]}"


def test_creds_bare_redis_url_without_password_is_not_a_credential():
    res = _run_creds()
    redis = [f for f in res.findings if f.key == "cred_db_url_redis"]
    # Only the redis://:password@ URL counts; the bare redis://localhost
    # carries no credential and must not appear (or crash the plugin).
    assert len(redis) == 1, f"redis findings: {[f.value for f in redis]}"
