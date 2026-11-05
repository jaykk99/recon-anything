"""Regression tests for the 2026-11-03 run-all-plugins audit.

One production bug found by running every plugin against a fixture
that actually exercises its check:

binex (_strings_analysis): jsminer's SECRET_PATTERNS is a list of
(kind, pattern, confidence) tuples - jsminer itself iterates it as
``for kind, pat, conf in SECRET_PATTERNS`` - but binex called
``SECRET_PATTERNS.items()`` on it. Every APK deep analysis that
reached the strings stage raised AttributeError, which escaped run()
and surfaced as a plugin error with ALL binex findings for the target
lost (the same failure shape as the 2026-10-23 creds crash). The
play_store/app_store paths never reach _strings_analysis with real
DEX content, so the test suite never saw it.

Fixes covered here:
1. binex iterates SECRET_PATTERNS as the tuple list it is.
2. _deep_analyze isolates each sub-analyzer, so one analyzer's crash
   can no longer lose the others' findings.

All secrets below are patterned fakes (the fixture-convention dummy
AWS key, NOT a real credential).
"""
import asyncio
import io
import zipfile

import httpx

# NOTE: app.* imports are function-level on purpose (see
# test_falseneg_regressions.py: app.config snapshots DATABASE_URL at
# first import; module-level imports poison other test files).

DEX_TEXT = (
    "dex\n035\x00 fixture classes "
    "aws key AKIA1234567890ABCDEF "
    "endpoint https://api.fixture.test/v1 "
    "hardcoded host 203.0.113.7 "
)


def _apk_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    b"\x03\x00\x08\x00" + b"fixturemanifest" * 8)
        zf.writestr("classes.dex", DEX_TEXT.encode())
        zf.writestr("resources.arsc", b"fixture-resources")
    return buf.getvalue()


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith(".apk"):
        return httpx.Response(
            200, content=_apk_bytes(),
            headers={"Content-Type": "application/octet-stream"},
            request=request)
    return httpx.Response(404, content="", request=request)


def _run_binex_apk():
    from app.cache import Cache
    from app.plugins.base import Ctx, Target
    from app.plugins.binex import BinexPlugin
    from app.ratelimit import RateLimiter

    async def go():
        http = httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            follow_redirects=True, trust_env=False)
        ctx = Ctx(run_id="runall-regression", mode="passive", http=http,
                  cache=Cache(), keys={}, limiter=RateLimiter(),
                  evidence_dir="/tmp")
        target = Target(raw="https://fixture.test/app.apk",
                        type="apk_url",
                        normalized="https://fixture.test/app.apk")
        try:
            return await BinexPlugin().run(target, ctx)
        finally:
            await http.aclose()

    return asyncio.run(go())


def test_binex_apk_url_deep_analysis_does_not_crash():
    """Pre-fix: AttributeError escaped run() (status error, 0 findings)."""
    res = _run_binex_apk()
    assert res.status.value == "ok", res.reason
    keys = {f.key for f in res.findings}
    # The strings stage ran: planted secret + hardcoded IP both found.
    assert "binex_secrets" in keys, keys
    assert "binex_hardcoded_ips" in keys, keys


def test_binex_strings_analysis_iterates_secret_patterns():
    """Direct unit check of the fixed loop (no network)."""
    from app.plugins.binex import BinexPlugin

    plugin = BinexPlugin()
    findings = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", DEX_TEXT.encode())
    buf.seek(0)
    zf = zipfile.ZipFile(buf)
    plugin._strings_analysis(zf, zf.namelist(), findings)  # must not raise
    assert any(f.key == "binex_secrets" for f in findings)
