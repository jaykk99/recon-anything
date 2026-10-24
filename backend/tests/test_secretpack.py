"""Unit gate for the sec_* secret-exposure pack (5 detectors).

Every sec plugin runs through the REAL Ctx against a canary served via
httpx MockTransport (secretpack_samples.py): each family must fire on
the canary, every plugin must stay silent on the clean site, and no
full planted fake secret may appear in any finding (masked plus
SHA-256 fingerprint only). Seed phrases are never shown even in part.
"""

import asyncio
import hashlib
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secretpack_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.plugins.secretpack import SEC_IDS  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "canary.test"
CLEAN = "clean.test"


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path or "/"
    routes = samples.CANARY_ROUTES if host == CANARY else (
        samples.CLEAN_ROUTES if host == CLEAN else {})
    route = routes.get(path)
    if route is not None:
        ctype, body = route
        return httpx.Response(200, content=body,
                              headers={"Content-Type": ctype},
                              request=request)
    return httpx.Response(404, content="not found", request=request)


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="secretpack-test", mode="active", http=client,
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


def _by_key(result, key):
    return [f for f in result.findings if f.key == key]


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _blob(result) -> str:
    return json.dumps([f.value for f in result.findings]) + json.dumps(
        [f.evidence for f in result.findings], default=str)


def _assert_no_planted(result):
    blob = _blob(result)
    for secret in samples.PLANTED:
        assert secret not in blob, f"planted value leaked: {secret[:8]}..."
    assert samples.PEM_BODY.strip() not in blob


# ---------------------------------------------------------------------------

def test_exactly_5_new_detectors_registered():
    sec = sorted(k for k in discover() if k.startswith("sec_"))
    assert sec == sorted(SEC_IDS)
    assert len(sec) == 5
    assert len(discover()) == 607  # 602 before this pack


def test_js_hardcoded_fires():
    r = _run("sec_js_hardcoded", CANARY)
    assert _by_key(r, "sec_js_credential"), r.reason
    assert _by_key(r, "sec_js_private_key"), r.reason
    fps = {f.evidence.get("fingerprint_sha256") for f in r.findings}
    assert _fp(samples.AWS_KEY) in fps
    assert _fp(samples.GENERIC_SECRET) in fps
    assert _fp(samples.JWT) in fps
    _assert_no_planted(r)


def test_js_seed_phrase_never_shown():
    r = _run("sec_js_hardcoded", CANARY)
    hits = _by_key(r, "sec_js_seed_phrase")
    assert hits, r.reason
    assert hits[0].evidence.get("word_count") == 12
    _assert_no_planted(r)
    for word in samples.SEED_WORDS:
        if len(word) > 4:
            assert word not in _blob(r)


def test_js_mobile_binary_fires():
    r = _run("sec_js_hardcoded", CANARY)
    apk_hits = [f for f in r.findings
                if f.evidence.get("asset_kind") == "mobile binary"]
    assert apk_hits, r.reason
    _assert_no_planted(r)


def test_committed_config_fires():
    r = _run("sec_committed_config", CANARY)
    hits = _by_key(r, "sec_exposed_config")
    assert hits, r.reason
    fps = {f.evidence.get("fingerprint_sha256") for f in r.findings}
    assert _fp(samples.ENV_SECRET) in fps
    assert _fp(samples.DB_PASSWORD) in fps
    _assert_no_planted(r)


def test_public_storage_fires():
    r = _run("sec_public_storage", CANARY)
    assert _by_key(r, "sec_bucket_listing"), r.reason
    assert _by_key(r, "sec_storage_listing"), r.reason
    assert _by_key(r, "sec_storage_archive_secrets"), r.reason
    _assert_no_planted(r)


def test_log_exposure_fires():
    r = _run("sec_log_exposure", CANARY)
    hits = _by_key(r, "sec_log_token")
    assert hits, r.reason
    fps = {f.evidence.get("fingerprint_sha256") for f in r.findings}
    assert _fp(samples.BEARER) in fps
    assert _fp(samples.GENERIC_SECRET) in fps
    _assert_no_planted(r)


def test_weak_crypto_fires_with_nuance():
    r = _run("sec_weak_crypto", CANARY)
    assert _by_key(r, "sec_weak_hash_md5"), r.reason
    assert _by_key(r, "sec_weak_hash_sha1"), r.reason
    blob = _blob(r)
    assert ("does not directly derive an asymmetric private key"
            in blob)
    assert ("unseeded deterministic key" in blob)
    _assert_no_planted(r)


def test_all_quiet_on_clean_site():
    for pid in SEC_IDS:
        r = _run(pid, CLEAN)
        assert r.findings == [], (pid, r.findings)
