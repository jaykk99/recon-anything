"""Hashcracker plugin + direct-mode engine tests.

Covers the Oct 23 repair:
- pasted hashes classify as file_hash and the plugin accepts them
  (direct mode was unreachable: the runner skipped every file_hash
  job because `accepts` was domain/url only);
- $-format hashes (bcrypt/Argon2/crypt) classify as file_hash too;
- HIBP k-anonymity parsing (mocked transport, no network);
- the MD5 public-DB lookup against gromweb's current HTML result
  page (its JSON API is gone), with re-hash verification so a wrong
  candidate can never be reported;
- the direct-mode dictionary+rules engine (vectors ported from the
  standalone hash-cracker tool), time-boxed;
- the settled boundary: SCAN MODE IS ANALYSIS-ONLY. Scan findings
  never contain a recovered plaintext and the engine never runs
  during a scan, even when the public DB knows the plaintext.
"""
import asyncio
import hashlib
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.classifier import classify  # noqa: E402
from app.plugins import hashcrack_engine as engine  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.hashcracker import (  # noqa: E402
    HashcrackerPlugin, _hibp_sha1_count, _identify, _md5_rainbow_lookup)
from app.plugins.md4 import ntlm_hex, self_test as md4_self_test  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

MD5_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"          # "password"
SHA1_PASSWORD = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"  # "password"
SHA256_PASSWORD = hashlib.sha256(b"password").hexdigest()
SHA256_PASSWORD1 = hashlib.sha256(b"Password1").hexdigest()
MD5_LETMEIN123 = hashlib.md5(b"letmein123").hexdigest()
MD5_DRAGON7 = hashlib.md5(b"dragon7").hexdigest()
NTLM_PASSWORD = "8846f7eaee8fb117ad06bdd830b7586c"          # "password"
MD5_STRONG = "a74dfc7cafb12827ab6d65dda95a2688"  # "Xq9!vR2#mZp7$kLw"
BCRYPT_SAMPLE = ("$2b$12$LJ3m4y9cLYpQapfLpYyP6uEI0pQQvhJdTsHGhpFLY."
                 "mFHOxMzGqKe")
BCRYPT_PASSWORD_COST4 = ("$2b$04$9LeQrrw54hu7.S7cO9TDdOaHS1MxLWcI/"
                         "AY70lZ3uG2.O63lnLwpG")  # "password", cost 4
ARGON2_SAMPLE = ("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ"
                 "$RdescudvJCsgt3ub+b+dWRWJTmaaJObG")

HIBP_SUFFIX = SHA1_PASSWORD[5:].upper()
HIBP_COUNT = 987654
HIBP_BODY = ("001B7F3A2C9D4E5F6A7B8C9D0E1F2A3B4C5:12\n"
             f"{HIBP_SUFFIX}:{HIBP_COUNT}\n"
             "FFFE4D3C2B1A0987654321FEDCBA09876543:3\n")

GROMWEB_HIT = (
    '<html><body><p class="word-break-all">The MD5 hash '
    f'<a class="Hash" href="/?md5={MD5_PASSWORD}">{MD5_PASSWORD}</a> '
    'was successfully reversed into the string '
    '<a class="String" href="/?string=password">password</a></p>'
    "</body></html>")
GROMWEB_MISS = ("<html><body><p>The MD5 hash could not be reversed "
                "into a string: no reverse string was found.</p>"
                "</body></html>")
GROMWEB_WRONG = (
    '<html><body><p class="word-break-all">The MD5 hash '
    f'<a class="Hash" href="/?md5={MD5_PASSWORD}">{MD5_PASSWORD}</a> '
    'was successfully reversed into the string '
    '<a class="String" href="/?string=hunter2">hunter2</a></p>'
    "</body></html>")

SCAN_PAGE = (
    "<html><body><h1>Fixture</h1>"
    f"<p>legacy admin hash: {MD5_PASSWORD}</p>"
    f"<p>old sha1: {SHA1_PASSWORD}</p>"
    f"<p>bcrypt: {BCRYPT_SAMPLE}</p>"
    "</body></html>")


def _handler_factory(hibp_body=HIBP_BODY, gromweb=GROMWEB_HIT,
                     page=SCAN_PAGE):
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "api.pwnedpasswords.com":
            return httpx.Response(200, text=hibp_body, request=request)
        if host == "md5.gromweb.com":
            return httpx.Response(200, text=gromweb, request=request)
        if host == "fixture.test":
            return httpx.Response(200, text=page, request=request)
        return httpx.Response(404, text="", request=request)
    return handler


def _ctx(handler) -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="hashcracker-test", mode="passive", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run_plugin(target: Target, handler) -> object:
    async def go():
        ctx = _ctx(handler)
        try:
            return await HashcrackerPlugin().run(target, ctx)
        finally:
            await ctx.http.aclose()
    return asyncio.run(go())


# ---------------------------------------------------------------------------
# Routing: classifier + accepts (the "doesn't work" root cause)
# ---------------------------------------------------------------------------

def test_classify_hex_hashes_are_file_hash():
    for h, detail in ((MD5_PASSWORD, "md5"), (SHA1_PASSWORD, "sha1"),
                      (SHA256_PASSWORD, "sha256")):
        c = classify(h)
        assert c["type"] == "file_hash", c
        assert c["detail"] == detail, c
        assert c["normalized"] == h


def test_classify_dollar_hashes_are_file_hash():
    assert classify(BCRYPT_SAMPLE)["type"] == "file_hash"
    assert classify(BCRYPT_SAMPLE)["detail"] == "bcrypt"
    assert classify(ARGON2_SAMPLE)["type"] == "file_hash"
    assert classify(ARGON2_SAMPLE)["detail"] == "argon2"
    # normalized must keep the original case-sensitive value
    assert classify(BCRYPT_SAMPLE)["normalized"] == BCRYPT_SAMPLE


def test_plugin_accepts_file_hash():
    assert "file_hash" in HashcrackerPlugin.accepts
    from app.plugins.registry import discover
    assert "hashcracker" in discover()


# ---------------------------------------------------------------------------
# Analyzer units
# ---------------------------------------------------------------------------

def test_identify_vectors():
    assert _identify(MD5_PASSWORD)[0] == "md5"
    assert _identify(SHA1_PASSWORD)[0] == "sha1"
    assert _identify(SHA256_PASSWORD)[0] == "sha256"
    assert _identify(hashlib.sha512(b"x").hexdigest())[0] == "sha512"
    assert _identify(BCRYPT_SAMPLE)[0] == "bcrypt"
    assert _identify(ARGON2_SAMPLE)[0] == "argon2"
    hid, val, *_ = _identify(f"ntlm:{NTLM_PASSWORD}")
    assert hid == "ntlm" and val == NTLM_PASSWORD
    assert _identify("not a hash") is None


def test_hibp_count_parsed():
    ctx = _ctx(_handler_factory())
    try:
        n = asyncio.run(_hibp_sha1_count(SHA1_PASSWORD, ctx))
    finally:
        asyncio.run(ctx.http.aclose())
    assert n == HIBP_COUNT


def test_hibp_not_found_returns_zero():
    ctx = _ctx(_handler_factory(hibp_body="AAAA:1\nBBBB:2\n"))
    try:
        n = asyncio.run(_hibp_sha1_count(SHA1_PASSWORD, ctx))
    finally:
        asyncio.run(ctx.http.aclose())
    assert n == 0


def test_hibp_error_returns_none():
    def handler(request):
        return httpx.Response(500, text="", request=request)
    ctx = _ctx(handler)
    try:
        n = asyncio.run(_hibp_sha1_count(SHA1_PASSWORD, ctx))
    finally:
        asyncio.run(ctx.http.aclose())
    assert n is None


def test_md5_lookup_html_hit():
    ctx = _ctx(_handler_factory())
    try:
        p = asyncio.run(_md5_rainbow_lookup(MD5_PASSWORD, ctx))
    finally:
        asyncio.run(ctx.http.aclose())
    assert p == "password"


def test_md5_lookup_html_miss():
    ctx = _ctx(_handler_factory(gromweb=GROMWEB_MISS))
    try:
        p = asyncio.run(_md5_rainbow_lookup(MD5_PASSWORD, ctx))
    finally:
        asyncio.run(ctx.http.aclose())
    assert p is None


def test_md5_lookup_json_hit():
    def handler(request):
        return httpx.Response(200, json={"string": "password"},
                              request=request)
    ctx = _ctx(handler)
    try:
        p = asyncio.run(_md5_rainbow_lookup(MD5_PASSWORD, ctx))
    finally:
        asyncio.run(ctx.http.aclose())
    assert p == "password"


def test_md5_lookup_wrong_candidate_rejected():
    # Page claims the plaintext is "hunter2"; re-hashing proves it is
    # not the plaintext for this hash, so it must NOT be reported.
    ctx = _ctx(_handler_factory(gromweb=GROMWEB_WRONG))
    try:
        p = asyncio.run(_md5_rainbow_lookup(MD5_PASSWORD, ctx))
    finally:
        asyncio.run(ctx.http.aclose())
    assert p is None


# ---------------------------------------------------------------------------
# Engine units (vectors ported from the standalone hash-cracker)
# ---------------------------------------------------------------------------

def test_md4_rfc_and_ntlm():
    assert md4_self_test()
    assert ntlm_hex("password") == NTLM_PASSWORD


def test_engine_identify():
    assert engine.identify(MD5_PASSWORD)[1] == ["md5", "ntlm"]
    assert engine.identify(SHA1_PASSWORD)[1] == ["sha1"]
    assert engine.identify(SHA256_PASSWORD)[1] == ["sha256", "sha3_256"]
    assert engine.identify(BCRYPT_SAMPLE)[0] == "bcrypt"
    assert engine.identify("zzzz")[0] == "unknown"


def test_engine_cracks_md5_password_bundled_wordlist():
    r = engine.crack_submitted(MD5_PASSWORD, deadline_s=30)
    assert r["cracked"] and r["plaintext"] == "password"
    assert r["algo"] == "md5"


def test_engine_cracks_sha1_password_bundled_wordlist():
    r = engine.crack_submitted(SHA1_PASSWORD, deadline_s=30)
    assert r["cracked"] and r["plaintext"] == "password"


def test_engine_cracks_sha256_capitalized_plus_digit():
    r = engine.crack_submitted(SHA256_PASSWORD1, deadline_s=30,
                               words=["password"])
    assert r["cracked"] and r["plaintext"] == "Password1"
    assert "capitalized" in r["rule"]


def test_engine_cracks_md5_append_123():
    r = engine.crack_submitted(MD5_LETMEIN123, deadline_s=30,
                               words=["letmein"])
    assert r["cracked"] and r["plaintext"] == "letmein123"


def test_engine_cracks_md5_midlist_digit_suffix():
    r = engine.crack_submitted(MD5_DRAGON7, deadline_s=30,
                               words=["dragon"])
    assert r["cracked"] and r["plaintext"] == "dragon7"


def test_engine_cracks_ntlm_password():
    r = engine.crack_submitted(NTLM_PASSWORD, deadline_s=30,
                               words=["password"])
    assert r["cracked"] and r["plaintext"] == "password"
    assert r["algo"] == "ntlm"


def test_engine_strong_password_not_cracked():
    r = engine.crack_submitted(MD5_STRONG, deadline_s=30,
                               words=["alpha", "bravo", "charlie"])
    assert not r["cracked"] and r["plaintext"] is None


def test_engine_timebox_stops():
    import time as _time
    t0 = _time.monotonic()
    r = engine.crack_submitted(MD5_STRONG, deadline_s=0.2)
    elapsed = _time.monotonic() - t0
    assert elapsed < 10
    assert not r["cracked"] and r["timed_out"]


def test_engine_bcrypt_top_candidate():
    pytest.importorskip("bcrypt")
    r = engine.crack_submitted(BCRYPT_PASSWORD_COST4, deadline_s=30)
    assert r["cracked"] and r["plaintext"] == "password"


def test_wordlist_bundled_with_attribution():
    words = engine.load_words()
    assert len(words) >= 9000
    assert "password" in words
    attr = engine.WORDLIST_PATH.parent / "ATTRIBUTION.txt"
    assert "SecLists" in attr.read_text()


# ---------------------------------------------------------------------------
# Direct mode end-to-end (mocked network)
# ---------------------------------------------------------------------------

def test_direct_sha1_flagged_compromised_and_cracked():
    res = _run_plugin(
        Target(raw=SHA1_PASSWORD, type="file_hash",
               normalized=SHA1_PASSWORD),
        _handler_factory())
    by_key = {f.key: f for f in res.findings}
    assert "hash_cracked_public" in by_key
    assert f"{HIBP_COUNT} breaches" in by_key["hash_cracked_public"].value
    assert "hash_cracked_direct" in by_key
    assert "'password'" in by_key["hash_cracked_direct"].value


def test_direct_md5_cracked_with_plaintext():
    res = _run_plugin(
        Target(raw=MD5_PASSWORD, type="file_hash",
               normalized=MD5_PASSWORD),
        _handler_factory())
    by_key = {f.key: f for f in res.findings}
    assert "hash_cracked_public" in by_key
    assert "Plaintext: password" in by_key["hash_cracked_public"].value
    assert "hash_cracked_direct" in by_key
    assert by_key["hash_cracked_direct"].evidence["plaintext"] == "password"


def test_direct_bcrypt_verdict_only_format(monkeypatch):
    # bcrypt (cost 12 sample): engine may try top candidates or report
    # the package note, but the analysis verdict must be present and
    # nothing may claim a crack of the sample. Candidate limit is cut
    # so the test stays fast where the bcrypt package exists (cost-12
    # checks are ~250ms each by design).
    monkeypatch.setattr(engine, "BCRYPT_CANDIDATE_LIMIT", 5)
    res = _run_plugin(
        Target(raw=BCRYPT_SAMPLE, type="file_hash",
               normalized=BCRYPT_SAMPLE),
        _handler_factory())
    keys = {f.key for f in res.findings}
    assert "hash_analyzed" in keys
    assert "hash_cracked_direct" not in keys
    assert "hash_cracked_public" not in keys


def test_direct_hash_not_cracked(monkeypatch):
    monkeypatch.setattr(engine, "DIRECT_CRACK_TIMEBOX_S", 2.0)
    res = _run_plugin(
        Target(raw=MD5_STRONG, type="file_hash", normalized=MD5_STRONG),
        _handler_factory(gromweb=GROMWEB_MISS))
    by_key = {f.key: f for f in res.findings}
    assert "hash_crack_attempt" in by_key
    assert "NOT CRACKED" in by_key["hash_crack_attempt"].value
    assert "hash_cracked_direct" not in by_key


# ---------------------------------------------------------------------------
# Scan mode: analysis-only, NO plaintext, engine never runs
# ---------------------------------------------------------------------------

def test_scan_mode_never_emits_plaintext(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("engine must never run in scan mode")
    monkeypatch.setattr(engine, "crack_submitted", _boom)

    res = _run_plugin(
        Target(raw="fixture.test", type="domain",
               normalized="fixture.test"),
        _handler_factory())
    assert res.findings, "scan should assess the hashes on the page"
    keys = {f.key for f in res.findings}
    assert "hash_cracked_public" in keys      # breach status reported
    assert "hash_analyzed" in keys            # verdict for the bcrypt
    assert "hash_cracked_direct" not in keys  # engine findings absent
    assert "hash_crack_attempt" not in keys
    blob = json.dumps([{"value": f.value, "evidence": f.evidence}
                       for f in res.findings])
    assert "Plaintext:" not in blob
    assert "is 'password'" not in blob
    for f in res.findings:
        assert not (f.evidence or {}).get("plaintext_public")
        assert not (f.evidence or {}).get("plaintext")
    # ...while the breach STATUS (count) is still reported for SHA-1.
    sha1_f = next(f for f in res.findings
                  if f.key == "hash_cracked_public"
                  and "SHA-1" in f.value)
    assert f"{HIBP_COUNT} breaches" in sha1_f.value
