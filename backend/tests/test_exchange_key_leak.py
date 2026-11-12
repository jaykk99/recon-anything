"""Unit gate for the exchange-key-leak pack (4 detectors).

Ports k.py's detectors into plugins. Every plugin runs through the REAL
Ctx against a canary served via httpx MockTransport
(exchange_key_leak_samples.py): each provider must fire on the canary,
every plugin must stay silent on the clean site, validation tags must
match the mocked exchange responses, and no full planted fake key/secret
may appear in any finding (masked plus SHA-256 fingerprint only).
Live exchange endpoints are never called with fake keys in unit tests:
validation is mocked at the transport layer.
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

import exchange_key_leak_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.exchange_key_leak import (  # noqa: E402
    EXCHANGE_KEY_IDS,
    _github_repo_from_target,
    _is_fake_value,
    validate_binance,
    validate_bybit,
    validate_kucoin,
    validate_okx,
)
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "canary.test"
CLEAN = "clean.test"


def _exchange_response(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path or "/"
    if host == "api.binance.com" and path.endswith("/apiRestrictions"):
        key = request.headers.get("X-MBX-APIKEY", "")
        if key == samples.ROT_BIN_KEY:
            return httpx.Response(401, content=b"{}", request=request)
        if key == samples.IP_BIN_KEY:
            return httpx.Response(200, json={
                "ipRestrict": True, "enableWithdrawals": True,
                "enableReading": False}, request=request)
        if key == samples.RO_BIN_KEY:
            return httpx.Response(200, json={
                "ipRestrict": False, "enableWithdrawals": False,
                "enableReading": False}, request=request)
        return httpx.Response(200, json={
            "ipRestrict": False, "enableWithdrawals": True,
            "enableReading": True}, request=request)
    if host == "api.binance.com" and path.endswith("/api/v3/account"):
        return httpx.Response(200, json={"balances": [
            {"asset": "USDT", "free": "100.00", "locked": "23.45"},
            {"asset": "BTC", "free": "1", "locked": "0"},
        ]}, request=request)
    if host == "api.bybit.com":
        key = request.headers.get("X-BAPI-API-KEY", "")
        if key == samples.BYB_ACTION_KEY:
            return httpx.Response(200, json={
                "retCode": 0,
                "result": {"permissions": {"Spot": ["Order", "Withdraw"]}},
            }, request=request)
        if key == samples.BYB_KEY:
            return httpx.Response(200, json={
                "retCode": 0,
                "result": {"permissions": {"Spot": ["Order"]}},
            }, request=request)
        return httpx.Response(403, content=b"{}", request=request)
    if host == "www.okx.com":
        key = request.headers.get("OK-ACCESS-KEY", "")
        if key == samples.OKX_ROT_KEY:
            return httpx.Response(200, json={
                "code": "50111", "msg": "Invalid API key"},
                request=request)
        return httpx.Response(200, json={
            "code": "0", "msg": "",
            "data": [{"uid": "1", "withdraw": True}]}, request=request)
    return httpx.Response(404, content=b"not found", request=request)


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host in ("api.binance.com", "api.bybit.com", "www.okx.com"):
        return _exchange_response(request)
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
    return Ctx(run_id="exchange-key-leak-test", mode="active", http=client,
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


def _validate(coro):
    ctx = _ctx()
    try:
        return asyncio.run(coro(ctx.http))
    finally:
        asyncio.run(ctx.http.aclose())


# ---------------------------------------------------------------------------

def test_exactly_4_new_detectors_registered():
    got = sorted(k for k in discover() if k.endswith("_leaked_api_key"))
    assert got == sorted(EXCHANGE_KEY_IDS)
    assert len(got) == 4
    assert len(discover()) == 1350  # 1346 master + 4 exchange-key-leak plugins


def test_binance_fires_actionable():
    r = _run("binance_leaked_api_key", CANARY)
    hits = _by_key(r, "binance_leaked_api_key")
    assert len(hits) == 1, r.reason
    f = hits[0]
    assert f.evidence.get("tag") == "ACTIONABLE"
    assert f.evidence.get("usd_stablecoin_balance") == 123.45
    assert f.evidence.get("fingerprint_sha256") == _fp(samples.BIN_SEC)
    assert f.evidence.get("secret_fingerprint16") == _fp(samples.BIN_SEC)[:16]
    assert f.confidence == 95
    _assert_no_planted(r)


def test_bybit_fires_read_only():
    r = _run("bybit_leaked_api_key", CANARY)
    hits = _by_key(r, "bybit_leaked_api_key")
    assert len(hits) == 1, r.reason
    assert hits[0].evidence.get("tag") == "READ-ONLY"
    _assert_no_planted(r)


def test_okx_fires_actionable():
    r = _run("okx_leaked_api_key", CANARY)
    hits = _by_key(r, "okx_leaked_api_key")
    assert len(hits) == 1, r.reason
    assert hits[0].evidence.get("tag") == "ACTIONABLE"
    _assert_no_planted(r)


def test_kucoin_fires_unverified():
    r = _run("kucoin_leaked_api_key", CANARY)
    hits = _by_key(r, "kucoin_leaked_api_key")
    assert len(hits) == 1, r.reason
    assert hits[0].evidence.get("tag") == "UNVERIFIED"
    _assert_no_planted(r)


def test_clean_silent_for_all_four():
    for pid in EXCHANGE_KEY_IDS:
        r = _run(pid, CLEAN)
        assert r.findings == [], (pid, r.reason, r.findings)


def test_placeholder_pair_skipped():
    # /.env.local holds ONLY the "example" pair: it must not produce a
    # second Binance finding next to the real pair from /.env.
    r = _run("binance_leaked_api_key", CANARY)
    assert len(_by_key(r, "binance_leaked_api_key")) == 1
    assert _is_fake_value(samples.FAKE_BIN_SEC)
    assert not _is_fake_value(samples.BIN_SEC)


def test_no_planted_value_in_any_finding():
    for pid in EXCHANGE_KEY_IDS:
        _assert_no_planted(_run(pid, CANARY))


# --- validation unit tests (mocked transport, no live exchange calls) ---

def test_validate_binance_rotated():
    tag, usd, _ = _validate(
        lambda http: validate_binance(http, samples.ROT_BIN_KEY, "s" * 64))
    assert tag == "ROTATED" and usd == 0


def test_validate_binance_ip_bound():
    tag, usd, extra = _validate(
        lambda http: validate_binance(http, samples.IP_BIN_KEY, "s" * 64))
    assert tag == "IP-BOUND"
    assert extra.get("ip_restrict") is True


def test_validate_binance_read_only():
    tag, usd, extra = _validate(
        lambda http: validate_binance(http, samples.RO_BIN_KEY, "s" * 64))
    assert tag == "READ-ONLY"
    assert extra.get("withdrawals_enabled") is False


def test_validate_bybit_actionable_and_rotated():
    tag, _, _ = _validate(
        lambda http: validate_bybit(http, samples.BYB_ACTION_KEY,
                                    samples.BYB_ACTION_SEC))
    assert tag == "ACTIONABLE"
    tag, _, _ = _validate(
        lambda http: validate_bybit(http, "NopeKey1234567890",
                                    "s" * 32))
    assert tag == "ROTATED"


def test_validate_okx_rotated_and_no_passphrase():
    tag, _, _ = _validate(
        lambda http: validate_okx(http, samples.OKX_ROT_KEY, "S" * 32,
                                  samples.OKX_PASS))
    assert tag == "ROTATED"
    tag, _, _ = _validate(
        lambda http: validate_okx(http, samples.OKX_KEY, samples.OKX_SEC,
                                  None))
    assert tag == "UNVERIFIED"


def test_validate_kucoin_unverified():
    tag, _, extra = _validate(
        lambda http: validate_kucoin(http, samples.KC_KEY, samples.KC_SEC,
                                     samples.KC_PASS))
    assert tag == "UNVERIFIED"
    assert "k.py" in extra.get("note", "")


def test_github_repo_parse():
    t = Target(raw="https://github.com/jaykk99/recon-anything", type="url",
               normalized="https://github.com/jaykk99/recon-anything")
    assert _github_repo_from_target(t) == ("jaykk99", "recon-anything")
    t2 = Target(raw="https://example.com/", type="url",
                normalized="https://example.com/")
    assert _github_repo_from_target(t2) is None
