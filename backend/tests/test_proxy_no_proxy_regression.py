"""Regression: NO_PROXY entries that crash httpx at client construction.

2026-11-20, Wrapped SOL scan (mint So11111111111111111111111111111111111111112):
the Solana program-account fetch in app/plugins/deep_solana.py built a
bare httpx.AsyncClient (trust_env=True, the httpx default). In this
sandbox NO_PROXY contains bracketed IPv6 entries ("[::1]",
"[fd8b:4f84:7d32:99::1]") and httpx's own env-proxy parser dies on
them before the first request:

    httpx.InvalidURL: Invalid port: ':1]'

The scan crashed once and only finished after switching to the
scanner's own client by hand. The fix (app/net.py):
sanitize_no_proxy_env() rewrites bracketed IPv6 / IPv6-CIDR entries
into the form httpx accepts, net.async_client/sync_client call it,
it runs at net import so bare httpx clients in-process are protected
too, and the Solana / infra / breachwatch call sites now use
net.async_client. net._mount_host also stopped bracketing
"host:port" entries ("[localhost:8080]" is not valid IPv6 and
crashed net's own mounts with InvalidURL).

These tests use no live network and no funds: the Solana fetch test
answers the RPC call with a canned getAccountInfo response.
"""
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import net as net_mod
from app.http_client import sanitize_no_proxy

# The exact NO_PROXY this sandbox sets (2026-11-20).
SANDBOX_NO_PROXY = (
    "localhost,127.0.0.1,::1,[::1],198.19.0.1,198.19.0.2,"
    "fd8b:4f84:7d32:99::1,[fd8b:4f84:7d32:99::1],"
    "fd8b:4f84:7d32:99::2,[fd8b:4f84:7d32:99::2]"
)


@pytest.fixture
def breaking_env(monkeypatch):
    monkeypatch.setenv("NO_PROXY", SANDBOX_NO_PROXY)
    monkeypatch.setenv("no_proxy", SANDBOX_NO_PROXY)
    return SANDBOX_NO_PROXY


def test_raw_httpx_crashes_on_bracketed_ipv6_without_sanitize(breaking_env):
    """Pins the upstream breaking input: bare httpx dies on '[::1]'."""
    with pytest.raises(httpx.InvalidURL, match="Invalid port"):
        httpx.Client(timeout=5)


def test_sanitize_rewrites_bracketed_ipv6_and_dedupes(breaking_env):
    assert net_mod.sanitize_no_proxy_env() is True
    val = os.environ["NO_PROXY"]
    assert "[" not in val and "]" not in val
    for host in ("localhost", "127.0.0.1", "::1", "198.19.0.1",
                 "198.19.0.2", "fd8b:4f84:7d32:99::1",
                 "fd8b:4f84:7d32:99::2"):
        assert host in val.split(",")
    assert os.environ["no_proxy"] == val
    # Second call is a no-op (idempotent).
    assert net_mod.sanitize_no_proxy_env() is False


def test_sanitize_strips_ipv6_cidr_but_keeps_ipv4_cidr(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "::1/128,192.168.0.0/16,example.com")
    monkeypatch.setenv("no_proxy", "::1/128,192.168.0.0/16,example.com")
    net_mod.sanitize_no_proxy_env()
    assert os.environ["NO_PROXY"] == "::1,192.168.0.0/16,example.com"


def test_raw_httpx_client_survives_after_sanitize(breaking_env):
    net_mod.sanitize_no_proxy_env()
    with httpx.Client(timeout=5) as c:
        assert c is not None
    # Construction is what crashes (InvalidURL in get_environment_proxies);
    # no request is made here.
    c = httpx.AsyncClient(timeout=5)
    assert c is not None


def test_net_clients_survive_host_port_no_proxy(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "localhost:8080,example.com:8080")
    monkeypatch.setenv("no_proxy", "localhost:8080,example.com:8080")
    mounts = net_mod._direct_mounts()
    assert "http://localhost" in mounts
    assert "http://example.com" in mounts
    assert not any("[" in k for k in mounts)
    with net_mod.sync_client() as c:
        assert c is not None
    # Construction is what crashes; no request is made here.
    c = net_mod.async_client()
    assert c is not None


def test_http_client_sanitize_keeps_ipv6_bypass(breaking_env):
    sanitize_no_proxy()
    val = os.environ["NO_PROXY"]
    assert "::1" in val.split(",")
    assert "fd8b:4f84:7d32:99::1" in val.split(",")
    assert "[" not in val


def test_deep_solana_fetch_under_breaking_env(monkeypatch, breaking_env):
    """The exact Wrapped SOL crash path, with a canned RPC answer.

    _fetch_program_account must construct its client and parse the
    account instead of dying in httpx's NO_PROXY parser. No live
    network: the transport answers getAccountInfo for Wrapped SOL.
    """
    from app.plugins.deep_solana import _fetch_program_account

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/"
        return httpx.Response(200, json={
            "result": {"value": {
                "data": ["aGVsbG8=", "base64"],
                "owner": "11111111111111111111111111111111",
                "executable": True,
            }},
        })

    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        # net.async_client passes mounts + proxy, and httpx routes via
        # those mounts ahead of `transport`, so clear them here: the
        # point of this test is the client construction + response
        # parsing in _fetch_program_account, not the live proxy.
        kwargs["transport"] = httpx.MockTransport(handler)
        kwargs["mounts"] = None
        kwargs["proxy"] = None
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(net_mod.httpx, "AsyncClient", patched_async_client)
    import asyncio

    result = asyncio.run(_fetch_program_account(
        None, "So11111111111111111111111111111111111111112"))
    assert result is not None
    assert result["program_id"] == "So11111111111111111111111111111111111111112"
    assert result["account_data_base64"] == "aGVsbG8="
    assert result["owner"] == "11111111111111111111111111111111"
    assert result["executable"] is True
    # The fix normalized the env instead of crashing on it.
    assert "[" not in os.environ["NO_PROXY"]
