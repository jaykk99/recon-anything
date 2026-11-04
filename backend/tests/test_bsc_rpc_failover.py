"""BSC RPC failover (fix/bsc-rpc-failover).

Proven problem (2026-11-03): the BSC chain config carried only two
public RPC endpoints (bsc-rpc.publicnode.com + bsc-dataseed.bnbchain.org).
Both failed / rate-limited for a full afternoon, so every BSC scan came
back DEGRADED (plugins analyzed 0 contracts) while hand probes to other
keyless BSC endpoints (the Binance dataseed family, Ankr) answered fine.

These tests pin:
1. The BSC endpoint list itself: broad, unique, keyless (plain HTTPS,
   no API-key-shaped URLs), with the verified dataseed family present.
2. The failover contract of the chain readers: rpc_get_code and
   rpc_get_storage_at must skip a dead endpoint (exception), a
   rate-limited / error endpoint (non-200, or HTTP 200 carrying a
   JSON-RPC error) and return the next endpoint's answer - and must
   return None only when EVERY endpoint failed.
3. contract_sim.eth_call fails over its public JSON-RPC routes the
   same way (Blockscout eth-rpc dead + first RPC dead -> second RPC's
   answer wins).
"""
import asyncio

from app.plugins import contract_chain as cc
from app.plugins import contract_sim


ADDR = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"  # WBNB


class FakeCtx:
    def __init__(self):
        self.http = None
        self.limiter = None


class Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


# ---------------------------------------------------------------------------
# 1. The endpoint list
# ---------------------------------------------------------------------------

def test_bsc_rpc_list_is_broad_keyless_and_unique():
    urls = cc.CHAINS["bsc"].rpc_urls
    assert len(urls) >= 7, urls
    assert len(set(urls)) == len(urls), "duplicate endpoints"
    for u in urls:
        assert u.startswith("https://"), u
        # keyless: no api key / token query params baked into the URL
        assert "?" not in u and "key" not in u.lower(), u
    # the family that answered hand probes while the old pair was down
    assert "https://bsc-dataseed.binance.org" in urls
    assert "https://bsc-dataseed1.binance.org" in urls
    # the old pair stays in the rotation as fallbacks, not the whole list
    assert "https://bsc-dataseed.bnbchain.org" in urls
    assert "https://bsc-rpc.publicnode.com" in urls


def test_every_chain_keeps_multiple_rpc_endpoints():
    for chain in cc.CHAINS.values():
        assert len(chain.rpc_urls) >= 2, chain.id


# ---------------------------------------------------------------------------
# 2. rpc_get_code / rpc_get_storage_at failover
# ---------------------------------------------------------------------------

def _patch_fetch(monkeypatch, behavior, calls, module=cc):
    async def fake_fetch(client, limiter, method, url, **kw):
        calls.append(url)
        action = behavior[url]
        if action == "raise":
            raise ConnectionError("endpoint down")
        if isinstance(action, int):
            return Resp(status_code=action)
        return Resp(payload=action)
    monkeypatch.setattr(module, "fetch", fake_fetch)


def test_rpc_get_code_fails_over_dead_and_rate_limited(monkeypatch):
    chain = cc.CHAINS["bsc"]
    behavior = {u: "raise" for u in chain.rpc_urls}
    behavior[chain.rpc_urls[0]] = "raise"          # dead
    behavior[chain.rpc_urls[1]] = 429              # rate-limited
    behavior[chain.rpc_urls[2]] = {"result": "0x60806040"}
    calls = []
    _patch_fetch(monkeypatch, behavior, calls)
    out = asyncio.run(cc.rpc_get_code(FakeCtx(), chain, ADDR))
    assert out == "0x60806040"
    assert calls == list(chain.rpc_urls[:3])


def test_rpc_get_code_skips_jsonrpc_error_responses(monkeypatch):
    chain = cc.CHAINS["bsc"]
    behavior = {u: "raise" for u in chain.rpc_urls}
    # HTTP 200 but a JSON-RPC error body (the usual rate-limit shape):
    # no "result", so the reader must move on, not give up.
    behavior[chain.rpc_urls[0]] = {"error": {"code": -32005,
                                             "message": "limit exceeded"}}
    behavior[chain.rpc_urls[1]] = {"result": "0x00"}
    calls = []
    _patch_fetch(monkeypatch, behavior, calls)
    out = asyncio.run(cc.rpc_get_code(FakeCtx(), chain, ADDR))
    assert out == "0x00"
    assert calls == list(chain.rpc_urls[:2])


def test_rpc_get_code_returns_none_only_when_all_fail(monkeypatch):
    chain = cc.CHAINS["bsc"]
    behavior = {u: "raise" for u in chain.rpc_urls}
    calls = []
    _patch_fetch(monkeypatch, behavior, calls)
    out = asyncio.run(cc.rpc_get_code(FakeCtx(), chain, ADDR))
    assert out is None
    assert calls == list(chain.rpc_urls)  # every endpoint was tried


def test_rpc_get_storage_at_fails_over(monkeypatch):
    chain = cc.CHAINS["bsc"]
    word = "0x" + "00" * 12 + "bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
    behavior = {u: 503 for u in chain.rpc_urls}
    behavior[chain.rpc_urls[1]] = {"result": word}
    calls = []
    _patch_fetch(monkeypatch, behavior, calls)
    out = asyncio.run(cc.rpc_get_storage_at(
        FakeCtx(), chain, ADDR, cc.EIP1967_IMPLEMENTATION_SLOT))
    assert out == word
    assert calls == list(chain.rpc_urls[:2])


# ---------------------------------------------------------------------------
# 3. contract_sim.eth_call failover across its routes
# ---------------------------------------------------------------------------

def test_eth_call_fails_over_routes(monkeypatch):
    chain = cc.CHAINS["bsc"]
    calls = []

    async def fake_fetch(client, limiter, method, url, **kw):
        calls.append(url)
        if "blockscout" in url:
            raise ConnectionError("blockscout eth-rpc down")
        if url == chain.rpc_urls[0]:
            return Resp(status_code=500)
        return Resp(payload={"result": "0xdeadbeef"})
    monkeypatch.setattr(contract_sim, "fetch", fake_fetch)
    out = asyncio.run(contract_sim.eth_call(
        FakeCtx(), chain, ADDR, "0x06fdde03",
        "0x00000000000000000000000000000000deaDBeef"))
    assert out["status"] == "success"
    assert out["result"] == "0xdeadbeef"
    # blockscout route tried first, then RPCs in config order
    assert "blockscout" in calls[0]
    assert calls[1] == chain.rpc_urls[0]
    assert calls[2] == chain.rpc_urls[1]
