"""Track 2: RPC provider pool + batched deep-lane transports.

Pins the contract of app/rpc_pool.py and the batched readers built
on it (contract_chain.rpc_batch chunking / rpc_get_storage_batch /
resolve_implementation batching, contract_sim.eth_call_batch,
_tier10_common.rpc_batch):

- the pool is KEYLESS (plain HTTPS, no API-key-shaped URLs), rotates
  across healthy endpoints, trips its dead-host breaker only after
  a failure STREAK (mirroring the continuous scanner's HostHealth),
  escalates cooldowns, and treats a 429 as exponential throttle
  backoff rather than instant death;
- batched reads issue ONE HTTP POST per chunk (instrumented count,
  not an assertion about timing), match responses by JSON-RPC id,
  and return results in request order;
- every batched path returns None on total failure so callers fall
  back to the per-call helpers with identical results.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.rpc_pool import RpcPool, throttle_backoff_s  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_sim  # noqa: E402
from app.plugins import _tier10_common as t10  # noqa: E402

ADDR = "0x1111111111111111111111111111111111111111"
IMPL = "0x2222222222222222222222222222222222222222"


def _word(addr):
    return "0x" + "00" * 12 + addr[2:]


class FakeCtx:
    def __init__(self, http=None):
        self.keys = {}
        self.mode = "passive"
        self.http = http
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


class Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


# ---------------------------------------------------------------------------
# Pool: keyless endpoints, rotation, breaker, 429 backoff
# ---------------------------------------------------------------------------

def test_pool_endpoints_are_keyless_and_widen_the_chain_list():
    pool = RpcPool()
    urls = pool.endpoints("ethereum", cc.CHAINS["ethereum"].rpc_urls)
    assert len(urls) > len(cc.CHAINS["ethereum"].rpc_urls)
    assert len(set(urls)) == len(urls)
    for u in urls:
        assert u.startswith("https://"), u
        assert "?" not in u and "key" not in u.lower(), u


def test_pool_rotates_across_healthy_endpoints():
    pool = RpcPool()
    base = ["https://a", "https://b", "https://c"]
    starts = [pool.order("testchain", base)[0] for _ in range(3)]
    assert starts == base  # round-robin: a, b, c


def test_pool_breaker_trips_only_after_a_streak():
    pool = RpcPool()
    base = ["https://dead", "https://good"]
    pool.note_response("https://good", 200)
    for _ in range(4):
        pool.note_transport_error("https://dead")
    # 4 < HARD_STREAK: still offered first-class, not cooling.
    assert pool.order("testchain", base)[0] == "https://dead"
    pool.note_transport_error("https://dead")
    order = pool.order("testchain", base)
    assert order[0] == "https://good"
    assert order[-1] == "https://dead"  # kept as last-resort fallback
    # A success closes the breaker and resets the streak.
    pool.note_response("https://dead", 200)
    assert not pool.stats()["hosts"]["https://dead"]["cooling"]


def test_pool_429_is_exponential_throttle_not_death():
    assert throttle_backoff_s(1) == 2.0
    assert throttle_backoff_s(2) == 4.0
    assert throttle_backoff_s(3) == 8.0
    assert throttle_backoff_s(99) == 60.0  # capped
    pool = RpcPool()
    base = ["https://busy", "https://good"]
    pool.note_response("https://busy", 429)
    st = pool.stats()["hosts"]["https://busy"]
    assert st["throttled"] and not st["cooling"]  # one 429 != dead
    assert pool.order("testchain", base)[0] == "https://good"
    pool.note_response("https://busy", 200)
    st = pool.stats()["hosts"]["https://busy"]
    assert not st["throttled"] and st["throttle_streak"] == 0


def test_pool_soft_rule_needs_a_working_network_first():
    pool = RpcPool()
    base = ["https://dead", "https://alsodead"]
    for _ in range(12):
        pool.note_response("https://dead", 404)
    # Zero successes anywhere: outage signature, soft rule unarmed.
    assert not pool.stats()["hosts"]["https://dead"]["cooling"]
    pool.note_response("https://alsodead", 200)
    for _ in range(12):
        pool.note_response("https://dead", 404)
    assert pool.stats()["hosts"]["https://dead"]["cooling"]


# ---------------------------------------------------------------------------
# contract_chain: chunked rpc_batch, storage batch + cache seeding
# ---------------------------------------------------------------------------

def _batch_fake_fetch(posts):
    async def fake_fetch(http, limiter, method, url, **kw):
        payload = kw["json"]
        posts.append(payload)
        return Resp([{"jsonrpc": "2.0", "id": item["id"],
                      "result": f"0x{item['id']:x}"} for item in payload])
    return fake_fetch


def test_rpc_batch_chunks_large_read_sets(monkeypatch):
    posts = []
    monkeypatch.setattr(cc, "fetch", _batch_fake_fetch(posts))
    ctx = FakeCtx(http=object())
    calls = [("eth_getStorageAt", [ADDR, hex(i), "latest"])
             for i in range(250)]
    out = asyncio.run(cc.rpc_batch(ctx, cc.CHAINS["ethereum"], calls))
    assert out is not None and len(out) == 250
    assert out[0] == "0x1" and out[249] == "0xfa"
    # 250 calls at RPC_BATCH_MAX=100 -> exactly 3 POSTs, not 250.
    assert [len(p) for p in posts] == [100, 100, 50]


def test_rpc_get_storage_batch_seeds_the_storage_cache(monkeypatch):
    posts = []
    monkeypatch.setattr(cc, "fetch", _batch_fake_fetch(posts))
    ctx = FakeCtx(http=object())
    chain = cc.CHAINS["ethereum"]
    slots = ["0x0", "0x1"]

    async def go():
        out = await cc.rpc_get_storage_batch(ctx, chain, ADDR, slots)
        assert out == {"0x0": "0x1", "0x1": "0x2"}
        assert len(posts) == 1
        # The per-slot helper now serves both words from cache:
        # no further POSTs.
        assert await cc.rpc_get_storage_at(ctx, chain, ADDR, "0x0") == "0x1"
        assert await cc.rpc_get_storage_at(ctx, chain, ADDR, "0x1") == "0x2"
        assert len(posts) == 1

    asyncio.run(go())


def test_rpc_get_storage_batch_needs_a_client():
    out = asyncio.run(cc.rpc_get_storage_batch(
        FakeCtx(http=None), cc.CHAINS["ethereum"], ADDR, ["0x0"]))
    assert out is None  # caller falls back to per-slot reads


def test_resolve_implementation_reads_both_slots_in_one_post(monkeypatch):
    posts = []

    async def fake_fetch(http, limiter, method, url, **kw):
        payload = kw["json"]
        posts.append(payload)
        assert isinstance(payload, list) and len(payload) == 2
        out = []
        for item in payload:
            slot = item["params"][1]
            out.append({"jsonrpc": "2.0", "id": item["id"],
                        "result": _word(IMPL)
                        if slot == cc.EIP1967_IMPLEMENTATION_SLOT
                        else "0x" + "0" * 64})
        return Resp(out)

    monkeypatch.setattr(cc, "fetch", fake_fetch)
    res = asyncio.run(cc.resolve_implementation(
        FakeCtx(http=object()), cc.CHAINS["ethereum"], ADDR,
        "0x6000", {}))
    assert res["implementation"] == IMPL.lower()
    assert res["via"] == "eip1967_slot"
    assert len(posts) == 1  # both slots in a single round-trip


# ---------------------------------------------------------------------------
# contract_sim.eth_call_batch
# ---------------------------------------------------------------------------

def test_eth_call_batch_one_post_id_matched(monkeypatch):
    posts = []

    async def fake_fetch(http, limiter, method, url, **kw):
        payload = kw["json"]
        posts.append(payload)
        items = []
        for item in payload:
            if item["id"] == 2:
                items.append({"jsonrpc": "2.0", "id": 2,
                              "error": {"code": 3, "message": "revert"}})
            else:
                items.append({"jsonrpc": "2.0", "id": item["id"],
                              "result": "0x2a"})
        return Resp(list(reversed(items)))  # shuffled: ids must rule

    monkeypatch.setattr(contract_sim, "fetch", fake_fetch)
    ctx = FakeCtx(http=object())
    calls = [{"to": ADDR, "data": "0x06fdde03",
              "sender": contract_sim.FUZZ_CALLER} for _ in range(3)]
    out = asyncio.run(contract_sim.eth_call_batch(
        ctx, cc.CHAINS["ethereum"], calls))
    assert out is not None and len(posts) == 1
    assert [r["status"] for r in out] == ["success", "revert", "success"]
    assert out[0]["result"] == "0x2a"


def test_eth_call_batch_failure_returns_none_for_fallback(monkeypatch):
    async def fake_fetch(http, limiter, method, url, **kw):
        return Resp({"jsonrpc": "2.0", "id": 1, "result": "0x"},
                    status_code=200)  # single-object body: not a batch

    monkeypatch.setattr(contract_sim, "fetch", fake_fetch)
    ctx = FakeCtx(http=object())
    out = asyncio.run(contract_sim.eth_call_batch(
        ctx, cc.CHAINS["ethereum"],
        [{"to": ADDR, "data": "0x06fdde03",
          "sender": contract_sim.FUZZ_CALLER}]))
    assert out is None


def test_eth_call_batch_needs_a_client():
    out = asyncio.run(contract_sim.eth_call_batch(
        FakeCtx(http=None), cc.CHAINS["ethereum"],
        [{"to": ADDR, "data": "0x06fdde03",
          "sender": contract_sim.FUZZ_CALLER}]))
    assert out is None


# ---------------------------------------------------------------------------
# _tier10_common.rpc_batch / eth_call_many
# ---------------------------------------------------------------------------

class _FakeHttp:
    def __init__(self):
        self.posts = []

    async def post(self, url, json=None, timeout=None):
        self.posts.append(json)
        return Resp([{"jsonrpc": "2.0", "id": item["id"],
                      "result": "0x10"} for item in json])


def test_tier10_rpc_batch_and_eth_call_many():
    ctx = FakeCtx(http=_FakeHttp())

    async def go():
        results, err = await t10.rpc_batch(ctx, [
            ("eth_blockNumber", []),
            ("eth_getBalance", [ADDR, "latest"])])
        assert err == "" and results == ["0x10", "0x10"]
        many = await t10.eth_call_many(ctx, [(ADDR, "0x06fdde03"),
                                             (ADDR, "0x18160ddd")])
        assert many == [("0x10", ""), ("0x10", "")]
        assert len(ctx.http.posts) == 2  # one POST per batch

    asyncio.run(go())
