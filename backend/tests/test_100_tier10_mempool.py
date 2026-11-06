"""Tier-10 Real-Time Mempool, MEV & Transaction Monitoring.

HARD BOUNDARY under test: MONITORING / ANALYSIS ONLY. A dedicated
test asserts no Tier-10 module contains transaction-submission
surface (eth_sendBundle, eth_sendRawTransaction, send_transaction,
bundle building). Aave / Uniswap plugins are read-only quoters /
state readers; the arb plugin is a read-only state reader whose
findings are labeled non-actionable analysis.

Coverage map (master 4bb8195, 853 plugins): every pre-existing
mempool/MEV-adjacent plugin is a SOURCE-pattern detector
(flash_loan_* / mev_* deep-audit detectors, defi / defi_risk /
tokenapproval scanning page/contract source). tokenapproval in
particular never reads live allowances. watch_transitions lives in
the continuous scanner (state slots / owners), not the mempool.
All 10 Tier-10 tools are therefore genuine remainders: live pending
pool polling, live quoter reads, live Aave state, live allowance
audit, receipt/trace parsing, relay + MEV-Share + bloXroute status
readers. Zero DUPLICATE-OF.

Per plugin: fires on RICH mocked fixture (canned pending block /
trace / quote / receipt payloads through the real parsers over an
httpx MockTransport), silent on CLEAN, no crash on malformed.
"""
import asyncio
import json
import os
import sys
from urllib.parse import urlparse

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins import _tier10_common as C  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

NEW_IDS = ["flashbots_protect_status", "bloxroute_stream",
           "mempool_sniffer", "aave_v3_state", "uniswap_quoter",
           "revoke_watcher", "mev_tx_parser", "evm_tracer",
           "mev_share_status", "arb_state_reader"]
RICH, CLEAN, BAD, AUTHBAD = "rich", "clean", "bad", "authbad"
MODE = {"v": RICH}
WATCH = "0x1111111111111111111111111111111111111111"
OTHER = "0x2222222222222222222222222222222222222222"
EXTRACTOR = "0x3333333333333333333333333333333333333333"
TXHASH = "0x" + "ab" * 32
MAXU = (1 << 256) - 1


def _w(n):
    return format(int(n), "064x")


def _tx(frm, to, value, inp, h):
    return {"from": frm, "to": to, "value": hex(value), "input": inp,
            "hash": h}


def _pending_block(rich):
    if not rich:
        return {"number": "0x1", "transactions": []}
    swap = "0x414bf389" + "00" * 96
    approve = ("0x095ea7b3"
               + C.pad_addr(C.UNI_V2_ROUTER) + _w(MAXU))
    return {"number": "0x1", "transactions": [
        _tx(OTHER, C.UNI_V3_ROUTER, 0, swap, "0x" + "01" * 32),
        _tx(WATCH, C.USDT, 0, approve, "0x" + "02" * 32),
        _tx(WATCH, OTHER, 20 * 10**18, "0x", "0x" + "03" * 32),
        _tx(OTHER, OTHER, 10**16, "0x", "0x" + "04" * 32),
    ]}


def _receipt(rich):
    if not rich:
        return {"status": "0x1", "logs": []}
    def transfer(token, frm, to, value):
        return {"address": token,
                "topics": [C.TRANSFER_TOPIC,
                           "0x" + C.pad_addr(frm),
                           "0x" + C.pad_addr(to)],
                "data": "0x" + _w(value)}
    return {"status": "0x1", "logs": [
        transfer(C.USDT, OTHER, EXTRACTOR, 500 * 10**6),
        transfer(C.WETH, OTHER, EXTRACTOR, 10**18),
        transfer(C.USDT, EXTRACTOR, OTHER, 400 * 10**6),
        {"address": C.UNI_V3_ROUTER,
         "topics": [C.SWAP_V3_TOPIC], "data": "0x"},
    ]}


def _trace(rich):
    if not rich:
        return {"type": "CALL", "from": OTHER, "to": OTHER,
                "value": "0x0", "calls": []}
    return {"type": "CALL", "from": OTHER, "to": C.UNI_V3_ROUTER,
            "value": "0x0", "calls": [
                {"type": "DELEGATECALL", "from": OTHER,
                 "to": "0x9999999999999999999999999999999999999999",
                 "value": "0x0", "calls": []},
                {"type": "CALL", "from": OTHER, "to": C.AAVE_V3_POOL,
                 "value": hex(10**18), "error": "execution reverted",
                 "calls": []}]}


def _eth_call_result(to, data, rich):
    to_l = (to or "").lower()
    sel = data[2:10] if len(data) >= 10 else ""
    body = data[10:]
    words = [body[i * 64:(i + 1) * 64] for i in range(len(body) // 64)]
    if to_l == C.AAVE_V3_POOL.lower():
        if sel == C.SEL["getReservesList"]:
            if not rich:
                return "0x" + _w(32) + _w(0)
            return ("0x" + _w(32) + _w(2) + C.pad_addr(C.WETH)
                    + C.pad_addr(C.USDT))
        if sel == C.SEL["getReserveData"]:
            out = [_w(0), _w(0), _w(12345), _w(0), _w(6789), _w(0),
                   _w(1700000000), _w(0),
                   C.pad_addr("0x" + "aa" * 20)]
            out += [_w(0)] * 6
            return "0x" + "".join(out)
    if sel == C.SEL["balanceOf"]:
        return "0x" + _w(5000 * 10**18 if rich else 0)
    if sel == C.SEL["allowance"]:
        if not rich or len(words) < 2:
            return "0x" + _w(0)
        spender = "0x" + words[1][-40:]
        if spender.lower() == C.UNI_V3_ROUTER.lower():
            return "0x" + _w(MAXU)
        if to_l == C.USDC.lower() and \
                spender.lower() == C.PERMIT2.lower():
            return "0x" + _w(1000 * 10**6)
        return "0x" + _w(0)
    if to_l in (C.UNI_V3_QUOTER_V1.lower(), C.UNI_V3_QUOTER_V2.lower()):
        if not rich:
            return "0x"
        # tokenOut is word 1 in both encodings used here.
        tout = "0x" + words[1][-40:] if len(words) > 1 else ""
        dec = 6 if tout.lower() in (C.USDT.lower(), C.USDC.lower()) \
            else 18
        return "0x" + _w(3400 * 10**dec) + _w(0) + _w(0) + _w(0)
    if to_l == C.UNI_V2_ROUTER.lower() and \
            sel == C.SEL["getAmountsOut"]:
        if not rich:
            return "0x"
        return ("0x" + _w(32) + _w(2) + _w(10**18)
                + _w(3390 * 10**6))
    return "0x"


def _rpc_result(payload, rich):
    method = payload.get("method")
    params = payload.get("params") or []
    if method == "eth_chainId":
        return {"jsonrpc": "2.0", "id": 1, "result": "0x1"}
    if method == "eth_getBlockByNumber":
        return {"jsonrpc": "2.0", "id": 1,
                "result": _pending_block(rich)}
    if method == "txpool_content":
        return {"jsonrpc": "2.0", "id": 1,
                "result": {"pending": {}, "queued": {}}}
    if method == "eth_call":
        call = params[0] if params else {}
        return {"jsonrpc": "2.0", "id": 1,
                "result": _eth_call_result(call.get("to", ""),
                                           call.get("data", "0x"),
                                           rich)}
    if method == "eth_getTransactionReceipt":
        return {"jsonrpc": "2.0", "id": 1, "result": _receipt(rich)}
    if method == "eth_getTransactionByHash":
        return {"jsonrpc": "2.0", "id": 1,
                "result": {"to": C.UNI_V3_ROUTER, "hash": TXHASH}}
    if method == "debug_traceTransaction":
        return {"jsonrpc": "2.0", "id": 1, "result": _trace(rich)}
    return {"jsonrpc": "2.0", "id": 1, "result": None}


def _handler(request: httpx.Request) -> httpx.Response:
    url = urlparse(str(request.url))
    host = url.hostname or ""
    rich = MODE["v"] == RICH
    if MODE["v"] == BAD:
        return httpx.Response(200, content="{{{not json",
                              request=request)
    if host == "api.blxrbdn.com":
        if MODE["v"] == AUTHBAD:
            return httpx.Response(401, json={}, request=request)
        if rich:
            return httpx.Response(200, json={"result": {
                "connections": 3, "quota": "ok"}}, request=request)
        return httpx.Response(200, json={"result": {}},
                              request=request)
    if host == "relay.flashbots.net":
        if rich:
            return httpx.Response(200, content="ok", request=request)
        return httpx.Response(503, content="down", request=request)
    if host == "blocks.flashbots.net":
        if rich:
            return httpx.Response(200, json={"blocks": [
                {"block_number": 21000001, "num_bundles": 3,
                 "num_txs": 12},
                {"block_number": 21000000, "num_bundles": 2,
                 "num_txs": 9}]}, request=request)
        return httpx.Response(200, json={"blocks": [
            {"block_number": 21000001, "num_bundles": 0,
             "num_txs": 0}]}, request=request)
    # JSON-RPC hosts (public RPCs + Flashbots Protect).
    try:
        payload = json.loads(request.content or b"{}")
    except Exception:
        payload = {}
    if not rich and host == "rpc.flashbots.net":
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32000, "message": "down"}},
            request=request)
    return httpx.Response(200, json=_rpc_result(payload, rich),
                          request=request)


def make_ctx(keys=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_handler),
        follow_redirects=True, trust_env=False)
    return Ctx(run_id="tier10-test", mode="passive", http=client,
               cache=Cache(), keys=keys or {},
               limiter=RateLimiter(default_rps=10000.0),
               evidence_dir="/tmp", source_type="website")


def run(cls, raw, keys=None, mode=RICH, type_="url"):
    MODE["v"] = mode

    async def _go():
        ctx = make_ctx(keys=keys)
        try:
            return await cls().run(
                Target(raw=raw, type=type_, normalized=raw), ctx)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def keys_of(res):
    return {f.key for f in res.findings}


def test_registry_count_tier10():
    reg = discover()
    assert len(reg) == 1106, f"registry size {len(reg)}, expected 1106"
    for pid in NEW_IDS:
        assert pid in reg, f"{pid} missing"


def test_boundary_no_submission_surface():
    import app.plugins as pkg
    base = os.path.dirname(pkg.__file__)
    banned = ["eth_sendBundle", "eth_sendRawTransaction",
              "eth_sendPrivateTransaction", "send_transaction(",
              "sign_transaction", "submit_bundle"]
    for mod in ["_tier10_common", "flashbots_protect_status",
                "bloxroute_stream", "mempool_sniffer", "aave_v3_state",
                "uniswap_quoter", "revoke_watcher", "mev_tx_parser",
                "evm_tracer", "mev_share_status", "arb_state_reader"]:
        src = open(os.path.join(base, mod + ".py")).read()
        for b in banned:
            assert b not in src, f"{mod} contains banned surface {b}"


# --- flashbots_protect_status ----------------------------------------------
def test_flashbots_fires_rich():
    from app.plugins.flashbots_protect_status import \
        FlashbotsProtectStatusPlugin
    res = run(FlashbotsProtectStatusPlugin, "https://example.com")
    assert "flashbots_relay_health" in keys_of(res), keys_of(res)
    assert "flashbots_protect_endpoint" in keys_of(res)


def test_flashbots_clean_degraded():
    from app.plugins.flashbots_protect_status import \
        FlashbotsProtectStatusPlugin
    res = run(FlashbotsProtectStatusPlugin, "https://example.com",
              mode=CLEAN)
    assert "flashbots_relay_health" not in keys_of(res)
    assert "flashbots_relay_health_degraded" in keys_of(res)


def test_flashbots_malformed_no_crash():
    from app.plugins.flashbots_protect_status import \
        FlashbotsProtectStatusPlugin
    assert run(FlashbotsProtectStatusPlugin, "https://example.com",
               mode=BAD) is not None


# --- bloxroute_stream --------------------------------------------------------
def test_bloxroute_needs_key_skip():
    from app.plugins.bloxroute_stream import BloxrouteStreamPlugin
    res = run(BloxrouteStreamPlugin, "https://example.com")
    assert res.findings == []
    assert "BXR_AUTH_HEADER" in res.reason


def test_bloxroute_fires_with_key():
    from app.plugins.bloxroute_stream import BloxrouteStreamPlugin
    res = run(BloxrouteStreamPlugin, "https://example.com",
              keys={"BXR_AUTH_HEADER": "fixture"})
    assert "bloxroute_stream_state" in keys_of(res), keys_of(res)


def test_bloxroute_auth_rejected():
    from app.plugins.bloxroute_stream import BloxrouteStreamPlugin
    res = run(BloxrouteStreamPlugin, "https://example.com",
              keys={"BXR_AUTH_HEADER": "fixture"}, mode=AUTHBAD)
    assert "bloxroute_auth_rejected" in keys_of(res)


def test_bloxroute_malformed_no_crash():
    from app.plugins.bloxroute_stream import BloxrouteStreamPlugin
    assert run(BloxrouteStreamPlugin, "https://example.com",
               keys={"BXR_AUTH_HEADER": "fixture"}, mode=BAD) is not None


# --- mempool_sniffer ---------------------------------------------------------
def test_mempool_fires_rich():
    from app.plugins.mempool_sniffer import MempoolSnifferPlugin
    res = run(MempoolSnifferPlugin, f"ethereum:{WATCH}",
              type_="crypto_wallet")
    ks = keys_of(res)
    assert "mempool_unlimited_approval_pending" in ks, ks
    assert "mempool_large_value_pending" in ks
    assert "mempool_watched_swap_pending" in ks
    assert "mempool_target_tx_pending" in ks
    assert "mempool_sample_summary" in ks


def test_mempool_silent_clean():
    from app.plugins.mempool_sniffer import MempoolSnifferPlugin
    res = run(MempoolSnifferPlugin, "https://example.com", mode=CLEAN)
    assert res.findings == [], keys_of(res)


def test_mempool_malformed_no_crash():
    from app.plugins.mempool_sniffer import MempoolSnifferPlugin
    assert run(MempoolSnifferPlugin, "https://example.com",
               mode=BAD) is not None


def test_mempool_parser_txpool_shape():
    from app.plugins.mempool_sniffer import parse_pending
    tx = _tx(OTHER, OTHER, 0, "0x", "0x" + "05" * 32)
    assert parse_pending({"pending": {OTHER: {"0": tx}}}) == [tx]
    assert parse_pending(None) == []
    assert parse_pending({"transactions": "junk"}) == []


# --- aave_v3_state -----------------------------------------------------------
def test_aave_fires_rich():
    from app.plugins.aave_v3_state import AaveV3StatePlugin
    res = run(AaveV3StatePlugin, "https://example.com")
    ks = keys_of(res)
    assert "aave_v3_reserves" in ks, ks
    assert "aave_v3_weth_reserve" in ks
    assert "aave_v3_weth_liquidity" in ks
    f = [x for x in res.findings if x.key == "aave_v3_reserves"][0]
    assert f.evidence["reserve_count"] == 2


def test_aave_clean_partial():
    from app.plugins.aave_v3_state import AaveV3StatePlugin
    res = run(AaveV3StatePlugin, "https://example.com", mode=CLEAN)
    f = [x for x in res.findings if x.key == "aave_v3_reserves"]
    assert f and f[0].evidence["reserve_count"] == 0


def test_aave_malformed_no_crash():
    from app.plugins.aave_v3_state import AaveV3StatePlugin
    assert run(AaveV3StatePlugin, "https://example.com",
               mode=BAD) is not None


# --- uniswap_quoter ----------------------------------------------------------
def test_uniswap_fires_rich():
    from app.plugins.uniswap_quoter import UniswapQuoterPlugin
    res = run(UniswapQuoterPlugin, "https://example.com")
    ks = keys_of(res)
    assert "uniswap_v3_quote" in ks, ks
    assert "uniswap_fee_tier_spread" in ks
    f = [x for x in res.findings if x.key == "uniswap_v3_quote"][0]
    assert abs(f.evidence["implied_price"] - 3400.0) < 0.01


def test_uniswap_silent_clean():
    from app.plugins.uniswap_quoter import UniswapQuoterPlugin
    res = run(UniswapQuoterPlugin, "https://example.com", mode=CLEAN)
    assert res.findings == [], keys_of(res)


def test_uniswap_malformed_no_crash():
    from app.plugins.uniswap_quoter import UniswapQuoterPlugin
    assert run(UniswapQuoterPlugin, "https://example.com",
               mode=BAD) is not None


# --- revoke_watcher ----------------------------------------------------------
def test_revoke_fires_rich():
    from app.plugins.revoke_watcher import RevokeWatcherPlugin
    res = run(RevokeWatcherPlugin, f"ethereum:{WATCH}",
              type_="crypto_wallet")
    ks = keys_of(res)
    assert "unlimited_allowance_live" in ks, ks
    assert "standing_allowance_live" in ks


def test_revoke_silent_clean():
    from app.plugins.revoke_watcher import RevokeWatcherPlugin
    res = run(RevokeWatcherPlugin, f"ethereum:{WATCH}",
              mode=CLEAN, type_="crypto_wallet")
    assert res.findings == [], keys_of(res)


def test_revoke_no_address_skips():
    from app.plugins.revoke_watcher import RevokeWatcherPlugin
    res = run(RevokeWatcherPlugin, "https://example.com")
    assert res.findings == []


def test_revoke_malformed_no_crash():
    from app.plugins.revoke_watcher import RevokeWatcherPlugin
    assert run(RevokeWatcherPlugin, f"ethereum:{WATCH}", mode=BAD,
               type_="crypto_wallet") is not None


# --- mev_tx_parser -----------------------------------------------------------
def test_mev_parser_fires_rich():
    from app.plugins.mev_tx_parser import MevTxParserPlugin
    res = run(MevTxParserPlugin, f"ethereum:{TXHASH}",
              type_="crypto_wallet")
    ks = keys_of(res)
    assert "mev_tx_summary" in ks, ks
    assert "mev_tx_transfer" in ks
    assert "mev_profit_shaped_flow" in ks


def test_mev_parser_clean_no_profit():
    from app.plugins.mev_tx_parser import MevTxParserPlugin
    res = run(MevTxParserPlugin, f"ethereum:{TXHASH}", mode=CLEAN,
              type_="crypto_wallet")
    assert "mev_profit_shaped_flow" not in keys_of(res)
    assert "mev_tx_transfer" not in keys_of(res)


def test_mev_parser_no_hash_skips():
    from app.plugins.mev_tx_parser import MevTxParserPlugin
    res = run(MevTxParserPlugin, "https://example.com")
    assert res.findings == []


def test_mev_parser_malformed_no_crash():
    from app.plugins.mev_tx_parser import MevTxParserPlugin
    assert run(MevTxParserPlugin, f"ethereum:{TXHASH}", mode=BAD,
               type_="crypto_wallet") is not None


# --- evm_tracer --------------------------------------------------------------
def test_tracer_fires_rich():
    from app.plugins.evm_tracer import EvmTracerPlugin
    res = run(EvmTracerPlugin, f"ethereum:{TXHASH}",
              type_="crypto_wallet")
    ks = keys_of(res)
    assert "evm_trace_summary" in ks, ks
    assert "evm_trace_delegatecall" in ks
    assert "evm_trace_known_contract" in ks


def test_tracer_clean_summary_only():
    from app.plugins.evm_tracer import EvmTracerPlugin
    res = run(EvmTracerPlugin, f"ethereum:{TXHASH}", mode=CLEAN,
              type_="crypto_wallet")
    assert "evm_trace_delegatecall" not in keys_of(res)
    assert "evm_trace_summary" in keys_of(res)


def test_tracer_malformed_no_crash():
    from app.plugins.evm_tracer import EvmTracerPlugin
    assert run(EvmTracerPlugin, f"ethereum:{TXHASH}", mode=BAD,
               type_="crypto_wallet") is not None


def test_tracer_parser_pure():
    from app.plugins.evm_tracer import parse_trace
    out = parse_trace(_trace(True))
    assert out["total"] == 3 and len(out["delegatecalls"]) == 1
    assert out["reverted"] == 1


# --- mev_share_status --------------------------------------------------------
def test_mev_share_fires_rich():
    from app.plugins.mev_share_status import MevShareStatusPlugin
    res = run(MevShareStatusPlugin, "https://example.com")
    ks = keys_of(res)
    assert "mev_share_inclusion_stats" in ks, ks
    f = [x for x in res.findings
         if x.key == "mev_share_inclusion_stats"][0]
    assert f.evidence["total_bundles"] == 5


def test_mev_share_clean_zero_bundles():
    from app.plugins.mev_share_status import MevShareStatusPlugin
    res = run(MevShareStatusPlugin, "https://example.com", mode=CLEAN)
    assert "mev_share_no_bundles" in keys_of(res)


def test_mev_share_malformed_no_crash():
    from app.plugins.mev_share_status import MevShareStatusPlugin
    assert run(MevShareStatusPlugin, "https://example.com",
               mode=BAD) is not None


# --- arb_state_reader ----------------------------------------------------------
def test_arb_fires_rich_analysis_labeled():
    from app.plugins.arb_state_reader import ArbStateReaderPlugin
    res = run(ArbStateReaderPlugin, "https://example.com")
    ks = keys_of(res)
    assert "arb_spread_observation_analysis" in ks, ks
    for f in res.findings:
        assert f.evidence.get("analysis_only") is True
        assert f.evidence.get("non_actionable") is True
        assert "ANALYSIS" in f.value


def test_arb_silent_clean():
    from app.plugins.arb_state_reader import ArbStateReaderPlugin
    res = run(ArbStateReaderPlugin, "https://example.com", mode=CLEAN)
    assert res.findings == [], keys_of(res)


def test_arb_malformed_no_crash():
    from app.plugins.arb_state_reader import ArbStateReaderPlugin
    assert run(ArbStateReaderPlugin, "https://example.com",
               mode=BAD) is not None
