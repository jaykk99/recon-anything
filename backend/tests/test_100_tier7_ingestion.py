"""Tier-7 Blockchain Ingestion & Smart Contract Discovery.

Per shipped plugin: fires on the RICH/mocked fixture, silent on the
CLEAN/empty fixture, no crash on malformed input. All HTTP runs over
an httpx MockTransport; keyed plugins (QuickNode, Alchemy, Dune,
TheGraph gateway) verify the needs-key clean skip with no key and
the real query path with a fixture key.

Duplicate mapping (master dee4763, 853 plugins): chain_osint /
contract_audit / defi_risk already fetch Etherscan getsourcecode +
Sourcify source TEXT for analyzers (single chain, bundle discarded)
and flag latestRoundData in source; cp_apikey_* only scan for leaked
keys. Tier-7 ships the remainders: multi-explorer bundle inventory,
Sourcify match-quality, Blockscout crawl (new), keyed stream/webhook
describe-validate (new), RPC head consistency (new), LIVE Chainlink
feed reads (new), Dune export (new), Subsquid archive discovery
(new), The Graph health (new).
"""
import asyncio
import json
import os
import sys
import time
from urllib.parse import urlparse

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

NEW_IDS = ["etherscan_bundle", "sourcify_fetch", "blockscout_crawler",
           "quicknode_streams", "alchemy_webhooks", "helios_consistency",
           "chainlink_feeds", "dune_exporter", "subsquid_discovery",
           "thegraph_subgraphs"]
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
RICH = "rich"
CLEAN = "clean"
BAD = "bad"
MODE = {"v": RICH}


def _w(n, signed=False):
    if signed and n < 0:
        n += 1 << 256
    return format(n, "064x")


def _handler(request: httpx.Request) -> httpx.Response:
    url = urlparse(str(request.url))
    host, path = url.hostname or "", url.path or "/"
    rich = MODE["v"] == RICH
    bad = MODE["v"] == BAD
    if bad:
        return httpx.Response(200, content="{{{not json", request=request)

    if "etherscan" in host or "bscscan" in host or "polygonscan" in host \
            or "arbiscan" in host or "basescan" in host:
        if rich:
            return httpx.Response(200, json={"status": "1", "result": [{
                "SourceCode": "contract WETH9 { } // " + "x" * 500,
                "ABI": json.dumps([{"type": "function", "name": "deposit"},
                                   {"type": "function", "name": "withdraw"}]),
                "ContractName": "WETH9", "CompilerVersion": "v0.4.19",
                "ConstructorArguments": "00" * 32, "Proxy": "0"}]},
                request=request)
        return httpx.Response(200, json={"status": "1", "result": [{
            "SourceCode": "", "ABI": "Contract source code not verified",
            "ContractName": "", "CompilerVersion": "",
            "ConstructorArguments": "", "Proxy": "0"}]}, request=request)

    if host == "sourcify.dev":
        if rich:
            return httpx.Response(200, json={
                "match": "partial", "verified": "partial_match",
                "compilation": {"name": "WETH9",
                                "compilerVersion": "0.4.19"},
                "sources": {"WETH9.sol": {}, "a.sol": {}}},
                request=request)
        return httpx.Response(404, json={}, request=request)

    if "blockscout" in host:
        if path == "/api":  # Etherscan-compatible getsourcecode route
            if rich:
                return httpx.Response(200, json={"status": "1", "result": [{
                    "SourceCode": "contract WETH9 { } // " + "x" * 500,
                    "ABI": json.dumps(
                        [{"type": "function", "name": "deposit"},
                         {"type": "function", "name": "withdraw"}]),
                    "ContractName": "WETH9", "CompilerVersion": "v0.4.19",
                    "ConstructorArguments": "00" * 32, "Proxy": "0"}]},
                    request=request)
            return httpx.Response(200, json={"status": "1", "result": [{
                "SourceCode": "",
                "ABI": "Contract source code not verified",
                "ContractName": "", "CompilerVersion": "",
                "ConstructorArguments": "", "Proxy": "0"}]}, request=request)
        if "/counters" in path:
            return httpx.Response(200, json={
                "transactions_count": "12000",
                "token_transfers_count": "3000",
                "internal_transactions_count": "2500"}, request=request)
        if "/addresses/" in path:
            return httpx.Response(200, json={
                "is_contract": True, "name": "WETH9",
                "is_verified": True}, request=request)
        return httpx.Response(404, json={}, request=request)

    if host == "api.quicknode.com":
        if rich:
            return httpx.Response(200, json={"data": [{
                "id": "s1", "name": "watch-weth", "status": "running",
                "network": "ethereum-mainnet",
                "destination_type": "webhook",
                "filter": WETH.lower()}]}, request=request)
        return httpx.Response(200, json={"data": []}, request=request)

    if host == "dashboard.alchemy.com":
        if rich:
            return httpx.Response(200, json={"data": [{
                "id": "wbh_1", "url": "https://hooks.example/x",
                "network": "ETH_MAINNET", "is_active": True,
                "addresses": [WETH]}]}, request=request)
        return httpx.Response(200, json={"data": []}, request=request)

    if host in ("ethereum-rpc.publicnode.com", "eth.drpc.org"):
        try:
            body = json.loads(request.content or b"{}")
        except Exception:
            body = {}
        method = body.get("method")
        if method == "eth_getBlockByNumber":
            number, h = 21000000, "0x" + "ab" * 32
            if rich and host == "eth.drpc.org":
                h = "0x" + "cd" * 32  # same height, different hash
            return httpx.Response(200, json={"result": {
                "number": hex(number), "hash": h,
                "timestamp": hex(int(time.time()))}}, request=request)
        if method == "eth_call":
            if not rich:
                return httpx.Response(200, json={"result": "0x"},
                                      request=request)
            stale = int(time.time()) - 7200
            data = "0x" + _w(100) + _w(250000000000, signed=True) + \
                _w(stale) + _w(stale) + _w(100)
            return httpx.Response(200, json={"result": data},
                                  request=request)
        return httpx.Response(200, json={"result": None}, request=request)

    if host == "api.dune.com":
        if rich:
            return httpx.Response(200, json={
                "state": "QUERY_STATE_COMPLETED", "submitted_at": "t",
                "is_execution_finished": False,
                "execution_ended_at": None,
                "result": {"rows": [{"a": 1}, {"a": 2}],
                           "metadata": {"row_count": 2}}},
                request=request)
        return httpx.Response(200, json={
            "state": "QUERY_STATE_COMPLETED",
            "is_execution_finished": True, "execution_ended_at": "t",
            "result": {"rows": [], "metadata": {"row_count": 0}}},
            request=request)

    if host == "v2.archive.subsquid.io":
        if rich:
            return httpx.Response(200, content="21000000",
                                  request=request)
        return httpx.Response(503, content="", request=request)

    if host == "api.thegraph.com" or host == "gateway.thegraph.com":
        if rich:
            return httpx.Response(200, json={"data": {"_meta": {
                "block": {"number": 21000000},
                "hasIndexingErrors": True,
                "deployment": "QmTest"}}}, request=request)
        return httpx.Response(200, json={"data": {"_meta": {
            "block": {"number": 21000000},
            "hasIndexingErrors": False,
            "deployment": "QmTest"}}}, request=request)

    return httpx.Response(404, content="", request=request)


def make_ctx(keys=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_handler),
        follow_redirects=True, trust_env=False)
    return Ctx(run_id="tier7-test", mode="passive", http=client,
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


def test_registry_count_tier7():
    reg = discover()
    assert len(reg) == 1191, f"registry size {len(reg)}, expected 1191"
    for pid in NEW_IDS:
        assert pid in reg, f"{pid} missing"


# --- etherscan_bundle -------------------------------------------------------
def test_etherscan_bundle_fires_rich():
    from app.plugins.etherscan_bundle import EtherscanBundlePlugin
    res = run(EtherscanBundlePlugin, f"https://etherscan.io/address/{WETH}")
    assert "verified_source_bundle" in keys_of(res), keys_of(res)
    assert "constructor_args_present" in keys_of(res)


def test_etherscan_bundle_unverified_is_finding_not_bundle():
    from app.plugins.etherscan_bundle import EtherscanBundlePlugin
    res = run(EtherscanBundlePlugin, WETH, mode=CLEAN)
    assert "verified_source_bundle" not in keys_of(res)
    assert "unverified_contract" in keys_of(res)


def test_etherscan_bundle_malformed_no_crash():
    from app.plugins.etherscan_bundle import EtherscanBundlePlugin
    res = run(EtherscanBundlePlugin, WETH, mode=BAD)
    assert res is not None


def test_etherscan_bundle_no_address_skips():
    from app.plugins.etherscan_bundle import EtherscanBundlePlugin
    res = run(EtherscanBundlePlugin, "https://example.com")
    assert res.findings == []


# --- sourcify_fetch ---------------------------------------------------------
def test_sourcify_fires_partial():
    from app.plugins.sourcify_fetch import SourcifyFetchPlugin
    res = run(SourcifyFetchPlugin, WETH)
    assert "sourcify_partial_match" in keys_of(res), keys_of(res)


def test_sourcify_silent_clean():
    from app.plugins.sourcify_fetch import SourcifyFetchPlugin
    res = run(SourcifyFetchPlugin, WETH, mode=CLEAN)
    assert res.findings == [], keys_of(res)


def test_sourcify_malformed_no_crash():
    from app.plugins.sourcify_fetch import SourcifyFetchPlugin
    assert run(SourcifyFetchPlugin, WETH, mode=BAD) is not None


# --- blockscout_crawler -----------------------------------------------------
def test_blockscout_fires_rich():
    from app.plugins.blockscout_crawler import BlockscoutCrawlerPlugin
    res = run(BlockscoutCrawlerPlugin, WETH)
    assert "blockscout_tx_summary" in keys_of(res), keys_of(res)
    assert "blockscout_heavy_internal_calls" in keys_of(res)


def test_blockscout_malformed_no_crash():
    from app.plugins.blockscout_crawler import BlockscoutCrawlerPlugin
    assert run(BlockscoutCrawlerPlugin, WETH, mode=BAD) is not None


# --- quicknode_streams ------------------------------------------------------
def test_quicknode_needs_key_skip():
    from app.plugins.quicknode_streams import QuickNodeStreamsPlugin
    res = run(QuickNodeStreamsPlugin, WETH)
    assert res.findings == []
    assert "QUICKNODE_API_KEY" in res.reason


def test_quicknode_fires_with_key():
    from app.plugins.quicknode_streams import QuickNodeStreamsPlugin
    res = run(QuickNodeStreamsPlugin, WETH, keys={"quicknode": "qk-test"})
    assert "quicknode_stream_watching_address" in keys_of(res), keys_of(res)


def test_quicknode_clean_with_key():
    from app.plugins.quicknode_streams import QuickNodeStreamsPlugin
    res = run(QuickNodeStreamsPlugin, WETH,
              keys={"quicknode": "qk-test"}, mode=CLEAN)
    assert res.findings == []


# --- alchemy_webhooks -------------------------------------------------------
def test_alchemy_needs_key_skip():
    from app.plugins.alchemy_webhooks import AlchemyWebhooksPlugin
    res = run(AlchemyWebhooksPlugin, WETH)
    assert res.findings == []
    assert "ALCHEMY_API_KEY" in res.reason


def test_alchemy_fires_with_key():
    from app.plugins.alchemy_webhooks import AlchemyWebhooksPlugin
    res = run(AlchemyWebhooksPlugin, WETH, keys={"alchemy": "al-test"})
    assert "alchemy_webhook_tracking_address" in keys_of(res), keys_of(res)


def test_alchemy_clean_with_key():
    from app.plugins.alchemy_webhooks import AlchemyWebhooksPlugin
    res = run(AlchemyWebhooksPlugin, WETH,
              keys={"alchemy": "al-test"}, mode=CLEAN)
    assert res.findings == []


# --- helios_consistency -----------------------------------------------------
def test_helios_fires_on_hash_mismatch():
    from app.plugins.helios_consistency import HeliosConsistencyPlugin
    res = run(HeliosConsistencyPlugin, "https://example.com")
    assert "rpc_head_hash_mismatch" in keys_of(res), keys_of(res)


def test_helios_silent_when_heads_agree():
    from app.plugins.helios_consistency import HeliosConsistencyPlugin
    res = run(HeliosConsistencyPlugin, "https://example.com", mode=CLEAN)
    assert res.findings == [], keys_of(res)


def test_helios_malformed_no_crash():
    from app.plugins.helios_consistency import HeliosConsistencyPlugin
    assert run(HeliosConsistencyPlugin, "https://example.com",
               mode=BAD) is not None


# --- chainlink_feeds --------------------------------------------------------
def test_chainlink_fires_stale_and_price():
    from app.plugins.chainlink_feeds import ChainlinkFeedsPlugin
    res = run(ChainlinkFeedsPlugin, "https://example.com")
    assert "chainlink_feed_price" in keys_of(res), keys_of(res)
    assert "chainlink_stale_feed" in keys_of(res)


def test_chainlink_silent_clean():
    from app.plugins.chainlink_feeds import ChainlinkFeedsPlugin
    res = run(ChainlinkFeedsPlugin, "https://example.com", mode=CLEAN)
    assert res.findings == [], keys_of(res)


def test_chainlink_malformed_no_crash():
    from app.plugins.chainlink_feeds import ChainlinkFeedsPlugin
    assert run(ChainlinkFeedsPlugin, "https://example.com",
               mode=BAD) is not None


# --- dune_exporter ----------------------------------------------------------
def test_dune_needs_key_skip():
    from app.plugins.dune_exporter import DuneExporterPlugin
    res = run(DuneExporterPlugin, "dune:1234567")
    assert res.findings == []
    assert "DUNE_API_KEY" in res.reason


def test_dune_fires_with_key():
    from app.plugins.dune_exporter import DuneExporterPlugin
    res = run(DuneExporterPlugin, "dune:1234567", keys={"dune": "dk-test"})
    assert "dune_query_result" in keys_of(res), keys_of(res)
    assert "dune_result_pending" in keys_of(res)


def test_dune_malformed_no_crash():
    from app.plugins.dune_exporter import DuneExporterPlugin
    assert run(DuneExporterPlugin, "dune:1234567",
               keys={"dune": "dk-test"}, mode=BAD) is not None


# --- subsquid_discovery -----------------------------------------------------
def test_subsquid_fires_rich():
    from app.plugins.subsquid_discovery import SubsquidDiscoveryPlugin
    res = run(SubsquidDiscoveryPlugin, "https://example.com")
    assert "subsquid_archive_available" in keys_of(res), keys_of(res)
    assert len(res.findings) == 5


def test_subsquid_silent_clean():
    from app.plugins.subsquid_discovery import SubsquidDiscoveryPlugin
    res = run(SubsquidDiscoveryPlugin, "https://example.com", mode=CLEAN)
    assert res.findings == []


def test_subsquid_malformed_no_crash():
    from app.plugins.subsquid_discovery import SubsquidDiscoveryPlugin
    assert run(SubsquidDiscoveryPlugin, "https://example.com",
               mode=BAD) is not None


# --- thegraph_subgraphs -----------------------------------------------------
def test_thegraph_fires_on_indexing_errors():
    from app.plugins.thegraph_subgraphs import TheGraphSubgraphsPlugin
    res = run(TheGraphSubgraphsPlugin, "https://example.com")
    assert "subgraph_indexing_errors" in keys_of(res), keys_of(res)


def test_thegraph_healthy_no_error_finding():
    from app.plugins.thegraph_subgraphs import TheGraphSubgraphsPlugin
    res = run(TheGraphSubgraphsPlugin, "https://example.com", mode=CLEAN)
    assert "subgraph_indexing_errors" not in keys_of(res)


def test_thegraph_malformed_no_crash():
    from app.plugins.thegraph_subgraphs import TheGraphSubgraphsPlugin
    assert run(TheGraphSubgraphsPlugin, "https://example.com",
               mode=BAD) is not None
