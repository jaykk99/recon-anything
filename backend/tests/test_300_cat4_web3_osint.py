"""Cat-4 (300-expansion) Web3 Frontend, DApp Capture & OSINT plugins.

Per plugin: fires on the VULN fixture, silent on the CLEAN fixture,
no crash on malformed input. Capture/interceptor-named plugins are
STATIC detectors over supplied bundles/pages - fixtures are bundle
texts and storage dumps, never live sessions. The two MEV modules
add a boundary test: their source must contain no transaction
construction/submission surface at all.

HTTP runs over a local httpx MockTransport; external keyless APIs are
bypassed in fixtures by operator-supplied artifact data (the plugins'
documented artifact lane), so the suite is fully deterministic.
"""
import asyncio
import inspect
import json
import os
import sys
from urllib.parse import urlparse

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = ["arweave_data_fetcher", "multicall_aggregator_decode",
       "front_end_phishing_differ", "coingecko_price_validator",
       "defillama_tvl_verify", "tenderly_trace_parser",
       "snapshot_governance_scraper", "tally_proposal_decoder",
       "dapp_state_sniffer", "wallet_connect_interceptor",
       "metamask_rpc_hook", "ethers_provider_spy",
       "web3js_payload_dumper", "ipfs_gateway_resolver",
       "ens_reverse_lookup", "contract_creator_osint",
       "gas_pump_frontrunner", "signature_request_inspector",
       "flashbots_bundle_builder", "gnosis_safe_multisig_audit",
       "token_holder_cluster", "dex_liquidity_depth_calc",
       "sandwich_attack_profiler", "tor_rpc_node_scanner",
       "web3auth_session_leak"]

A1 = "0x" + "11" * 20
A2 = "0x" + "22" * 20
A3 = "0x" + "33" * 20
A4 = "0x" + "44" * 20
BOT = "0x" + "b0" * 20
VICTIM = "0x" + "v1".replace("v", "9") * 20

STATE_JS = """
const p = window.ethereum;
p.request({method: 'eth_call', params: [{to: '%s', data: '0x70a08231%s'}, 'latest']});
p.request({method: 'eth_getStorageAt', params: ['%s', '0x5', 'latest']});
""" % (A1, "0" * 24 + "11" * 20, A2)

WC_JS = """
const uri = 'wc:12345678-abcd-1234-abcd-1234567890ab@2?relay-protocol=irn&symKey=9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c';
signClient.request({ chainId: 'eip155:1', request: { method: 'eth_sendTransaction', params: [] } });
"""

MM_JS = """
window.addEventListener('load', async () => {
  await ethereum.request({method: 'eth_sendTransaction', params: [{to: '%s', value: '0x1'}]});
});
""" % A3

ETHERS_JS = """
const provider = new ethers.JsonRpcProvider('https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef');
const c = new ethers.Contract('%s', ABI, provider);
c.on('Transfer', (from, to, v) => {});
""" % A1

WEB3_JS = """
const c = new web3.eth.Contract(ABI, '%s');
c.methods.approve('%s', '115792089237316195423570985008687907853269984665640564039457584007913129639935').send({from: acct});
""" % (A1, A2)

CLEAN_JS = """
fetch('/api/prices');
ethereum.request({method: 'eth_chainId'});
const bp = new ethers.BrowserProvider(window.ethereum);
const rp = new ethers.JsonRpcProvider('https://rpc.example.org/mainnet');
token.methods.balanceOf(acct).call();
"""

LEGIT_HTML = """<html><head><title>LegitSwap</title>
<script src="https://app.legitswap.example/app.js"></script></head>
<body><h1>LegitSwap</h1>
<p>Deposit to %s</p>
<form><input name="amount" type="text"></form>
</body></html>""" % A1

PHISH_HTML = """<html><head><title>LegitSwap</title>
<script src="https://evil-cdn.example.net/app.js"></script></head>
<body><h1>LegitSwap</h1>
<div id="web3modal"><div class="walletconnect-modal">Connect</div></div>
<p>Deposit to %s</p>
<form><input name="amount" type="text">
<input name="seed_phrase" type="text"></form>
</body></html>""" % A2

PAGES = {
    "state.test": "<html><body><script>%s</script></body></html>" % STATE_JS,
    "wc.test": "<html><body><script>%s</script></body></html>" % WC_JS,
    "mm.test": "<html><body><script>%s</script></body></html>" % MM_JS,
    "ethers.test": "<html><body><script>%s</script></body></html>" % ETHERS_JS,
    "web3.test": "<html><body><script>%s</script></body></html>" % WEB3_JS,
    "clean.test": "<html><body><script>%s</script></body></html>" % CLEAN_JS,
    "legit.test": LEGIT_HTML,
    "phish.test": PHISH_HTML,
}


def _handler(request: httpx.Request) -> httpx.Response:
    url = urlparse(str(request.url))
    host = url.hostname or ""
    if host in PAGES and url.path in ("/", "/index.html"):
        return httpx.Response(200, content=PAGES[host], request=request)
    return httpx.Response(404, content="not found", request=request)


def _ctx(artifacts=None, reference=None) -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False,
                               headers={"User-Agent": "Recon-Cat4-Test"})
    ctx = Ctx(run_id="cat4-test", mode="active", http=client,
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    if artifacts is not None:
        ctx.shared["cat4_artifacts"] = list(artifacts)
    if reference is not None:
        ctx.shared["cat4_reference_html"] = [reference]
    return ctx


def _url(host: str) -> Target:
    return Target(raw=f"https://{host}/", type="url",
                  normalized=f"https://{host}/")


def _wallet() -> Target:
    return Target(raw=A1, type="crypto_wallet", normalized=A1)


async def _run(pid, target, artifacts=None, reference=None):
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx(artifacts, reference)
    try:
        return await asyncio.wait_for(cls().run(target, ctx), timeout=60)
    finally:
        await ctx.http.aclose()


def run(pid, target, artifacts=None, reference=None):
    return asyncio.run(_run(pid, target, artifacts, reference))


def keys_of(res):
    return {f.key for f in res.findings}


JUNK_ARTIFACTS = ["\x00\xff garbage {not json", 12345, None,
                  {"unrelated": [1, 2, 3]}, ["nested", "junk"]]


def assert_malformed_ok(pid):
    res = run(pid, _wallet(), artifacts=JUNK_ARTIFACTS)
    assert res.status.value == "ok"
    assert isinstance(res.findings, list)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_all_cat4_plugins_registered():
    from app.plugins.registry import discover
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"
    assert len(reg) == 1419


# ---------------------------------------------------------------------------
# 1. dapp_state_sniffer
# ---------------------------------------------------------------------------

def test_dapp_state_fires_on_vuln():
    res = run("dapp_state_sniffer", _url("state.test"))
    assert "dapp_storage_slot_probe" in keys_of(res)
    assert "dapp_read_map_entry" in keys_of(res)


def test_dapp_state_silent_on_clean():
    res = run("dapp_state_sniffer", _url("clean.test"))
    assert res.findings == []


def test_dapp_state_malformed():
    assert_malformed_ok("dapp_state_sniffer")
    from app.plugins.dapp_state_sniffer import analyse_dapp_reads
    assert analyse_dapp_reads("") == []
    assert analyse_dapp_reads(None) == []


# ---------------------------------------------------------------------------
# 2. wallet_connect_interceptor
# ---------------------------------------------------------------------------

def test_walletconnect_fires_on_vuln():
    res = run("wallet_connect_interceptor", _url("wc.test"))
    assert "walletconnect_symkey_in_code" in keys_of(res)
    assert "walletconnect_sign_request_shape" in keys_of(res)


def test_walletconnect_silent_on_clean():
    res = run("wallet_connect_interceptor", _url("clean.test"))
    assert res.findings == []


def test_walletconnect_malformed():
    assert_malformed_ok("wallet_connect_interceptor")
    from app.plugins.wallet_connect_interceptor import analyse_walletconnect
    assert analyse_walletconnect(None) == []


# ---------------------------------------------------------------------------
# 3. metamask_rpc_hook
# ---------------------------------------------------------------------------

def test_metamask_fires_on_vuln():
    res = run("metamask_rpc_hook", _url("mm.test"))
    assert "metamask_signing_call_site" in keys_of(res)
    sev = {f.evidence["severity"] for f in res.findings}
    assert "high" in sev  # load-context auto invocation


def test_metamask_silent_on_clean():
    res = run("metamask_rpc_hook", _url("clean.test"))
    assert res.findings == []


def test_metamask_malformed():
    assert_malformed_ok("metamask_rpc_hook")
    from app.plugins.metamask_rpc_hook import analyse_metamask_calls
    assert analyse_metamask_calls(123) == []


# ---------------------------------------------------------------------------
# 4. ethers_provider_spy
# ---------------------------------------------------------------------------

def test_ethers_spy_fires_on_vuln():
    res = run("ethers_provider_spy", _url("ethers.test"))
    assert "ethers_rpc_key_embedded" in keys_of(res)
    blob = json.dumps([f.evidence for f in res.findings])
    assert "0123456789abcdef0123456789abcdef" not in blob  # masked


def test_ethers_spy_silent_on_clean():
    res = run("ethers_provider_spy", _url("clean.test"))
    assert res.findings == []


def test_ethers_spy_malformed():
    assert_malformed_ok("ethers_provider_spy")
    from app.plugins.ethers_provider_spy import analyse_ethers
    assert analyse_ethers("") == []


# ---------------------------------------------------------------------------
# 5. web3js_payload_dumper
# ---------------------------------------------------------------------------

def test_web3js_fires_on_vuln():
    res = run("web3js_payload_dumper", _url("web3.test"))
    assert "web3js_risky_send_payload" in keys_of(res)


def test_web3js_silent_on_clean():
    res = run("web3js_payload_dumper", _url("clean.test"))
    assert res.findings == []


def test_web3js_malformed():
    assert_malformed_ok("web3js_payload_dumper")
    from app.plugins.web3js_payload_dumper import analyse_web3js
    assert analyse_web3js(None) == []


# ---------------------------------------------------------------------------
# 6. ipfs_gateway_resolver
# ---------------------------------------------------------------------------

CID = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"


def test_ipfs_fires_on_divergence():
    art = {"gateway_results": {CID: {
        "https://ipfs.io/ipfs/": {"status": 200, "sha256": "a" * 64},
        "https://dweb.link/ipfs/": {"status": 200, "sha256": "b" * 64}}}}
    res = run("ipfs_gateway_resolver", _wallet(), artifacts=[art])
    assert "ipfs_gateway_divergence" in keys_of(res)


def test_ipfs_silent_when_consistent():
    art = {"gateway_results": {CID: {
        "https://ipfs.io/ipfs/": {"status": 200, "sha256": "a" * 64},
        "https://dweb.link/ipfs/": {"status": 200, "sha256": "a" * 64}}}}
    res = run("ipfs_gateway_resolver", _wallet(), artifacts=[art])
    assert res.findings == []


def test_ipfs_malformed():
    assert_malformed_ok("ipfs_gateway_resolver")
    from app.plugins.ipfs_gateway_resolver import analyse_gateway_results
    assert analyse_gateway_results(CID, {}) == []
    assert analyse_gateway_results(CID, {"g": "junk"}) == []


# ---------------------------------------------------------------------------
# 7. arweave_data_fetcher
# ---------------------------------------------------------------------------

TXID = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_abcde0"


def test_arweave_fires_on_divergent_mirror():
    art = {"arweave_mirrors": {TXID: "<html><body>OLD FORK - send "
                                     "funds here</body></html>"}}
    res = run("arweave_data_fetcher", _url("legit.test"), artifacts=[art])
    assert "arweave_mirror_divergence" in keys_of(res)


def test_arweave_silent_without_refs():
    res = run("arweave_data_fetcher", _url("clean.test"))
    assert res.findings == []


def test_arweave_malformed():
    assert_malformed_ok("arweave_data_fetcher")
    from app.plugins.arweave_data_fetcher import analyse_mirror
    assert analyse_mirror("x", "", TXID) == []
    assert analyse_mirror("x", None, TXID) == []


# ---------------------------------------------------------------------------
# 8. ens_reverse_lookup
# ---------------------------------------------------------------------------

def test_ens_fires_on_mismatch():
    art = {"ens_reverse_records": [{
        "address": A1, "primary_name": "vitalik.eth",
        "forward_resolves_to": A2}]}
    res = run("ens_reverse_lookup", _wallet(), artifacts=[art])
    assert "ens_reverse_forward_mismatch" in keys_of(res)


def test_ens_silent_when_consistent():
    art = {"ens_reverse_records": [{
        "address": A1, "primary_name": "vitalik.eth",
        "forward_resolves_to": A1}]}
    res = run("ens_reverse_lookup", _wallet(), artifacts=[art])
    assert res.findings == []


def test_ens_malformed():
    assert_malformed_ok("ens_reverse_lookup")
    from app.plugins.ens_reverse_lookup import analyse_reverse_records
    assert analyse_reverse_records("junk") == []
    assert analyse_reverse_records([{"address": 1}, "x"]) == []


# ---------------------------------------------------------------------------
# 9. contract_creator_osint
# ---------------------------------------------------------------------------

def test_creator_fires_on_mixer_funded():
    art = {"creation_info": [{
        "contract": A1, "creator": A2, "funder": A3,
        "funder_label": "Tornado Cash mixer", "creator_tx_count": 3}]}
    res = run("contract_creator_osint", _wallet(), artifacts=[art])
    assert "creator_mixer_funded_deployer" in keys_of(res)


def test_creator_silent_on_exchange_funded():
    art = {"creation_info": [{
        "contract": A1, "creator": A2, "funder": A3,
        "funder_label": "Coinbase exchange hot wallet",
        "creator_tx_count": 400}]}
    res = run("contract_creator_osint", _wallet(), artifacts=[art])
    assert res.findings == []


def test_creator_malformed():
    assert_malformed_ok("contract_creator_osint")
    from app.plugins.contract_creator_osint import analyse_creation
    assert analyse_creation({}) == []
    assert analyse_creation("junk") == []


# ---------------------------------------------------------------------------
# 10. multicall_aggregator_decode
# ---------------------------------------------------------------------------

def _w(n):
    return n.to_bytes(32, "big")


def _addrw(a):
    return bytes(12) + bytes.fromhex(a[2:])


def _batch(calls):
    def tup(t, c):
        pad = (32 - len(c) % 32) % 32
        return _addrw(t) + _w(64) + _w(len(c)) + c + bytes(pad)
    parts = [tup(t, c) for t, c in calls]
    offs, pos = [], 32 * len(parts)
    for p in parts:
        offs.append(_w(pos))
        pos += len(p)
    body = _w(32) + _w(len(parts)) + b"".join(offs) + b"".join(parts)
    return "0x252dba42" + body.hex()


BALANCEOF = bytes.fromhex("70a08231") + _addrw(A3)
TOTALSUPPLY = bytes.fromhex("18160ddd")
APPROVE = bytes.fromhex("095ea7b3") + _addrw(A4) + _w(1000)


def test_multicall_fires_on_hidden_approval():
    art = {"calldata": _batch([(A1, BALANCEOF), (A2, APPROVE)])}
    res = run("multicall_aggregator_decode", _wallet(), artifacts=[art])
    assert "multicall_hidden_approval_subcall" in keys_of(res)


def test_multicall_silent_on_reads_only():
    art = {"calldata": _batch([(A1, BALANCEOF), (A2, TOTALSUPPLY)])}
    res = run("multicall_aggregator_decode", _wallet(), artifacts=[art])
    assert res.findings == []


def test_multicall_malformed():
    assert_malformed_ok("multicall_aggregator_decode")
    from app.plugins.multicall_aggregator_decode import decode_multicall
    assert decode_multicall("0xzz") == []
    assert decode_multicall("0x252dba42") == []
    assert decode_multicall(None) == []
    assert decode_multicall(1234) == []


# ---------------------------------------------------------------------------
# 11. signature_request_inspector
# ---------------------------------------------------------------------------

PERMIT_TD = {
    "types": {"EIP712Domain": [], "Permit": []},
    "primaryType": "Permit",
    "domain": {"name": "FakeToken", "verifyingContract": A1},
    "message": {"owner": A2, "spender": A3,
                "value": "115792089237316195423570985008687907853269984665"
                         "640564039457584007913129639935",
                "deadline": "9999999999"}}

BENIGN_TD = {
    "types": {"EIP712Domain": [], "Mail": []},
    "primaryType": "Mail",
    "domain": {"name": "Example", "verifyingContract": A1},
    "message": {"contents": "Hello, welcome back"}}


def test_signature_fires_on_permit():
    res = run("signature_request_inspector", _wallet(),
              artifacts=[PERMIT_TD])
    ks = keys_of(res)
    assert "eip712_permit_style_payload" in ks
    assert "eip712_unlimited_amount" in ks


def test_signature_silent_on_benign():
    res = run("signature_request_inspector", _wallet(),
              artifacts=[BENIGN_TD])
    assert res.findings == []


def test_signature_malformed():
    assert_malformed_ok("signature_request_inspector")
    from app.plugins.signature_request_inspector import grade_typed_data
    assert grade_typed_data("junk") == []
    assert grade_typed_data({"primaryType": 5, "message": "x"}) == []


# ---------------------------------------------------------------------------
# 12. front_end_phishing_differ
# ---------------------------------------------------------------------------

def test_phishing_differ_fires_on_clone():
    res = run("front_end_phishing_differ", _url("phish.test"),
              reference=LEGIT_HTML)
    ks = keys_of(res)
    assert "phishing_diff_payment_address_swapped" in ks
    assert "phishing_diff_credential_form_fields_added" in ks
    assert "phishing_diff_injected_wallet_overlay" in ks


def test_phishing_differ_silent_on_identical():
    res = run("front_end_phishing_differ", _url("legit.test"),
              reference=LEGIT_HTML)
    assert res.findings == []


def test_phishing_differ_malformed_no_reference():
    res = run("front_end_phishing_differ", _url("phish.test"))
    assert res.findings == []  # degraded, never crashes
    from app.plugins.front_end_phishing_differ import diff_frontends
    assert diff_frontends(None, LEGIT_HTML) == []
    assert diff_frontends(PHISH_HTML, None) == []


# ---------------------------------------------------------------------------
# 13. coingecko_price_validator
# ---------------------------------------------------------------------------

def test_price_fires_on_divergence():
    art = {"price_claims": [{"token_id": "ethereum", "displayed": 1000.0}],
           "reference_prices": {"ethereum": 3500.0}}
    res = run("coingecko_price_validator", _wallet(), artifacts=[art])
    assert "displayed_price_divergence" in keys_of(res)


def test_price_silent_when_close():
    art = {"price_claims": [{"token_id": "ethereum", "displayed": 3490.0}],
           "reference_prices": {"ethereum": 3500.0}}
    res = run("coingecko_price_validator", _wallet(), artifacts=[art])
    assert res.findings == []


def test_price_malformed():
    assert_malformed_ok("coingecko_price_validator")
    from app.plugins.coingecko_price_validator import compare_prices
    assert compare_prices("abc", None) is None
    assert compare_prices(-5, 100) is None


# ---------------------------------------------------------------------------
# 14. defillama_tvl_verify
# ---------------------------------------------------------------------------

def test_tvl_fires_on_overstatement():
    art = {"tvl_checks": [{"protocol": "fake-proto",
                           "reported_tvl": 100_000_000,
                           "contract_balances": {A1: 40_000_000,
                                                   A2: 20_000_000}}]}
    res = run("defillama_tvl_verify", _wallet(), artifacts=[art])
    assert "tvl_report_divergence" in keys_of(res)


def test_tvl_silent_when_matching():
    art = {"tvl_checks": [{"protocol": "real-proto",
                           "reported_tvl": 61_000_000,
                           "onchain_tvl": 60_000_000}]}
    res = run("defillama_tvl_verify", _wallet(), artifacts=[art])
    assert res.findings == []


def test_tvl_malformed():
    assert_malformed_ok("defillama_tvl_verify")
    from app.plugins.defillama_tvl_verify import compare_tvl, sum_balances
    assert compare_tvl("x", None) is None
    assert sum_balances({"a": "junk"}) is None


# ---------------------------------------------------------------------------
# 15. tenderly_trace_parser
# ---------------------------------------------------------------------------

VULN_TRACE = {
    "status": "failed",
    "revert_reason": "Insufficient allowance",
    "call_trace": {"from": A1, "to": A2, "gas_used": 900,
                   "calls": [{"from": A2, "to": A3, "gas_used": 100}]},
    "state_diff": [{"address": A2, "key": "allowance", "after": "max"}]}

CLEAN_TRACE = {
    "status": "success",
    "call_trace": {"from": A1, "to": A2, "gas_used": 100,
                   "calls": [{"from": A2, "to": A3, "gas_used": 100}]},
    "state_diff": []}


def test_tenderly_fires_on_vuln_trace():
    res = run("tenderly_trace_parser", _wallet(),
              artifacts=[{"trace": VULN_TRACE}])
    ks = keys_of(res)
    assert "tenderly_trace_reverted" in ks
    assert "tenderly_state_diff_approval" in ks


def test_tenderly_silent_on_clean_trace():
    res = run("tenderly_trace_parser", _wallet(),
              artifacts=[{"trace": CLEAN_TRACE}])
    assert res.findings == []


def test_tenderly_malformed():
    assert_malformed_ok("tenderly_trace_parser")
    from app.plugins.tenderly_trace_parser import parse_trace
    assert parse_trace("not json {{") == []
    assert parse_trace(12345) == []


# ---------------------------------------------------------------------------
# 16. snapshot_governance_scraper
# ---------------------------------------------------------------------------

SNAP_VULN = {
    "proposals": [{"id": "p1", "title": "Move treasury", "state": "active"}],
    "votes": [{"proposal": "p1", "voter": BOT, "power": 900,
               "voter_proposal_count": 1},
              {"proposal": "p1", "voter": VICTIM, "power": 100,
               "voter_proposal_count": 40}]}

SNAP_CLEAN = {
    "proposals": [{"id": "p1", "title": "Routine", "state": "active"}],
    "votes": [{"proposal": "p1", "voter": f"0x{i:040x}", "power": 100,
               "voter_proposal_count": 25} for i in range(10)]}


def test_snapshot_fires_on_capture():
    res = run("snapshot_governance_scraper", _wallet(),
              artifacts=[SNAP_VULN])
    ks = keys_of(res)
    assert "snapshot_single_voter_majority" in ks
    assert "snapshot_new_whale_voter" in ks


def test_snapshot_silent_on_distributed():
    res = run("snapshot_governance_scraper", _wallet(),
              artifacts=[SNAP_CLEAN])
    assert res.findings == []


def test_snapshot_malformed():
    assert_malformed_ok("snapshot_governance_scraper")
    from app.plugins.snapshot_governance_scraper import analyse_snapshot
    assert analyse_snapshot({"votes": [{"power": "abc"}]}) == []
    assert analyse_snapshot("junk") == []


# ---------------------------------------------------------------------------
# 17. tally_proposal_decoder
# ---------------------------------------------------------------------------

PROP_VULN = {"id": 7, "title": "Routine parameter update",
             "targets": [A1], "values": [0],
             "signatures": ["setVotingDelay(uint256)"],
             "calldatas": ["0x095ea7b3" + "0" * 24 + "44" * 20
                           + format(10 ** 30, "064x")]}

PROP_CLEAN = {"id": 8, "title": "Voting delay tweak",
              "targets": [A1], "values": [0],
              "signatures": ["setVotingDelay(uint256)"],
              "calldatas": ["0x12345678" + format(100, "064x")]}


def test_tally_fires_on_hidden_approval():
    res = run("tally_proposal_decoder", _wallet(), artifacts=[PROP_VULN])
    ks = keys_of(res)
    assert "proposal_approval_payload" in ks
    assert "proposal_signature_calldata_mismatch" in ks


def test_tally_silent_on_benign():
    res = run("tally_proposal_decoder", _wallet(), artifacts=[PROP_CLEAN])
    assert res.findings == []


def test_tally_malformed():
    assert_malformed_ok("tally_proposal_decoder")
    from app.plugins.tally_proposal_decoder import decode_proposal
    assert decode_proposal(42) == []
    assert decode_proposal({"targets": "junk"}) == []


# ---------------------------------------------------------------------------
# 18. gas_pump_frontrunner (BOUNDARY: monitoring/analysis only)
# ---------------------------------------------------------------------------

PAD = "0x" + "aa" * 20
GAS_VULN = {"launchpads": [PAD], "mempool_txs": [
    {"hash": "0x1", "from": BOT, "to": PAD, "method": "buy",
     "block": 100, "gas_price_gwei": 300, "seconds_after_launch": 5},
    {"hash": "0x2", "from": A1, "to": PAD, "method": "buy",
     "block": 100, "gas_price_gwei": 10},
    {"hash": "0x3", "from": A2, "to": PAD, "method": "buy",
     "block": 100, "gas_price_gwei": 25},
    {"hash": "0x4", "from": A3, "to": PAD, "method": "buy",
     "block": 100, "gas_price_gwei": 60}]}

GAS_CLEAN = {"launchpads": [PAD], "mempool_txs": [
    {"hash": "0x5", "from": A1, "to": PAD, "method": "buy",
     "block": 200, "gas_price_gwei": 20, "seconds_after_launch": 3600},
    {"hash": "0x6", "from": A2, "to": PAD, "method": "buy",
     "block": 201, "gas_price_gwei": 22, "seconds_after_launch": 4000}]}


def test_gas_pump_fires_on_sniper_and_bidwar():
    res = run("gas_pump_frontrunner", _wallet(), artifacts=[GAS_VULN])
    ks = keys_of(res)
    assert "frontrun_launch_sniper_fee_premium" in ks
    assert "frontrun_fee_bidding_war" in ks


def test_gas_pump_silent_on_normal_activity():
    res = run("gas_pump_frontrunner", _wallet(), artifacts=[GAS_CLEAN])
    assert res.findings == []


def test_gas_pump_malformed():
    assert_malformed_ok("gas_pump_frontrunner")
    from app.plugins.gas_pump_frontrunner import profile_launch_activity
    assert profile_launch_activity("junk") == []
    assert profile_launch_activity([{"to": PAD}, "x"]) == []


# ---------------------------------------------------------------------------
# 19. flashbots_bundle_builder (BOUNDARY: inclusion analysis only)
# ---------------------------------------------------------------------------

FB_VULN = {"inclusion_records": [
    {"tx_hash": "0xabc", "route": "private",
     "seen_public_before_inclusion": True, "included_block": 100,
     "builder": "beaver"}]}

FB_CLEAN = {"inclusion_records": [
    {"tx_hash": f"0x{i}", "route": "private",
     "seen_public_before_inclusion": False, "included_block": 100 + i,
     "builder": b} for i, b in enumerate(
        ["beaver", "titan", "rsync", "flashbots"])]}


def test_flashbots_fires_on_privacy_leak():
    res = run("flashbots_bundle_builder", _wallet(), artifacts=[FB_VULN])
    assert "bundle_private_tx_leaked_to_mempool" in keys_of(res)


def test_flashbots_silent_on_clean_inclusion():
    res = run("flashbots_bundle_builder", _wallet(), artifacts=[FB_CLEAN])
    assert res.findings == []


def test_flashbots_malformed():
    assert_malformed_ok("flashbots_bundle_builder")
    from app.plugins.flashbots_bundle_builder import analyse_inclusion
    assert analyse_inclusion({"not": "a list"}) == []
    assert analyse_inclusion([None, 5]) == []


def test_flashbots_centralisation_unit():
    from app.plugins.flashbots_bundle_builder import analyse_inclusion
    recs = [{"tx_hash": f"0x{i}", "route": "public", "builder": "one"}
            for i in range(6)]
    kinds = {h["kind"] for h in analyse_inclusion(recs)}
    assert "builder_centralisation" in kinds


# ---------------------------------------------------------------------------
# 20. BOUNDARY: no transaction-submission surface in the MEV modules
# ---------------------------------------------------------------------------

FORBIDDEN_SURFACE = ("eth_sendTransaction", "send_raw_transaction",
                     "sendRawTransaction", "sign_transaction",
                     "signTransaction", "build_transaction",
                     "submit_bundle", "send_bundle", "eth_send_bundle",
                     "sendBundle", "private_key", "mnemonic")


def test_mev_modules_have_no_tx_submission_surface():
    import app.plugins.flashbots_bundle_builder as fb
    import app.plugins.gas_pump_frontrunner as gp
    for mod in (fb, gp):
        src = inspect.getsource(mod)
        for bad in FORBIDDEN_SURFACE:
            assert bad not in src, \
                f"{mod.__name__} contains forbidden surface: {bad}"


# ---------------------------------------------------------------------------
# 21. gnosis_safe_multisig_audit
# ---------------------------------------------------------------------------

SAFE_VULN = {"safe_states": [{
    "address": A1, "owners": [A2, A3, A4], "threshold": 1,
    "modules": ["0x" + "99" * 20], "guard": None, "pending_txs": 0}]}

SAFE_CLEAN = {"safe_states": [{
    "address": A1, "owners": [A2, A3, A4], "threshold": 2,
    "modules": [], "guard": None, "pending_txs": 0}]}


def test_safe_fires_on_threshold_one_and_module():
    res = run("gnosis_safe_multisig_audit", _wallet(),
              artifacts=[SAFE_VULN])
    ks = keys_of(res)
    assert "safe_threshold_one_multisig" in ks
    assert "safe_module_enabled" in ks


def test_safe_silent_on_healthy_config():
    res = run("gnosis_safe_multisig_audit", _wallet(),
              artifacts=[SAFE_CLEAN])
    assert res.findings == []


def test_safe_malformed():
    assert_malformed_ok("gnosis_safe_multisig_audit")
    from app.plugins.gnosis_safe_multisig_audit import audit_safe_state
    assert audit_safe_state(None) == []
    assert audit_safe_state({"owners": "abc", "threshold": "x"}) == []


# ---------------------------------------------------------------------------
# 22. token_holder_cluster
# ---------------------------------------------------------------------------

FUNDER = "0x" + "ff" * 20
HOLDERS_VULN = {"holders": [
    {"address": f"0x{i:040x}", "balance_pct": 0.08, "funder": FUNDER,
     "funder_label": "unknown wallet"} for i in range(1, 5)]}

HOLDERS_CLEAN = {"holders": [
    {"address": f"0x{i:040x}", "balance_pct": 0.05,
     "funder": "0x" + "ee" * 20, "funder_label": "Binance exchange"}
    for i in range(1, 5)] + [
    {"address": A1, "balance_pct": 0.04, "funder": FUNDER,
     "funder_label": "unknown wallet"}]}


def test_holder_cluster_fires_on_coordination():
    res = run("token_holder_cluster", _wallet(), artifacts=[HOLDERS_VULN])
    assert "coordinated_holder_cluster" in keys_of(res)


def test_holder_cluster_silent_on_organic():
    res = run("token_holder_cluster", _wallet(), artifacts=[HOLDERS_CLEAN])
    assert res.findings == []


def test_holder_cluster_malformed():
    assert_malformed_ok("token_holder_cluster")
    from app.plugins.token_holder_cluster import cluster_holders
    assert cluster_holders("junk") == []
    assert cluster_holders([{"balance_pct": "abc", "funder": FUNDER}]) == []


# ---------------------------------------------------------------------------
# 23. dex_liquidity_depth_calc
# ---------------------------------------------------------------------------

POOL_VULN = {"pools": [{
    "pair": A1, "liquidity_usd": 4000, "market_cap_usd": 10_000_000,
    "history": [{"ts": 1, "liquidity_usd": 100000},
                {"ts": 2, "liquidity_usd": 4000}]}]}

POOL_CLEAN = {"pools": [{
    "pair": A1, "liquidity_usd": 5_000_000, "market_cap_usd": 20_000_000,
    "history": [{"ts": 1, "liquidity_usd": 5_100_000},
                {"ts": 2, "liquidity_usd": 5_000_000}]}]}


def test_dex_depth_fires_on_collapse():
    res = run("dex_liquidity_depth_calc", _wallet(), artifacts=[POOL_VULN])
    ks = keys_of(res)
    assert "dex_liquidity_collapse" in ks
    assert "dex_shallow_absolute_depth" in ks


def test_dex_depth_silent_on_deep_pool():
    res = run("dex_liquidity_depth_calc", _wallet(), artifacts=[POOL_CLEAN])
    assert res.findings == []


def test_dex_depth_malformed():
    assert_malformed_ok("dex_liquidity_depth_calc")
    from app.plugins.dex_liquidity_depth_calc import analyse_pool
    assert analyse_pool({"liquidity_usd": "abc"}) == []
    assert analyse_pool(None) == []


# ---------------------------------------------------------------------------
# 24. sandwich_attack_profiler
# ---------------------------------------------------------------------------

POOL = "0x" + "dd" * 20
SANDWICH_VULN = {"swap_txs": [
    {"block": 100, "index": 1, "from": BOT, "method": "swap", "pool": POOL},
    {"block": 100, "index": 2, "from": VICTIM, "method": "swap",
     "pool": POOL},
    {"block": 100, "index": 3, "from": BOT, "method": "swap", "pool": POOL}]}

SANDWICH_CLEAN = {"swap_txs": [
    {"block": 100, "index": i, "from": f"0x{i:040x}", "method": "swap",
     "pool": POOL} for i in range(1, 5)]}


def test_sandwich_fires_on_triple():
    res = run("sandwich_attack_profiler", _wallet(),
              artifacts=[SANDWICH_VULN])
    assert "mev_sandwich_triple" in keys_of(res)


def test_sandwich_silent_on_organic_flow():
    res = run("sandwich_attack_profiler", _wallet(),
              artifacts=[SANDWICH_CLEAN])
    assert res.findings == []


def test_sandwich_malformed():
    assert_malformed_ok("sandwich_attack_profiler")
    from app.plugins.sandwich_attack_profiler import profile_sandwiches
    assert profile_sandwiches("junk") == []
    assert profile_sandwiches([{"method": "swap"}, None]) == []


# ---------------------------------------------------------------------------
# 25. tor_rpc_node_scanner
# ---------------------------------------------------------------------------

ONION = "aaaabbbbccccdddd22223333.onion"
TOR_VULN = {"onion_rpc_probes": [{
    "endpoint": ONION, "chain": "ethereum", "client_version": "geth/1.13",
    "modules": ["eth", "net", "admin", "debug"], "cors_origin": "*"}]}

TOR_CLEAN = {"onion_rpc_probes": [{
    "endpoint": ONION, "chain": "ethereum", "client_version": "geth/1.13",
    "modules": ["eth", "net", "web3"], "cors_origin": None}]}


def test_tor_rpc_fires_on_dangerous_modules():
    res = run("tor_rpc_node_scanner", _wallet(), artifacts=[TOR_VULN])
    ks = keys_of(res)
    assert "onion_rpc_dangerous_rpc_modules" in ks
    assert "onion_rpc_wildcard_cors" in ks


def test_tor_rpc_silent_on_readonly_node():
    res = run("tor_rpc_node_scanner", _wallet(), artifacts=[TOR_CLEAN])
    assert res.findings == []


def test_tor_rpc_malformed():
    assert_malformed_ok("tor_rpc_node_scanner")
    from app.plugins.tor_rpc_node_scanner import analyse_onion_probe
    assert analyse_onion_probe({}) == []
    assert analyse_onion_probe("junk") == []


# ---------------------------------------------------------------------------
# 26. web3auth_session_leak (masked evidence only)
# ---------------------------------------------------------------------------

SECRET_SHARE = "ab" * 32
LEAK_DUMP = json.dumps({"web3auth_state": {
    "privKeyShare": SECRET_SHARE, "appId": "BN-example",
    "storage": "localStorage"}})

CLEAN_DUMP = json.dumps({"web3auth_state": {
    "appId": "BN-example", "verifier": "google", "network": "mainnet"}})


def test_web3auth_fires_on_share_material():
    res = run("web3auth_session_leak", _wallet(), artifacts=[LEAK_DUMP])
    assert "web3auth_key_material_stored" in keys_of(res)
    blob = json.dumps([f.value + json.dumps(f.evidence or {})
                       for f in res.findings])
    assert SECRET_SHARE not in blob  # evidence is masked, never raw


def test_web3auth_silent_on_public_metadata():
    res = run("web3auth_session_leak", _wallet(), artifacts=[CLEAN_DUMP])
    assert res.findings == []


def test_web3auth_malformed():
    assert_malformed_ok("web3auth_session_leak")
    from app.plugins.web3auth_session_leak import scan_web3auth_material
    assert scan_web3auth_material("") == []
    assert scan_web3auth_material(None) == []
