"""Tests for aml_typologies: 8 AML typology detectors, all offline.

detect() is pure, so most tests run it directly on fixture
documents. The run-path test monkeypatches collect_texts and
_contract_docs (the module's only network surfaces). Precision
matters as much as recall: the clean controls (ordinary landing
page, ordinary job posting, ordinary token contract, gift shop)
must produce ZERO aml findings from all eight plugins.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins import aml_typologies as aml  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.cryptopack_util import xmr_encode  # noqa: E402

TORNADO_1ETH = "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"
TORNADO_01ETH = "0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc"
WORMHOLE_CORE = "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
ACROSS_SPOKEPOOL = "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"

ALL_PLUGINS = [aml.AmlMixerPlugin, aml.AmlXmrConversionPlugin,
               aml.AmlChainHopPlugin, aml.AmlNonKycExchangePlugin,
               aml.AmlP2pCashPlugin, aml.AmlGiftcardSwapPlugin,
               aml.AmlMuleNetworkPlugin, aml.AmlShellAccountPlugin]


def _ctx():
    return Ctx(run_id="test", mode="passive", http=None,
               cache=Cache(), keys={}, limiter=None,
               evidence_dir="/tmp")


def _target(raw="example.com", type="domain"):
    return Target(raw=raw, type=type, normalized=raw)


def _web(text, where="homepage HTML"):
    return {"kind": "web", "where": where, "text": text,
            "url": "https://example.com/"}


def _contract(text, where="verified source of contract "
                          "0x1111111111111111111111111111111111111111 "
                          "on ethereum"):
    return {"kind": "contract", "where": where, "text": text,
            "url": None,
            "address": "0x1111111111111111111111111111111111111111",
            "chain": "ethereum"}


def _detect(cls, docs, target=None):
    return cls().detect(docs, target or _target())


def _all_findings(docs, target=None):
    out = []
    for cls in ALL_PLUGINS:
        out.extend(_detect(cls, docs, target))
    return out


# ---------------- registries ----------------

def test_mixer_registry_matches_ofac_notice():
    # The four ETH pool addresses, exactly as printed in the OFAC
    # designation notice (Federal Register 2022-17272).
    assert "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc" in \
        aml.MIXER_CONTRACTS
    assert "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936" in \
        aml.MIXER_CONTRACTS
    assert "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf" in \
        aml.MIXER_CONTRACTS
    assert "0xa160cdab225685da1d56aa342ad8841c3b53f291" in \
        aml.MIXER_CONTRACTS
    assert len(aml.MIXER_CONTRACTS) == 46
    entry = aml.MIXER_CONTRACTS[TORNADO_1ETH.lower()]
    assert entry["service"] == "Tornado Cash"
    assert "OFAC" in entry["registry_source"]


def test_bridge_registry_shape():
    assert len(aml.BRIDGE_ROUTERS) == 44
    svc, chains = aml.BRIDGE_ROUTERS[WORMHOLE_CORE.lower()]
    assert svc == "Wormhole Core Bridge"
    assert "ethereum" in chains


def test_registry_discovers_all_eight():
    from app.plugins.registry import discover
    reg = discover()
    for pid in ("aml_mixer", "aml_xmr_conversion", "aml_chain_hop",
                "aml_non_kyc_exchange", "aml_p2p_cash",
                "aml_giftcard_swap", "aml_mule_network",
                "aml_shell_account"):
        assert pid in reg


# ---------------- mixer ----------------

def test_mixer_address_in_contract_source_is_high():
    src = ("contract Vault {\n"
           f"  address constant POOL = {TORNADO_1ETH};\n"
           "  function sweep() public { POOL.call(\"\"); }\n}")
    findings = _detect(aml.AmlMixerPlugin, [_contract(src)])
    assert len(findings) == 1
    f = findings[0]
    assert f.key == "aml_mixer"
    assert f.evidence["severity"] == "high"
    assert f.evidence["matched_address"] == TORNADO_1ETH
    assert TORNADO_1ETH in f.evidence["snippet"]


def test_mixer_address_in_web_text_is_medium():
    page = _web(f"<p>Pool: {TORNADO_01ETH}</p>")
    findings = _detect(aml.AmlMixerPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "medium"


def test_mixer_target_itself_is_high():
    t = Target(raw=TORNADO_1ETH, type="crypto_wallet",
               normalized=TORNADO_1ETH)
    findings = _detect(aml.AmlMixerPlugin, [], t)
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "high"
    assert "itself" in findings[0].value


def test_mixer_domain_reference_is_medium():
    page = _web('<a href="https://tornado.cash">mix here</a>')
    findings = _detect(aml.AmlMixerPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["matched_domain"] == "tornado.cash"


# ---------------- Monero conversion ----------------

def _valid_xmr():
    payload = bytes([0x12]) + bytes(range(64))
    return xmr_encode(payload)


def test_xmr_valid_address_in_web_text():
    addr = _valid_xmr()
    assert aml.find_xmr_addresses(f"donate: {addr}") == [addr]
    findings = _detect(aml.AmlXmrConversionPlugin,
                       [_web(f"Swap into Monero: {addr}")])
    assert len(findings) == 1
    f = findings[0]
    assert f.key == "aml_xmr_conversion"
    assert f.evidence["severity"] == "medium"
    assert f.evidence["matched_address"] == addr
    assert "opaque by design" in f.value


def test_xmr_checksum_invalid_address_rejected():
    addr = _valid_xmr()
    bad = addr[:-1] + ("1" if addr[-1] != "1" else "2")
    assert aml.find_xmr_addresses(f"addr {bad}") == []
    assert _detect(aml.AmlXmrConversionPlugin,
                   [_web(f"pay {bad}")]) == []


def test_xmr_address_in_contract_source_is_high():
    addr = _valid_xmr()
    findings = _detect(aml.AmlXmrConversionPlugin,
                       [_contract(f'// payout {addr}')])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "high"


def test_xmr_exchange_monero_mention_is_medium():
    page = _web('Convert to Monero instantly at '
                '<a href="https://fixedfloat.com">FixedFloat</a>')
    findings = _detect(aml.AmlXmrConversionPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["matched_domain"] == \
        "fixedfloat.com"


# ---------------- chain-hopping ----------------

def test_chain_hop_two_bridge_routers_in_contract():
    src = ("contract Hop {\n"
           f"  address constant WH = {WORMHOLE_CORE};\n"
           f"  address constant AC = {ACROSS_SPOKEPOOL};\n"
           "  function depositAndBridge() public payable {}\n}")
    findings = _detect(aml.AmlChainHopPlugin, [_contract(src)])
    assert len(findings) == 1
    f = findings[0]
    assert f.key == "aml_chain_hop"
    assert f.evidence["severity"] == "medium"
    assert set(f.evidence["matched_addresses"]) == \
        {WORMHOLE_CORE.lower(), ACROSS_SPOKEPOOL.lower()}


def test_chain_hop_single_bridge_router_is_silent():
    src = ("contract BridgeApp {\n"
           f"  address constant WH = {WORMHOLE_CORE};\n"
           "  function deposit() public payable {}\n}")
    assert _detect(aml.AmlChainHopPlugin, [_contract(src)]) == []


def test_chain_hop_no_account_swap_advertising():
    page = _web("Instant cross-chain swaps, no account needed. "
                "Bridge any token in seconds.")
    findings = _detect(aml.AmlChainHopPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "medium"


# ---------------- non-KYC exchanges ----------------

def test_non_kyc_exchange_link_in_web_is_medium():
    page = _web('<a href="https://sideshift.ai/btc/eth">'
                "swap now</a>")
    findings = _detect(aml.AmlNonKycExchangePlugin, [page])
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["severity"] == "medium"
    assert f.evidence["matched_domain"] == "sideshift.ai"
    assert f.evidence["service"] == "SideShift.ai"


def test_non_kyc_exchange_in_contract_source_is_high():
    src = '// payout rail: godex.io widget endpoint\ncontract C {}'
    findings = _detect(aml.AmlNonKycExchangePlugin,
                       [_contract(src)])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "high"


def test_non_kyc_lookalike_domain_is_silent():
    page = _web('<a href="https://notsideshift.ai">x</a> '
                '<a href="https://sideshift.ai.example.com">y</a>')
    assert _detect(aml.AmlNonKycExchangePlugin, [page]) == []


# ---------------- P2P cash ----------------

def test_p2p_platform_with_cash_language_is_medium():
    page = _web('Trade on <a href="https://hodlhodl.com">HodlHodl'
                "</a> and pay cash in person.")
    findings = _detect(aml.AmlP2pCashPlugin, [page])
    sev = {f.evidence["severity"] for f in findings}
    assert "medium" in sev
    assert any(f.evidence.get("matched_domain") == "hodlhodl.com"
               for f in findings)


def test_p2p_platform_bare_reference_is_low():
    page = _web('Also listed on <a href="https://bisq.network">'
                "Bisq</a>.")
    findings = _detect(aml.AmlP2pCashPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "low"


def test_p2p_cash_by_mail_language():
    page = _web("Buy bitcoin with cash by mail, no ID needed.")
    findings = _detect(aml.AmlP2pCashPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["pattern"] == "cash by mail"


# ---------------- gift cards ----------------

def test_giftcard_sell_for_btc_language():
    page = _web("Sell your gift cards for BTC instantly, any "
                "brand, any balance.")
    findings = _detect(aml.AmlGiftcardSwapPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "medium"
    assert findings[0].evidence["pattern"] == \
        "sell gift cards for crypto"


def test_giftcard_service_reference_is_low():
    page = _web('Cards via <a href="https://www.bitrefill.com">'
                "Bitrefill</a>")
    findings = _detect(aml.AmlGiftcardSwapPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "low"


# ---------------- money mules ----------------

_MULE_PAGE = (
    "Work from home as a payment processing agent! No experience "
    "needed. You will receive transfers and forward the funds to "
    "our partners, and keep 10% as your commission. We are hiring "
    "agents in all states.")


def test_mule_recruitment_page_flags_with_exact_text():
    findings = _detect(aml.AmlMuleNetworkPlugin, [_web(_MULE_PAGE)])
    assert len(findings) == 1
    f = findings[0]
    assert f.key == "aml_mule_network"
    assert f.evidence["severity"] == "medium"
    assert f.evidence["candidate"] is True
    signals = f.evidence["signals"]
    assert "forward" in signals["money_movement"]
    assert "10%" in signals["commission"]
    assert "receive transfers" in f.evidence["matched_text"] or \
        "forward the funds" in f.evidence["matched_text"]


def test_mule_two_signals_only_is_silent():
    # Movement + recruitment, but no commission: not enough.
    page = _web("Work from home! Receive transfers and forward "
                "the funds to our partners. Apply today.")
    assert _detect(aml.AmlMuleNetworkPlugin, [page]) == []


# ---------------- shell accounts ----------------

def test_shell_verified_account_sale_is_high():
    page = _web("Verified Binance accounts for sale - full KYC "
                "done, ready to trade.")
    findings = _detect(aml.AmlShellAccountPlugin, [page])
    assert len(findings) >= 1
    assert findings[0].evidence["severity"] == "high"
    assert "for sale" in findings[0].evidence["matched_text"]


def test_shell_nominee_bundle_is_medium():
    page = _web("Every package includes a nominee director and a "
                "verified exchange account in the company name.")
    findings = _detect(aml.AmlShellAccountPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["severity"] == "medium"
    assert findings[0].evidence["pattern"] == \
        "nominee + exchange account"


def test_shell_formation_bundle_is_medium():
    page = _web("Company formation plus crypto account opening, "
                "handled end to end for one flat fee in BTC.")
    findings = _detect(aml.AmlShellAccountPlugin, [page])
    assert len(findings) == 1
    assert findings[0].evidence["pattern"] == \
        "formation + crypto account"


# ---------------- clean controls: ZERO findings ----------------

_CLEAN_PAGE = (
    "Welcome to Prairie Coffee Roasters. We roast small-batch "
    "beans in Winnipeg and ship across Canada. Buy gift cards for "
    "friends, book a tasting, or read our brewing guides. We "
    "accept gift cards as payment in store. Open weekdays 8-5.")

_CLEAN_JOB = (
    "We are hiring a payment processing clerk for our Winnipeg "
    "office. Work from home two days a week after probation. "
    "Salary $55,000 per year plus benefits. You will process "
    "payments and invoices for our clients and answer phones.")

_CLEAN_CONTRACT = (
    "// SPDX-License-Identifier: MIT\n"
    "contract CoffeeToken {\n"
    f"  address constant BRIDGE = {WORMHOLE_CORE};\n"
    "  mapping(address => uint256) public balanceOf;\n"
    "  function deposit() public payable {}\n"
    "  function transfer(address to, uint256 amt) public {}\n}")


def test_clean_controls_produce_zero_aml_findings():
    assert _all_findings([_web(_CLEAN_PAGE)]) == []
    assert _all_findings([_web(_CLEAN_JOB)]) == []
    assert _all_findings([_contract(_CLEAN_CONTRACT)]) == []
    assert _all_findings([_web(_CLEAN_PAGE), _web(_CLEAN_JOB),
                          _contract(_CLEAN_CONTRACT)]) == []


# ---------------- run path (network surfaces mocked) ----------------

def test_run_path_uses_shared_doc_gathering(monkeypatch):
    async def fake_collect(ctx, target, max_js=8):
        return [("homepage HTML", _MULE_PAGE, "https://example.com/")]

    async def fake_contract_docs(ctx, target):
        return []

    monkeypatch.setattr(aml, "collect_texts", fake_collect)
    monkeypatch.setattr(aml, "_contract_docs", fake_contract_docs)
    ctx = _ctx()
    res = asyncio.run(aml.AmlMuleNetworkPlugin().run(_target(), ctx))
    assert len(res.findings) == 1
    assert res.findings[0].key == "aml_mule_network"
    # Docs are cached on the run bus: a second plugin on the same
    # run reuses them instead of re-gathering.
    res2 = asyncio.run(aml.AmlMixerPlugin().run(_target(), ctx))
    assert res2.findings == []
