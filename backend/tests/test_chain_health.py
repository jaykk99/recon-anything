"""Regression gate for the 2026-11-14 chain-health fixes.

Pins the behaviour that failed the chain matrix test:

- every supported chain address classifies as a crypto target (and
  Polkadot is NOT labelled Bitcoin);
- the checksum address detectors accept an address-shaped target and
  actually fire on it end-to-end;
- content-only packs (secrets/miners) stay out of wallet runs;
- chain_enrich reports DEGRADED (never a clean OK) when every source
  refuses, and a normal profile when a source answers;
- Avalanche has a contract-recon chain config and Polygon no longer
  leads with its dead endpoint;
- the stablecoin detector knows USDT-TRON and USDC on L2s.

Pure offline: the network is stubbed.
"""
import asyncio
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.cache import Cache  # noqa: E402
from app.classifier import classify  # noqa: E402
from app.plugins import chain_enrich as ce  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import cryptopack_util as U  # noqa: E402
from app.plugins.base import Ctx, PageData, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

REG = discover()
H20 = bytes(range(20))
DOMAIN = "fixture.test"


def b58c(payload: bytes) -> str:
    return U.b58check_encode(payload)


def dot_addr() -> str:
    pub = bytes([0]) + bytes(range(32))
    ck = hashlib.blake2b(b"SS58PRE" + pub, digest_size=64).digest()[:2]
    return U.b58encode(pub + ck)


def ton_addr() -> str:
    import base64
    pay = bytes([0x11, 0x00]) + bytes(range(32))
    return base64.urlsafe_b64encode(
        pay + U.crc16_xmodem(pay).to_bytes(2, "big")).decode().rstrip("=")


# --- classifier ------------------------------------------------------------

ADDRESS_CASES = [
    ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "btc"),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc"),
    (b58c(bytes([0x30]) + H20), "ltc"),
    (b58c(bytes([0x1E]) + H20), "doge"),
    (b58c(bytes([0x4C]) + H20), "dash"),
    (b58c(bytes([0x41]) + H20), "trx"),
    (b58c(b"\x1c\xb8" + H20), "zec"),
    ("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "bch"),
    (U.b58check_encode(bytes([0]) + H20, U.XRP_ALPHABET), "xrp"),
    (U.bech32_encode("addr", bytes(range(57))), "ada"),
    (dot_addr(), "dot"),
    (ton_addr(), "ton"),
    (U.xmr_encode(bytes([0x12]) + bytes(range(32))
                  + bytes(range(32, 64))), "xmr"),
    ("sui:0x" + "ab" * 32, "sui"),
    ("aptos:0x" + "cd" * 32, "aptos"),
    ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "eth"),
]


@pytest.mark.parametrize("addr,chain", ADDRESS_CASES)
def test_address_formats_classify_as_crypto(addr, chain):
    c = classify(addr)
    assert c["type"] == "crypto_wallet", (addr, c)
    assert c["chain"] == chain, (addr, c)


def test_polkadot_is_not_bitcoin():
    addr = dot_addr()
    c = classify(addr)
    assert c["chain"] == "dot", c
    # And the same string is not a checksum-valid Bitcoin legacy address.
    assert not __import__("app.classifier", fromlist=["x"])._looks_like_btc(addr)


def test_mutated_address_is_not_crypto():
    bad = U.b58check_encode(bytes([0x30]) + H20)
    bad = bad[:-1] + ("2" if bad[-1] != "2" else "3")
    assert classify(bad)["type"] != "crypto_wallet"


# --- detector routing ------------------------------------------------------

def make_ctx() -> Ctx:
    ctx = Ctx(run_id="chain-health", mode="passive", http=None,
              cache=Cache(), keys={})

    async def fetch_page(url, timeout=10):
        return PageData({"status_code": 200, "headers": {},
                         "text": "", "url": f"https://{DOMAIN}/"})
    ctx.fetch_page = fetch_page
    return ctx


def test_address_detectors_accept_wallet_targets():
    for pid in ("cp_btc_legacy", "cp_ltc_validated", "cp_doge_validated",
                "cp_dash_addr", "cp_trx_validated", "cp_xrp_addr",
                "cp_ada_addr", "cp_dot_addr", "cp_ton_addr",
                "cp_xmr_standard", "cp_zec_addr", "cp_bch_addr"):
        assert "crypto_wallet" in REG[pid].accepts, pid


def test_content_packs_stay_out_of_wallet_runs():
    for pid in ("cp_secret_env_privkey", "cp_miner_coinhive"):
        assert "crypto_wallet" not in REG[pid].accepts, pid


@pytest.mark.parametrize("pid,addr,key", [
    ("cp_ltc_validated", b58c(bytes([0x30]) + H20), "ltc_address"),
    ("cp_trx_validated", b58c(bytes([0x41]) + H20), "trx_address"),
    ("cp_dot_addr", dot_addr(), "dot_address"),
    ("cp_sui_addr", "sui:0x" + "ab" * 32, "sui_address"),
    ("cp_aptos_addr", "aptos:0x" + "cd" * 32, "aptos_address"),
])
def test_detector_fires_on_pasted_address(pid, addr, key):
    plugin = REG[pid]()
    target = Target(raw=addr, type="crypto_wallet", normalized=addr)
    res = asyncio.run(plugin.run(target, make_ctx()))
    assert key in [f.key for f in res.findings], (pid, res.reason)


def test_stablecoin_detector_covers_tron_and_l2s():
    plugin = REG["cp_web3_canonical_contracts"]()
    text = ("USDT TRON: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t "
            "USDC Base: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
    hits = []
    for rx, key, _label, _conf, validator in plugin._patterns():
        for m in rx.finditer(text):
            if validator is None or validator(m.group(0)):
                hits.append(key)
    assert "contract_usdt_tron" in hits
    assert "contract_usdc_base" in hits


# --- enrichment health -----------------------------------------------------

class _Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def _wallet_ctx(addr: str, chain: str):
    ctx = Ctx(run_id="chain-health", mode="passive", http=object(),
              cache=Cache(), keys={})
    ctx.shared = {"crypto_addresses": [
        {"address": addr, "chain": chain, "key": f"{chain}_address"}]}
    return ctx


def _target(addr: str):
    return Target(raw=addr, type="crypto_wallet", normalized=addr)


def test_enrich_uses_esplora_for_bitcoin(monkeypatch):
    calls = []

    async def fake_fetch(http, limiter, method, url, **kw):
        calls.append(url)
        return _Resp({"chain_stats": {"funded_txo_sum": 300000000,
                                      "spent_txo_sum": 100000000,
                                      "tx_count": 5}})

    monkeypatch.setattr(ce, "fetch", fake_fetch)
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    res = asyncio.run(ce.ChainEnrichPlugin().run(
        _target(addr), _wallet_ctx(addr, "btc")))
    assert "enriched 1" in res.reason, res.reason
    assert "mempool.space" in calls[0], calls
    prof = [f for f in res.findings if f.key == "chain_profile"]
    assert prof and prof[0].evidence["balance"] == 2.0


def test_enrich_degrades_when_every_source_refuses(monkeypatch):
    async def refuse(http, limiter, method, url, **kw):
        return _Resp({"context": {"code": 430}}, status_code=430)

    monkeypatch.setattr(ce, "fetch", refuse)
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    res = asyncio.run(ce.ChainEnrichPlugin().run(
        _target(addr), _wallet_ctx(addr, "btc")))
    assert res.reason.startswith("DEGRADED:"), res.reason
    assert "refused" in res.reason


def test_enrich_tron_prefers_trongrid(monkeypatch):
    seen = []

    async def fake_fetch(http, limiter, method, url, **kw):
        seen.append(url)
        if "trongrid" in url:
            return _Resp({"data": [{"balance": 4500000,
                                    "totalTransactionCount": 2}]})
        return _Resp({"Error": "rate limited"}, status_code=429)

    monkeypatch.setattr(ce, "fetch", fake_fetch)
    addr = b58c(bytes([0x41]) + H20)
    res = asyncio.run(ce.ChainEnrichPlugin().run(
        _target(addr), _wallet_ctx(addr, "trx")))
    assert "enriched 1" in res.reason, res.reason
    assert "trongrid" in seen[0]


# --- chain config ----------------------------------------------------------

def test_avalanche_contract_chain_is_configured():
    chain = cc.CHAINS["avalanche"]
    assert chain.chain_id == 43114
    assert "avax" in cc.CHAIN_ALIASES
    assert cc.parse_target_address(
        "avax:0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E")[0] == "avalanche"


def test_polygon_does_not_lead_with_dead_endpoint():
    urls = cc.CHAINS["polygon"].rpc_urls
    assert urls and "polygon-rpc.com" not in urls[0]
    assert len(urls) >= 2
