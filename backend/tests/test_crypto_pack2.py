"""Crypto pack wave 2 (cp_* additions) tests.

Same three layers as wave 1:
1. Validator unit tests against independent vectors (BIP-38 spec
   example, the Bitcoin-wiki WIF examples, the BIP-32 test-vector
   xprv/xpub, EIP-55 spec address re-prefixed to XDC) plus
   roundtrips built with hashlib directly in the test and mutation
   negatives.
2. Per-plugin positive tests: every new plugin against a stubbed
   page (or stubbed probe/fetch surface for the file-exposure
   plugins) containing its artifact.
3. Negative sweep: every new plugin against a clean page / empty
   probe surface produces zero findings.
"""
import asyncio
import hashlib
import json
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, PageData, PluginStatus, Target  # noqa: E402
from app.plugins import cryptopack_util as U  # noqa: E402
from app.plugins import cryptopack_util2 as U2  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

REG = discover()
PACK = {pid: cls for pid, cls in REG.items() if pid.startswith("cp_")}

V1_COUNT = 110
NEW_PACK = {pid: cls for pid, cls in PACK.items()
            if cls.__module__.rsplit(".", 1)[1] in (
                "cryptopack_addr2", "cryptopack_secrets2",
                "cryptopack_phish2", "cryptopack_miners2",
                "cryptopack_nodes", "cryptopack_wallet_files")}

DOMAIN = "fixture.test"
H20 = bytes(range(20))
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
CHECKSUMMED = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


# ---------------------------------------------------------------------------
# Layer 1: validators
# ---------------------------------------------------------------------------

def test_wif_famous_vectors():
    # Bitcoin wiki worked examples (key 0x0C28...AA1D, uncompressed)
    # and private key 1 (compressed) - both widely republished.
    assert U2.wif_verify(
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        0x80, False)
    assert U2.wif_verify(
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
        0x80, True)
    # cross-checks must fail
    assert not U2.wif_verify(
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
        0x80, False)
    assert not U2.wif_verify(
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        0xEF, False)
    # mutation
    assert not U2.wif_verify(
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm",
        0x80, True)


def test_bip38_spec_vector_and_roundtrip():
    # BIP-38 draft spec example (no EC multiply), passphrase
    # "TestingOneTwoThree" - structure + checksum validation only.
    assert U2.bip38_verify(
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg")
    mine = U.b58check_encode(b"\x01\x42\xc0" + bytes(range(36)))
    assert mine.startswith("6P") and U2.bip38_verify(mine)
    assert not U2.bip38_verify(mine[:-1] + ("1" if mine[-1] != "1" else "2"))
    # a WIF is not a BIP-38 key
    assert not U2.bip38_verify(
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")


def test_xprv_xpub_bip32_vectors():
    xpub = ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2"
            "gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    xprv = ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqji"
            "ChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    assert U2.xpub_verify(xpub) and U2.xprv_verify(xprv)
    assert not U2.xprv_verify(xpub) and not U2.xpub_verify(xprv)
    assert not U2.xpub_verify(xpub[:-2] + "AA")


def test_ergo_roundtrip_and_mutation():
    body = b"\x01" + bytes(range(33))
    ck = hashlib.blake2b(body, digest_size=32).digest()[:4]
    addr = U.b58encode(body + ck)
    assert addr.startswith("9") and U2.ergo_verify(addr)
    bad = addr[:10] + ("1" if addr[10] != "1" else "2") + addr[11:]
    assert not U2.ergo_verify(bad)
    assert not U2.ergo_verify(GENESIS)


def test_eos_pub_k1_roundtrip():
    pub = bytes(range(33))
    ck = hashlib.new("ripemd160", pub + b"K1").digest()[:4]
    key = "PUB_K1_" + U.b58encode(pub + ck)
    assert U2.eos_key_verify(key)
    assert not U2.eos_key_verify(key[:-1] + ("1" if key[-1] != "1" else "2"))
    legacy_ck = hashlib.new("ripemd160", pub).digest()[:4]
    legacy = "EOS" + U.b58encode(pub + legacy_ck)
    assert U2.eos_key_verify(legacy)


def test_xdc_from_eip55_vector():
    xdc = "xdc" + CHECKSUMMED[2:]
    assert U2.xdc_verify(xdc) and U2.xdc_checksummed(xdc)
    # flip one checksum-significant letter's case -> bad checksum
    bad = "xdc" + CHECKSUMMED[2:].replace("A", "a", 1)
    assert U.eip55_state("0x" + bad[3:]) == "bad"
    assert not U2.xdc_checksummed(bad)
    assert U2.xdc_verify("xdc" + CHECKSUMMED[2:].lower())


def test_ton_raw_and_kaspa_testnet():
    assert U2.ton_raw_verify("0:" + "ab" * 32)
    assert U2.ton_raw_verify("-1:" + "00" * 32)
    assert not U2.ton_raw_verify("0:" + "ab" * 31)
    assert not U2.ton_raw_verify("2:" + "ab" * 32)

    def kas_like(prefix):
        payload = U._convertbits(bytes([0]) + bytes(range(32)), 8, 5)
        exp = [ord(c) & 31 for c in prefix] + [0]
        pm = U._cash_polymod(exp + payload + [0] * 8)
        ck = [(pm >> 5 * (7 - i)) & 31 for i in range(8)]
        return prefix + ":" + "".join(U._CASH_CHARSET[d] for d in payload + ck)
    addr = kas_like("kaspatest")
    assert U2.kaspa_testnet_verify(addr)
    assert not U2.kaspa_testnet_verify(addr[:-1] + "q")


def test_hns_and_zen_and_avax():
    def segwit(hrp, version, prog):
        data = [version] + U._convertbits(prog, 8, 5)
        const = 1 if version == 0 else 0x2BC830A3
        pm = U._bech32_polymod(U._bech32_hrp_expand(hrp) + data + [0] * 6)
        pm ^= const
        ck = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
        return hrp + "1" + "".join(U._BECH32_CHARSET[d] for d in data + ck)
    hs = segwit("hs", 0, H20)
    assert hs.startswith("hs1") and U2.hns_verify(hs)
    assert not U2.hns_verify(hs[:-1] + ("q" if hs[-1] != "q" else "p"))
    zen = U.b58check_encode(b"\x20\x89" + H20)
    assert zen.startswith("zn")
    from app.plugins.cryptopack_util import b58check_prefix
    assert b58check_prefix(zen, (b"\x20\x89", b"\x20\x92"), 26)
    avax = U.bech32_encode("avax", H20)
    assert U2.avax_verify(avax)


# ---------------------------------------------------------------------------
# Harness (mirrors test_crypto_pack.py)
# ---------------------------------------------------------------------------

def make_ctx(html: str, js: str = ""):
    ctx = Ctx(run_id="pack2-test", mode="passive", http=None,
              cache=Cache(), keys={})

    async def fetch_page(url, timeout=10):
        if url.endswith(".js"):
            return PageData({"status_code": 200, "headers": {},
                             "text": js, "url": url})
        return PageData({"status_code": 200, "headers": {},
                         "text": html, "url": f"https://{DOMAIN}/"})
    ctx.fetch_page = fetch_page
    return ctx


def run_plugin(pid: str, html: str, js: str = ""):
    plugin = PACK[pid]()
    ctx = make_ctx(html, js)
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = asyncio.run(plugin.run(target, ctx))
    status = result.status
    if isinstance(status, PluginStatus):
        status = status.value
    assert status in ("ok", "skipped", "degraded"), (pid, status)
    return result.findings


def page(body: str) -> str:
    return ("<html><head><script src=\"/app.js\"></script></head>"
            f"<body>{body}</body></html>")


def bip39_phrase() -> str:
    from app.plugins.cryptopack_secrets import BIP39_WORDS
    ent = bytes(16)
    bits = "".join(format(b, "08b") for b in ent)
    bits += format(hashlib.sha256(ent).digest()[0], "08b")[:4]
    return " ".join(BIP39_WORDS[int(bits[i:i + 11], 2)]
                    for i in range(0, len(bits), 11))


def _bech(hrp):
    return U.bech32_encode(hrp, H20)


def _segwit_hrp(hrp):
    data = [0] + U._convertbits(H20, 8, 5)
    pm = U._bech32_polymod(U._bech32_hrp_expand(hrp) + data + [0] * 6) ^ 1
    ck = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(U._BECH32_CHARSET[d] for d in data + ck)


def _kaspatest():
    payload = U._convertbits(bytes([0]) + bytes(range(32)), 8, 5)
    exp = [ord(c) & 31 for c in "kaspatest"] + [0]
    pm = U._cash_polymod(exp + payload + [0] * 8)
    ck = [(pm >> 5 * (7 - i)) & 31 for i in range(8)]
    return "kaspatest:" + "".join(U._CASH_CHARSET[d] for d in payload + ck)


def _ergo():
    body = b"\x01" + bytes(range(33))
    return U.b58encode(body + hashlib.blake2b(
        body, digest_size=32).digest()[:4])


def _eos_k1():
    pub = b"\x02" + bytes(range(32))
    ck = hashlib.new("ripemd160", pub + b"K1").digest()[:4]
    return "PUB_K1_" + U.b58encode(pub + ck)


def _xmr():
    return U.xmr_encode(bytes([0x12]) + bytes(range(32))
                        + bytes(range(32, 64)))


SAMPLES2 = {
    # addr2
    "cp_ton_raw_addr": ("TON wallet: 0:" + "ab" * 32, "ton_raw_address"),
    "cp_near_implicit_addr": ("NEAR account " + "cd" * 32,
                              "near_implicit_account"),
    "cp_xdc_addr": ("xdc" + CHECKSUMMED[2:], "xdc_address_checksummed"),
    "cp_hbar_addr": ("Hedera account 0.0.1234567", "hbar_account"),
    "cp_eos_key": (_eos_k1(), "eosio_public_key"),
    "cp_vet_addr": (f"VeChain wallet {CHECKSUMMED}", "vet_addr"),
    "cp_ftm_addr": (f"Fantom wallet {CHECKSUMMED}", "ftm_addr"),
    "cp_celo_addr": (f"Celo wallet {CHECKSUMMED}", "celo_addr"),
    "cp_avax_addr": (_bech("avax"), "avax_address"),
    "cp_hns_addr": (_segwit_hrp("hs"), "hns_address"),
    "cp_ergo_addr": (_ergo(), "ergo_address"),
    "cp_dgb_addr": (_segwit_hrp("dgb"), "dgb_address"),
    "cp_vtc_addr": (_segwit_hrp("vtc"), "vtc_address"),
    "cp_via_addr": (_segwit_hrp("via"), "via_address"),
    "cp_zen_addr": (U.b58check_encode(b"\x20\x89" + H20), "zen_address"),
    "cp_kas_testnet_addr": (_kaspatest(), "kas_testnet_address"),
    "cp_spl_mint": ("SPL token mint: 11111111111111111111111111111111",
                    "spl_token_mint"),
    "cp_erc721_contracts": (f"ERC721 contract: {CHECKSUMMED}",
                            "erc721_contract"),
    "cp_erc1155_contracts": (f"ERC1155 contract: {CHECKSUMMED}",
                             "erc1155_contract"),
    "cp_web3_canonical_contracts": (
        "WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "contract_weth"),
    "cp_ordinals_inscriptions": ("ab" * 32 + "i0",
                                 "ordinals_inscription_id"),
    "cp_brc20_refs": ('{"p":"brc-20","op":"mint","tick":"ordi"}',
                      "brc20_operation_blob"),
    # secrets2
    "cp_apikey_gemini": ("GEMINI_API_KEY=abc123def456ghi789jkl0",
                         "gemini_api_key"),
    "cp_apikey_bitstamp": ("BITSTAMP_API_KEY=" + "a1" * 20,
                           "bitstamp_api_key"),
    "cp_apikey_bitfinex": ("BITFINEX_API_KEY=" + "a" * 43,
                           "bitfinex_api_key"),
    "cp_apikey_deribit": ("DERIBIT_CLIENT_ID=" + "b" * 24,
                          "deribit_api_key"),
    "cp_apikey_gateio": ("GATE_API_KEY=" + "ab" * 32, "gateio_api_key"),
    "cp_apikey_mexc": ("MEXC_API_KEY=mx0" + "c" * 32, "mexc_api_key"),
    "cp_apikey_htx": ("HTX_API_KEY=" + "d" * 44, "htx_api_key"),
    "cp_apikey_bingx": ("BINGX_API_KEY=" + "e" * 64, "bingx_api_key"),
    "cp_apikey_blockdaemon": ("BLOCKDAEMON_API_KEY=" + "f" * 40,
                              "blockdaemon_api_key"),
    "cp_apikey_tenderly": ("TENDERLY_ACCESS_TOKEN=" + "g" * 40,
                           "tenderly_access_token"),
    "cp_apikey_chainstack": ("node.p2pify.com/" + "ab" * 16,
                             "chainstack_endpoint"),
    "cp_apikey_ankr": ("https://rpc.ankr.com/eth/" + "ab" * 32,
                       "ankr_endpoint_token"),
    "cp_apikey_infstones": ("INFSTONES_API_KEY=" + "h" * 40,
                            "infstones_api_key"),
    "cp_secret_telegram_bot": (
        "trading bot token: 123456789:" + "A" * 35, "telegram_bot_token"),
    "cp_secret_discord_webhook": (
        "trading alerts: https://discord.com/api/webhooks/"
        "123456789012345678/" + "a" * 68, "discord_webhook"),
    "cp_secret_wif_compressed": (
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
        "wif_private_key"),
    "cp_secret_wif_uncompressed": (
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        "wif_private_key"),
    "cp_secret_wif_testnet": (
        U.b58check_encode(b"\xef" + bytes(range(32))), "wif_testnet_key"),
    "cp_secret_bip38": (
        U.b58check_encode(b"\x01\x42\xc0" + bytes(range(36))),
        "bip38_key"),
    "cp_secret_xprv": (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqji"
        "ChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        "extended_private_key"),
    "cp_web3_xpub": (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2"
        "gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        "extended_public_key"),
    "cp_secret_signer_hex_ctx": (
        "deployer private key: 0x" + "ab" * 32, "signer_hex_key"),
    "cp_secret_js_comment_keys": (
        "// temp deployer key 0x" + "cd" * 32, "comment_private_key"),
    "cp_secret_env_privkey2": (
        "FAUCET_PRIVATE_KEY=0x" + "ef" * 32, "env_private_key_2"),
    "cp_secret_keystore_path_refs": (
        "UTC--2024-01-15T10-30-45.123456789Z--"
        "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "keystore_filename"),
    # phish2
    "cp_drainer_inferno": ("inferno-drainer loader", "inferno_drainer"),
    "cp_drainer_pink": ("PinkDrainer config loaded", "pink_drainer"),
    "cp_drainer_angel": ("AngelDrainer v2", "angel_drainer"),
    "cp_drainer_ms": ("msdrainer.js", "ms_drainer"),
    "cp_drainer_permit2": ("SignatureTransfer", "permit2_flow"),
    "cp_phish_eligibility_scam": (
        "Check your eligibility for the airdrop - connect wallet",
        "eligibility_scam"),
    "cp_phish_presale_scam": (
        "Presale live: send ETH to this address to buy",
        "presale_direct_send"),
    # miners2
    "cp_pool_2miners": ("eth.2miners.com:2020", "pool_2miners"),
    "cp_pool_nanopool": ("xmr.nanopool.org:14444", "pool_nanopool"),
    "cp_pool_hiveon": ("eu.hiveon.net:4444", "pool_hiveon"),
    "cp_pool_viabtc": ("pool.viabtc.com:3333", "pool_viabtc"),
    "cp_pool_luxor": ("btc.mining.luxor.tech:700", "pool_luxor"),
    "cp_miner_xmrig_proxy": ("xmrig-proxy v6.15", "miner_xmrig_proxy"),
    "cp_miner_config_wallet": (
        '{"pools": [{"url": "pool.example.org:3333", '
        '"user": "wallet-abc"}]}', "miner_config_wallet"),
    "cp_miner_dashboard_refs": ("https://hiveos.farm/login",
                                "miner_dashboard_hiveos"),
    "cp_miner_deepminer": ("deepminer.min.js", "miner_deepminer"),
    "cp_miner_webminerpool": ("webminerpool.com", "miner_webminerpool"),
    "cp_miner_minero": ("https://minero.cc/lib/miner.js",
                        "miner_minero"),
    # nodes
    "cp_node_bitcoind_rpc": (
        "http://rpcuser:rpcpass@node.example.org:8332",
        "bitcoind_rpc_url"),
    "cp_node_electrum_server": (
        "electrum://electrum.example.org:50002", "electrum_server"),
    "cp_node_devnode_refs": ("http://localhost:8545", "devnode_endpoint"),
    "cp_node_hardhat_accounts": (
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "hardhat_test_account"),
    "cp_node_rpc_creds": (
        "our ethereum rpc: https://user:secretpass@node.example.org/",
        "rpc_url_credentials"),
    "cp_node_btcpay_config": ("BTCPayServer.db", "btcpay_artifact"),
    "cp_node_near_rpc": ("https://rpc.mainnet.near.org",
                         "near_rpc_endpoint"),
    # wallet content plugins
    "cp_wallet_metamask_vault": (
        '{"KeyringController": {"vault": "x"}}', "metamask_vault_state"),
    "cp_wallet_phantom_vault": (
        '{"phantom": {"seed": "' + "A" * 80 + '"}}',
        "phantom_vault_blob"),
    "cp_wallet_seed_file_refs": (
        '<a href="/files/seed-backup.txt">your backup</a>',
        "wallet_file_link"),
    "cp_wallet_config_creds": ("rpcpassword=hunter2hunter2",
                               "rpc_password_value"),
    "cp_wallet_qr_payload": (
        '<img src="https://api.qrserver.com/v1/create-qr-code/'
        '?data=bitcoin:' + GENESIS + '">', "qr_payment_payload"),
}

# cosmos factory samples added programmatically
for _hrp in ("stars", "juno", "cro", "kava", "evmos", "secret", "akash",
             "terra", "kuji", "persistence", "stride", "fetch", "sei"):
    SAMPLES2[f"cp_{_hrp}_addr"] = (_bech(_hrp), f"{_hrp}_address")


@pytest.mark.parametrize("pid", sorted(SAMPLES2))
def test_pack2_plugin_positive(pid):
    body, expected_key = SAMPLES2[pid]
    findings = run_plugin(pid, page(body))
    keys = [f.key for f in findings]
    assert expected_key in keys, (pid, keys)


def test_pack2_registry_growth():
    assert len(PACK) >= 200, len(PACK)
    assert len(NEW_PACK) >= 90, len(NEW_PACK)
    for pid, cls in NEW_PACK.items():
        assert cls.label and cls.description, pid
        assert cls.group == "web3", pid


def test_pack2_checksum_mutations_produce_nothing():
    # mutated bech32 (cosmos) must not verify
    good = _bech("juno")
    bad = good[:-1] + ("q" if good[-1] != "q" else "p")
    assert run_plugin("cp_juno_addr", page(bad)) == []
    # WIF with a broken checksum
    assert run_plugin(
        "cp_secret_wif_compressed",
        page("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm")) == []
    # bad-checksum XDC (mixed case, one letter flipped)
    bad_xdc = "xdc" + CHECKSUMMED[2:].replace("A", "a", 1)
    findings = run_plugin("cp_xdc_addr", page(bad_xdc))
    assert [f.key for f in findings] == []
    # QR payload whose address has a broken checksum is not a payload
    bad_qr = ('<img src="https://api.qrserver.com/v1/create-qr-code/'
              '?data=bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb">')
    assert run_plugin("cp_wallet_qr_payload", page(bad_qr)) == []


def test_spl_mint_needs_context():
    # a bare 32-byte base58 string with no mint context: the wave-1
    # solana plugin owns that; the mint inventory must stay silent
    assert run_plugin("cp_spl_mint",
                      page("11111111111111111111111111111111")) == []


def test_typosquat_links():
    html = page('<a href="https://metamask-support.com/claim">x</a>')
    findings = run_plugin("cp_phish_typosquat_links", html)
    assert [f.key for f in findings] == ["typosquat_link"]
    ok = page('<a href="https://metamask.io/download">x</a>')
    assert run_plugin("cp_phish_typosquat_links", ok) == []
    homoglyph = page('<a href="https://rn3tamask.io/">x</a>')
    findings = run_plugin("cp_phish_typosquat_links", homoglyph)
    assert [f.key for f in findings] == ["typosquat_link"]


def test_miner_config_xmr_wallet_validated():
    body = '{"algo": "rx/0", "user": "' + _xmr() + '"}'
    findings = run_plugin("cp_miner_config_wallet", page(body))
    assert "miner_config_xmr_wallet" in [f.key for f in findings]
    # same shape, corrupted checksum -> silent
    bad = _xmr()
    bad = bad[:20] + ("1" if bad[20] != "1" else "2") + bad[21:]
    body = '{"algo": "rx/0", "user": "' + bad + '"}'
    findings = run_plugin("cp_miner_config_wallet", page(body))
    assert "miner_config_xmr_wallet" not in [f.key for f in findings]


CLEAN = page("Welcome to our bakery. Fresh bread daily, since 1987. "
             "Call 204-555-0100 for catering and wedding cakes.")

_CONTENT_NEW = [pid for pid in NEW_PACK
                if pid not in (
                    "cp_wallet_dat_file", "cp_wallet_keystore_file",
                    "cp_wallet_electrum_file", "cp_wallet_backup_text",
                    "cp_wallet_btc_conf", "cp_wallet_archive_file",
                    "cp_wallet_dir_listing", "cp_wallet_git_served",
                    "cp_wallet_served_docs", "cp_wallet_sourcemap")]


@pytest.mark.parametrize("pid", sorted(_CONTENT_NEW))
def test_pack2_plugin_clean_page(pid):
    findings = run_plugin(pid, CLEAN)
    assert findings == [], (pid, [(f.key, f.value) for f in findings])


# ---------------------------------------------------------------------------
# Probe-based wallet file plugins (stubbed ctx.probe surface)
# ---------------------------------------------------------------------------

PROBE_PIDS = (
    "cp_wallet_dat_file", "cp_wallet_keystore_file",
    "cp_wallet_electrum_file", "cp_wallet_backup_text",
    "cp_wallet_btc_conf", "cp_wallet_archive_file",
    "cp_wallet_dir_listing",
)


def make_probe_ctx(pages_map):
    """pages_map: path -> (status, text, headers, length)."""
    ctx = Ctx(run_id="pack2-probe", mode="passive", http=None,
              cache=Cache(), keys={})

    async def probe(url, timeout=8):
        path = urlparse(url).path
        status, text, headers, length = pages_map.get(
            path, (404, "", {}, 0))
        return {"status": status, "headers": headers, "text": text,
                "url": url, "length": length}
    ctx.probe = probe
    return ctx


def run_probe_plugin(pid, pages_map):
    plugin = PACK[pid]()
    ctx = make_probe_ctx(pages_map)
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = asyncio.run(plugin.run(target, ctx))
    status = result.status
    if isinstance(status, PluginStatus):
        status = status.value
    assert status in ("ok", "skipped", "degraded"), (pid, status)
    return result.findings


def test_wallet_dat_probe():
    binary = "\x00\x01\x02binarywalletdata" + "x" * 400
    findings = run_probe_plugin("cp_wallet_dat_file", {
        "/wallet.dat": (200, binary,
                        {"content-type": "application/octet-stream"},
                        5000)})
    assert [f.key for f in findings] == ["wallet_dat_exposed"]
    # an HTML 200 (SPA fallback) is not a wallet
    findings = run_probe_plugin("cp_wallet_dat_file", {
        "/wallet.dat": (200, "<html><body>app</body></html>",
                        {"content-type": "text/html"}, 5000)})
    assert findings == []
    # guarded counts as exists-but-guarded
    findings = run_probe_plugin("cp_wallet_dat_file", {
        "/wallet.dat": (403, "", {}, 0)})
    assert [f.key for f in findings] == ["wallet_dat_exposed_guarded"]


def test_keystore_probe():
    body = json.dumps({"version": 3, "address": "aa",
                       "crypto": {"ciphertext": "bb", "kdf": "scrypt"}})
    findings = run_probe_plugin("cp_wallet_keystore_file", {
        "/keystore.json": (200, body, {}, len(body))})
    assert [f.key for f in findings] == ["keystore_file_exposed"]
    # random JSON at the same path is not a keystore
    findings = run_probe_plugin("cp_wallet_keystore_file", {
        "/keystore.json": (200, '{"hello": "world"}', {}, 20)})
    assert findings == []


def test_electrum_probe():
    body = json.dumps({"wallet_type": "standard", "seed_version": 12,
                       "keystore": {"type": "bip32"}})
    findings = run_probe_plugin("cp_wallet_electrum_file", {
        "/default_wallet": (200, body, {}, len(body))})
    assert [f.key for f in findings] == ["electrum_wallet_exposed"]


def test_backup_text_probe_requires_real_material():
    body = "my wallet backup\n" + bip39_phrase() + "\n"
    findings = run_probe_plugin("cp_wallet_backup_text", {
        "/seed.txt": (200, body, {}, len(body))})
    assert [f.key for f in findings] == ["wallet_backup_text_exposed"]
    assert "BIP-39" in findings[0].value
    # a file NAMED like a backup but with no wallet material: silent
    findings = run_probe_plugin("cp_wallet_backup_text", {
        "/seed.txt": (200, "shopping list: eggs, flour", {}, 25)})
    assert findings == []
    # an address-bearing note counts too
    body = "cold wallet: " + GENESIS
    findings = run_probe_plugin("cp_wallet_backup_text", {
        "/wallet.txt": (200, body, {}, len(body))})
    assert [f.key for f in findings] == ["wallet_backup_text_exposed"]


def test_btc_conf_probe_requires_creds():
    body = "server=1\nrpcuser=satoshi\nrpcpassword=hunter2hunter2\n"
    findings = run_probe_plugin("cp_wallet_btc_conf", {
        "/bitcoin.conf": (200, body, {}, len(body))})
    assert [f.key for f in findings] == ["node_conf_creds_exposed"]
    findings = run_probe_plugin("cp_wallet_btc_conf", {
        "/bitcoin.conf": (200, "server=1\ntxindex=1\n", {}, 20)})
    assert findings == []


def test_archive_probe():
    findings = run_probe_plugin("cp_wallet_archive_file", {
        "/wallet.zip": (200, "PK\x03\x04rest-of-zip",
                        {"content-type": "application/zip"}, 99999)})
    assert [f.key for f in findings] == ["wallet_archive_exposed"]
    findings = run_probe_plugin("cp_wallet_archive_file", {
        "/wallet.zip": (200, "<html>spa</html>",
                        {"content-type": "text/html"}, 99999)})
    assert findings == []


def test_dir_listing_probe():
    body = ('<a href="wallet.dat">wallet.dat</a> '
            '<a href="UTC--2024-01-01T00-00-00.000Z--aabbcc">k</a> '
            '<a href="notes.txt">notes.txt</a>')
    findings = run_probe_plugin("cp_wallet_dir_listing", {
        "/backup/": (200, body, {}, len(body))})
    assert [f.key for f in findings] == ["wallet_files_in_listing"]


@pytest.mark.parametrize("pid", PROBE_PIDS)
def test_probe_plugins_empty_surface(pid):
    assert run_probe_plugin(pid, {}) == []


# ---------------------------------------------------------------------------
# Fetch-based plugins: served .git, served docs, source maps
# ---------------------------------------------------------------------------

def make_fetch_ctx(routes):
    """routes: url suffix -> (status, text)."""
    ctx = Ctx(run_id="pack2-fetch", mode="passive", http=None,
              cache=Cache(), keys={})

    async def fetch_page(url, timeout=10):
        for suffix, (status, text) in routes.items():
            if url.endswith(suffix):
                return PageData({"status_code": status, "headers": {},
                                 "text": text, "url": url})
        return PageData({"status_code": 404, "headers": {}, "text": "",
                         "url": url})
    ctx.fetch_page = fetch_page
    return ctx


def run_fetch_plugin(pid, routes):
    plugin = PACK[pid]()
    ctx = make_fetch_ctx(routes)
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = asyncio.run(plugin.run(target, ctx))
    status = result.status
    if isinstance(status, PluginStatus):
        status = status.value
    assert status in ("ok", "skipped", "degraded"), (pid, status)
    return result.findings


def test_git_served_wallet_refs():
    reflog = ("0" * 40 + " " + "1" * 40 +
              " dev <d@x> 1700000000 +0000\tcommit: add wallet.dat "
              "and seed backup\n")
    findings = run_fetch_plugin("cp_wallet_git_served",
                                {"/.git/logs/HEAD": (200, reflog)})
    assert [f.key for f in findings] == ["git_history_wallet_refs"]
    # a reflog with no wallet material: silent
    clean = ("0" * 40 + " " + "1" * 40 +
             " dev <d@x> 1700000000 +0000\tcommit: fix readme\n")
    assert run_fetch_plugin("cp_wallet_git_served",
                            {"/.git/logs/HEAD": (200, clean)}) == []
    # wallet words in non-reflog text at the path: silent (format gate)
    assert run_fetch_plugin(
        "cp_wallet_git_served",
        {"/.git/logs/HEAD": (200, "wallet.dat seed keystore")}) == []


def test_served_docs_addresses():
    readme = "# Project\nDonate BTC: " + GENESIS + "\n"
    findings = run_fetch_plugin("cp_wallet_served_docs",
                                {"/README.md": (200, readme)})
    assert [f.key for f in findings] == ["served_doc_address"]
    # broken-checksum address in a doc: silent
    bad = "# Project\nDonate BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb\n"
    assert run_fetch_plugin("cp_wallet_served_docs",
                            {"/README.md": (200, bad)}) == []


def test_sourcemap_findings():
    phrase = bip39_phrase()
    map_doc = json.dumps({
        "version": 3,
        "sources": ["config.js"],
        "sourcesContent": ["// backup phrase: " + phrase],
    })
    js = "console.log(1);\n//# sourceMappingURL=app.js.map"
    html = ('<html><head><script src="/app.js"></script></head>'
            "<body>x</body></html>")
    ctx = Ctx(run_id="pack2-sm", mode="passive", http=None,
              cache=Cache(), keys={})

    async def fetch_page(url, timeout=10):
        if url.endswith(".map"):
            return PageData({"status_code": 200, "headers": {},
                             "text": map_doc, "url": url})
        if url.endswith(".js"):
            return PageData({"status_code": 200, "headers": {},
                             "text": js, "url": url})
        return PageData({"status_code": 200, "headers": {},
                         "text": html, "url": f"https://{DOMAIN}/"})
    ctx.fetch_page = fetch_page
    plugin = PACK["cp_wallet_sourcemap"]()
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = asyncio.run(plugin.run(target, ctx))
    keys = [f.key for f in result.findings]
    assert "sourcemap_seed_phrase" in keys, keys
    # the raw phrase must never appear in a finding value
    assert phrase not in " ".join(f.value for f in result.findings)


def test_fetch_plugins_clean():
    for pid in ("cp_wallet_git_served", "cp_wallet_served_docs",
                "cp_wallet_sourcemap"):
        assert run_fetch_plugin(pid, {}) == [], pid
