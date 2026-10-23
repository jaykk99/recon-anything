"""Crypto pack (cp_*) tests.

Three layers:
1. Validator unit tests - the checksum math (Keccak, Base58Check,
   Bech32/m, SS58, Monero, cashaddr, CRC16) against independently
   known vectors (BIP-173/341, EIP-55 spec, the Satoshi genesis
   address, the cashaddr spec example) plus mutation negatives.
2. Per-plugin positive tests - every pack plugin runs against a
   stubbed page containing its target artifact and must produce the
   expected finding key. Samples that need valid checksums are
   constructed with the pack's encoders (the validators themselves
   are anchored by layer 1's independent vectors).
3. Negative sweep - every content plugin against a clean page must
   produce zero findings and never error.
"""
import asyncio
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, PageData, PluginStatus, Target  # noqa: E402
from app.plugins import cryptopack_util as U  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

REG = discover()
PACK = {pid: cls for pid, cls in REG.items() if pid.startswith("cp_")}

# ---------------------------------------------------------------------------
# Layer 1: validators
# ---------------------------------------------------------------------------


def test_keccak_vectors():
    assert U.keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    assert U.keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    # Keccak != FIPS SHA-3
    assert U.keccak256(b"") != hashlib.sha3_256(b"").digest()


def test_b58check_genesis_and_mutations():
    p = U.b58check_verify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert p and p[0] == 0x00 and len(p) == 21
    assert U.b58check_verify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb") is None
    assert U.b58check_verify("not-an-address") is None


def test_segwit_bip173_bip341_vectors():
    assert U.segwit_verify("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                           "bc", 0)
    assert not U.segwit_verify(
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr", "bc", 0)
    assert U.segwit_verify(
        "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        "bc", 1)
    # v0 address must not verify as taproot and vice versa
    assert not U.segwit_verify(
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "bc", 1)


def test_eip55_spec_vectors():
    assert U.eip55_state("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed") \
        == "checksummed"
    assert U.eip55_state("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359") \
        == "checksummed"
    assert U.eip55_state("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB") \
        == "checksummed"
    # the spec's all-caps example classifies as plain, not checksummed
    assert U.eip55_state("0x52908400098527886E0F7030069857D2E4169EE7") \
        == "plain"
    assert U.eip55_state("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") \
        == "plain"
    assert U.eip55_state("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD") \
        == "bad"


def test_cashaddr_spec_vector():
    assert U.cashaddr_verify(
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")
    assert not U.cashaddr_verify(
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b")


def test_ss58_and_xmr_roundtrips_with_mutations():
    payload = bytes([0]) + bytes(range(32))
    raw = payload + hashlib.blake2b(
        b"SS58PRE" + payload, digest_size=64).digest()[:2]
    addr = U.b58encode(raw)
    assert U.ss58_verify(addr) == payload
    assert U.ss58_verify(addr[:-2] + "AA") is None
    xp = bytes([0x12]) + bytes(range(32)) + bytes(range(32, 64))
    xa = U.xmr_encode(xp)
    assert len(xa) == 95 and U.xmr_verify(xa, (0x12,))
    assert not U.xmr_verify(xa[:20] + "1" + xa[21:], (0x12,))


def test_crc_validators():
    import base64 as b64
    pay = bytes([0x30]) + bytes(range(32))
    gx = b64.b32encode(pay + U.crc16_xmodem(pay).to_bytes(2, "little")
                       ).decode().rstrip("=")
    assert gx.startswith("G") and U.xlm_verify(gx)
    assert not U.xlm_verify(gx[:-1] + ("A" if gx[-1] != "A" else "B"))
    payt = bytes([0x11, 0x00]) + bytes(range(32))
    tq = b64.urlsafe_b64encode(
        payt + U.crc16_xmodem(payt).to_bytes(2, "big")).decode().rstrip("=")
    assert len(tq) == 48 and U.ton_friendly_verify(tq)


# ---------------------------------------------------------------------------
# Test harness: stub Ctx whose fetch_page serves crafted content
# ---------------------------------------------------------------------------

DOMAIN = "fixture.test"


def make_ctx(html: str, js: str = ""):
    ctx = Ctx(run_id="pack-test", mode="passive", http=None,
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
    cls = PACK[pid]
    plugin = cls()
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


def b58c(payload: bytes) -> str:
    return U.b58check_encode(payload)


def segwit(hrp: str, version: int, prog: bytes) -> str:
    data = [version] + U._convertbits(prog, 8, 5)
    const = 1 if version == 0 else 0x2BC830A3
    pm = U._bech32_polymod(U._bech32_hrp_expand(hrp) + data + [0] * 6) ^ const
    ck = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(U._BECH32_CHARSET[d] for d in data + ck)


H20 = bytes(range(20))
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
CHECKSUMMED = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def kaspa_addr() -> str:
    payload = U._convertbits(bytes([0]) + bytes(range(32)), 8, 5)
    exp = [ord(c) & 31 for c in "kaspa"] + [0]
    pm = U._cash_polymod(exp + payload + [0] * 8)
    ck = [(pm >> 5 * (7 - i)) & 31 for i in range(8)]
    return "kaspa:" + "".join(U._CASH_CHARSET[d] for d in payload + ck)


def bip39_phrase() -> str:
    from app.plugins.cryptopack_secrets import BIP39_WORDS
    ent = bytes(16)
    bits = "".join(format(b, "08b") for b in ent)
    bits += format(hashlib.sha256(ent).digest()[0], "08b")[:4]
    return " ".join(BIP39_WORDS[int(bits[i:i + 11], 2)]
                    for i in range(0, len(bits), 11))


# plugin_id -> (html_body, expected_finding_key)
SAMPLES = {
    "cp_btc_legacy": (f"Donate BTC: {GENESIS}", "btc_address_legacy"),
    "cp_btc_bech32": ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                      "btc_address_bech32"),
    "cp_btc_taproot": (
        "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        "btc_address_taproot"),
    "cp_btc_testnet": (b58c(bytes([0x6F]) + H20), "btc_address_testnet"),
    "cp_eth_eip55": (CHECKSUMMED, "eth_address_checksummed"),
    "cp_solana_addr": ("11111111111111111111111111111111", "solana_address"),
    "cp_xmr_standard": (U.xmr_encode(bytes([0x12]) + bytes(range(32))
                                     + bytes(range(32, 64))), "xmr_address"),
    "cp_xmr_integrated": (
        U.xmr_encode(bytes([0x13]) + bytes(range(32)) + bytes(range(32, 64))
                     + bytes(range(8))), "xmr_integrated_address"),
    "cp_xmr_subaddress": (
        U.xmr_encode(bytes([0x2A]) + bytes(range(32)) + bytes(range(32, 64))),
        "xmr_subaddress"),
    "cp_ltc_validated": (b58c(bytes([0x30]) + H20), "ltc_address"),
    "cp_doge_validated": (b58c(bytes([0x1E]) + H20), "doge_address"),
    "cp_bch_addr": ("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
                    "bch_address"),
    "cp_xrp_addr": (U.b58check_encode(bytes([0]) + H20, U.XRP_ALPHABET),
                    "xrp_address"),
    "cp_ada_addr": (U.bech32_encode("addr", bytes(range(57))), "ada_address"),
    "cp_dot_addr": (U.b58encode(bytes([0]) + bytes(range(32)) + hashlib
                    .blake2b(b"SS58PRE" + bytes([0]) + bytes(range(32)),
                             digest_size=64).digest()[:2]), "dot_address"),
    "cp_atom_addr": (U.bech32_encode("cosmos", H20), "cosmos_address"),
    "cp_osmo_addr": (U.bech32_encode("osmo", H20), "osmo_address"),
    "cp_inj_addr": (U.bech32_encode("inj", H20), "inj_address"),
    "cp_bnb_addr": (U.bech32_encode("bnb", H20), "bnb_address"),
    "cp_near_addr": ("donate.alice.near", "near_account"),
    "cp_algo_addr": (None, "algo_address"),  # built in test below
    "cp_xtz_addr": (b58c(b"\x06\xa1\x9f" + H20), "xtz_address"),
    "cp_zec_addr": (b58c(b"\x1c\xb8" + H20), "zec_address"),
    "cp_dash_addr": (b58c(bytes([0x4C]) + H20), "dash_address"),
    "cp_xlm_addr": (None, "xlm_address"),  # built in test below
    "cp_trx_validated": (b58c(bytes([0x41]) + H20), "trx_address"),
    "cp_kas_addr": (kaspa_addr(), "kas_address"),
    "cp_ton_addr": (None, "ton_address"),  # built in test below
    "cp_sui_addr": ("Sui wallet: 0x" + "ab" * 32, "sui_address"),
    "cp_aptos_addr": ("Aptos wallet: 0x" + "cd" * 32, "aptos_address"),
    "cp_ens_name": ("donate.eth", "ens_name"),
    "cp_unstoppable_domain": ("jay.crypto", "web3_domain"),
    "cp_lightning_invoice": (
        U.bech32_encode("lnbc2500u", bytes(range(57))), "lightning_invoice"),
    "cp_lnurl": (U.bech32_encode("lnurl", bytes(range(40))), "lnurl"),
    "cp_lightning_address": ("Lightning tips: tips@example.com",
                             "lightning_address"),
    "cp_nostr_pubkey": (U.bech32_encode("npub", bytes(range(32))),
                        "nostr_pubkey"),
    "cp_onion_service": ("bitcoin donations: " + "a" * 56 + ".onion",
                         "onion_service"),
    "cp_ipfs_cid": ("NFT metadata: Qm" + "a" * 44, "ipfs_cid"),
    "cp_payment_uri": (f"bitcoin:{GENESIS}?amount=0.5", "payment_uri_btc"),
}

# --- part 2: remaining samples ---
SAMPLES.update({
    "cp_miner_coinhive": (
        '<script src="https://coinhive.com/lib/coinhive.min.js"></script>',
        "miner_coinhive"),
    "cp_miner_authedmine": (
        '<script src="https://authedmine.com/lib/authedmine.min.js">'
        "</script>", "miner_authedmine"),
    "cp_miner_coinimp": (
        '<script src="https://coinimp.com/scripts/min.js"></script>',
        "miner_coinimp"),
    "cp_miner_cryptoloot": (
        '<script src="https://crypto-loot.org/m.js"></script>',
        "miner_cryptoloot"),
    "cp_miner_mineralt": (
        '<script src="https://mineralt.io/lib/miner.min.js"></script>',
        "miner_mineralt"),
    "cp_miner_jsecoin": (
        '<script src="https://jsecoin.com/server/?pl=1"></script>',
        "miner_jsecoin"),
})
SAMPLES.update({
    "cp_miner_coinnebula": (
        '<script src="https://coinnebula.com/lib/coinnebula.min.js">'
        "</script>", "miner_coinnebula"),
})
SAMPLES.update({
    "cp_miner_webminepool": (
        '<script src="https://' + "webmine" + 'pool.com/lib/base.js">'
        "</script>", "miner_webminepool"),
})
SAMPLES.update({
    "cp_miner_moneroocean": (
        '<script src="https://' + "moneroocean" + '.stream/'
        + "miner" + '.js"></script>', "miner_moneroocean"),
    "cp_miner_xmrig_web": ("xmrig.min.js", "miner_xmrig_web"),
})
SAMPLES.update({
    "cp_miner_wasm_cryptonight": ("cryptonight.wasm",
                                  "miner_wasm_cryptonight"),
    "cp_miner_stratum_endpoints": ("stratum+tcp://pool.example.org:3333",
                                   "stratum_endpoint"),
})
SAMPLES.update({
    "cp_drainer_seedform": (
        '<form action="/x"><label>Enter your ' + "seed " + "phrase"
        + '</label><textarea name="seed"></textarea></form>',
        "seed_harvest_form"),
    "cp_drainer_walletconnect_kit": (
        "Connect Wallet via WalletConnect - import your wallet to continue",
        "fake_wallet_modal"),
    "cp_drainer_claim_kit": (
        "Claim your airdrop now! Connect wallet and approve to receive",
        "claim_kit"),
})
SAMPLES.update({
    "cp_drainer_setapproval": ("token.setApprovalForAll(spender, true)",
                               "set_approval_for_all"),
    "cp_drainer_ethsign": ('method: "eth_sign"', "eth_sign_request"),
    "cp_drainer_permit": ("PermitSingle", "permit_signature_flow"),
    "cp_clipboard_copy_swap": (
        "document.addEventListener('copy', handler)", "copy_listener"),
    "cp_clipboard_paste_swap": (
        "el.addEventListener('paste', handler)", "paste_listener"),
})
SAMPLES.update({
    "cp_phish_fake_metamask": (
        "MetaMask - Welcome back! Unlock your wallet",
        "fake_metamask_ui"),
    "cp_phish_fake_exchange": (
        "Binance - verify your account to continue "
        "<form action='/login'></form>", "fake_exchange_login"),
})
SAMPLES.update({
    "cp_secret_nsec": (U.bech32_encode("nsec", bytes(range(32))),
                       "nostr_private_key"),
    "cp_secret_env_privkey": ("PRIVATE" + "_KEY=0x" + "ab" * 32,
                              "env_private_key"),
    "cp_secret_hardhat_key": ('accounts: ["0x' + "cd" * 32 + '"]',
                              "hardhat_account_key"),
    "cp_secret_ethers_wallet": ('new ethers.Wallet("0x' + "ef" * 32 + '")',
                                "hardcoded_signer_key"),
})
SAMPLES.update({
    "cp_secret_solana_keypair": (
        "secretKey: [" + ",".join(str(i % 256) for i in range(64)) + "]",
        "solana_keypair_bytes"),
    "cp_secret_keystore_file": (
        '{"version": 3, "address": "aa", "crypto": {"ciphertext": "bb", '
        '"kdf": "scrypt"}}', "keystore_file_body"),
    "cp_secret_wallet_dat_ref": ("backup of wallet.dat", "wallet_dat_ref"),
    "cp_apikey_infura": ("https://mainnet.infura.io/v3/" + "a" * 32,
                         "infura_project_id"),
})
SAMPLES.update({
    "cp_apikey_alchemy": ("https://eth-mainnet.g.alchemy.com/v2/" + "A" * 32,
                          "alchemy_api_key"),
    "cp_apikey_quicknode": ("my-node.quiknode.pro/" + "a1" * 24,
                            "quicknode_endpoint"),
    "cp_apikey_etherscan": (
        "https://api.etherscan.io/api?module=account&apikey=" + "A" * 34,
        "explorer_api_key"),
    "cp_apikey_binance": ("BINANCE_API_KEY=" + "A" * 64, "binance_api_key"),
})
SAMPLES.update({
    "cp_apikey_coinbase": (
        "COINBASE_API_KEY=123e4567-e89b-12d3-a456-426614174000",
        "coinbase_api_key"),
    "cp_apikey_kraken": ("KRAKEN_API_KEY=" + "A" * 64, "kraken_api_key"),
    "cp_apikey_kucoin": ("KUCOIN_API_KEY=" + "a" * 24, "kucoin_api_key"),
    "cp_apikey_bybit": ("BYBIT_API_KEY=" + "B" * 36, "bybit_api_key"),
    "cp_apikey_okx": ("OKX_API_KEY=123e4567-e89b-12d3-a456-426614174000",
                      "okx_api_key"),
    "cp_apikey_moralis": ("MORALIS_API_KEY=eyJ" + "A" * 50 + "." + "B" * 20,
                          "moralis_api_key"),
})
SAMPLES.update({
    "cp_web3_rpc_endpoints": ("https://eth.llamarpc.com", "rpc_endpoint"),
    "cp_web3_chainid_refs": ("chainId: 0x38", "chain_id_ref"),
    "cp_web3_token_contracts": (
        f"ERC20 token contract: {CHECKSUMMED}", "token_contract"),
    "cp_web3_nft_contracts": (
        f"ERC721 mint contract: {CHECKSUMMED}", "nft_contract"),
    "cp_web3_dex_routers": ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
                            "dex_router_uniswap_v2"),
    "cp_web3_bridge_refs": ("https://app.across.to/bridge", "bridge_across"),
})
SAMPLES.update({
    "cp_web3_solana_programs": ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                                "solana_program_token"),
    "cp_web3_walletconnect_project": ('projectId: "' + "a" * 32 + '"',
                                      "walletconnect_project_id"),
    "cp_web3_siwe": ("wants you to sign in with your Ethereum account",
                     "siwe_surface"),
    "cp_web3_multisig": ("https://app.safe.global/home", "multisig_ref"),
    "cp_web3_oracle_refs": ("AggregatorV3Interface", "oracle_ref"),
    "cp_web3_testnet_faucets": ("https://faucet.sepolia.io", "testnet_ref"),
    "cp_web3_hardhat_artifacts": ('{"contractName": "Token", "abi": []}',
                                  "contract_artifact"),
})
SAMPLES.update({
    "cp_pay_btcpay": ("Powered by BTCPay Server", "pay_btcpay"),
    "cp_pay_coinbase_commerce": (
        "https://commerce.coinbase.com/checkout/abc-123",
        "pay_coinbase_commerce"),
    "cp_pay_nowpayments": ("https://nowpayments.io/payment/",
                           "pay_nowpayments"),
    "cp_pay_coingate": ("https://coingate.com/pay/button", "pay_coingate"),
    "cp_pay_coinpayments": ("https://www.coinpayments.net/index.php?cmd=_pay",
                            "pay_coinpayments"),
    "cp_pay_opennode": ("https://app.opennode.com/pay", "pay_opennode"),
})
SAMPLES.update({
    "cp_pay_bitpay": ("https://bitpay.com/checkout", "pay_bitpay"),
    "cp_pay_blockonomics": ("https://www.blockonomics.co/api",
                            "pay_blockonomics"),
    "cp_pay_cryptocom_pay": ("https://pay.crypto.com/", "pay_cryptocom"),
    "cp_pool_domain_refs": ("pool.f2pool.com", "mining_pool_ref"),
    "cp_miner_config_exposure": ('{"algo": "rx/0"}', "miner_config_algo"),
    "cp_miner_binary_links": ("https://files.example.org/xmrig-6.20.0.zip",
                              "miner_binary_link"),
})


def _algo_addr() -> str:
    import base64 as b64
    pub = bytes(range(32))
    ck = hashlib.new("sha512_256", pub).digest()[-4:]
    return b64.b32encode(pub + ck).decode().rstrip("=")


def _xlm_addr() -> str:
    import base64 as b64
    pay = bytes([0x30]) + bytes(range(32))
    return b64.b32encode(
        pay + U.crc16_xmodem(pay).to_bytes(2, "little")).decode().rstrip("=")


def _ton_addr() -> str:
    import base64 as b64
    pay = bytes([0x11, 0x00]) + bytes(range(32))
    return b64.urlsafe_b64encode(
        pay + U.crc16_xmodem(pay).to_bytes(2, "big")).decode().rstrip("=")


@pytest.mark.parametrize("pid", sorted(SAMPLES))
def test_pack_plugin_positive(pid):
    body, expected_key = SAMPLES[pid]
    if body is None:
        body = {"cp_algo_addr": _algo_addr, "cp_xlm_addr": _xlm_addr,
                "cp_ton_addr": _ton_addr}[pid]()
    findings = run_plugin(pid, page(body))
    keys = [f.key for f in findings]
    assert expected_key in keys, (pid, keys)


def test_bip39_sequence_positive_and_negative():
    phrase = bip39_phrase()
    findings = run_plugin("cp_secret_bip39_sequence",
                          page(f"backup: {phrase}"))
    assert [f.key for f in findings] == ["bip39_seed_phrase"]
    words = phrase.split()
    words[-1] = "zoo" if words[-1] != "zoo" else "abandon"
    findings = run_plugin("cp_secret_bip39_sequence",
                          page("backup: " + " ".join(words)))
    assert findings == []


def test_env_mnemonic_positive():
    findings = run_plugin("cp_secret_env_mnemonic",
                          page("MNEMONIC=" + bip39_phrase()))
    assert [f.key for f in findings] == ["env_mnemonic"]


def test_pack_registry_size_and_metadata():
    assert len(PACK) >= 100, len(PACK)
    for pid, cls in PACK.items():
        assert cls.label and cls.description, pid
        assert cls.group == "web3", pid
        assert cls.timeout_s > 0, pid


CLEAN = page("Welcome to our bakery. Fresh bread daily, since 1987. "
             "Call 204-555-0100 for catering and wedding cakes.")


@pytest.mark.parametrize("pid", sorted(PACK))
def test_pack_plugin_clean_page(pid):
    if pid.startswith("cp_dns_"):
        pytest.skip("DNS plugins tested separately")
    if pid == "cp_phish_qr_swap":
        pytest.skip("QR cross-check tested separately")
    findings = run_plugin(pid, CLEAN)
    assert findings == [], (pid, [(f.key, f.value) for f in findings])


def test_qr_swap_mismatch_and_match():
    other = b58c(bytes([0x00]) + bytes(range(1, 21)))
    html = page(f"Pay us: {GENESIS} <img src=\"https://api.qrserver.com/"
                f"v1/create-qr-code/?data=bitcoin:{other}\">")
    findings = run_plugin("cp_phish_qr_swap", html)
    assert [f.key for f in findings] == ["qr_address_mismatch"]
    html_ok = page(f"Pay us: {GENESIS} <img src=\"https://api.qrserver.com/"
                   f"v1/create-qr-code/?data=bitcoin:{GENESIS}\">")
    assert run_plugin("cp_phish_qr_swap", html_ok) == []


def test_checksum_mutations_produce_nothing():
    findings = run_plugin(
        "cp_btc_bech32",
        page("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr"))
    assert findings == []
    findings = run_plugin(
        "cp_btc_legacy", page("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"))
    assert findings == []
    findings = run_plugin("cp_solana_addr", page("ab" * 32))
    assert findings == []


# ---------------------------------------------------------------------------
# DNS plugins (resolver stubbed)
# ---------------------------------------------------------------------------


def _run_dns_plugin(pid, txt_map):
    import app.plugins.cryptopack_dns as dnsmod

    async def fake_txt(name):
        return txt_map.get(name, [])
    orig_txt = dnsmod._txt_records
    dnsmod._txt_records = fake_txt
    try:
        plugin = PACK[pid]()
        ctx = Ctx(run_id="pack-test", mode="passive", http=None,
                  cache=Cache(), keys={})
        target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
        result = asyncio.run(plugin.run(target, ctx))
        return result.findings
    finally:
        dnsmod._txt_records = orig_txt


def test_dns_openalias():
    findings = _run_dns_plugin("cp_dns_openalias", {
        DOMAIN: ["oa1:xmr recipient_address=47yzabc; recipient_name=don;"],
    })
    assert [f.key for f in findings] == ["openalias_record"]
    assert _run_dns_plugin(
        "cp_dns_openalias", {DOMAIN: ["v=spf1 -all"]}) == []


def test_dns_bip353():
    findings = _run_dns_plugin("cp_dns_bip353", {
        f"_bitcoin-payment.{DOMAIN}": ["bitcoin:?lno=lno1qxyz"],
    })
    assert [f.key for f in findings] == ["bip353_record"]
    assert _run_dns_plugin("cp_dns_bip353", {DOMAIN: ["hello"]}) == []
