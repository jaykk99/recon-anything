"""Crypto pack: validated per-chain address detectors.

The pre-existing `crypto` plugin regex-matches a handful of chains at
confidence ~70 with no checksum verification, so lookalike strings
(txids, hashes, random base58) flood its results. Each plugin here
detects ONE chain/format and only reports strings whose checksum
actually verifies (Base58Check, Bech32/Bech32m, SS58, Monero block
Base58 + Keccak, cashaddr, CRC16), which is the difference between
"might be an address" and "is an address" when pivoting on a target's
published wallets. Detection only - addresses are public data the
target itself serves.
"""
from __future__ import annotations

from .cryptopack_util import (
    PackPlugin, algo_verify, b58check_prefix, b58check_verify, b58decode,
    bech32_payload, cashaddr_verify, eip55_state, kaspa_verify,
    segwit_verify, ss58_verify, ton_friendly_verify, xlm_verify,
    xmr_verify, XRP_ALPHABET,
)

B58 = r"1-9A-HJ-NP-Za-km-z"
B32 = r"qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _v_b58(s, versions, ln=21):
    p = b58check_verify(s)
    return bool(p) and len(p) == ln and p[0] in versions


class CpBtcLegacy(PackPlugin):
    id = "cp_btc_legacy"
    label = "Bitcoin Legacy Address (checksum-verified)"
    description = ("Base58Check-verified Bitcoin P2PKH/P2SH addresses "
                   "(1.../3...) published by the target.")
    PATTERNS = [(rf"\b[13][{B58}]{{25,34}}\b", "btc_address_legacy",
                 "Bitcoin legacy address", 90,
                 lambda s: _v_b58(s, (0x00, 0x05)))]


class CpBtcBech32(PackPlugin):
    id = "cp_btc_bech32"
    label = "Bitcoin SegWit Address (BIP-173 verified)"
    description = "Bech32 checksum-verified native SegWit (bc1q) addresses."
    PATTERNS = [(rf"\bbc1q[{B32}]{{38,58}}\b", "btc_address_bech32",
                 "Bitcoin SegWit address", 92,
                 lambda s: segwit_verify(s, "bc", 0))]


class CpBtcTaproot(PackPlugin):
    id = "cp_btc_taproot"
    label = "Bitcoin Taproot Address (BIP-350 verified)"
    description = "Bech32m checksum-verified Taproot (bc1p) addresses."
    PATTERNS = [(rf"\bbc1p[{B32}]{{58}}\b", "btc_address_taproot",
                 "Bitcoin Taproot address", 92,
                 lambda s: segwit_verify(s, "bc", 1))]


class CpBtcTestnet(PackPlugin):
    id = "cp_btc_testnet"
    label = "Bitcoin Testnet Address"
    description = ("Testnet addresses (tb1/m/n/2) on a production site: "
                   "a test/prod mixup signal worth flagging.")
    PATTERNS = [
        (rf"\btb1[qp][{B32}]{{38,58}}\b", "btc_address_testnet",
         "Bitcoin testnet SegWit address", 80,
         lambda s: segwit_verify(s, "tb", 0) or segwit_verify(s, "tb", 1)),
        (rf"\b[mn2][{B58}]{{25,34}}\b", "btc_address_testnet",
         "Bitcoin testnet legacy address", 70,
         lambda s: _v_b58(s, (0x6F, 0xC4))),
    ]


class CpEthEip55(PackPlugin):
    id = "cp_eth_eip55"
    label = "Ethereum Address (EIP-55 checksum state)"
    description = ("0x addresses with EIP-55 checksum classification: "
                   "checksummed addresses are reported at high "
                   "confidence; a mixed-case address with a BROKEN "
                   "checksum is likely a typo that burns funds.")
    PATTERNS = [
        (r"\b0x[0-9a-fA-F]{40}\b", "eth_address_checksummed",
         "Ethereum address (EIP-55 checksummed)", 92,
         lambda s: eip55_state(s) == "checksummed"),
        (r"\b0x(?:[0-9a-f]{40}|[0-9A-F]{40})\b", "eth_address",
         "Ethereum address (no checksum case)", 78, None),
        (r"\b0x[0-9a-fA-F]{40}\b", "eth_address_bad_checksum",
         "Ethereum address (INVALID EIP-55 checksum - possible typo)",
         85, lambda s: eip55_state(s) == "bad"),
    ]


class CpSolanaAddr(PackPlugin):
    id = "cp_solana_addr"
    label = "Solana Address (32-byte verified)"
    description = ("Base58 strings that decode to exactly 32 bytes "
                   "(a real Ed25519 public key), not just look Solana-ish.")
    PATTERNS = [(rf"\b[{B58}]{{32,44}}\b", "solana_address",
                 "Solana address", 80,
                 lambda s: (lambda raw: bool(raw) and len(raw) == 32)(
                     b58decode(s)))]


class CpXmrStandard(PackPlugin):
    id = "cp_xmr_standard"
    label = "Monero Standard Address (Keccak-verified)"
    description = "Monero standard addresses with verified Keccak checksum."
    PATTERNS = [(rf"\b4[{B58}]{{94}}\b", "xmr_address",
                 "Monero standard address", 95,
                 lambda s: xmr_verify(s, (0x12, 0x35)))]


class CpXmrIntegrated(PackPlugin):
    id = "cp_xmr_integrated"
    label = "Monero Integrated Address (payment ID embedded)"
    description = ("106-char Monero integrated addresses: they embed a "
                   "payment ID, which usually means exchange/service "
                   "deposit infrastructure.")
    PATTERNS = [(rf"\b4[{B58}]{{105}}\b", "xmr_integrated_address",
                 "Monero integrated address", 95,
                 lambda s: xmr_verify(s, (0x13, 0x36)))]


class CpXmrSubaddress(PackPlugin):
    id = "cp_xmr_subaddress"
    label = "Monero Subaddress (Keccak-verified)"
    description = "Monero subaddresses (per-customer/per-purpose wallets)."
    PATTERNS = [(rf"\b8[{B58}]{{94}}\b", "xmr_subaddress",
                 "Monero subaddress", 95,
                 lambda s: xmr_verify(s, (0x2A, 0x45)))]


class CpLtcValidated(PackPlugin):
    id = "cp_ltc_validated"
    label = "Litecoin Address (checksum-verified)"
    description = "Base58Check (L/M/ltc1) and Bech32-verified Litecoin addresses."
    PATTERNS = [
        (rf"\b[LM][{B58}]{{25,34}}\b", "ltc_address",
         "Litecoin address", 90, lambda s: _v_b58(s, (0x30, 0x32, 0x05))),
        (rf"\bltc1q[{B32}]{{38,58}}\b", "ltc_address",
         "Litecoin SegWit address", 90,
         lambda s: segwit_verify(s, "ltc", 0)),
    ]


class CpDogeValidated(PackPlugin):
    id = "cp_doge_validated"
    label = "Dogecoin Address (checksum-verified)"
    description = "Base58Check-verified Dogecoin addresses (D.../9.../A...)."
    PATTERNS = [(rf"\b[DA9][{B58}]{{25,34}}\b", "doge_address",
                 "Dogecoin address", 88,
                 lambda s: _v_b58(s, (0x1E, 0x16)))]


class CpBchAddr(PackPlugin):
    id = "cp_bch_addr"
    label = "Bitcoin Cash Address (cashaddr-verified)"
    description = "Cashaddr-format BCH addresses with verified polymod checksum."
    PATTERNS = [(rf"\b(?:bitcoincash:)?[qp][{B32}]{{41}}\b", "bch_address",
                 "Bitcoin Cash address", 90, cashaddr_verify)]


class CpXrpAddr(PackPlugin):
    id = "cp_xrp_addr"
    label = "XRP Address (checksum-verified)"
    description = ("XRP addresses verified with the XRP Base58 alphabet "
                   "and double-SHA256 checksum.")
    PATTERNS = [(r"\br[0-9a-zA-Z]{24,34}\b", "xrp_address",
                 "XRP address", 90,
                 lambda s: (lambda p: bool(p) and len(p) == 21
                              and p[0] == 0x00)(
                     b58check_verify(s, XRP_ALPHABET)))]


class CpAdaAddr(PackPlugin):
    id = "cp_ada_addr"
    label = "Cardano Address (Bech32-verified)"
    description = "Shelley-era Cardano addr1/stake1 Bech32 addresses."
    PATTERNS = [
        (rf"\baddr1[{B32}]{{50,110}}\b", "ada_address",
         "Cardano address", 90,
         lambda s: (lambda p: p is not None and len(p) >= 50)(
             bech32_payload(s, "addr"))),
        (rf"\bstake1[{B32}]{{50,110}}\b", "ada_stake_address",
         "Cardano stake address", 90,
         lambda s: (lambda p: p is not None and len(p) >= 50)(
             bech32_payload(s, "stake"))),
    ]


class CpDotAddr(PackPlugin):
    id = "cp_dot_addr"
    label = "Polkadot/Kusama Address (SS58-verified)"
    description = "SS58 addresses with verified Blake2 checksum (formats 0/2)."
    PATTERNS = [(rf"\b[{B58}]{{46,48}}\b", "dot_address",
                 "Polkadot/Kusama SS58 address", 88,
                 lambda s: (lambda p: p is not None and p[0] in (0, 2))(
                     ss58_verify(s)))]


def _cosmos_plugin(hrp, coin):
    def _v(s):
        p = bech32_payload(s, hrp)
        return p is not None and len(p) in (20, 32)
    return [(rf"\b{hrp}1[{B32}]{{38,58}}\b", f"{hrp}_address",
             f"{coin} address", 88, _v)]


class CpAtomAddr(PackPlugin):
    id = "cp_atom_addr"
    label = "Cosmos Hub Address (Bech32-verified)"
    description = "cosmos1 Bech32 addresses with verified checksum."
    PATTERNS = _cosmos_plugin("cosmos", "Cosmos (ATOM)")


class CpOsmoAddr(PackPlugin):
    id = "cp_osmo_addr"
    label = "Osmosis Address (Bech32-verified)"
    description = "osmo1 Bech32 addresses with verified checksum."
    PATTERNS = _cosmos_plugin("osmo", "Osmosis (OSMO)")


class CpInjAddr(PackPlugin):
    id = "cp_inj_addr"
    label = "Injective Address (Bech32-verified)"
    description = "inj1 Bech32 addresses with verified checksum."
    PATTERNS = _cosmos_plugin("inj", "Injective (INJ)")


class CpBnbAddr(PackPlugin):
    id = "cp_bnb_addr"
    label = "BNB Beacon Chain Address (Bech32-verified)"
    description = "bnb1 Bech32 addresses with verified checksum."
    PATTERNS = _cosmos_plugin("bnb", "BNB Beacon Chain")


class CpNearAddr(PackPlugin):
    id = "cp_near_addr"
    label = "NEAR Account ID"
    description = "Named NEAR accounts (*.near / *.testnet) published by the target."
    PATTERNS = [(r"\b[a-z0-9_\-]*(?:\.[a-z0-9_\-]+)*\.(?:near|testnet)\b",
                 "near_account", "NEAR account", 85, None)]


class CpAlgoAddr(PackPlugin):
    id = "cp_algo_addr"
    label = "Algorand Address (checksum-verified)"
    description = "Algorand addresses with verified SHA-512/256 checksum."
    PATTERNS = [(r"\b[A-Z2-7]{58}\b", "algo_address",
                 "Algorand address", 92, algo_verify)]


class CpXtzAddr(PackPlugin):
    id = "cp_xtz_addr"
    label = "Tezos Address (checksum-verified)"
    description = "tz1/tz2/tz3/KT1 addresses with verified Base58Check checksum."
    PATTERNS = [(rf"\b(?:tz[123]|KT1)[{B58}]{{33}}\b", "xtz_address",
                 "Tezos address", 90,
                 lambda s: b58check_prefix(
                     s, (b"\x06\xa1\x9f", b"\x06\xa1\xa1", b"\x06\xa1\xa4",
                         b"\x02\x5a\x79"), 27))]


class CpZecAddr(PackPlugin):
    id = "cp_zec_addr"
    label = "Zcash Transparent Address (checksum-verified)"
    description = "t1/t3 Zcash addresses with verified Base58Check checksum."
    PATTERNS = [(rf"\bt[13][{B58}]{{33}}\b", "zec_address",
                 "Zcash transparent address", 90,
                 lambda s: b58check_prefix(
                     s, (b"\x1c\xb8", b"\x1c\xbd"), 26))]


class CpDashAddr(PackPlugin):
    id = "cp_dash_addr"
    label = "Dash Address (checksum-verified)"
    description = "Base58Check-verified Dash addresses (X.../7...)."
    PATTERNS = [(rf"\b[X7][{B58}]{{25,34}}\b", "dash_address",
                 "Dash address", 85, lambda s: _v_b58(s, (0x4C, 0x10)))]


class CpXlmAddr(PackPlugin):
    id = "cp_xlm_addr"
    label = "Stellar Address (CRC16-verified)"
    description = "Stellar G... account IDs with verified CRC16-XMODEM checksum."
    PATTERNS = [(r"\bG[A-Z2-7]{55}\b", "xlm_address",
                 "Stellar address", 92, xlm_verify)]


class CpTrxValidated(PackPlugin):
    id = "cp_trx_validated"
    label = "Tron Address (checksum-verified)"
    description = "Base58Check-verified Tron addresses (0x41 prefix)."
    PATTERNS = [(rf"\bT[{B58}]{{33}}\b", "trx_address",
                 "Tron address", 90, lambda s: _v_b58(s, (0x41,)))]


class CpKasAddr(PackPlugin):
    id = "cp_kas_addr"
    label = "Kaspa Address (checksum-verified)"
    description = "kaspa: addresses with verified cashaddr-family checksum."
    PATTERNS = [(rf"\bkaspa:[{B32}]{{55,70}}\b", "kas_address",
                 "Kaspa address", 88, kaspa_verify)]


class CpTonAddr(PackPlugin):
    id = "cp_ton_addr"
    label = "TON Address (CRC16-verified)"
    description = "TON user-friendly addresses with verified CRC16 checksum."
    PATTERNS = [(r"\b[UEk0][Qf][A-Za-z0-9_\-]{44,46}\b", "ton_address",
                 "TON address", 85, ton_friendly_verify)]


class CpSuiAddr(PackPlugin):
    id = "cp_sui_addr"
    label = "Sui Address (context-anchored)"
    description = ("0x 64-hex Sui addresses anchored to Sui context "
                   "(generic 0x64 strings alone are just hashes).")
    CONTEXT_RE = r"sui"
    VALUE_GROUP = 1
    PATTERNS = [(r"(0x[0-9a-fA-F]{64})", "sui_address",
                 "Sui address", 80, None)]


class CpAptosAddr(PackPlugin):
    id = "cp_aptos_addr"
    label = "Aptos Address (context-anchored)"
    description = "0x 64-hex Aptos addresses anchored to Aptos context."
    CONTEXT_RE = r"aptos"
    VALUE_GROUP = 1
    PATTERNS = [(r"(0x[0-9a-fA-F]{64})", "aptos_address",
                 "Aptos address", 80, None)]
