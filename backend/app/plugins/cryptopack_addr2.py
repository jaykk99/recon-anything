"""Crypto pack wave 2: more chains, more address formats.

Fills wave 1's known gaps (TON raw form, NEAR implicit accounts)
and widens chain coverage: XDC, Hedera, EOSIO keys, more Cosmos
chains (each Bech32 checksum-verified), Handshake, Ergo
(Blake2b checksum), Horizen (two-byte version), segwit forms for
DigiByte/Vertcoin/Viacoin, Kaspa testnet, plus context-anchored
EVM-chain attribution, SPL mints, split ERC-721/1155 inventories,
canonical contract addresses, Ordinals inscriptions and BRC-20.

Deliberately NOT here (checksum collisions would misattribute):
Ravencoin/Komodo legacy (both Base58Check 0x3C), DigiByte/Viacoin
legacy (0x1E / 0x47 collisions), Flux (Zcash parameters). Precision
beats breadth - see the wave-2 notes.
"""
from __future__ import annotations

from .cryptopack_util import (
    PackPlugin, b58check_prefix, b58decode, segwit_verify,
)
from .cryptopack_util2 import (
    avax_verify, bech32_hrp_verify, eos_key_verify, ergo_verify,
    hns_verify, kaspa_testnet_verify, ton_raw_verify, xdc_checksummed,
    xdc_verify,
)

B58 = r"1-9A-HJ-NP-Za-km-z"
B32 = r"qpzry9x8gf2tvdw0s3jn54khce6mua7l"


# ---------------------------------------------------------------------------
# Wave-1 gap fills
# ---------------------------------------------------------------------------

class CpTonRawAddr(PackPlugin):
    id = "cp_ton_raw_addr"
    label = "TON Raw Address (workchain:hash form)"
    description = ("TON raw-form addresses (0:<64 hex> / -1:<64 hex>) "
                   "- the form contracts and explorers use; wave 1 "
                   "only covered the user-friendly base64url form.")
    CONTEXT_RE = r"ton|tonkeeper|toncoin|wallet"
    PATTERNS = [(r"\b(?:-1|0):[0-9a-fA-F]{64}\b", "ton_raw_address",
                 "TON raw address", 85, ton_raw_verify)]


class CpNearImplicitAddr(PackPlugin):
    id = "cp_near_implicit_addr"
    label = "NEAR Implicit Account (64-hex)"
    description = ("NEAR implicit accounts are a bare 64-char "
                   "lowercase hex string (the public key itself) - "
                   "only reported with NEAR context nearby.")
    CONTEXT_RE = r"near"
    VALUE_GROUP = 1
    PATTERNS = [(r"\b([0-9a-f]{64})\b", "near_implicit_account",
                 "NEAR implicit account", 80, None)]


# ---------------------------------------------------------------------------
# New chains with real checksums
# ---------------------------------------------------------------------------

class CpXdcAddr(PackPlugin):
    id = "cp_xdc_addr"
    label = "XDC Network Address (EIP-55 verified)"
    description = ("xdc-prefixed addresses; the hex part carries an "
                   "EIP-55 checksum exactly as if 0x-prefixed.")
    PATTERNS = [
        (r"\bxdc[0-9a-fA-F]{40}\b", "xdc_address_checksummed",
         "XDC address (EIP-55 checksummed)", 88, xdc_checksummed),
        (r"\bxdc(?:[0-9a-f]{40}|[0-9A-F]{40})\b", "xdc_address",
         "XDC address (no checksum case)", 78,
         lambda s: xdc_verify(s) and not xdc_checksummed(s)),
    ]


class CpEosKey(PackPlugin):
    id = "cp_eos_key"
    label = "EOSIO Public Key (RIPEMD-160 verified)"
    description = ("EOSIO account public keys (legacy EOS... and "
                   "PUB_K1_/PUB_R1_ forms) with verified RIPEMD-160 "
                   "checksum - the keys controlling EOSIO accounts "
                   "the target publishes.")
    PATTERNS = [
        (rf"\bPUB_(?:K1|R1)_[{B58}]{{45,55}}\b", "eosio_public_key",
         "EOSIO public key (PUB_K1/R1)", 88, eos_key_verify),
        (rf"\bEOS[{B58}]{{45,53}}\b", "eosio_public_key_legacy",
         "EOSIO public key (legacy EOS)", 85, eos_key_verify),
    ]


class CpErgoAddr(PackPlugin):
    id = "cp_ergo_addr"
    label = "Ergo Address (Blake2b checksum-verified)"
    description = ("Ergo P2PK addresses verified against their "
                   "Blake2b-256 checksum (type byte + compressed key).")
    PATTERNS = [(rf"\b9[{B58}]{{49,52}}\b", "ergo_address",
                 "Ergo address", 88, ergo_verify)]


class CpHnsAddr(PackPlugin):
    id = "cp_hns_addr"
    label = "Handshake Address (Bech32-verified)"
    description = "Handshake (hs1) SegWit-style Bech32 addresses."
    PATTERNS = [(rf"\bhs1q[{B32}]{{38,58}}\b", "hns_address",
                 "Handshake address", 88, lambda s: hns_verify(s))]


class CpZenAddr(PackPlugin):
    id = "cp_zen_addr"
    label = "Horizen Address (checksum-verified)"
    description = ("Horizen transparent addresses (zn...) with "
                   "verified two-byte-version Base58Check checksum.")
    PATTERNS = [(rf"\bzn[{B58}]{{32,34}}\b", "zen_address",
                 "Horizen address", 88,
                 lambda s: b58check_prefix(
                     s, (b"\x20\x89", b"\x20\x92"), 26))]


class CpDgbAddr(PackPlugin):
    id = "cp_dgb_addr"
    label = "DigiByte SegWit Address (BIP-173 verified)"
    description = ("dgb1 native SegWit addresses. (DigiByte legacy "
                   "Base58Check shares Dogecoin's 0x1E version byte, "
                   "so legacy forms are not attributed.)")
    PATTERNS = [(rf"\bdgb1q[{B32}]{{38,58}}\b", "dgb_address",
                 "DigiByte SegWit address", 88,
                 lambda s: segwit_verify(s, "dgb", 0))]


class CpVtcAddr(PackPlugin):
    id = "cp_vtc_addr"
    label = "Vertcoin SegWit Address (BIP-173 verified)"
    description = "vtc1 native SegWit addresses, checksum-verified."
    PATTERNS = [(rf"\bvtc1q[{B32}]{{38,58}}\b", "vtc_address",
                 "Vertcoin SegWit address", 88,
                 lambda s: segwit_verify(s, "vtc", 0))]


class CpViaAddr(PackPlugin):
    id = "cp_via_addr"
    label = "Viacoin SegWit Address (BIP-173 verified)"
    description = ("via1 native SegWit addresses. (Viacoin legacy "
                   "shares Vertcoin's 0x47 version byte, so legacy "
                   "forms are not attributed.)")
    PATTERNS = [(rf"\bvia1q[{B32}]{{38,58}}\b", "via_address",
                 "Viacoin SegWit address", 88,
                 lambda s: segwit_verify(s, "via", 0))]


class CpKasTestnetAddr(PackPlugin):
    id = "cp_kas_testnet_addr"
    label = "Kaspa Testnet Address (checksum-verified)"
    description = ("kaspatest: addresses on a production site - a "
                   "test/prod mixup signal, like BTC testnet in wave 1.")
    PATTERNS = [(rf"\bkaspatest:[{B32}]{{55,70}}\b",
                 "kas_testnet_address", "Kaspa testnet address", 80,
                 kaspa_testnet_verify)]


# ---------------------------------------------------------------------------
# Cosmos family expansion (Bech32 factory, as in wave 1)
# ---------------------------------------------------------------------------

def _cosmos2(hrp, coin):
    return [(rf"\b{hrp}1[{B32}]{{38,58}}\b", f"{hrp}_address",
             f"{coin} address", 88,
             lambda s: bech32_hrp_verify(s, hrp))]


def _cosmos_cls(id_, hrp, coin):
    return type(id_, (PackPlugin,), {
        "id": id_,
        "label": f"{coin} Address (Bech32-verified)",
        "description": f"{hrp}1 Bech32 addresses with verified checksum.",
        "__module__": __name__,
        "PATTERNS": _cosmos2(hrp, coin),
    })


CpStarsAddr = _cosmos_cls("cp_stars_addr", "stars", "Stargaze (STARS)")
CpJunoAddr = _cosmos_cls("cp_juno_addr", "juno", "Juno (JUNO)")
CpCroAddr = _cosmos_cls("cp_cro_addr", "cro", "Crypto.org Chain (CRO)")
CpKavaAddr = _cosmos_cls("cp_kava_addr", "kava", "Kava (KAVA)")
CpEvmosAddr = _cosmos_cls("cp_evmos_addr", "evmos", "Evmos (EVMOS)")
CpSecretAddr = _cosmos_cls("cp_secret_addr", "secret",
                           "Secret Network (SCRT)")
CpAkashAddr = _cosmos_cls("cp_akash_addr", "akash", "Akash (AKT)")
CpTerraAddr = _cosmos_cls("cp_terra_addr", "terra", "Terra (LUNA)")
CpKujiAddr = _cosmos_cls("cp_kuji_addr", "kuji", "Kujira (KUJI)")
CpPersistenceAddr = _cosmos_cls("cp_persistence_addr", "persistence",
                                "Persistence (XPRT)")
CpStrideAddr = _cosmos_cls("cp_stride_addr", "stride", "Stride (STRD)")
CpFetchAddr = _cosmos_cls("cp_fetch_addr", "fetch", "Fetch.ai (FET)")
CpSeiAddr = _cosmos_cls("cp_sei_addr", "sei", "Sei (SEI)")


class CpAvaxAddr(PackPlugin):
    id = "cp_avax_addr"
    label = "Avalanche X-Chain Address (Bech32-verified)"
    description = "avax1 Bech32 addresses with verified checksum."
    PATTERNS = [(rf"\bavax1[{B32}]{{38,58}}\b", "avax_address",
                 "Avalanche X-Chain address", 88, avax_verify)]


# ---------------------------------------------------------------------------
# Context-anchored formats (the raw shape is shared; context decides)
# ---------------------------------------------------------------------------

def _evm_ctx(id_, chain, ctx_re):
    return type(id_, (PackPlugin,), {
        "id": id_,
        "label": f"{chain} Address (context-anchored)",
        "description": (f"0x addresses anchored to {chain} context - "
                        "the EVM address shape is shared across chains, "
                        "so attribution comes from the surrounding text."),
        "__module__": __name__,
        "CONTEXT_RE": ctx_re,
        "VALUE_GROUP": 1,
        "PATTERNS": [(r"(0x[0-9a-fA-F]{40})", f"{id_[3:]}",
                      f"{chain} address", 78, None)],
    })


CpVetAddr = _evm_ctx("cp_vet_addr", "VeChain (VET)", r"vechain|\bvet\b|thor")
CpFtmAddr = _evm_ctx("cp_ftm_addr", "Fantom (FTM)", r"fantom|opera chain|\bftm\b")
CpCeloAddr = _evm_ctx("cp_celo_addr", "Celo (CELO)", r"celo")


class CpHbarAddr(PackPlugin):
    id = "cp_hbar_addr"
    label = "Hedera Account ID (context-anchored)"
    description = ("Hedera account IDs (0.0.NNNN) - the dotted form "
                   "is only reported with Hedera/HBAR context nearby.")
    CONTEXT_RE = r"hedera|hbar|hashgraph"
    VALUE_GROUP = 1
    PATTERNS = [(r"\b(0\.0\.\d{2,10})\b", "hbar_account",
                 "Hedera account ID", 78, None)]


class CpSplMint(PackPlugin):
    id = "cp_spl_mint"
    label = "SPL Token Mint (context-anchored, 32-byte verified)"
    description = ("Solana addresses anchored to mint/SPL-token "
                   "context - the token mints the target works with, "
                   "as opposed to arbitrary wallets.")
    CONTEXT_RE = r"mint|spl[ \-]?token|token mint"
    PATTERNS = [(rf"\b[{B58}]{{32,44}}\b", "spl_token_mint",
                 "SPL token mint", 85,
                 lambda s: (lambda raw: bool(raw) and len(raw) == 32)(
                     b58decode(s)))]


# ---------------------------------------------------------------------------
# Contract inventories, wave 2
# ---------------------------------------------------------------------------

class CpErc721Contracts(PackPlugin):
    id = "cp_erc721_contracts"
    label = "ERC-721 Contract Inventory"
    description = ("Contract addresses anchored specifically to "
                   "ERC-721 context (wave 1 lumped 721/1155 together).")
    CONTEXT_RE = r"erc721|erc-721"
    VALUE_GROUP = 1
    PATTERNS = [(r"(0x[0-9a-fA-F]{40})", "erc721_contract",
                 "ERC-721 contract address", 78, None)]


class CpErc1155Contracts(PackPlugin):
    id = "cp_erc1155_contracts"
    label = "ERC-1155 Contract Inventory"
    description = "Contract addresses anchored specifically to ERC-1155 context."
    CONTEXT_RE = r"erc1155|erc-1155"
    VALUE_GROUP = 1
    PATTERNS = [(r"(0x[0-9a-fA-F]{40})", "erc1155_contract",
                 "ERC-1155 contract address", 78, None)]


class CpWeb3CanonicalContracts(PackPlugin):
    id = "cp_web3_canonical_contracts"
    label = "Canonical Contract References (WETH, stablecoins, Permit2)"
    description = ("The canonical mainnet contracts every Web3 "
                   "security review checks for: WETH, the big "
                   "stablecoins, the Beacon deposit contract, "
                   "Permit2, Seaport, the ENS registry.")
    PATTERNS = [
        (r"\b0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\b",
         "contract_weth", "WETH contract", 85, None),
        (r"\b0xdAC17F958D2ee523a2206206994597C13D831ec7\b",
         "contract_usdt", "USDT contract", 85, None),
        (r"\b0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\b",
         "contract_usdc", "USDC contract", 85, None),
        (r"\b0x6B175474E89094C44Da98b954EedeAC495271d0F\b",
         "contract_dai", "DAI contract", 85, None),
        (r"\b0x00000000219ab540356cBB839Cbe05303d7705Fa\b",
         "contract_beacon_deposit", "Beacon Chain deposit contract",
         85, None),
        (r"\b0x000000000022D473030F116dDEE9F6B43aC78BA3\b",
         "contract_permit2", "Permit2 contract", 88, None),
        (r"\b0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC\b",
         "contract_seaport", "OpenSea Seaport contract", 85, None),
        (r"\b0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e\b",
         "contract_ens_registry", "ENS registry contract", 85, None),
        (r"\b0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD\b",
         "contract_universal_router", "Uniswap Universal Router",
         85, None),
    ]


# ---------------------------------------------------------------------------
# Ordinals / BRC-20
# ---------------------------------------------------------------------------

class CpOrdinalsInscriptions(PackPlugin):
    id = "cp_ordinals_inscriptions"
    label = "Ordinals Inscription References"
    description = ("Bitcoin Ordinals inscription IDs (<txid>i<n>) "
                   "and explorer links the target publishes.")
    PATTERNS = [
        (r"\b[0-9a-f]{64}i\d{1,7}\b", "ordinals_inscription_id",
         "Ordinals inscription ID", 85, None),
        (r"(?:ordinals\.com/inscription/|ord\.io/inscription/)",
         "ordinals_inscription_link", "Ordinals inscription link",
         80, None),
    ]


class CpBrc20Refs(PackPlugin):
    id = "cp_brc20_refs"
    label = "BRC-20 Token References"
    description = ("BRC-20 deploy/mint/transfer JSON blobs and "
                   "ticker references in the target's content.")
    PATTERNS = [
        (r"\{\s*\"p\"\s*:\s*\"brc-20\"\s*,\s*\"op\"\s*:\s*\""
         r"(?:deploy|mint|transfer)\"[^}]{0,120}\}",
         "brc20_operation_blob", "BRC-20 operation blob", 88, None),
        (r"\"tick\"\s*:\s*\"[a-z0-9]{4}\"", "brc20_ticker",
         "BRC-20 ticker reference", 65, None),
    ]
    CONTEXT_RE = r"brc-20|brc20|ordinals"
