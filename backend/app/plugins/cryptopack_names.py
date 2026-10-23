"""Crypto pack: naming systems, payment identifiers, URIs.

ENS / Unstoppable names, Lightning invoices (BOLT11, checksum
verified), LNURL, Nostr public keys, BIP-21 payment URIs, onion
services and IPFS content IDs in crypto context. These are the
join keys between a target's web presence and its crypto footprint.
"""
from __future__ import annotations

import re

from .cryptopack_util import PackPlugin, bech32_decode

B32 = r"qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bolt11(s: str) -> bool:
    dec = bech32_decode(s.lower())
    return bool(dec) and dec[2] == "bech32" and len(dec[1]) >= 80


def _lnurl(s: str) -> bool:
    dec = bech32_decode(s.lower())
    return bool(dec) and dec[0] == "lnurl" and len(dec[1]) >= 40


def _npub(s: str) -> bool:
    dec = bech32_decode(s.lower())
    return bool(dec) and dec[0] == "npub"


class CpEnsName(PackPlugin):
    id = "cp_ens_name"
    label = "ENS Name"
    description = "Ethereum Name Service names (*.eth) published by the target."
    PATTERNS = [(r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.eth\b", "ens_name",
                 "ENS name", 85, None)]


class CpUnstoppableDomain(PackPlugin):
    id = "cp_unstoppable_domain"
    label = "Unstoppable Domains Name"
    description = ("Web3 naming domains (.crypto/.nft/.x/.wallet/"
                   ".bitcoin/.dao/.888/.zil) published by the target.")
    PATTERNS = [(r"\b[a-z0-9\-]+\.(?:crypto|nft|x|wallet|bitcoin|dao|888|zil)\b",
                 "web3_domain", "Unstoppable Domains name", 75, None)]


class CpLightningInvoice(PackPlugin):
    id = "cp_lightning_invoice"
    label = "Lightning Invoice (BOLT11 verified)"
    description = ("BOLT11 Lightning invoices with verified Bech32 "
                   "checksum - live payment requests the target publishes.")
    PATTERNS = [(rf"\bln(?:bc|tb|bcrt)\d*[munp]?1[{B32}]{{60,}}\b",
                 "lightning_invoice", "Lightning BOLT11 invoice", 90,
                 _bolt11)]


class CpLnurl(PackPlugin):
    id = "cp_lnurl"
    label = "LNURL (Bech32-verified)"
    description = "LNURL bech32 strings (Lightning payment/withdraw links)."
    VALUE_GROUP = 1
    PATTERNS = [
        (rf"\b(lnurl1[{B32}]{{60,}})\b", "lnurl", "LNURL", 85, _lnurl),
    ]


class CpLightningAddress(PackPlugin):
    id = "cp_lightning_address"
    label = "Lightning Address"
    description = ("Lightning Addresses (user@domain) - email-shaped, "
                   "so they are only reported in Lightning context.")
    CONTEXT_RE = r"lightning|lnurl|bitcoin|btc"
    VALUE_GROUP = 1
    PATTERNS = [
        (r"\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b",
         "lightning_address", "Lightning Address", 75, None),
    ]


class CpNostrPubkey(PackPlugin):
    id = "cp_nostr_pubkey"
    label = "Nostr Public Key (npub)"
    description = "Nostr npub identifiers (Bech32-verified) published by the target."
    PATTERNS = [(rf"\bnpub1[{B32}]{{58}}\b", "nostr_pubkey",
                 "Nostr public key", 88, _npub)]


class CpOnionService(PackPlugin):
    id = "cp_onion_service"
    label = "Tor Onion Service (crypto context)"
    description = ("v3 onion services referenced near crypto/payment "
                   "keywords - the target's darknet payment/support door.")
    CONTEXT_RE = r"bitcoin|btc|crypto|payment|donat|monero|xmr|wallet"
    VALUE_GROUP = 1
    PATTERNS = [(r"\b([a-z2-7]{56}\.onion)\b", "onion_service",
                 "Tor v3 onion service", 70, None)]


class CpIpfsCid(PackPlugin):
    id = "cp_ipfs_cid"
    label = "IPFS Content ID (crypto context)"
    description = ("IPFS CIDs referenced with NFT/token context - the "
                   "actual asset storage behind the target's Web3 claims.")
    CONTEXT_RE = r"nft|token|mint|metadata|erc721|erc1155|collect"
    VALUE_GROUP = 1
    PATTERNS = [
        (r"\b(Qm[1-9A-HJ-NP-Za-km-z]{44})\b", "ipfs_cid", "IPFS CIDv0", 70, None),
        (r"\b(bafy[a-z2-7]{50,})\b", "ipfs_cid", "IPFS CIDv1", 70, None),
    ]


class CpPaymentUri(PackPlugin):
    id = "cp_payment_uri"
    label = "Crypto Payment URI (BIP-21 style)"
    description = ("bitcoin:/litecoin:/ethereum: payment URIs - the "
                   "click-to-pay form of a wallet address, often with "
                   "amount and label parameters worth inventorying.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"\b(bitcoin:[13][a-zA-HJ-NP-Z0-9]{25,34}(?:\?[^\s\"'<>]+)?)",
         "payment_uri_btc", "Bitcoin payment URI", 85, None),
        (r"\b(bitcoin:bc1[a-z0-9]{39,59}(?:\?[^\s\"'<>]+)?)",
         "payment_uri_btc", "Bitcoin payment URI", 85, None),
        (r"\b(ethereum:0x[0-9a-fA-F]{40}(?:@[0-9]+)?(?:\?[^\s\"'<>]+)?)",
         "payment_uri_eth", "Ethereum payment URI", 85, None),
        (r"\b(litecoin:[a-zA-HJ-NP-Z0-9]{25,34}(?:\?[^\s\"'<>]+)?)",
         "payment_uri_ltc", "Litecoin payment URI", 80, None),
        (r"\b(monero:4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:\?[^\s\"'<>]+)?)",
         "payment_uri_xmr", "Monero payment URI", 85, None),
    ]
