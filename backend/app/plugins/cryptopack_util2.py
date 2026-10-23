"""Crypto pack v2: additional validators for wave-2 detectors.

Same rule as wave 1 (cryptopack_util): a format only counts when its
checksum/structure actually verifies. Wave 2 adds Ergo (Blake2b
checksum), EOSIO keys (RIPEMD-160 checksum), XDC (EIP-55 over the
xdc-prefixed hex), Handshake (Bech32 segwit, hrp hs), Horizen
(two-byte Base58Check version), Kaspa testnet (cashaddr-family
polymod), TON raw form, BIP-38 encrypted keys, WIF private keys and
BIP-32 extended keys (xprv/xpub families).

Detection only, as everywhere in the pack.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

from .cryptopack_util import (
    _cash_style_verify, _convertbits, b58check_verify, b58decode,
    bech32_decode, bech32_payload, eip55_state,
)


# ---------------------------------------------------------------------------
# Generic Bech32 helpers for the Cosmos-family factory
# ---------------------------------------------------------------------------

def bech32_hrp_verify(s: str, hrp: str, lengths=(20, 32)) -> bool:
    p = bech32_payload(s, hrp)
    return p is not None and len(p) in lengths


# ---------------------------------------------------------------------------
# TON raw form: "<workchain>:<64 hex>" (0: or -1:), as opposed to the
# user-friendly base64url form wave 1 covers.
# ---------------------------------------------------------------------------

_TON_RAW_RE = re.compile(r"^(?:-1|0):[0-9a-fA-F]{64}$")


def ton_raw_verify(s: str) -> bool:
    if not _TON_RAW_RE.match(s):
        return False
    try:
        bytes.fromhex(s.split(":", 1)[1])
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Kaspa testnet: same 40-bit cashaddr-family polymod, kaspatest prefix.
# ---------------------------------------------------------------------------

def kaspa_testnet_verify(s: str) -> bool:
    if not s.lower().startswith("kaspatest:"):
        return False
    return _cash_style_verify(s.split(":", 1)[1].lower(), "kaspatest")


# ---------------------------------------------------------------------------
# Handshake (HNS): Bech32 segwit v0, hrp "hs", 20/32-byte program.
# ---------------------------------------------------------------------------

def hns_verify(s: str) -> bool:
    dec = bech32_decode(s)
    if not dec:
        return False
    hrp, data, enc = dec
    if hrp != "hs" or enc != "bech32" or not data or data[0] != 0:
        return False
    prog = _convertbits(data[1:], 5, 8, pad=False)
    return prog is not None and len(prog) in (20, 32)


# ---------------------------------------------------------------------------
# Avalanche X-Chain: Bech32, hrp "avax", 20-byte payload.
# ---------------------------------------------------------------------------

def avax_verify(s: str) -> bool:
    p = bech32_payload(s, "avax")
    return p is not None and len(p) in (20, 32)


# ---------------------------------------------------------------------------
# Ergo: Base58, payload = type byte + content + 4-byte Blake2b-256
# checksum of (type+content). P2PK = type 0x01 + 33-byte compressed
# public key -> 38 bytes total, addresses start with '9'.
# ---------------------------------------------------------------------------

def ergo_verify(s: str) -> bool:
    raw = b58decode(s)
    if raw is None or len(raw) != 38 or raw[0] != 0x01:
        return False
    body, cksum = raw[:-4], raw[-4:]
    return hashlib.blake2b(body, digest_size=32).digest()[:4] == cksum


# ---------------------------------------------------------------------------
# EOSIO public keys: legacy "EOS..." (Base58 of 33-byte key + RIPEMD160
# checksum) and modern "PUB_K1_..." / "PUB_R1_..." (checksum over
# key || curve suffix).
# ---------------------------------------------------------------------------

def _ripemd160(data: bytes) -> Optional[bytes]:
    try:
        return hashlib.new("ripemd160", data).digest()
    except Exception:
        return None


def eos_key_verify(s: str) -> bool:
    if s.startswith("EOS"):
        raw = b58decode(s[3:])
        if raw is None or len(raw) != 37:
            return False
        ck = _ripemd160(raw[:33])
        return ck is not None and ck[:4] == raw[33:]
    for prefix, suffix in (("PUB_K1_", b"K1"), ("PUB_R1_", b"R1")):
        if s.startswith(prefix):
            raw = b58decode(s[len(prefix):])
            if raw is None or len(raw) != 37:
                return False
            ck = _ripemd160(raw[:33] + suffix)
            return ck is not None and ck[:4] == raw[33:]
    return False


# ---------------------------------------------------------------------------
# XDC: "xdc" + 40 hex; the hex part carries an EIP-55 checksum when
# mixed-case, exactly as if it were 0x-prefixed.
# ---------------------------------------------------------------------------

def xdc_verify(s: str) -> bool:
    if not s.startswith("xdc") or len(s) != 43:
        return False
    hexpart = s[3:]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", hexpart):
        return False
    return eip55_state("0x" + hexpart) in ("checksummed", "plain")


def xdc_checksummed(s: str) -> bool:
    return s.startswith("xdc") and len(s) == 43 \
        and eip55_state("0x" + s[3:]) == "checksummed"


# ---------------------------------------------------------------------------
# BIP-38 encrypted private keys: Base58Check, 43 bytes decoded,
# payload (39 bytes) starts with 0x01 0x42.
# ---------------------------------------------------------------------------

def bip38_verify(s: str) -> bool:
    p = b58check_verify(s)
    return bool(p) and len(p) == 39 and p[:2] == b"\x01\x42"


# ---------------------------------------------------------------------------
# WIF private keys: Base58Check; payload = version + 32-byte key
# (+ trailing 0x01 when the key is for a compressed public key).
# BTC mainnet version 0x80, testnet 0xEF.
# ---------------------------------------------------------------------------

def wif_verify(s: str, version: int, compressed: bool) -> bool:
    p = b58check_verify(s)
    if not p or p[0] != version:
        return False
    if compressed:
        return len(p) == 34 and p[-1] == 0x01
    return len(p) == 33


# ---------------------------------------------------------------------------
# BIP-32 extended keys: Base58Check, 78-byte payload, 4-byte version.
# ---------------------------------------------------------------------------

_XPRV_VERSIONS = {
    b"\x04\x88\xad\xe4",  # xprv
    b"\x04\x9d\x78\x78",  # yprv
    b"\x04\xb2\x43\x0c",  # zprv
    b"\x02\x95\xb0\x05",  # Yprv (multisig)
    b"\x02\xaa\x7a\x99",  # Zprv (multisig)
}
_XPUB_VERSIONS = {
    b"\x04\x88\xb2\x1e",  # xpub
    b"\x04\x9d\x7c\xb2",  # ypub
    b"\x04\xb2\x47\x46",  # zpub
    b"\x02\x95\xb4\x3f",  # Ypub
    b"\x02\xaa\x7e\xd3",  # Zpub
}


def xprv_verify(s: str) -> bool:
    p = b58check_verify(s)
    return bool(p) and len(p) == 78 and p[:4] in _XPRV_VERSIONS


def xpub_verify(s: str) -> bool:
    p = b58check_verify(s)
    return bool(p) and len(p) == 78 and p[:4] in _XPUB_VERSIONS


# ---------------------------------------------------------------------------
# Solana full keypair in Base58 (Phantom-style export): decodes to
# exactly 64 bytes (32-byte seed + 32-byte public key).
# ---------------------------------------------------------------------------

def solana_keypair_b58_verify(s: str) -> bool:
    raw = b58decode(s)
    return raw is not None and len(raw) == 64
