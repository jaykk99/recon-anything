"""Shared machinery for the crypto detection pack (cp_* plugins).

The pack is ~100 small, single-purpose DETECTION plugins (validated
per-chain address formats, cryptojacking kit signatures, drainer /
clipboard-swapper patterns, leaked crypto keys, Web3 infra inventory,
payment rails, DNS crypto traces). They all scan the same surface -
the target's own public homepage + same-domain JS bundles, fetched
once through Ctx.fetch_page's cross-plugin cache - so the common
work lives here:

- collect_texts(): homepage + JS texts, shared/cached, never raises.
- PackPlugin: config-driven scanner base (regex patterns + optional
  cryptographic validators + finding shaping/redaction).
- Validators: REAL checksum verification (Base58Check, Bech32 /
  Bech32m per BIP-173/350, EIP-55 via a pure-Python Keccak-256,
  SS58, Monero block Base58 + Keccak checksum, cashaddr polymod,
  CRC16-XMODEM for Stellar/TON). The pre-existing `crypto` plugin
  matches loose regexes at confidence ~70; the pack only reports
  addresses whose checksums actually verify, which is what makes
  per-chain findings trustworthy enough to act on.

Detection only: nothing here transacts, sweeps, or derives keys.
Secret-shaped findings are redacted in value AND evidence.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain

# ---------------------------------------------------------------------------
# Keccak-256 (pure Python; hashlib.sha3_256 is FIPS SHA-3, NOT Keccak -
# different padding - and EIP-55 / Monero checksums need real Keccak).
# ---------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK64 = (1 << 64) - 1


def _rol64(x: int, n: int) -> int:
    if n == 0:
        return x & _MASK64
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(state: List[int]) -> None:
    for rc in _KECCAK_RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15]
             ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(
                    state[x + 5 * y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088-bit rate for 256-bit output
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)  # Keccak (not SHA-3) domain suffix
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f1600(state)
    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out[:32]


# ---------------------------------------------------------------------------
# Base58 / Base58Check
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def b58decode(s: str, alphabet: str = B58_ALPHABET) -> Optional[bytes]:
    try:
        n = 0
        for ch in s:
            n = n * 58 + alphabet.index(ch)
        pad = len(s) - len(s.lstrip(alphabet[0]))
        body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        return b"\x00" * pad + body
    except (ValueError, OverflowError):
        return None


def b58encode(data: bytes, alphabet: str = B58_ALPHABET) -> str:
    n = int.from_bytes(data, "big") if data else 0
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * pad + (out or (alphabet[0] if not data else ""))


def b58check_verify(s: str, alphabet: str = B58_ALPHABET) -> Optional[bytes]:
    """Return the payload (version+data, checksum stripped) or None."""
    raw = b58decode(s, alphabet)
    if raw is None or len(raw) < 5:
        return None
    payload, cksum = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return payload if digest[:4] == cksum else None


def b58check_encode(payload: bytes, alphabet: str = B58_ALPHABET) -> str:
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return b58encode(payload + digest[:4], alphabet)


# ---------------------------------------------------------------------------
# Bech32 / Bech32m (BIP-173 / BIP-350)
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    chk = 1
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_decode(s: str) -> Optional[Tuple[str, List[int], str]]:
    """Return (hrp, data5bit_without_checksum, encoding) or None."""
    # No 90-char cap: BIP-173's limit is segwit-specific; Cardano and
    # LNURL bech32 strings run longer. Segwit validity is enforced by
    # segwit_verify's witness-program length check instead.
    if not s or len(s) > 1024 or s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return None
    hrp, part = s[:pos], s[pos + 1:]
    try:
        data = [_BECH32_CHARSET.index(c) for c in part]
    except ValueError:
        return None
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if pm == 1:
        enc = "bech32"
    elif pm == 0x2BC830A3:
        enc = "bech32m"
    else:
        return None
    return hrp, data[:-6], enc


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, payload: bytes, enc: str = "bech32") -> str:
    data = _convertbits(payload, 8, 5)
    const = 1 if enc == "bech32" else 0x2BC830A3
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0] * 6) ^ const
    cksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + cksum)


def segwit_verify(s: str, hrp: str, version: int) -> bool:
    dec = bech32_decode(s)
    if not dec:
        return False
    h, data, enc = dec
    if h != hrp or not data or data[0] != version:
        return False
    if version == 0 and enc != "bech32":
        return False
    if version >= 1 and enc != "bech32m":
        return False
    prog = _convertbits(data[1:], 5, 8, pad=False)
    return prog is not None and 2 <= len(prog) <= 40


# ---------------------------------------------------------------------------
# Cashaddr (Bitcoin Cash) - bech32-like polymod with prefix expansion
# ---------------------------------------------------------------------------

_CASH_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _cash_polymod(values) -> int:
    c = 1
    gen = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8,
           0x1E4F43E470]
    for v in values:
        top = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                c ^= gen[i]
    return c ^ 1


def cashaddr_verify(s: str) -> bool:
    s = s.lower()
    if ":" in s:
        prefix, part = s.split(":", 1)
    else:
        prefix, part = "bitcoincash", s
    if prefix not in ("bitcoincash", "bchtest"):
        return False
    try:
        data = [_CASH_CHARSET.index(c) for c in part]
    except ValueError:
        return False
    if len(data) < 8:
        return False
    expanded = [ord(c) & 31 for c in prefix] + [0]
    return _cash_polymod(expanded + data) == 0


# ---------------------------------------------------------------------------
# SS58 (Polkadot/Substrate)
# ---------------------------------------------------------------------------

def ss58_verify(s: str) -> Optional[bytes]:
    raw = b58decode(s)
    if raw is None or len(raw) < 3:
        return None
    payload, cksum = raw[:-2], raw[-2:]
    h = hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()
    return payload if h[:2] == cksum else None


# ---------------------------------------------------------------------------
# Monero block Base58 + Keccak checksum
# ---------------------------------------------------------------------------

_XMR_DEC_WIDTH = {2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}


def _xmr_b58_decode(s: str) -> Optional[bytes]:
    out = bytearray()
    for i in range(0, len(s), 11):
        block = s[i:i + 11]
        size = _XMR_DEC_WIDTH.get(len(block))
        if size is None:
            raise ValueError("bad monero block width")
        n = 0
        for ch in block:
            n = n * 58 + B58_ALPHABET.index(ch)
        out += n.to_bytes(size, "big")
    return bytes(out)


def _xmr_b58_encode(data: bytes) -> str:
    out = ""
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        n = int.from_bytes(block, "big")
        enc = ""
        while n:
            n, r = divmod(n, 58)
            enc = B58_ALPHABET[r] + enc
        width = {1: 2, 2: 3, 3: 5, 4: 6, 5: 7, 6: 9, 7: 10, 8: 11}[len(block)]
        out += enc.rjust(width, "1")
    return out


def xmr_verify(s: str, prefixes: Tuple[int, ...]) -> bool:
    try:
        raw = _xmr_b58_decode(s)
    except Exception:
        return False
    if raw is None or len(raw) < 5 or raw[0] not in prefixes:
        return False
    payload, cksum = raw[:-4], raw[-4:]
    return keccak256(payload)[:4] == cksum


def xmr_encode(payload: bytes) -> str:
    return _xmr_b58_encode(payload + keccak256(payload)[:4])


def b58check_prefix(s: str, prefixes: Tuple[bytes, ...],
                      total_len: int) -> bool:
    """Base58Check with multi-byte version prefixes (Tezos, Zcash)."""
    raw = b58decode(s)
    if raw is None or len(raw) != total_len:
        return False
    payload, cksum = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return digest[:4] == cksum and any(
        payload.startswith(p) for p in prefixes)


def _cash_style_verify(part: str, prefix: str) -> bool:
    try:
        data = [_CASH_CHARSET.index(c) for c in part]
    except ValueError:
        return False
    if len(data) < 8:
        return False
    expanded = [ord(c) & 31 for c in prefix] + [0]
    return _cash_polymod(expanded + data) == 0


def kaspa_verify(s: str) -> bool:
    """Kaspa uses the cashaddr-family 40-bit polymod with its prefix."""
    if not s.lower().startswith("kaspa:"):
        return False
    return _cash_style_verify(s.split(":", 1)[1].lower(), "kaspa")


def algo_verify(s: str) -> bool:
    try:
        raw = base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))
    except Exception:
        return False
    if len(raw) != 36:
        return False
    return hashlib.new("sha512_256", raw[:32]).digest()[-4:] == raw[32:]


def bech32_payload(s: str, hrp: str) -> Optional[bytes]:
    dec = bech32_decode(s)
    if not dec or dec[0] != hrp:
        return None
    payload = _convertbits(dec[1], 5, 8, pad=False)
    return bytes(payload) if payload is not None else None


# ---------------------------------------------------------------------------
# CRC16-XMODEM (Stellar, TON friendly addresses)
# ---------------------------------------------------------------------------

def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 \
                else (crc << 1) & 0xFFFF
    return crc


def xlm_verify(s: str) -> bool:
    try:
        raw = base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))
    except Exception:
        return False
    if len(raw) != 35 or raw[0] != 0x30:  # version byte for G... accounts
        return False
    return crc16_xmodem(raw[:-2]) == int.from_bytes(raw[-2:], "little")


def ton_friendly_verify(s: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))
    except Exception:
        return False
    if len(raw) != 36:
        return False
    return crc16_xmodem(raw[:-2]) == int.from_bytes(raw[-2:], "big")


# ---------------------------------------------------------------------------
# EIP-55
# ---------------------------------------------------------------------------

def eip55_state(addr: str) -> str:
    """'checksummed' (valid mixed-case), 'plain' (all lower/upper), 'bad'."""
    hexpart = addr[2:]
    if hexpart.lower() == hexpart or hexpart.upper() == hexpart:
        return "plain"
    digest = keccak256(hexpart.lower().encode()).hex()
    for i, ch in enumerate(hexpart):
        if ch.isalpha():
            if (int(digest[i], 16) >= 8) != ch.isupper():
                return "bad"
    return "checksummed"


# ---------------------------------------------------------------------------
# Shared scan surface: homepage + same-domain JS, via fetch_page cache
# ---------------------------------------------------------------------------

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


async def collect_texts(ctx: Ctx, target: Target,
                        max_js: int = 8) -> List[Tuple[str, str, str]]:
    """[(where, text, url)] for the homepage and its same-domain JS.

    Every fetch goes through Ctx.fetch_page, whose cache is shared by
    all plugins in the run - the ~100 pack plugins together cost one
    homepage fetch plus one fetch per JS bundle, not 100x that.
    Never raises; returns [] when the site is unreachable.
    """
    from ..classifier import domain_from_target
    domain = domain_from_target(target.type, target.normalized)
    if not domain:
        return []
    if target.type == "url":
        bases = [target.normalized]
    else:
        bases = [f"https://{domain}", f"http://{domain}"]
    page = None
    for base in bases:
        try:
            page = await ctx.fetch_page(base, timeout=20)
        except Exception:
            page = None
        if page is not None:
            break
    if page is None:
        return []
    try:
        html = page["text"][:500_000]
        page_url = page["url"]
    except Exception:
        return []
    texts: List[Tuple[str, str, str]] = [("homepage HTML", html, page_url)]
    seen_js = set()
    for m in _SCRIPT_SRC.finditer(html):
        if len(seen_js) >= max_js:
            break
        full = urljoin(page_url, m.group(1))
        if full in seen_js or not same_domain(full, domain):
            continue
        seen_js.add(full)
        try:
            jr = await ctx.fetch_page(full, timeout=15)
        except Exception:
            continue
        if jr is None:
            continue
        try:
            if jr["status_code"] == 200 and jr["text"]:
                texts.append(("JS bundle", jr["text"][:500_000], full))
        except Exception:
            continue
    # Crypto-class runs (Jay's order, 2026-10-23): the pack's
    # env-assignment detectors (MNEMONIC=, PRIVATE_KEY=, WIF) must
    # also see the target's served config files, not just the
    # homepage and its JS - a leaked .env is the canonical
    # exposed-key surface on a crypto site. Gated on the run flag
    # so non-crypto scans keep their exact old fetch profile.
    # Fetches ride the shared fetch_page cache, so the ~200 pack
    # plugins together pay for these files once.
    try:
        is_crypto_run = bool((getattr(ctx, "shared", None) or {})
                             .get("crypto_target"))
    except Exception:
        is_crypto_run = False
    if is_crypto_run:
        for cfg_path in ("/.env", "/.env.local"):
            cfg_url = urljoin(page_url, cfg_path)
            try:
                cr = await ctx.fetch_page(cfg_url, timeout=10)
            except Exception:
                continue
            if cr is None:
                continue
            try:
                if cr["status_code"] == 200 and cr["text"]:
                    texts.append(("config file", cr["text"][:500_000],
                                  cfg_url))
            except Exception:
                continue
    return texts


# ---------------------------------------------------------------------------
# Config-driven pack plugin base
# ---------------------------------------------------------------------------

class PackPlugin(Plugin):
    """One detector = one subclass with PATTERNS config.

    PATTERNS entries: (regex, key, label, confidence, validator|None)
    - validator(match_str) -> bool gates the finding (checksum etc.)
    - CONTEXT_RE, when set, must also appear within WINDOW chars of
      the match (kills format collisions between chains).
    Findings are deduplicated per (key, value). SECRET=True redacts.
    """

    id = None  # abstract: Plugin.id defaults to "base"; opt out of
    # registry discovery (the health gate counts it as a duplicate).
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 45

    PATTERNS: List[Tuple[str, str, str, int, Optional[Callable]]] = []
    CATEGORY = "crypto"
    SECRET = False
    CONTEXT_RE: Optional[str] = None
    WINDOW = 120
    MAX_FINDINGS = 25
    VALUE_GROUP = 0  # regex group holding the value (context patterns)
    _compiled: Optional[List] = None

    def _patterns(self):
        if self._compiled is None:
            out = []
            for pat, key, label, conf, validator in self.PATTERNS:
                # Case-insensitive matching for prose/signature patterns;
                # address precision is preserved by the checksum
                # validators, which are case-exact.
                out.append((re.compile(pat, re.I), key, label, conf,
                            validator))
            type(self)._compiled = out
        return self._compiled

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        findings: List[Finding] = []
        seen = set()
        ctx_re = re.compile(self.CONTEXT_RE, re.I) if self.CONTEXT_RE else None
        for where, text, url in texts:
            low = text.lower()
            for rx, key, label, conf, validator in self._patterns():
                for m in rx.finditer(text):
                    value = m.group(self.VALUE_GROUP)
                    if validator is not None:
                        try:
                            if not validator(value):
                                continue
                        except Exception:
                            continue
                    if ctx_re is not None:
                        lo = max(0, m.start() - self.WINDOW)
                        hi = min(len(text), m.end() + self.WINDOW)
                        if not ctx_re.search(text[lo:hi]):
                            continue
                    dedup = (key, value)
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    ev = {"detector": self.id, "matched": label,
                          "where": where}
                    if self.SECRET:
                        from .secretutils import redact
                        ev["match_redacted"] = redact(value, show=4)
                        ev["full_value"] = value
                        display = f"{label}: {value}"
                    else:
                        ev["match"] = value
                        display = self._display(label, value)
                    findings.append(self._f(
                        self.CATEGORY, key, display,
                        source=f"{self.label}", source_url=url,
                        confidence=conf, passive=True, evidence=ev))
                    # Feed the enrichment bus. Every checksum-verified
                    # address detector publishes its hit to crypto_addresses
                    # with a chain tag (derived from the key prefix) so the
                    # multi-chain enrichment plugin can look up balance,
                    # activity and labels. Was missing: only ETH contracts
                    # reached the bus, so BTC/LTC/DOGE/XRP/... addresses were
                    # detected but never enriched. Skip secret matches and
                    # bad-checksum non-addresses.
                    if ("address" in key and "bad_checksum" not in key
                            and not self.SECRET):
                        chain = key.split("_", 1)[0]
                        ctx.publish("crypto_addresses",
                                    {"address": value, "chain": chain,
                                     "key": key})
                    if len(findings) >= self.MAX_FINDINGS:
                        break
                if len(findings) >= self.MAX_FINDINGS:
                    break
            if len(findings) >= self.MAX_FINDINGS:
                break
            _ = low
        res = self._ok(findings,
                       f"{len(findings)} {self.label} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    def _display(self, label: str, value: str) -> str:
        v = value if len(value) <= 44 else f"{value[:20]}...{value[-12:]}"
        return f"{label}: {v}"
