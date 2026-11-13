"""Live proxy / upgrade + bridge invariant checks (Wave 1.3).

The static defense detectors (``defense_upgrade_window_open`` et al.)
describe an upgrade window in source; nothing in the repo polled the
live proxy slots or diffed an implementation after it changed, and
every ``bridge_*`` check was a static regex. This module is the live
half, inside the repo:

- Proxy lane: read the EIP-1967 implementation / admin / beacon slots
  plus the ZeppelinOS implementation slot via read-only
  ``eth_getStorageAt``; fetch implementation bytecode via
  ``eth_getCode``; diff selectors/functions before vs after an
  upgrade; re-run the repo's existing contract analysis (defense
  family + fork-path) on the NEW implementation's verified source.
- Bridge lane: read-only ``eth_call`` invariants - locked vs minted
  across the bridge's two sides, quorum vs the live validator set,
  nonce continuity. A fire needs a live-measured break with both
  sides' numbers in evidence; no name-matching anywhere.

Transport: a stdlib-urllib sync JSON-RPC reader over the public
keyless endpoints in ``contract_chain.CHAINS`` (no foundry, no keys,
no extra dependencies). Every method passes through
``rpc_guard.assert_read_only`` - ``eth_getStorageAt`` / ``eth_getCode``
/ ``eth_call`` / ``eth_getBalance`` only; anything else is refused at
the transport layer. Checkers are ``async`` over a tiny reader
protocol (``eth_call`` / ``get_code`` / ``get_storage_at``) so the
same code runs under the plugin engine (``CtxReader``), the CLI /
smoke script (``SyncRpcReader``) and tests (fake readers).

Findings are candidates (``report_class: "candidate"``) until the
existing validator live-probes them; nothing here stamps
VERIFIED_REAL. A read that fails is reported as degraded/unavailable,
never as clean.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .plugins import contract_chain as cc
from .rpc_guard import assert_read_only

# ---------------------------------------------------------------------------
# Slots (all verified against keccak256; see the
# test_proxy_bridge_live slot test, which recomputes them)
# ---------------------------------------------------------------------------

SLOT_IMPLEMENTATION = cc.EIP1967_IMPLEMENTATION_SLOT
SLOT_BEACON = cc.EIP1967_BEACON_SLOT
SLOT_ADMIN = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
# ZeppelinOS slots: the ORIGINAL ZeppelinOS lineage (which USDC's
# FiatTokenProxy comes from) uses the RAW keccak256, no "-1".
# Proof, read live 2026-11-12: USDC's proxy bytecode SLOADs
# ...3f8c3 / ...390b (not the keccak-1 ...3f8c2 / ...390a), and the
# raw slots hold the live implementation
# (0x43506849d7c04f9138d1a2050bbf3a0c054402dd) and admin while the
# keccak-1 slots read zero. The keccak-1 variant is what
# openzeppelin-sdk's later AdminUpgradeabilityProxy used, so both
# are read - raw first, keccak-1 as fallback.
SLOT_ZEPPELINOS_IMPLEMENTATION = (
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3")
SLOT_ZEPPELINOS_IMPLEMENTATION_MINUS1 = (
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c2")
SLOT_ZEPPELINOS_ADMIN = (
    "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b")
SLOT_ZEPPELINOS_ADMIN_MINUS1 = (
    "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390a")

ZERO_WORD = "0x" + "0" * 64
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# 4-byte selectors needed by the live reads (hardcoded, verified in
# tests against keccak256 - the module must not depend on an external
# keccak library at import time).
SEL_BALANCE_OF = "70a08231"
SEL_TOTAL_SUPPLY = "18160ddd"
SEL_OWNER = "8da5cb5b"

# Opcodes whose *appearance* in a new implementation is new attack
# surface (scanned with PUSH-skipping, so PUSH data cannot fake one).
OP_DELEGATECALL = 0xF4
OP_CALLCODE = 0xF2
OP_SELFDESTRUCT = 0xFF
OP_CREATE2 = 0xF5
DANGEROUS_OPCODES = {
    OP_DELEGATECALL: "DELEGATECALL",
    OP_CALLCODE: "CALLCODE",
    OP_SELFDESTRUCT: "SELFDESTRUCT",
    OP_CREATE2: "CREATE2",
}


# ---------------------------------------------------------------------------
# keccak-256 (pure python; only used for arbitrary function signatures
# supplied in bridge configs and for the slot self-check in tests)
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
_KECCAK_R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK64 = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x & _MASK64


def _keccak_f1600(a: List[int]) -> List[int]:
    for rc in _KECCAK_RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(
                    a[x + 5 * y], _KECCAK_R[x][y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = (b[x + 5 * y]
                                ^ (~b[(x + 1) % 5 + 5 * y]
                                   & b[(x + 2) % 5 + 5 * y])) & _MASK64
        a[0] ^= rc
    return a


def keccak_256(data: bytes) -> bytes:
    """keccak-256 (original Keccak padding, NOT NIST SHA3)."""
    rate = 136
    state = [0] * 25
    # Absorb full blocks.
    off = 0
    while len(data) - off >= rate:
        block = data[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        state = _keccak_f1600(state)
        off += rate
    # Last block + pad10*1.
    tail = bytearray(data[off:])
    tail.append(0x01)
    while len(tail) % rate != rate - 1:
        tail.append(0x00)
    tail.append(0x80)
    for i in range(rate // 8):
        state[i] ^= int.from_bytes(tail[i * 8:(i + 1) * 8], "little")
    state = _keccak_f1600(state)
    out = b""
    while len(out) < 32:
        for i in range(rate // 8):
            out += state[i].to_bytes(8, "little")
        if len(out) >= 32:
            break
        state = _keccak_f1600(state)
    return out[:32]


def selector(signature: str) -> str:
    """4-byte selector (hex, no 0x) for a canonical signature."""
    return keccak_256(signature.encode()).hex()[:8]


def slot_from_preimage(preimage: str) -> str:
    """EIP-1967 / ZeppelinOS style slot: keccak256(preimage) - 1."""
    v = int.from_bytes(keccak_256(preimage.encode()), "big") - 1
    return "0x" + v.to_bytes(32, "big").hex()


def parse_guardian_set(raw: Optional[str]) -> Optional[Dict[str, int]]:
    """Parse a Wormhole ``getGuardianSet(uint32)`` return.

    The return is a ``GuardianSet`` struct ``{address[] keys;
    uint32 expirationTime}`` ABI-encoded as: word0 = offset to the
    struct (0x20), word1 = offset to the keys array (0x40, relative
    to the struct), word2 = expirationTime, word3 = keys length,
    then the keys. The array length is at word index 3 - NOT word
    index 2 (word2 is the expiry; the current set has expiry 0, so
    reading word2 as the count reports 0 guardians and a false
    "unreachable quorum" - caught live 2026-11-13 against
    getGuardianSet(7), which really holds 19 guardians).
    """
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    h = raw[2:]
    if len(h) < 4 * 64:
        return None
    try:
        words = [int(h[i * 64:(i + 1) * 64], 16) for i in range(4)]
    except ValueError:
        return None
    if words[0] != 0x20 or words[1] != 0x40:
        return None
    count, expiry = words[3], words[2]
    if count > 1000 or len(h) < (4 + count) * 64:
        return None
    return {"guardian_count": count, "expiry": expiry}


# ---------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------

def decode_uint(data: Optional[str], word: int = 0) -> Optional[int]:
    if not isinstance(data, str) or not data.startswith("0x"):
        return None
    h = data[2:]
    if len(h) < (word + 1) * 64:
        return None
    try:
        return int(h[word * 64:(word + 1) * 64], 16)
    except ValueError:
        return None


def decode_address(data: Optional[str], word: int = 0) -> Optional[str]:
    if not isinstance(data, str) or not data.startswith("0x"):
        return None
    h = data[2:]
    if len(h) < (word + 1) * 64:
        return None
    addr = "0x" + h[word * 64 + 24:(word + 1) * 64]
    return addr if _ADDRESS_RE.match(addr) else None


def decode_address_array_len(data: Optional[str]) -> Optional[int]:
    """Length word of an ABI address[] return (offset word + length)."""
    if not isinstance(data, str) or not data.startswith("0x"):
        return None
    h = data[2:]
    if len(h) < 128:
        return None
    try:
        return int(h[64:128], 16)
    except ValueError:
        return None


def address_from_storage_word(word: Optional[str]) -> Optional[str]:
    if not word or word == ZERO_WORD:
        return None
    return decode_address(word, 0)


def pad_addr(addr: str) -> str:
    return addr.lower().replace("0x", "").rjust(64, "0")


def pad_uint(n: int) -> str:
    return format(int(n), "064x")


# ---------------------------------------------------------------------------
# Sync JSON-RPC reader (stdlib only, keyless public endpoints)
# ---------------------------------------------------------------------------

class SyncRpcReader:
    """Read-only JSON-RPC over the chain's public endpoints.

    Tries each URL in order; a dead / rate-limited / erroring host is
    skipped, never fatal. Only allowlisted read methods are ever
    sent (enforced by rpc_guard). ``last_error`` records the last
    failure for degraded reporting.

    Large responses (eth_getCode on a ~10 KB implementation, verified
    source) are truncated mid-body by this VM's shared-egress proxy
    when fetched with urllib (IncompleteRead) while curl fetches the
    same URL fine, so a failed urllib attempt falls back to a
    same-method, same-body ``curl`` subprocess for that URL before
    moving on. Still read-only, still keyless; curl is only a
    transport workaround, never a new data source.
    """

    def __init__(self, rpc_urls: Optional[Dict[str, List[str]]] = None,
                 timeout: float = 12.0):
        self._overrides = rpc_urls or {}
        self.timeout = timeout
        self.last_error: str = ""

    def _curl_call(self, url: str, body: bytes) -> Optional[Any]:
        import shutil
        import subprocess

        if not shutil.which("curl"):
            return None
        try:
            proc = subprocess.run(
                ["curl", "-s", "-m", str(int(self.timeout)), "-X",
                 "POST", url, "-H", "Content-Type: application/json",
                 "-d", "@-"],
                input=body, capture_output=True, timeout=self.timeout + 5)
        except Exception as e:  # noqa: BLE001 - next URL
            self.last_error = f"{url}: curl {type(e).__name__}"
            return None
        if proc.returncode != 0:
            self.last_error = f"{url}: curl exit {proc.returncode}"
            return None
        try:
            data = json.loads(proc.stdout.decode())
        except Exception:
            self.last_error = f"{url}: curl malformed response"
            return None
        if data.get("error"):
            self.last_error = f"{url}: RPC error " \
                f"{str(data['error'])[:160]}"
            return None
        if "result" in data:
            return data["result"]
        self.last_error = f"{url}: curl no result field"
        return None

    def _urls(self, chain: str) -> List[str]:
        if chain in self._overrides:
            return list(self._overrides[chain])
        cfg = cc.CHAINS.get(chain)
        urls = list(cfg.rpc_urls) if cfg else []
        try:  # repo's own keyless pool widens the rotation
            from .rpc_pool import EXTRA_KEYLESS_RPCS
            for extra in EXTRA_KEYLESS_RPCS.get(chain, ()):
                if extra not in urls:
                    urls.append(extra)
        except Exception:
            pass
        return urls

    def call(self, chain: str, method: str,
             params: list) -> Optional[Any]:
        assert_read_only(method)
        payload = {"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": params}
        body = json.dumps(payload).encode()
        # Two attempts per endpoint: the keyless publics 403 / drop
        # connections under shared-egress load, and a transient
        # refusal must not lose the read.
        for url in self._urls(chain):
            for _attempt in range(2):
                try:
                    req = urllib.request.Request(
                        url, data=body,
                        headers={"Content-Type": "application/json",
                                 "User-Agent": "recon-anything/live-read"})
                    with urllib.request.urlopen(
                            req, timeout=self.timeout) as r:
                        if r.status != 200:
                            self.last_error = \
                                f"{url}: HTTP {r.status}"
                            break
                        data = json.loads(r.read().decode())
                except Exception as e:  # noqa: BLE001 - retry / next
                    self.last_error = f"{url}: {type(e).__name__} " \
                        f"{str(e)[:120]}"
                    time.sleep(1)
                    continue
                if not isinstance(data, dict):
                    self.last_error = f"{url}: malformed response"
                    break
                if data.get("error"):
                    self.last_error = f"{url}: RPC error " \
                        f"{str(data['error'])[:160]}"
                    break
                if "result" in data:
                    return data["result"]
                self.last_error = f"{url}: no result field"
                break
            # urllib failed on this URL (truncated large responses
            # under shared egress are the usual cause): one curl
            # attempt with the identical body before moving on.
            res = self._curl_call(url, body)
            if res is not None:
                return res
        return None

    # -- sync protocol ------------------------------------------------
    def get_storage_at(self, chain: str, address: str,
                       slot: str) -> Optional[str]:
        return self.call(chain, "eth_getStorageAt",
                         [address, slot, "latest"])

    def get_code(self, chain: str, address: str) -> Optional[str]:
        return self.call(chain, "eth_getCode", [address, "latest"])

    def get_balance(self, chain: str, address: str) -> Optional[int]:
        raw = self.call(chain, "eth_getBalance", [address, "latest"])
        if isinstance(raw, str) and raw.startswith("0x"):
            try:
                return int(raw, 16)
            except ValueError:
                return None
        return None

    def eth_call(self, chain: str, to: str, data: str) -> Optional[str]:
        raw = self.call(chain, "eth_call",
                        [{"to": to, "data": data}, "latest"])
        if isinstance(raw, str) and raw.startswith("0x") and raw != "0x":
            return raw
        return None

    # -- async protocol (same calls, off the event loop) -------------
    async def aget_storage_at(self, chain: str, address: str,
                              slot: str) -> Optional[str]:
        return await asyncio.to_thread(self.get_storage_at, chain,
                                       address, slot)

    async def aget_code(self, chain: str,
                        address: str) -> Optional[str]:
        return await asyncio.to_thread(self.get_code, chain, address)

    async def aeth_call(self, chain: str, to: str,
                        data: str) -> Optional[str]:
        return await asyncio.to_thread(self.eth_call, chain, to, data)


# Reader protocol for the checkers below: any object with async
# methods aget_storage_at(chain, address, slot),
# aget_code(chain, address), aeth_call(chain, to, data).


class CtxReader:
    """Reader protocol over the plugin engine's ctx (shared
    rate-limited fetch + per-run cache in contract_chain)."""

    def __init__(self, ctx: Any):
        self.ctx = ctx

    async def aget_storage_at(self, chain: str, address: str,
                              slot: str) -> Optional[str]:
        return await cc.rpc_get_storage_at(
            self.ctx, cc.CHAINS[chain], address, slot)

    async def aget_code(self, chain: str, address: str) -> Optional[str]:
        return await cc.rpc_get_code(self.ctx, cc.CHAINS[chain], address)

    async def aeth_call(self, chain: str, to: str,
                        data: str) -> Optional[str]:
        res = await cc.rpc_batch(
            self.ctx, cc.CHAINS[chain],
            [("eth_call", [{"to": to, "data": data}, "latest"])])
        if res and isinstance(res[0], str) and res[0] != "0x":
            return res[0]
        return None


# ---------------------------------------------------------------------------
# Bytecode diffing
# ---------------------------------------------------------------------------

def code_hash(code_hex: Optional[str]) -> Optional[str]:
    if not code_hex or not code_hex.startswith("0x"):
        return None
    return hashlib.sha256(code_hex.encode()).hexdigest()


def extract_selectors(code_hex: Optional[str]) -> set:
    """4-byte function selectors referenced by PUSH4 in the bytecode.

    Walks with PUSH-length skipping, so PUSH data bytes can never be
    mistaken for opcodes or selectors.
    """
    out = set()
    if not code_hex or not code_hex.startswith("0x"):
        return out
    try:
        b = bytes.fromhex(code_hex[2:])
    except ValueError:
        return out
    i = 0
    while i < len(b):
        op = b[i]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            if op == 0x63 and i + 5 <= len(b):
                out.add("0x" + b[i + 1:i + 5].hex())
            i += 1 + n
        else:
            i += 1
    return out


def extract_opcodes(code_hex: Optional[str]) -> set:
    """Opcode bytes present, PUSH data skipped (same walk)."""
    out = set()
    if not code_hex or not code_hex.startswith("0x"):
        return out
    try:
        b = bytes.fromhex(code_hex[2:])
    except ValueError:
        return out
    i = 0
    while i < len(b):
        op = b[i]
        out.add(op)
        if 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
        else:
            i += 1
    return out


def diff_implementations(old_code: Optional[str],
                         new_code: Optional[str]) -> Dict[str, Any]:
    """Bytecode diff between two implementations.

    Returns code hashes, added/removed 4-byte selectors, and
    added/removed dangerous opcodes (DELEGATECALL / CALLCODE /
    SELFDESTRUCT / CREATE2). A missing side is reported, never
    treated as empty code.
    """
    old_hash = code_hash(old_code)
    new_hash = code_hash(new_code)
    old_sels = extract_selectors(old_code)
    new_sels = extract_selectors(new_code)
    old_ops = extract_opcodes(old_code)
    new_ops = extract_opcodes(new_code)
    added_ops = {DANGEROUS_OPCODES[o] for o in (new_ops - old_ops)
                 if o in DANGEROUS_OPCODES}
    removed_ops = {DANGEROUS_OPCODES[o] for o in (old_ops - new_ops)
                   if o in DANGEROUS_OPCODES}
    return {
        "changed": old_hash != new_hash,
        "old_code_hash": old_hash,
        "new_code_hash": new_hash,
        "old_code_available": old_code is not None,
        "new_code_available": new_code is not None,
        "old_selectors": sorted(old_sels),
        "new_selectors": sorted(new_sels),
        "added_selectors": sorted(new_sels - old_sels),
        "removed_selectors": sorted(old_sels - new_sels),
        "added_dangerous_opcodes": sorted(added_ops),
        "removed_dangerous_opcodes": sorted(removed_ops),
    }


# ---------------------------------------------------------------------------
# Live proxy slot reads
# ---------------------------------------------------------------------------

async def read_proxy_slots(reader: Any, chain: str,
                           address: str) -> Dict[str, Any]:
    """Live EIP-1967 + ZeppelinOS slot reads for one proxy.

    Returns {implementation, admin, beacon, zeppelinos_implementation,
    zeppelinos_implementation_sdk, zeppelinos_admin,
    zeppelinos_admin_sdk, beacon_implementation, unavailable}.
    A zero word means "slot not set" (not a proxy of that flavour)
    and is listed unavailable, never treated as an address. When the
    EIP-1967 implementation slot is empty but a beacon is set, the
    beacon's own slot 0 is read for the implementation (OpenZeppelin
    UpgradeableBeacon). When no slot yields an implementation, the
    implementation() view is tried (custom proxies whose admin-gated
    getters revert for strangers stay unreadable - reported, never
    guessed). The ZeppelinOS implementation AND admin are read at
    BOTH the raw keccak slots (original ZOS lineage, e.g. USDC) and
    the keccak-1 slots (openzeppelin-sdk lineage); whichever is set
    wins, and a ZeppelinOS admin fills ``admin`` when the EIP-1967
    admin slot is empty.
    """
    out: Dict[str, Any] = {
        "chain": chain, "address": address,
        "implementation": None, "admin": None, "beacon": None,
        "zeppelinos_implementation": None,
        "zeppelinos_implementation_sdk": None,
        "zeppelinos_admin": None,
        "zeppelinos_admin_sdk": None,
        "beacon_implementation": None,
        "unavailable": [],
    }
    words = {}
    for name, slot in (
            ("implementation", SLOT_IMPLEMENTATION),
            ("admin", SLOT_ADMIN),
            ("beacon", SLOT_BEACON),
            ("zeppelinos_implementation",
             SLOT_ZEPPELINOS_IMPLEMENTATION),
            ("zeppelinos_implementation_sdk",
             SLOT_ZEPPELINOS_IMPLEMENTATION_MINUS1),
            ("zeppelinos_admin", SLOT_ZEPPELINOS_ADMIN),
            ("zeppelinos_admin_sdk", SLOT_ZEPPELINOS_ADMIN_MINUS1)):
        word = await reader.aget_storage_at(chain, address, slot)
        words[name] = word
        addr = address_from_storage_word(word)
        if addr is None:
            out["unavailable"].append(name)
        else:
            out[name] = addr
    if out["admin"] is None:
        for name in ("zeppelinos_admin", "zeppelinos_admin_sdk"):
            if out.get(name):
                out["admin"] = out[name]
                out["admin_via"] = name
                break
    if out["implementation"] is None:
        for name in ("zeppelinos_implementation",
                     "zeppelinos_implementation_sdk"):
            if out.get(name):
                out["implementation"] = out[name]
                out["implementation_via"] = name
                break
    if out["implementation"] is None and out["beacon"]:
        bword = await reader.aget_storage_at(chain, out["beacon"], "0x0")
        bimpl = address_from_storage_word(bword)
        if bimpl is None:
            out["unavailable"].append("beacon_implementation")
        else:
            out["beacon_implementation"] = bimpl
            out["implementation"] = bimpl
    if out["implementation"] is None:
        # Custom proxies (e.g. admin-gated getters on transparent
        # proxies) expose implementation() / admin() views that
        # revert for strangers. A revert means the views do not
        # answer for us; only a returned address is trusted.
        raw = await reader.aeth_call(
            chain, address, "0x" + selector("implementation()"))
        impl = decode_address(raw, 0)
        if impl:
            out["implementation"] = impl
            out["implementation_via"] = "implementation() call"
        else:
            out["unavailable"].append("implementation_call")
        if out["admin"] is None:
            raw = await reader.aeth_call(
                chain, address, "0x" + selector("admin()"))
            admin = decode_address(raw, 0)
            if admin:
                out["admin"] = admin
    return out


# ---------------------------------------------------------------------------
# Re-run the repo's existing analysis on an implementation's source
# ---------------------------------------------------------------------------

def analyze_implementation_source(source: str,
                                  contract_name: str = ""
                                  ) -> List[Dict[str, Any]]:
    """Run the defense family + fork-path analyzer over source.

    Lazy imports keep this module light for callers that only do
    live reads. Returns hits as {id, severity, function, code,
    detail, report_class} - the same shape the static lane emits,
    so the upgrade report can carry them verbatim.
    """
    from .plugins import bsc_common as bc
    from .plugins.defense_monitor import SPECS as def_specs
    from .plugins.fork_attack_path import analyze_forkpath_source

    hits: List[Dict[str, Any]] = []
    for spec in def_specs:
        for h in bc.analyze_bsc_source(source, spec, "",
                                       contract_name=contract_name):
            h = dict(h)
            h["report_class"] = "candidate"
            hits.append(h)
    for h in analyze_forkpath_source(source,
                                     contract_name=contract_name):
        h = dict(h)
        h["kind"] = "fork_attack_path_complete"
        hits.append(h)
    return hits


# ---------------------------------------------------------------------------
# Upgrade analysis: two snapshots -> one report
# ---------------------------------------------------------------------------

async def analyze_upgrade(prev: Dict[str, Any], cur: Dict[str, Any],
                          code_reader: Callable[[str, str], Any],
                          source_analyzer: Optional[Callable[
                              [str, str], Any]] = None
                          ) -> Dict[str, Any]:
    """Diff an implementation change between two snapshots.

    ``code_reader(chain, address)`` returns deployed bytecode hex
    (awaitable). ``source_analyzer(chain, address)`` optionally
    returns {"source_available": bool, "hits": [...]} for the new
    implementation (the plugin path wires the verified-source fetch
    + ``analyze_implementation_source`` here).

    The report always records the change; it carries findings only
    when the new implementation (a) gains dangerous opcodes, or
    (b) trips the existing analysis - in particular an open upgrade
    window (``defense_upgrade_window_open``) on the NEW
    implementation. A benign change with clean re-analysis reports
    verdict "clean"; missing code/source reports "degraded", never
    clean. Findings are candidates, never VERIFIED_REAL.
    """
    chain = cur.get("chain") or prev.get("chain")
    prev_impl = (prev or {}).get("implementation")
    cur_impl = (cur or {}).get("implementation")
    report: Dict[str, Any] = {
        "changed": False,
        "chain": chain,
        "previous_implementation": prev_impl,
        "implementation": cur_impl,
        "selector_diff": None,
        "reanalysis": {"source_available": None, "hits": []},
        "findings": [],
        "verdict": "clean",
    }
    if not prev_impl or not cur_impl or prev_impl == cur_impl:
        return report
    report["changed"] = True
    old_code = await code_reader(chain, prev_impl)
    new_code = await code_reader(chain, cur_impl)
    diff = diff_implementations(old_code, new_code)
    report["selector_diff"] = diff
    if not diff["old_code_available"] or not diff["new_code_available"]:
        report["verdict"] = "degraded"
        report["detail"] = ("implementation changed but one side's "
                            "bytecode could not be fetched - the "
                            "change is recorded, not cleared")
        return report
    if diff["added_dangerous_opcodes"]:
        report["findings"].append({
            "id": "proxy_live_implementation_diff",
            "severity": "high",
            "report_class": "candidate",
            "detail": ("New implementation gains dangerous opcodes "
                       f"{diff['added_dangerous_opcodes']} that the "
                       "previous implementation did not have - new "
                       "attack surface (delegatecall / selfdestruct "
                       "/ create2) behind the same proxy."),
            "evidence": diff,
        })
    if source_analyzer is not None:
        try:
            res = await source_analyzer(chain, cur_impl)
        except Exception as e:  # noqa: BLE001 - degraded, not clean
            res = {"source_available": False, "hits": [],
                   "error": str(e)[:200]}
        report["reanalysis"] = {
            "source_available": res.get("source_available"),
            "hits": res.get("hits") or [],
        }
        if not res.get("source_available"):
            report["verdict"] = "degraded"
            report["detail"] = ("implementation changed; the new "
                                "implementation has no verified source "
                                "available, so re-analysis could not "
                                "run - bytecode diff only, not cleared")
        for h in res.get("hits") or []:
            report["findings"].append({
                "id": h.get("kind") or h.get("id"),
                "severity": h.get("severity", "high"),
                "report_class": h.get("report_class", "candidate"),
                "function": h.get("function", ""),
                "code": h.get("code", ""),
                "detail": h.get("detail", ""),
            })
    if report["findings"]:
        report["verdict"] = "candidate"
    return report


# ---------------------------------------------------------------------------
# Bridge invariants (all async over the reader protocol)
# ---------------------------------------------------------------------------

async def _try_sigs(reader: Any, chain: str, to: str,
                    sigs: Tuple[str, ...],
                    args: Tuple[str, ...] = ()
                    ) -> Tuple[Optional[str], Optional[str]]:
    """First signature that answers wins. Returns (raw, sig_used).

    An unparseable argument (bad address / non-integer) is a
    caller error, not a chain read: return (None, None) instead of
    raising, so one bad arg can never crash a check.
    """
    for sig in sigs:
        data = "0x" + selector(sig)
        try:
            for a in args:
                if a.startswith("0x") and len(a) == 42:
                    data += pad_addr(a)
                else:
                    data += pad_uint(int(a))
        except (ValueError, AttributeError):
            return None, None
        raw = await reader.aeth_call(chain, to, data)
        if raw is not None:
            return raw, sig
    return None, None


async def erc20_balance(reader: Any, chain: str, token: str,
                        holder: str) -> Optional[int]:
    raw, _ = await _try_sigs(
        reader, chain, token, ("balanceOf(address)",), (holder,))
    return decode_uint(raw, 0)


async def erc20_total_supply(reader: Any, chain: str,
                             token: str) -> Optional[int]:
    raw, _ = await _try_sigs(reader, chain, token, ("totalSupply()",))
    return decode_uint(raw, 0)


@dataclass
class BridgeLockMintConfig:
    """Locked-vs-minted: vault + token on the lock side, minted token
    on the other side. Locked is the token balance of the vault;
    minted is the wrapped token's totalSupply."""
    chain_a: str
    vault_a: str
    token_a: str
    chain_b: str
    mint_token_b: str
    label: str = ""


async def check_locked_vs_minted(
        reader: Any, cfg: BridgeLockMintConfig) -> Dict[str, Any]:
    """Live invariant: minted must never exceed locked.

    Fires only on a live-measured break (minted > locked) with both
    numbers in evidence. Unreadable side -> degraded, never clean.
    A small in-flight gap is expected on live bridges (messages in
    transit); the report carries the raw numbers so the reader can
    judge, and the finding says so.
    """
    locked = await erc20_balance(reader, cfg.chain_a, cfg.token_a,
                                 cfg.vault_a)
    minted = await erc20_total_supply(reader, cfg.chain_b,
                                      cfg.mint_token_b)
    res: Dict[str, Any] = {
        "check": "bridge_live_locked_vs_minted",
        "label": cfg.label,
        "chain_a": cfg.chain_a, "vault_a": cfg.vault_a,
        "token_a": cfg.token_a, "chain_b": cfg.chain_b,
        "mint_token_b": cfg.mint_token_b,
        "locked": locked, "minted": minted,
        "broken": False, "verdict": "clean",
    }
    if locked is None or minted is None:
        res["verdict"] = "degraded"
        res["detail"] = ("locked or minted side unreadable "
                         f"(locked={locked}, minted={minted}) - "
                         "invariant not checked, not cleared")
        return res
    if minted > locked:
        res["broken"] = True
        res["verdict"] = "candidate"
        res["shortfall"] = minted - locked
        res["detail"] = (
            f"UNBACKED MINT: minted {minted} exceeds locked {locked} "
            f"by {minted - locked} (chain {cfg.chain_b} "
            f"{cfg.mint_token_b} vs chain {cfg.chain_a} vault "
            f"{cfg.vault_a}). Wrapped tokens exist with no matching "
            "lock on the other side. Some of the gap can be messages "
            "in transit on a live bridge, so this is a candidate "
            "for validator live-probing, not proof of a drain.")
    return res


@dataclass
class BridgeQuorumConfig:
    """Quorum vs live validator set, read from the bridge contract
    itself. quorum_sigs / count_sigs are tried in order; the first
    that answers wins and is recorded."""
    chain: str
    bridge: str
    quorum_sigs: Tuple[str, ...] = ("quorum()", "getQuorum()")
    count_sigs: Tuple[str, ...] = ("validatorCount()",
                                   "getValidators()",
                                   "signerCount()")
    label: str = ""


async def check_validator_quorum(
        reader: Any, cfg: BridgeQuorumConfig) -> Dict[str, Any]:
    """Live invariant: 1 < quorum <= live validator count.

    Fires when the quorum can never be reached (quorum > live
    validators), when the set is empty, or when quorum is 1 with
    more than one validator (single-signer takeover). Both the
    quorum and the live count are read on-chain; the signature that
    answered is recorded.
    """
    res: Dict[str, Any] = {
        "check": "bridge_live_validator_quorum",
        "label": cfg.label,
        "chain": cfg.chain, "bridge": cfg.bridge,
        "quorum": None, "quorum_sig": None,
        "validator_count": None, "count_sig": None,
        "broken": False, "verdict": "clean",
    }
    raw_q, sig_q = await _try_sigs(reader, cfg.chain, cfg.bridge,
                                   cfg.quorum_sigs)
    res["quorum"] = decode_uint(raw_q, 0)
    res["quorum_sig"] = sig_q
    raw_c, sig_c = await _try_sigs(reader, cfg.chain, cfg.bridge,
                                   cfg.count_sigs)
    if raw_c is not None:
        if sig_c and sig_c.startswith("getValidators"):
            res["validator_count"] = decode_address_array_len(raw_c)
        else:
            res["validator_count"] = decode_uint(raw_c, 0)
    res["count_sig"] = sig_c
    q, n = res["quorum"], res["validator_count"]
    if q is None or n is None:
        res["verdict"] = "degraded"
        res["detail"] = ("quorum or validator set unreadable "
                         f"(quorum={q}, validators={n}) - invariant "
                         "not checked, not cleared")
        return res
    if n == 0:
        res["broken"] = True
        res["verdict"] = "candidate"
        res["detail"] = ("validator set is EMPTY on-chain while the "
                         f"bridge requires quorum {q} - no honest "
                         "validator can ever sign")
    elif q is not None and q > n:
        res["broken"] = True
        res["verdict"] = "candidate"
        res["detail"] = (f"UNREACHABLE QUORUM: quorum {q} exceeds the "
                         f"live validator count {n} - the bridge can "
                         "never reach quorum (liveness break) or the "
                         "count read is stale; verify live")
    elif q == 1 and n > 1:
        res["broken"] = True
        res["verdict"] = "candidate"
        res["detail"] = (f"SINGLE-SIGNER QUORUM: quorum is 1 with {n} "
                         "live validators - any one validator can "
                         "authorize bridge messages alone")
    return res


@dataclass
class BridgeNonceConfig:
    """Nonce continuity across the bridge's two sides. Each side's
    counter is read with the first answering signature."""
    chain_a: str
    bridge_a: str
    chain_b: str
    bridge_b: str
    nonce_sigs: Tuple[str, ...] = ("nonce()",
                                   "lastProcessedNonce()",
                                   "processedNonce()")
    label: str = ""


async def check_nonce_continuity(
        reader: Any, cfg: BridgeNonceConfig) -> Dict[str, Any]:
    """Live invariant: destination processed must never exceed source
    emitted. Lag (dest < source) is normal - messages in transit.
    Dest ahead of source is impossible in honest operation and fires
    with both numbers.
    """
    src, sig_a = await _try_sigs(reader, cfg.chain_a, cfg.bridge_a,
                                 cfg.nonce_sigs)
    dst, sig_b = await _try_sigs(reader, cfg.chain_b, cfg.bridge_b,
                                 cfg.nonce_sigs)
    src_n, dst_n = decode_uint(src, 0), decode_uint(dst, 0)
    res: Dict[str, Any] = {
        "check": "bridge_live_nonce_continuity",
        "label": cfg.label,
        "chain_a": cfg.chain_a, "bridge_a": cfg.bridge_a,
        "chain_b": cfg.chain_b, "bridge_b": cfg.bridge_b,
        "source_nonce": src_n, "source_sig": sig_a,
        "dest_nonce": dst_n, "dest_sig": sig_b,
        "broken": False, "verdict": "clean",
    }
    if src_n is None or dst_n is None:
        res["verdict"] = "degraded"
        res["detail"] = ("nonce unreadable on one side "
                         f"(source={src_n}, dest={dst_n}) - "
                         "invariant not checked, not cleared")
        return res
    if dst_n > src_n:
        res["broken"] = True
        res["verdict"] = "candidate"
        res["detail"] = (
            f"NONCE AHEAD: destination processed nonce {dst_n} "
            f"exceeds source emitted nonce {src_n} by "
            f"{dst_n - src_n} - the destination processed messages "
            "the source never emitted (spoof / replay shape)")
    return res


# ---------------------------------------------------------------------------
# Bridge target specs (what the plugins parse from a scan target)
# ---------------------------------------------------------------------------

def parse_bridge_target(raw: str) -> Optional[Any]:
    """Parse a compact bridge spec from a scan target.

    bridge-lock:<chainA>:<vaultA>:<tokenA>:<chainB>:<mintTokenB>
    bridge-quorum:<chain>:<bridge>[:<quorumSig>[:<countSig>]]
    bridge-nonce:<chainA>:<bridgeA>:<chainB>:<bridgeB>
    Returns the config dataclass, or None when the target is not a
    bridge spec (plain addresses return None - the caller skips).
    """
    s = (raw or "").strip()
    parts = s.split(":")
    kind = parts[0].lower() if parts else ""
    if kind == "bridge-lock" and len(parts) == 6:
        _, chain_a, vault_a, token_a, chain_b, mint_b = parts
        if (chain_a in cc.CHAINS and chain_b in cc.CHAINS
                and _ADDRESS_RE.match(vault_a)
                and _ADDRESS_RE.match(token_a)
                and _ADDRESS_RE.match(mint_b)):
            return BridgeLockMintConfig(chain_a, vault_a, token_a,
                                      chain_b, mint_b, label=s)
        return None
    if kind == "bridge-quorum" and 3 <= len(parts) <= 5:
        chain, bridge = parts[1], parts[2]
        if chain not in cc.CHAINS or not _ADDRESS_RE.match(bridge):
            return None
        kw: Dict[str, Any] = {"label": s}
        if len(parts) >= 4 and parts[3]:
            kw["quorum_sigs"] = (parts[3],)
        if len(parts) >= 5 and parts[4]:
            kw["count_sigs"] = (parts[4],)
        return BridgeQuorumConfig(chain, bridge, **kw)
    if kind == "bridge-nonce" and len(parts) == 5:
        _, chain_a, bridge_a, chain_b, bridge_b = parts
        if (chain_a in cc.CHAINS and chain_b in cc.CHAINS
                and _ADDRESS_RE.match(bridge_a)
                and _ADDRESS_RE.match(bridge_b)):
            return BridgeNonceConfig(chain_a, bridge_a, chain_b,
                                     bridge_b, label=s)
        return None
    return None
