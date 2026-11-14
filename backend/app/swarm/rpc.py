"""Keyless public-RPC client, read-only by construction.

Pure stdlib (urllib). Every call goes through ``check_readonly`` from
rules.py, so no method outside the read-only allowlist can ever be
issued. Failover walks the per-chain endpoint list in order; a dead
host is skipped, never retried in the same call.

``transport`` is injectable for tests: a callable
``(url, payload_dict) -> response_dict``. Production passes None and
gets urllib.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from .rules import STRANGER_ADDRESS, check_readonly

CHAIN_IDS = {
    "ethereum": 1, "optimism": 10, "bsc": 56, "polygon": 137,
    "arbitrum": 42161, "base": 8453, "scroll": 534352,
    "linea": 59144, "avalanche": 43114,
}

# Keyless public endpoints. Same class the repo already uses
# (rpc_pool.EXTRA_KEYLESS_RPCS) plus the chains that list lacks.
ENDPOINTS: Dict[str, List[str]] = {
    "ethereum": [
        "https://eth.drpc.org",
        "https://rpc.ankr.com/eth",
        "https://1rpc.io/eth",
    ],
    "optimism": [
        "https://mainnet.optimism.io",
        "https://optimism.drpc.org",
        "https://rpc.ankr.com/optimism",
        "https://1rpc.io/op",
    ],
    "arbitrum": [
        "https://arbitrum.drpc.org",
        "https://rpc.ankr.com/arbitrum",
        "https://1rpc.io/arb",
    ],
    "base": [
        "https://base.drpc.org",
        "https://rpc.ankr.com/base",
        "https://1rpc.io/base",
    ],
    "bsc": [
        "https://bsc.drpc.org",
        "https://1rpc.io/bnb",
    ],
    "polygon": [
        "https://polygon.drpc.org",
        "https://rpc.ankr.com/polygon",
        "https://1rpc.io/matic",
    ],
    "scroll": [
        "https://rpc.scroll.io",
        "https://scroll.drpc.org",
        "https://1rpc.io/scroll",
    ],
    "linea": [
        "https://rpc.linea.build",
        "https://linea.drpc.org",
    ],
    "avalanche": [
        "https://api.avax.network/ext/bc/C/rpc",
        "https://avalanche.drpc.org",
    ],
}

# Verified-source (Blockscout) API roots, Etherscan-compatible.
BLOCKSCOUT_API = {
    "ethereum": "https://eth.blockscout.com/api",
    "optimism": "https://optimism.blockscout.com/api",
    "arbitrum": "https://arbitrum.blockscout.com/api",
    "base": "https://base.blockscout.com/api",
    "bsc": "https://bsc.blockscout.com/api",
    "polygon": "https://polygon.blockscout.com/api",
    "scroll": "https://blockscout.scroll.io/api",
    "linea": "https://linea.blockscout.com/api",
    "avalanche": "https://avalanche.blockscout.com/api",
}

USER_AGENT = "recon-swarm/1.0 (detection-only, read-only eth_call)"


def _default_transport(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": USER_AGENT},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


class RpcClient:
    """Read-only JSON-RPC client for one chain."""

    def __init__(self, chain: str, endpoints: Optional[List[str]] = None,
                 transport: Optional[Callable] = None,
                 timeout_s: float = 30.0) -> None:
        self.chain = chain
        self.chain_id = CHAIN_IDS.get(chain)
        self.endpoints = list(
            endpoints or ENDPOINTS.get(chain) or [])
        self.transport = transport or _default_transport
        self.timeout_s = timeout_s
        self.calls = 0
        self.errors: List[str] = []

    def call(self, method: str, params: Optional[List[Any]] = None,
             endpoint: Optional[str] = None,
             rounds: int = 2) -> Dict[str, Any]:
        """One JSON-RPC call, read-only methods only, with failover.

        Walks the endpoint list; if every endpoint fails, waits a
        second and walks it once more (public endpoints drop
        connections under this sandbox's egress). Returns the raw
        response dict (``result`` or ``error`` key). Raises
        RuntimeError only when every endpoint failed in every round.
        """
        check_readonly(method)
        payload = {"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": params or []}
        urls = [endpoint] if endpoint else self.endpoints
        last_error: Optional[str] = None
        failures = 0
        for round_no in range(max(1, rounds)):
            if round_no:
                time.sleep(1)
            for url in urls:
                try:
                    self.calls += 1
                    resp = self.transport(url, payload)
                    if not isinstance(resp, dict):
                        raise ValueError("non-dict RPC response")
                    return resp
                except Exception as e:  # noqa: BLE001 - failover, not fatal
                    last_error = f"{url}: {type(e).__name__}: {e}"
                    failures += 1
                    self.errors.append(last_error)
        raise RuntimeError(
            f"all RPC endpoints failed for {method} on {self.chain} "
            f"({failures} attempts): {last_error}")

    # -- typed helpers -------------------------------------------------

    def get_code(self, address: str, block: str = "latest") -> str:
        resp = self.call("eth_getCode", [address, block])
        return str(resp.get("result") or "")

    def get_balance(self, address: str, block: str = "latest") -> int:
        resp = self.call("eth_getBalance", [address, block])
        return int(str(resp.get("result") or "0x0"), 16)

    def block_number(self) -> int:
        resp = self.call("eth_blockNumber", [])
        return int(str(resp.get("result") or "0x0"), 16)

    def chain_id_live(self) -> int:
        resp = self.call("eth_chainId", [])
        return int(str(resp.get("result") or "0x0"), 16)

    def eth_call(self, to: str, data: str,
                 sender: str = STRANGER_ADDRESS,
                 block: str = "latest",
                 value: str = "0x0",
                 state_override: Optional[Dict[str, Any]] = None
                 ) -> Dict[str, Any]:
        """Read-only eth_call from the unfunded stranger.

        Never a transaction: no signing, no broadcast, no value moved.
        ``state_override`` (EIP-7928 style) only overrides what the
        call SEES; it changes nothing on chain. Returns the raw
        response dict so callers can show the real return/revert.
        """
        tx = {"from": sender, "to": to, "data": data, "value": value}
        params: List[Any] = [tx, block]
        if state_override:
            params.append(state_override)
        return self.call("eth_call", params)


# -- ABI-lite helpers (no eth_abi dependency) --------------------------

# Keccak-256 (original Keccak padding, NOT NIST SHA-3): the hash
# Ethereum uses for function selectors. Pure stdlib, ~50 lines,
# verified against known vectors in the test suite.
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
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_MASK64 = (1 << 64) - 1


def _keccak_f1600(state):
    for rnd in range(24):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ ((c[(x + 1) % 5] << 1 | c[(x + 1) % 5] >> 63) & _MASK64)
             for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho + Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                r = _KECCAK_R[x][y]
                v = state[x + 5 * y]
                b[y + 5 * ((2 * x + 3 * y) % 5)] = (
                    (v << r | v >> (64 - r)) & _MASK64) if r else v
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]))
        # Iota
        state[0] ^= _KECCAK_RC[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    """Keccak-256 digest of `data`."""
    rate = 136  # 1088-bit rate for 256-bit output
    state = [0] * 25
    # Absorb full blocks
    offset = 0
    while offset + rate <= len(data):
        block = data[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f1600(state)
        offset += rate
    # Final block with Keccak pad10*1 (0x01 ... 0x80)
    tail = bytearray(data[offset:])
    tail.append(0x01)
    tail.extend(b"\x00" * (rate - len(tail)))
    tail[-1] |= 0x80
    for i in range(rate // 8):
        state[i] ^= int.from_bytes(tail[i * 8:(i + 1) * 8], "little")
    _keccak_f1600(state)
    return b"".join(
        state[i].to_bytes(8, "little") for i in range(4))


def selector(signature: str) -> str:
    """First 4 bytes of keccak256(signature), as hex (no 0x)."""
    return keccak256(signature.encode()).hex()[:8]


def encode_address(addr: str) -> str:
    """32-byte ABI encoding of an address (no 0x prefix)."""
    clean = addr.lower().removeprefix("0x")
    return "0" * 24 + clean


def encode_uint256(value: int) -> str:
    return f"{int(value):064x}"


def decode_uint256(hexdata: str) -> Optional[int]:
    try:
        raw = hexdata.removeprefix("0x")
        if len(raw) < 64:
            return None
        return int(raw[-64:], 16)
    except (ValueError, TypeError):
        return None


def decode_address(hexdata: str) -> Optional[str]:
    try:
        raw = hexdata.removeprefix("0x")
        if len(raw) < 64:
            return None
        return "0x" + raw[-40:]
    except (ValueError, TypeError):
        return None


def fetch_verified_source(chain: str, address: str,
                          tries: int = 4) -> Dict[str, Any]:
    """Fetch verified source from the chain's Blockscout API.

    Tolerant of the flaky egress here (IncompleteRead partial bodies,
    dropped connections): retries, accepts a partial body only when it
    parses as JSON. Returns {"source": str|None, "name": str|None,
    "abi": str|None, "via": url, "error": str|None}.
    """
    import http.client

    base = BLOCKSCOUT_API.get(chain)
    if not base:
        return {"source": None, "name": None, "abi": None, "via": None,
                "error": f"no blockscout API configured for chain {chain!r}"}
    url = (f"{base}?module=contract&action=getsourcecode"
           f"&address={address}")
    last_error: Optional[str] = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT,
                              "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=40) as resp:
                body = resp.read()
            data = json.loads(body.decode("utf-8", "replace"))
            result = (data.get("result") or [{}])[0]
            source = result.get("SourceCode") or ""
            # Double-bracketed source is a JSON-wrapped multi-file tree.
            if source.startswith("{{"):
                source = source[1:-1]
            return {"source": source or None,
                    "name": result.get("ContractName") or None,
                    "abi": result.get("ABI") or None,
                    "via": url, "error": None}
        except http.client.IncompleteRead as e:
            last_error = f"IncompleteRead({len(e.partial)} bytes)"
            try:
                data = json.loads(e.partial.decode("utf-8", "replace"))
                result = (data.get("result") or [{}])[0]
                source = result.get("SourceCode") or ""
                if source.startswith("{{"):
                    source = source[1:-1]
                if source:
                    return {"source": source,
                            "name": result.get("ContractName") or None,
                            "abi": result.get("ABI") or None,
                            "via": url, "error": None}
            except Exception:  # noqa: BLE001 - retry on unparseable partial
                pass
            time.sleep(2)
        except Exception as e:  # noqa: BLE001 - retry, then report
            last_error = f"{type(e).__name__}: {e}"
            time.sleep(2)
    return {"source": None, "name": None, "abi": None, "via": url,
            "error": last_error}
