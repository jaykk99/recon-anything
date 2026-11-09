"""Stdlib-only local-EVM harness for the flash-loan simulation matrix.

Drives a LOCAL anvil process (fresh chain, or a local fork of a public RPC
for read-only state). Nothing here can talk to a live chain with a
transaction: the only RPC endpoint ever used is 127.0.0.1 anvil. Fork mode
makes anvil read state from a public RPC; all execution stays local.

Patterns (keccak, ABI codec, anvil lifecycle) adapted from the Nov 7
invariant fuzz engine so the two lanes behave identically.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- keccak
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
       0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
       0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_R = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
      [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x


def _keccak_f(state: List[int]) -> None:
    for rc in _RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _R[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y])
                                                     & b[(x + 2) % 5 + 5 * y])) & _MASK
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def selector(signature: str) -> bytes:
    return keccak256(signature.encode())[:4]


# ---------------------------------------------------------------- ABI codec
_STATIC = ("address", "uint256", "bool", "bytes32")


def _encode_static(t: str, v: Any) -> bytes:
    if t == "address":
        raw = v[2:] if isinstance(v, str) and v.startswith("0x") else v
        return bytes(12) + bytes.fromhex(raw)
    if t == "uint256":
        return (int(v) % (1 << 256)).to_bytes(32, "big")
    if t == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if t == "bytes32":
        raw = bytes.fromhex(v[2:] if isinstance(v, str) and v.startswith("0x") else v)
        return raw[:32].ljust(32, b"\x00")
    raise ValueError(f"not static: {t}")


def _encode_bytes(raw: bytes) -> bytes:
    pad = (32 - len(raw) % 32) % 32
    return len(raw).to_bytes(32, "big") + raw + bytes(pad)


def _encode_dynamic(t: str, v: Any) -> bytes:
    if t == "string":
        return _encode_bytes(str(v).encode())
    if t == "bytes":
        raw = bytes.fromhex(v[2:]) if isinstance(v, str) and v.startswith("0x") else bytes(v)
        return _encode_bytes(raw)
    if t.endswith("[]"):
        elem = t[:-2]
        items = list(v)
        if elem in _STATIC:
            return len(items).to_bytes(32, "big") + b"".join(
                _encode_static(elem, x) for x in items)
        if elem == "bytes":
            heads = []
            tails = []
            offset = 32 * len(items)
            for x in items:
                raw = bytes.fromhex(x[2:]) if isinstance(x, str) and x.startswith("0x") else bytes(x)
                enc = _encode_bytes(raw)
                heads.append(offset.to_bytes(32, "big"))
                tails.append(enc)
                offset += len(enc)
            return len(items).to_bytes(32, "big") + b"".join(heads) + b"".join(tails)
    raise ValueError(f"unsupported dynamic type: {t}")


def encode_args(types: Sequence[str], values: Sequence[Any]) -> bytes:
    if len(types) != len(values):
        raise ValueError("types/values length mismatch")
    heads: List[Optional[bytes]] = []
    tails: List[bytes] = []
    offset = 32 * len(types)
    for t, v in zip(types, values):
        if t in _STATIC:
            heads.append(_encode_static(t, v))
        else:
            enc = _encode_dynamic(t, v)
            heads.append(offset.to_bytes(32, "big"))
            tails.append(enc)
            offset += len(enc)
    return b"".join(h for h in heads if h is not None) + b"".join(tails)


def encode_call(signature: str, types: Sequence[str], values: Sequence[Any]) -> str:
    return "0x" + (selector(signature) + encode_args(types, values)).hex()


def decode_word(data: bytes, idx: int = 0) -> int:
    return int.from_bytes(data[idx * 32:(idx + 1) * 32], "big")


def decode_address(data: bytes, idx: int = 0) -> str:
    return "0x" + data[idx * 32 + 12:(idx + 1) * 32].hex()


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


# ---------------------------------------------------------------- RPC
class RpcError(Exception):
    pass


class Rpc:
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id,
                           "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                out = json.loads(resp.read())
        except Exception as e:  # noqa: BLE001
            raise RpcError(f"{method}: {e}") from e
        if "error" in out:
            raise RpcError(f"{method}: {out['error']}")
        return out["result"]

    # convenience wrappers -------------------------------------------------
    def eth_call(self, to: str, data: str, block: str = "latest") -> bytes:
        return hex_to_bytes(self.call("eth_call", [{"to": to, "data": data}, block]))

    def send(self, frm: str, to: Optional[str], data: str = "0x",
             value: int = 0, gas: int = 12_000_000) -> Dict[str, Any]:
        """Send a tx from an unlocked anvil account and wait for the receipt."""
        tx = {"from": frm, "data": data, "value": hex(value), "gas": hex(gas)}
        if to is not None:
            tx["to"] = to
        txh = self.call("eth_sendTransaction", [tx])
        for _ in range(200):
            rcpt = self.call("eth_getTransactionReceipt", [txh])
            if rcpt is not None:
                return rcpt
            time.sleep(0.05)
        raise RpcError(f"tx {txh} not mined")

    def deploy(self, frm: str, bytecode: str, *ctor: bytes) -> str:
        data = bytecode + b"".join(ctor).hex() if ctor else bytecode
        rcpt = self.send(frm, None, data)
        if rcpt["status"] != "0x1":
            raise RpcError(f"deploy failed: {rcpt}")
        return rcpt["contractAddress"]

    def snapshot(self) -> str:
        return self.call("evm_snapshot", [])

    def revert(self, snap_id: str) -> bool:
        return bool(self.call("evm_revert", [snap_id]))

    def set_balance(self, addr: str, wei: int) -> None:
        self.call("anvil_setBalance", [addr, hex(wei)])

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def get_storage(self, addr: str, slot: int) -> bytes:
        return hex_to_bytes(self.call("eth_getStorageAt", [addr, hex(slot), "latest"]))

    def accounts(self) -> List[str]:
        return self.call("eth_accounts", [])


def balance_of(rpc: Rpc, token: str, who: str) -> int:
    out = rpc.eth_call(token, encode_call("balanceOf(address)", ["address"], [who]))
    return decode_word(out, 0) if out else 0


# ---------------------------------------------------------------- anvil
ANVIL_CANDIDATES = ["/home/hatch/workspace/tools/audit/bin/anvil"]


def find_anvil() -> Optional[str]:
    import shutil
    for c in ANVIL_CANDIDATES:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which("anvil")


def find_solc() -> Optional[str]:
    import glob
    import shutil
    hits: List[str] = []
    for pat in (os.path.expanduser("~/.svm/*/solc-*"),
                os.path.expanduser("~/.foundry/svm/*/solc-*"),
                os.path.expanduser("~/.local/share/svm/*/solc-*")):
        hits += [h for h in glob.glob(pat) if os.access(h, os.X_OK)]
    if hits:
        def _ver(p: str):
            import re as _re
            m = _re.search(r"(\d+)\.(\d+)\.(\d+)", p)
            return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)
        return sorted(hits, key=_ver)[-1]
    return shutil.which("solc")


def compile_source(source: str, contract_name: str,
                   solc: Optional[str] = None) -> Tuple[str, list]:
    """Compile single-file source; return (bytecode_hex, abi) for the contract."""
    import tempfile
    solc = solc or find_solc()
    if not solc:
        raise RpcError("solc not found")
    with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
        f.write(source)
        path = f.name
    out = subprocess.run([solc, "--combined-json", "abi,bin", path],
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RpcError(f"solc failed: {out.stderr[:600]}")
    data = json.loads(out.stdout)
    for key, entry in data["contracts"].items():
        if key.endswith(":" + contract_name):
            abi = entry["abi"]
            if isinstance(abi, str):
                abi = json.loads(abi)
            return "0x" + entry["bin"], abi
    raise RpcError(f"contract {contract_name} not in compile output")


class Anvil:
    """Local anvil. fork_url pins a local fork of a public RPC (state is read
    from the RPC by anvil; execution is local only)."""

    def __init__(self, port: int, fork_url: Optional[str] = None,
                 fork_block: Optional[int] = None, chain_id: int = 31337):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.proc: Optional[subprocess.Popen] = None
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.chain_id = chain_id

    def __enter__(self) -> Rpc:
        anvil = find_anvil()
        if not anvil:
            raise RpcError("anvil binary not found")
        args = [anvil, "--port", str(self.port), "--silent",
                "--gas-limit", "30000000", "--balance", "100000"]
        if self.fork_url:
            args += ["--fork-url", self.fork_url]
            if self.fork_block is not None:
                args += ["--fork-block-number", str(self.fork_block)]
        else:
            args += ["--chain-id", str(self.chain_id)]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        rpc = Rpc(self.url, timeout=60.0)
        # Fork startup against a slow public RPC can take a while.
        attempts = 1500 if self.fork_url else 300
        for _ in range(attempts):
            try:
                rpc.call("eth_chainId", [])
                return rpc
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        raise RpcError("anvil did not start")

    def __exit__(self, *exc) -> None:
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                self.proc.kill()
