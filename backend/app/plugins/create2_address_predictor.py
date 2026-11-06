"""CREATE2 Address Predictor (Cat-1 #14, VARIANT of the CREATE2
collision detectors).

Delta: off-chain predictor mode. Given deployer, salt and init
code (or its hash), compute the CREATE2 address with the repo's
keccak helper - keccak256(0xff ++ deployer ++ salt ++
keccak256(init_code))[12:] - then report the predicted address's
status: when code already exists there (or a balance sits there)
the future deployment collides / the address is pre-funded, which
is reported; a clean empty prediction stays silent (the pure
function still returns the address for the caller).
Inputs arrive on the bus as a create2 record {deployer, salt,
init_code | init_code_hash, code_at_address?, balance?}; when the
code/balance are not supplied the wrapper reads them keyless.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C
from .cryptopack_util import keccak256


def _bytes_of(value: Any, want: Optional[int] = None) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    s = str(value or "").strip()
    if s.startswith("0x"):
        s = s[2:]
    try:
        b = bytes.fromhex(s)
    except ValueError:
        b = s.encode()
    if want and len(b) < want:
        b = b.rjust(want, b"\x00")
    return b


def predict_create2_address(deployer: str, salt: Any,
                            init_code: str = "",
                            init_code_hash: str = "") -> str:
    dep = _bytes_of(deployer, 20)[-20:]
    salt_b = _bytes_of(salt, 32)[-32:]
    if init_code_hash:
        ich = _bytes_of(init_code_hash, 32)[-32:]
    else:
        ich = keccak256(C.code_bytes(init_code) if isinstance(
            init_code, str) else bytes(init_code or b""))
    digest = keccak256(b"\xff" + dep + salt_b + ich)
    return "0x" + digest[-20:].hex()


def analyze_create2(params: Dict[str, Any]) -> Dict[str, Any]:
    addr = predict_create2_address(
        str(params.get("deployer", "")),
        params.get("salt", ""),
        str(params.get("init_code", "")),
        str(params.get("init_code_hash", "")))
    hits = []
    code = str(params.get("code_at_address") or "")
    balance = params.get("balance")
    try:
        balance_i = int(balance) if balance is not None else 0
    except Exception:
        balance_i = 0
    if code and code not in ("0x", "0x0"):
        hits.append(C.hit(
            "create2_predicted_collision",
            f"predicted CREATE2 address {addr} already holds "
            f"deployed code ({len(code) // 2 - 1} bytes): the "
            f"planned deployment collides with an existing "
            f"contract (or the address was pre-deployed).",
            "high",
            "Do not deploy to a colliding CREATE2 address; "
            "change the salt and re-derive, and investigate what "
            "already lives at the predicted address.",
            predicted_address=addr, check="create2_predictor"))
    elif balance_i > 0:
        hits.append(C.hit(
            "create2_predicted_prefunded",
            f"predicted CREATE2 address {addr} already holds a "
            f"balance of {balance_i} wei before deployment: "
            f"counterfactual funds are sitting on an address "
            f"whose future code is not yet fixed.",
            "medium",
            "Treat pre-funded CREATE2 addresses as at-risk: "
            "whoever controls the eventual deployment controls "
            "those funds.",
            predicted_address=addr, balance=balance_i,
            check="create2_predictor"))
    return {"address": addr, "hits": hits}


def analyze(data: Dict[str, Any]):
    for item in data["extras"].get("create2", []):
        if isinstance(item, dict) and item.get("deployer"):
            return analyze_create2(item)["hits"]
    return []


class Create2AddressPredictorPlugin(Plugin):
    id = "create2_address_predictor"
    label = "CREATE2 Address Predictor"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Off-chain CREATE2 predictor: computes the "
                   "future deployment address from deployer, salt "
                   "and init code, and reports collision or "
                   "pre-funded status at that address.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, extras=("create2",),
            source=False, bytecode=False,
            no_input="no CREATE2 parameters supplied: needs a "
                     "create2 record {deployer, salt, init_code}")
