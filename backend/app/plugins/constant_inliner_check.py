"""Constant Inliner Check (Cat-1 #23, VARIANT of bytecode_deep_analysis).

Delta: PUSH-operand constant extraction. The optimizer inlines
constants into deployed bytecode; this plugin collects every
PUSH8..PUSH32 operand, classifies the value (address-shaped,
small number, high-entropy / secret-shaped), and cross-checks it
against constants declared in verified source when supplied. A
high-entropy 32-byte constant that appears NOWHERE in the source
is reported - masked and fingerprinted only (first 4 / last 2
bytes + sha256 fingerprint), never in full - as a possible
hardcoded secret baked into the deployed code.
"""
from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    ent = 0.0
    for n in counts.values():
        p = n / len(data)
        ent -= p * math.log2(p)
    return ent


def extract_inlined_constants(code_hex: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for ins in C.disasm(code_hex or ""):
        if not ins["op"].startswith("PUSH"):
            continue
        try:
            n = int(ins["op"][4:])
        except ValueError:
            continue
        if n < 8:
            continue
        operand = ins["operand"]
        if operand in seen:
            continue
        seen.add(operand)
        raw = bytes.fromhex(operand) if operand else b""
        out.append({"offset": ins["offset"], "push": n,
                    "hex": operand, "entropy": round(_entropy(raw), 2),
                    "is_address_shaped": n == 20 or (
                        n == 32 and raw[:12] == b"\x00" * 12)})
    return out


def analyze_constants(code_hex: str, source: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    src_hex = (source or "").lower()
    for cst in extract_inlined_constants(code_hex):
        if cst["is_address_shaped"]:
            continue
        if cst["push"] < 16:
            continue
        if cst["hex"] in src_hex:
            continue  # declared in source: not a hidden inline
        if cst["entropy"] < 3.5:
            continue  # structured / low-entropy data, not secret-shaped
        fp = hashlib.sha256(bytes.fromhex(cst["hex"])).hexdigest()[:16]
        masked = cst["hex"][:8] + "..." + cst["hex"][-4:]
        hits.append(C.hit(
            "constant_inlined_secret_shaped",
            f"PUSH{cst['push']} at offset {cst['offset']} inlines "
            f"a high-entropy constant (entropy {cst['entropy']}) "
            f"that appears nowhere in the verified source: "
            f"{masked} (sha256 fingerprint {fp}). Optimizer-"
            f"inlined constants are public - if this is a key or "
            f"secret, it is exposed to every bytecode reader.",
            "medium",
            "Never hardcode secrets in contracts: bytecode is "
            "public. Rotate anything this constant represents "
            "and move secrets off-chain.",
            offset=cst["offset"], push=cst["push"],
            entropy=cst["entropy"], fingerprint=fp, masked=masked,
            check="constant_inliner"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_constants(data.get("bytecode", ""),
                             data.get("source", ""))


class ConstantInlinerCheckPlugin(Plugin):
    id = "constant_inliner_check"
    label = "Constant Inliner Check"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Extracts PUSH-inlined constants from runtime "
                   "bytecode, classifies secret-shaped / "
                   "high-entropy values, and cross-checks them "
                   "against verified source (masked output only).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True,
            no_input="no runtime bytecode to extract inlined "
                     "constants from")
