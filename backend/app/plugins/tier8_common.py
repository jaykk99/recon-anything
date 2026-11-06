"""Tier-8 (Static Analysis & Smart Contract AST Parsing) shared helpers.

The Tier-8 remainder plugins analyze contract SOURCE / BYTECODE
supplied as run artifacts, the same way the existing web3 analyzer
plugins (contract_logic, audit_toolbox, deep_layers) consume the
verified source / deployed bytecode for a target:

1. Artifacts already in the run: another lane may publish the
   material on the discovery bus - ctx.shared["contract_source"]
   (a Solidity source string, or a fetch_verified_source-style
   dict with a "source" key), ctx.shared["contract_sources"]
   (a list of either), ctx.shared["contract_bytecode"] /
   ctx.shared["bytecode"] (runtime bytecode hex). Tests and
   offline harnesses use exactly this seam.
2. Otherwise, when the target itself is a contract address
   (optionally chain-prefixed), the keyless contract_chain routes
   fetch verified source + deployed bytecode, exactly like
   audit_toolbox._collect / deep_layers.collect_targets.

Also here: a small linear EVM disassembler (PUSH immediates are
data, never opcodes) shared by the bytecode-sequence plugins
(oyente_bytecode, envis_bytecode). contract_chain.analyze_bytecode
already walks the same way for opcode PRESENCE; the Tier-8
bytecode plugins need the ordered instruction SEQUENCE, which no
existing lane exposes.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from . import contract_chain as cc
from .base import Ctx, Target

MAX_ARTIFACTS = 3

_SOURCE_KINDS = ("contract_source", "contract_sources", "source_code",
                 "solidity_source")
_BYTECODE_KINDS = ("contract_bytecode", "bytecode", "runtime_bytecode")


def _as_source_text(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(item.get("source") or "")
    return ""


def _as_bytecode_hex(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(item.get("bytecode") or item.get("code") or "")
    return ""


def artifacts_from_shared(ctx: Ctx) -> List[Dict[str, Any]]:
    """Artifacts published on the discovery bus, if any."""
    sources: List[str] = []
    codes: List[str] = []
    for kind in _SOURCE_KINDS:
        for item in ctx.shared.get(kind, []) or []:
            text = _as_source_text(item)
            if text and text not in sources:
                sources.append(text)
    for kind in _BYTECODE_KINDS:
        for item in ctx.shared.get(kind, []) or []:
            hx = _as_bytecode_hex(item)
            if hx and hx not in codes:
                codes.append(hx)
    out: List[Dict[str, Any]] = []
    for i in range(max(len(sources), len(codes))):
        out.append({
            "source": sources[i] if i < len(sources) else "",
            "bytecode": codes[i] if i < len(codes) else "",
            "address": "", "chain": "", "name": "",
        })
    return out[:MAX_ARTIFACTS]


async def collect_artifacts(target: Target, ctx: Ctx
                            ) -> List[Dict[str, Any]]:
    """Shared-bus artifacts first; otherwise fetch for an address
    target via the keyless contract_chain routes (never raises)."""
    shared = artifacts_from_shared(ctx)
    if shared:
        return shared
    chain_hint, addr = cc.parse_target_address(
        target.normalized or target.raw or "")
    if not addr:
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str((item or {}).get("address", ""))
                if cc.ADDRESS_RE.match(a or ""):
                    chain_hint, addr = None, a
                    break
            if addr:
                break
    if not addr:
        return []
    key = ctx.keys.get("etherscan") or \
        os.environ.get("ETHERSCAN_API_KEY") or None
    chain_ids = [chain_hint] if chain_hint else \
        list(cc.DEFAULT_CHAIN_ORDER)
    out: List[Dict[str, Any]] = []
    for cid in chain_ids[:3]:
        chain = cc.CHAINS[cid]
        try:
            code = await cc.rpc_get_code(ctx, chain, addr)
        except Exception:
            code = None
        if code is None or code == "0x" or len(code) < 4:
            continue
        src = None
        try:
            src = await cc.fetch_verified_source(ctx, chain, addr, key)
        except Exception:
            src = None
        out.append({
            "source": (src or {}).get("source") or "",
            "bytecode": code or "",
            "address": addr, "chain": chain.id,
            "name": (src or {}).get("contract_name") or "",
        })
        break
    return out[:MAX_ARTIFACTS]


# ---------------------------------------------------------------------------
# Linear EVM disassembly (ordered instruction sequence)
# ---------------------------------------------------------------------------

_OPCODE_NAMES: Dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB",
    0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
    0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
    0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR",
    0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR",
    0x1D: "SAR", 0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN",
    0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP",
    0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
    0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
    0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
    0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}


def disassemble(code_hex: str) -> List[Dict[str, Any]]:
    """Linear disassembly: [{offset, op, name, push}] in order.

    PUSHn immediates are consumed as data (a 0x42 byte inside a
    PUSH is not a TIMESTAMP). Malformed / non-hex input yields [].
    """
    h = (code_hex or "").strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    if not h or len(h) % 2 or re.search(r"[^0-9a-f]", h):
        return []
    try:
        code = bytes.fromhex(h)
    except ValueError:
        return []
    out: List[Dict[str, Any]] = []
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            n = op - 0x5F
            data = code[i + 1:i + 1 + n]
            out.append({"offset": i, "op": op,
                        "name": f"PUSH{n}", "push": data.hex()})
            i += 1 + n
            continue
        if 0x80 <= op <= 0x8F:
            name = f"DUP{op - 0x7F}"
        elif 0x90 <= op <= 0x9F:
            name = f"SWAP{op - 0x8F}"
        elif 0xA0 <= op <= 0xA4:
            name = f"LOG{op - 0xA0}"
        else:
            name = _OPCODE_NAMES.get(op, f"OP_{op:02x}")
        out.append({"offset": i, "op": op, "name": name, "push": ""})
        i += 1
    return out


def opcode_names(code_hex: str) -> List[str]:
    return [ins["name"] for ins in disassemble(code_hex)]
