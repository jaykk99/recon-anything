"""Per-selector bytecode path analysis for contracts with no
verified source.

The legacy bytecode lane in contract_logic counted risky opcodes
globally and emitted one low finding ("the bytecode contains
SELFDESTRUCT x1, DELEGATECALL x1"). That says a capability exists
SOMEWHERE in the code; it does not say which externally callable
function reaches it, which is the difference between an alarming
contract and an unremarkable one (a benign store() sitting next
to a kill() in the same dispatcher).

This module adds the missing attribution layer:

- Linear disassembly of the runtime bytecode (PUSHn immediates
  are data, never opcodes - the same walk contract_chain uses).
- Recognition of the standard solc selector dispatcher:
  PUSH4 <selector>, EQ, PUSHn <target>, JUMPI, in the orderings
  solc emits (with or without a DUP1 of the calldata selector in
  between, and with small instructions tolerated between the
  compare and the conditional jump).
- From each dispatch target, a bounded block-to-block walk
  (unconditional JUMPs followed to indexed JUMPDESTs, JUMPI
  targets explored as alternative blocks, STOP / RETURN /
  REVERT / SELFDESTRUCT / INVALID terminate a block, ~600
  instruction cap, visited set against loops) collecting the
  opcode names in visit order, the sensitive opcodes reached
  (CALL, CALLCODE, DELEGATECALL, SELFDESTRUCT, CREATE, CREATE2)
  and SLOAD / SSTORE slots when the slot is a PUSHn immediate
  directly preceding the storage opcode.
- EIP-1167 minimal-proxy detection, delegated to
  contract_chain.analyze_bytecode (the proxy has no logic of its
  own; its implementation address is the finding).

Detection only: this module never executes a call, never submits
a transaction, and produces data (paths and, one layer up, inert
eth_call probe sketches) for a human / validator to act on.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import contract_chain as cc

# ---------------------------------------------------------------------------
# Opcode table
# ---------------------------------------------------------------------------

_NAMES: Dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB",
    0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
    0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
    0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR",
    0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR",
    0x1D: "SAR",
    0x20: "SHA3",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN",
    0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP",
    0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE",
    0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
    0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY", 0x5F: "PUSH0",
    0xA0: "LOG0", 0xA1: "LOG1", 0xA2: "LOG2", 0xA3: "LOG3",
    0xA4: "LOG4",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE",
    0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2",
    0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

SENSITIVE_OPCODES = (
    "CALL", "CALLCODE", "DELEGATECALL", "SELFDESTRUCT",
    "CREATE", "CREATE2")

_TERMINATORS = frozenset(
    {"STOP", "RETURN", "REVERT", "SELFDESTRUCT", "INVALID"})

_MAX_STEPS = 600


def _opcode_name(op: int) -> str:
    if 0x60 <= op <= 0x7F:
        return f"PUSH{op - 0x5F}"
    if 0x80 <= op <= 0x8F:
        return f"DUP{op - 0x7F}"
    if 0x90 <= op <= 0x9F:
        return f"SWAP{op - 0x8F}"
    return _NAMES.get(op, f"OP_{op:02X}")


class _Instr:
    __slots__ = ("offset", "opcode", "name", "push_value",
                 "push_size")

    def __init__(self, offset: int, opcode: int,
                 push_value: Optional[int] = None,
                 push_size: int = 0):
        self.offset = offset
        self.opcode = opcode
        self.name = _opcode_name(opcode)
        self.push_value = push_value
        self.push_size = push_size

    @property
    def is_push(self) -> bool:
        return self.opcode == 0x5F or 0x60 <= self.opcode <= 0x7F


def _disassemble(code: bytes) -> List[_Instr]:
    """Linear disassembly: PUSHn immediates are data."""
    out: List[_Instr] = []
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            n = op - 0x5F
            data = code[i + 1:i + 1 + n]
            value = int.from_bytes(data, "big") if data else 0
            out.append(_Instr(i, op, value, n))
            i += 1 + n
            continue
        out.append(_Instr(i, op, 0 if op == 0x5F else None,
                          0 if op == 0x5F else 0))
        i += 1
    return out


def _slot_repr(value: int):
    """Storage slots are reported as ints when they fit a machine
    word comfortably, else as a hex string."""
    if value < 1 << 64:
        return value
    return "0x%064x" % value


# ---------------------------------------------------------------------------
# Dispatcher recognition
# ---------------------------------------------------------------------------

def _find_dispatcher(instrs: List[_Instr]) -> Dict[int, int]:
    """Map selector int -> dispatch target offset.

    Pattern (solc, both the classic and the DUP1-first ordering):
    a PUSH4 selector compared with EQ, followed by a PUSHn jump
    target and a JUMPI. The selector push may sit up to 3
    instructions before the EQ (DUP1 / SWAP shapes), and the
    target push must be the first push after the EQ with the
    JUMPI immediately behind it.
    """
    routes: Dict[int, int] = {}
    for idx, ins in enumerate(instrs):
        if ins.name != "EQ":
            continue
        selector = None
        for back in range(idx - 1, max(idx - 4, -1), -1):
            cand = instrs[back]
            if cand.is_push and cand.push_size == 4:
                selector = cand.push_value
                break
            if cand.name in ("CALLDATALOAD", "SHR", "AND"):
                continue
        if selector is None:
            continue
        target = None
        for fwd in range(idx + 1, min(idx + 4, len(instrs))):
            cand = instrs[fwd]
            if cand.is_push:
                if fwd + 1 < len(instrs) and \
                        instrs[fwd + 1].name == "JUMPI":
                    target = cand.push_value
                break
            if cand.name in ("DUP1", "DUP2", "SWAP1"):
                continue
            break
        if target is None:
            continue
        if selector not in routes:
            routes[selector] = target
    return routes


# ---------------------------------------------------------------------------
# Path walk
# ---------------------------------------------------------------------------

def _walk_path(start: int, by_offset: Dict[int, _Instr],
               ordered: List[int],
               jumpdests: frozenset) -> Dict[str, Any]:
    """Walk forward from a dispatch target, block to block.

    Returns opcode names in visit order, the sensitive opcodes
    reached, and the statically-known SLOAD / SSTORE slots.
    """
    index = {off: i for i, off in enumerate(ordered)}
    opcodes: List[str] = []
    sensitive: List[str] = []
    reads: List[Any] = []
    writes: List[Any] = []
    visited_instr = set()
    visited_blocks = set()
    worklist: List[int] = [start]
    steps = 0
    while worklist and steps < _MAX_STEPS:
        block = worklist.pop(0)
        if block in visited_blocks or block not in by_offset:
            continue
        visited_blocks.add(block)
        prev: Optional[_Instr] = None
        pos = index[block]
        while pos < len(ordered) and steps < _MAX_STEPS:
            ins = by_offset[ordered[pos]]
            if ins.offset in visited_instr:
                break  # loop back into already-walked code
            visited_instr.add(ins.offset)
            opcodes.append(ins.name)
            steps += 1
            if ins.name in SENSITIVE_OPCODES and \
                    ins.name not in sensitive:
                sensitive.append(ins.name)
            if ins.name in ("SLOAD", "SSTORE") and prev is not None \
                    and prev.is_push and prev.push_value is not None:
                slot = _slot_repr(prev.push_value)
                bucket = reads if ins.name == "SLOAD" else writes
                if slot not in bucket:
                    bucket.append(slot)
            if ins.name in _TERMINATORS:
                break
            if ins.name == "JUMP":
                if prev is not None and prev.is_push and \
                        prev.push_value in jumpdests:
                    worklist.append(prev.push_value)
                break  # unconditional: no fall-through
            if ins.name == "JUMPI":
                if prev is not None and prev.is_push and \
                        prev.push_value in jumpdests:
                    worklist.append(prev.push_value)
                # fall through to the not-taken branch
            prev = ins
            pos += 1
    return {"opcodes": opcodes, "sensitive_opcodes": sensitive,
            "storage_reads": reads, "storage_writes": writes}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze(code_hex: str) -> Dict[str, Any]:
    """Analyze runtime bytecode: dispatcher, per-selector paths,
    and EIP-1167 minimal-proxy detection.

    Returns {dispatcher_found, minimal_proxy_impl, selectors}:
    each selector entry carries the selector, its known signature
    (contract_chain.SELECTOR_TABLE, else None), the dispatch
    target offset, the opcode names on the walked path, the
    sensitive opcodes reached, and statically-known storage
    read / write slots.
    """
    out: Dict[str, Any] = {"dispatcher_found": False,
                           "minimal_proxy_impl": None,
                           "selectors": []}
    h = (code_hex or "").strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    try:
        code = bytes.fromhex(h) if h else b""
    except ValueError:
        return out
    if not code:
        return out

    out["minimal_proxy_impl"] = \
        cc.analyze_bytecode(code_hex).get("minimal_proxy_impl")

    instrs = _disassemble(code)
    if not instrs:
        return out
    by_offset = {ins.offset: ins for ins in instrs}
    ordered = [ins.offset for ins in instrs]
    jumpdests = frozenset(
        ins.offset for ins in instrs if ins.name == "JUMPDEST")

    routes = _find_dispatcher(instrs)
    if not routes:
        return out
    out["dispatcher_found"] = True
    for selector, target in routes.items():
        sel_hex = "%08x" % selector
        path = _walk_path(target, by_offset, ordered, jumpdests) \
            if target in by_offset else {
                "opcodes": [], "sensitive_opcodes": [],
                "storage_reads": [], "storage_writes": []}
        out["selectors"].append({
            "selector": "0x" + sel_hex,
            "signature": cc.SELECTOR_TABLE.get(sel_hex),
            "offset": target,
            "opcodes": path["opcodes"],
            "sensitive_opcodes": path["sensitive_opcodes"],
            "storage_reads": path["storage_reads"],
            "storage_writes": path["storage_writes"],
        })
    return out
