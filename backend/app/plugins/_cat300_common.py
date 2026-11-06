"""Shared scaffolding for the 300-expansion Category-1 (EVM) plugins.

Not a plugin itself (defines no Plugin subclass, so the registry
skips it). Each Cat-1 plugin keeps its analysis in a pure function
and a thin Plugin wrapper; this module holds the input collection
(source / bytecode / structured extras from the discovery bus or the
target itself), the keyless live fallback (public RPC + Sourcify /
Blockscout via chain_data, exactly like contract_logic), a small
EVM disassembler, a Solidity function splitter, and the finding
emitter (including the mechanical UNVERIFIED stamp for the local
simulation plugins: reentrancy-path-finder, flashloan-simulator,
ether-forcing-tester - local fixtures/forks ONLY, no live tx).
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .base import Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc

ALL_KINDS = (
    "contract_source", "source_code", "verified_source",
    "contract_bytecode", "bytecode", "storage_samples", "state_trace",
    "oracle_samples", "oracle_prices", "create2", "role_members",
    "roles", "role_data", "bytecode_pair", "bytecode_old",
    "bytecode_new", "trace", "traces", "immutable_refs",
    "constructor_args", "constructor_abi", "fallback_probes",
    "flashloan_scenario", "chain_contracts", "contract_addresses",
    "crypto_addresses",
)

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{40,}$")


def looks_like_source(text: str) -> bool:
    t = text or ""
    return any(m in t for m in (
        "contract ", "pragma solidity", "function ", "@version",
        "def ", "interface ", "library ", "object \"", "assembly"))


def collect(target: Target, ctx: Ctx) -> Dict[str, Any]:
    data: Dict[str, Any] = {"source": "", "bytecode": "", "abi": None,
                            "extras": {}, "address": "", "chain": ""}

    def feed(kind: str, item: Any) -> None:
        data["extras"].setdefault(kind, []).append(item)
        if isinstance(item, str):
            t = item.strip()
            if kind in ("contract_bytecode", "bytecode",
                        "bytecode_old", "bytecode_new") and \
                    re.match(r"^0x[0-9a-fA-F]{6,}$", t):
                if not data["bytecode"]:
                    data["bytecode"] = t
            elif _HEX_RE.match(t):
                if not data["bytecode"]:
                    data["bytecode"] = t
            elif looks_like_source(t):
                data["source"] = (data["source"] + "\n" + t).strip()
        elif isinstance(item, dict):
            for key in ("source", "SourceCode", "source_code", "text"):
                v = item.get(key)
                if isinstance(v, str) and looks_like_source(v):
                    data["source"] = (data["source"] + "\n" + v).strip()
            for key in ("bytecode", "runtime_code", "code_hex"):
                v = item.get(key)
                if isinstance(v, str) and _HEX_RE.match(v.strip()):
                    if not data["bytecode"]:
                        data["bytecode"] = v.strip()
            if isinstance(item.get("abi"), (list, dict)):
                data["abi"] = item["abi"]
            addr = item.get("address")
            if isinstance(addr, str) and _ADDR_RE.match(addr.strip()):
                if not data["address"]:
                    data["address"] = addr.strip()

    for kind in ALL_KINDS:
        try:
            items = ctx.consume(kind)
        except Exception:
            items = []
        for item in items or []:
            try:
                feed(kind, item)
            except Exception:
                continue
    raw = (target.normalized or target.raw or "").strip()
    if raw:
        try:
            hint, addr = cc.parse_target_address(raw)
            if addr:
                data["address"] = addr
                data["chain"] = hint or ""
        except Exception:
            pass
        if _ADDR_RE.match(raw):
            data["address"] = raw
        else:
            feed("target", raw)
    return data


def relevant(data: Dict[str, Any], extras: Tuple[str, ...] = (),
             source: bool = True, bytecode: bool = True) -> bool:
    if source and data.get("source"):
        return True
    if bytecode and data.get("bytecode"):
        return True
    return any(data["extras"].get(k) for k in extras)


async def fetch_live(ctx: Ctx, data: Dict[str, Any]) -> None:
    """Keyless live fallback: eth_getCode + verified source for the
    target address (ethereum by default, chain hint when given)."""
    addr = data.get("address")
    if not addr:
        return
    try:
        from . import chain_data
        chain = cc.CHAINS.get(data.get("chain") or "ethereum")
        if chain is None:
            chain = cc.CHAINS["ethereum"]
        try:
            code = await asyncio.wait_for(
                chain_data.get_code(ctx, chain, addr), timeout=25)
            if code and code != "0x":
                data["bytecode"] = code
        except Exception:
            pass
        try:
            src = await asyncio.wait_for(
                chain_data.get_source(ctx, chain, addr), timeout=25)
            if src and isinstance(src.get("source"), str):
                data["source"] = src["source"]
                data["abi"] = data["abi"] or src.get("abi")
        except Exception:
            pass
    except Exception:
        pass


def emit(plugin: Plugin, hits: List[Dict[str, Any]],
         stamp: bool = False) -> List[Finding]:
    out: List[Finding] = []
    for h in hits or []:
        ev: Dict[str, Any] = dict(h.get("evidence") or {})
        ev["severity"] = h.get("severity", "low")
        if h.get("remediation"):
            ev["remediation"] = h["remediation"]
        value = str(h.get("value", ""))
        if stamp:
            ev.update({"unverified": True, "sim_derived": True,
                       "not_verified_real": True})
            if not value.startswith("UNVERIFIED (sim): "):
                value = "UNVERIFIED (sim): " + value
        out.append(plugin._f(
            "web3", str(h.get("key", plugin.id)), value,
            source=plugin.label, confidence=int(h.get("confidence", 80)),
            evidence=ev))
    return out


async def finish(plugin: Plugin, target: Target, ctx: Ctx,
                 analyze: Callable[[Dict[str, Any]], List[Dict[str, Any]]],
                 extras: Tuple[str, ...] = (), fetch: bool = False,
                 stamp: bool = False, no_input: str = "no input",
                 source: bool = True, bytecode: bool = True
                 ) -> PluginResult:
    t0 = time.monotonic()
    try:
        data = collect(target, ctx)
    except Exception:
        data = {"source": "", "bytecode": "", "abi": None, "extras": {},
                "address": "", "chain": ""}
    if fetch and not relevant(data, extras, source, bytecode):
        await fetch_live(ctx, data)
    if not relevant(data, extras, source, bytecode):
        res = plugin._skipped(no_input)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
    try:
        hits = analyze(data)
    except Exception as exc:  # never raise fatally
        res = plugin._degraded(f"analysis degraded: {type(exc).__name__}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
    findings = emit(plugin, hits, stamp=stamp)
    res = plugin._ok(findings, f"{len(findings)} finding(s) from "
                               f"{plugin.label}")
    res.duration_ms = int((time.monotonic() - t0) * 1000)
    return res


# ---------------------------------------------------------------------------
# EVM disassembly (PUSH-aware linear walk)
# ---------------------------------------------------------------------------

_OPNAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x06: "MOD", 0x10: "LT", 0x11: "GT", 0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1B: "SHL",
    0x1C: "SHR", 0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE",
    0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
    0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY",
    0x3B: "EXTCODESIZE", 0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH",
    0x42: "TIMESTAMP", 0x43: "NUMBER", 0x47: "SELFBALANCE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x5B: "JUMPDEST",
    0x80: "DUP1", 0x90: "SWAP1", 0xA0: "LOG0", 0xA1: "LOG1",
    0xA2: "LOG2", 0xA3: "LOG3", 0xA4: "LOG4", 0xF0: "CREATE",
    0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT",
    0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}


def code_bytes(code_hex: str) -> bytes:
    h = (code_hex or "").strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    h = re.sub(r"[^0-9a-f]", "", h)
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""


def disasm(code_hex: str) -> List[Dict[str, Any]]:
    code = code_bytes(code_hex)
    out: List[Dict[str, Any]] = []
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            operand = code[i + 1:i + 1 + n]
            out.append({"offset": i, "op": f"PUSH{n}",
                        "opcode": op, "operand": operand.hex()})
            i += 1 + n
            continue
        out.append({"offset": i, "op": _OPNAMES.get(op, f"OP_{op:02x}"),
                    "opcode": op, "operand": ""})
        i += 1
    return out


# ---------------------------------------------------------------------------
# Solidity source helpers
# ---------------------------------------------------------------------------

def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src or "", flags=re.S)
    return re.sub(r"//[^\n]*", " ", src)


_FUNC_RE = re.compile(
    r"function\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)([^{;]*)\{", re.S)
_SPECIAL_RE = re.compile(
    r"(fallback|receive)\s*\(([^)]*)\)([^{;]*)\{", re.S)


def _body_at(src: str, brace_pos: int) -> str:
    depth = 0
    for i in range(brace_pos, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[brace_pos + 1:i]
    return src[brace_pos + 1:]


def functions(src: str) -> List[Dict[str, str]]:
    """Split Solidity source into function records (name/header/body)."""
    clean = strip_comments(src or "")
    out: List[Dict[str, str]] = []
    for m in _FUNC_RE.finditer(clean):
        out.append({"name": m.group(1), "args": m.group(2),
                    "header": (m.group(0)[:200]),
                    "mods": m.group(3),
                    "body": _body_at(clean, m.end() - 1)})
    for m in _SPECIAL_RE.finditer(clean):
        out.append({"name": m.group(1), "args": m.group(2),
                    "header": m.group(0)[:200], "mods": m.group(3),
                    "body": _body_at(clean, m.end() - 1)})
    return out


def state_vars(src: str) -> List[Dict[str, Any]]:
    """Contract-level state variable declarations (name/type/modifiers)."""
    clean = strip_comments(src or "")
    # remove function bodies so locals are not mistaken for state vars
    out: List[Dict[str, Any]] = []
    decl_re = re.compile(
        r"(?m)^\s*(address|bool|uint\d*|int\d*|bytes\d*|string|bytes|"
        r"mapping\s*\([^;]+?\)|[\w\[\]]+\[\])\s+"
        r"((?:public|private|internal|constant|immutable)\s+)*"
        r"([A-Za-z_][\w]*)\s*(?:=[^;]*)?;")
    depth = 0
    lines: List[str] = []
    for line in clean.splitlines():
        if depth <= 1:
            lines.append(line)
        depth += line.count("{") - line.count("}")
    flat = "\n".join(lines)
    for m in decl_re.finditer(flat):
        out.append({"type": m.group(1), "mods": (m.group(2) or "").strip(),
                    "name": m.group(3)})
    return out


def hit(key: str, value: str, severity: str = "low",
        remediation: str = "", **evidence: Any) -> Dict[str, Any]:
    return {"key": key, "value": value, "severity": severity,
            "remediation": remediation, "evidence": evidence}
