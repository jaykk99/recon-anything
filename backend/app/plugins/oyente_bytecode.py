"""Oyente remainder: classic EVM BYTECODE checks (Oyente-style).

Coverage map (master dee4763, 853 plugins): Oyente's four classic
classes are covered at SOURCE level (contract_logic overflow /
timestamp lanes, cp_proto_timestamp_randomness) and the symbolic
lane (Mythril via contract_sim + audit_toolbox) covers the
callstack-depth class with real path exploration. What no lane
does is Oyente's original surface - the classes read directly off
DEPLOYED BYTECODE for contracts with no verified source:

- contract_logic.analyze_logic_bytecode reports ONLY
  SELFDESTRUCT / DELEGATECALL / CALLCODE presence.
- deep_layers.analyze_bytecode_deep reports those opcodes plus
  dangerous PUSH4 selectors.
- toolbox.parse_heimdall_asm reports SELFDESTRUCT / DELEGATECALL
  / CALLCODE / CREATE2 presence.

None of them reads TIMESTAMP, arithmetic-vs-compiler-version, or
call gas handling off bytecode. This plugin ships exactly that
Oyente remainder, as labeled bytecode heuristics (low/medium,
never a confirmed verdict):

- oyente_timestamp_dependence: TIMESTAMP opcode in the runtime.
- oyente_timestamp_state_write: TIMESTAMP + SSTORE - block time
  flows into persistent state (Oyente's timestamp-dependence /
  transaction-ordering shape).
- oyente_pre08_integer_overflow: CBOR metadata solc < 0.8.0 (or a
  caller-supplied compiler version) AND arithmetic opcodes
  (ADD/MUL/SUB) present - pre-0.8 arithmetic wraps silently.
- oyente_callstack_depth_risk: a CALL/CALLCODE whose operand
  setup never reads the GAS opcode - the call's gas is not
  derived from the remaining-gas check Oyente's callstack-depth
  analysis looks for (1024-depth failure shape).

Detection only. Never sends a transaction.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from . import contract_chain as cc
from . import tier8_common as t8
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Verify these bytecode heuristics against the "
               "contract source when it becomes available: do not "
               "let block.timestamp decide value outcomes, compile "
               "with Solidity >= 0.8 (checked arithmetic), and "
               "bound external-call gas explicitly.")

_ARITHMETIC = ("ADD", "MUL", "SUB")


def _version_tuple(text: str) -> Optional[tuple]:
    parts = []
    for chunk in str(text or "").strip().split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            return None
    return tuple(parts) if parts else None


def analyze_oyente_bytecode(code_hex: str, compiler: str = ""
                            ) -> List[Dict[str, Any]]:
    """Oyente-style classes over runtime bytecode (pure)."""
    ins = t8.disassemble(code_hex or "")
    if not ins:
        return []
    names = [i["name"] for i in ins]
    present = set(names)
    out: List[Dict[str, Any]] = []
    info = {}
    try:
        info = cc.analyze_bytecode(code_hex)
    except Exception:
        info = {}
    meta_solc = ((info.get("metadata") or {}).get("solc")) or ""
    version = _version_tuple(compiler) or _version_tuple(meta_solc)

    if "TIMESTAMP" in present:
        out.append({
            "kind": "oyente_timestamp_dependence",
            "severity": "medium", "bytecode_only": True,
            "detail": "runtime bytecode executes TIMESTAMP: block "
                      "time is read by deployed code with no "
                      "verified source (Oyente timestamp-"
                      "dependence class, bytecode heuristic)"})
        if "SSTORE" in present:
            out.append({
                "kind": "oyente_timestamp_state_write",
                "severity": "medium", "bytecode_only": True,
                "detail": "runtime bytecode executes TIMESTAMP and "
                          "SSTORE: block time can flow into "
                          "persistent state, so miners / ordering "
                          "can influence stored outcomes (Oyente "
                          "TOD shape, bytecode heuristic)"})
    arith = [n for n in _ARITHMETIC if n in present]
    if version and version < (0, 8, 0) and arith:
        out.append({
            "kind": "oyente_pre08_integer_overflow",
            "severity": "medium", "bytecode_only": True,
            "detail": f"bytecode was compiled with solc "
                      f"{'.'.join(str(x) for x in version)} "
                      f"(< 0.8.0, no checked arithmetic) and "
                      f"executes {', '.join(arith)}: integer "
                      "overflow/underflow wraps silently (Oyente "
                      "integer-overflow class, bytecode heuristic)"})
    for idx, name in enumerate(names):
        if name in ("CALL", "CALLCODE"):
            window = names[max(0, idx - 12):idx]
            if "GAS" not in window and "GAS" not in present:
                out.append({
                    "kind": "oyente_callstack_depth_risk",
                    "severity": "low", "bytecode_only": True,
                    "detail": "runtime bytecode makes a CALL whose "
                              "gas operand is never derived from "
                              "the GAS opcode: no remaining-gas "
                              "awareness before the call (Oyente "
                              "callstack-depth shape, bytecode "
                              "heuristic)"})
            break
    return out


class OyenteBytecodePlugin(Plugin):
    id = "oyente_bytecode"
    label = "Oyente Bytecode Checks"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Oyente-style classic checks over deployed "
                   "BYTECODE for unverified contracts: timestamp "
                   "dependence, timestamp-driven state writes, "
                   "pre-0.8 arithmetic overflow surface, and "
                   "callstack-depth gas shape. Bytecode heuristics "
                   "only - no verified source required.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            artifacts = await t8.collect_artifacts(target, ctx)
        except Exception as e:
            res = self._degraded(f"artifact collection failed: "
                                 f"{str(e)[:120]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        used = 0
        for art in artifacts:
            code = art.get("bytecode") or ""
            if not code:
                continue
            used += 1
            for hit in analyze_oyente_bytecode(code):
                ev = {"severity": hit["severity"],
                      "tool": "oyente", "bytecode_only": True,
                      "address": art.get("address", ""),
                      "remediation": REMEDIATION}
                findings.append(self._f(
                    "web3", hit["kind"],
                    f"{hit['severity'].upper()}: oyente bytecode: "
                    f"{hit['detail']}",
                    source="oyente_bytecode (native)",
                    confidence=55, passive=True, evidence=ev))
        if not used:
            res = self._skipped("no contract bytecode supplied or "
                                "found for Oyente checks")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        res = self._ok(findings, f"oyente bytecode checks over "
                                 f"{used} artifact(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
