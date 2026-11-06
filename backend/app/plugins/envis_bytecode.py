"""4envis remainder: bytecode SEQUENCE pattern scanner (4naly3r-style).

Coverage map (master dee4763, 853 plugins): bytecode coverage on
master is all PRESENCE-level - contract_chain.analyze_bytecode
(opcode counts + PUSH4 selectors), contract_logic's bytecode lane
(SELFDESTRUCT/DELEGATECALL/CALLCODE presence),
deep_layers.analyze_bytecode_deep (presence + dangerous selector
names), toolbox.parse_heimdall_asm (presence) and the 4byte
selector lookup (identification). No lane reads the ORDER of
instructions in deployed bytecode.

This plugin is the sequence remainder, in the spirit of the
4naly3r/4envis bytecode heuristics - patterns that only exist as
instruction sequences, for contracts with no verified source:

- envis_unchecked_call_result: a CALL / CALLCODE / DELEGATECALL /
  STATICCALL with NO ISZERO result check within the next 8
  instructions - the bytecode shape of an unchecked low-level
  call (source lanes check this in source; unverified contracts
  had no equivalent).
- envis_call_before_state_write: a CALL followed by an SSTORE
  with no ISZERO check between them - the checks-effects-
  interactions violation shape at bytecode level.
- envis_mint_surface_ungated_shape: the dispatcher exposes the
  mint(address,uint256) selector (0x40c10f19) but NO owner()
  selector (0x8da5cb5b) exists anywhere in the bytecode - a
  mint surface with no owner accessor, the selector-combination
  shape presence scans cannot express (deep_layers fires on the
  first dangerous selector name alone and stops).

All findings are labeled bytecode heuristics at capped severity.
Detection only. Never sends a transaction.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from . import contract_chain as cc
from . import tier8_common as t8
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Get the contract source verified and confirm "
               "these bytecode sequence shapes: check every "
               "low-level call's return value, write state before "
               "external calls (checks-effects-interactions), and "
               "gate any mint function behind explicit ownership.")

_CALL_OPS = ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL")
_MINT_SELECTOR = "40c10f19"      # mint(address,uint256)
_OWNER_SELECTOR = "8da5cb5b"     # owner()
_CHECK_WINDOW = 8


def analyze_envis_bytecode(code_hex: str) -> List[Dict[str, Any]]:
    """Bytecode sequence patterns over runtime bytecode (pure)."""
    ins = t8.disassemble(code_hex or "")
    if not ins:
        return []
    names = [i["name"] for i in ins]
    out: List[Dict[str, Any]] = []

    for idx, name in enumerate(names):
        if name not in _CALL_OPS:
            continue
        window = names[idx + 1:idx + 1 + _CHECK_WINDOW]
        if "ISZERO" not in window:
            out.append({
                "kind": "envis_unchecked_call_result",
                "severity": "medium", "bytecode_only": True,
                "detail": f"{name} at bytecode offset "
                          f"{ins[idx]['offset']} is not followed "
                          f"by an ISZERO result check within "
                          f"{_CHECK_WINDOW} instructions - the "
                          "bytecode shape of an unchecked low-level "
                          "call (sequence heuristic)"})
        # first SSTORE after the call, with no ISZERO in between
        for j in range(idx + 1, len(names)):
            if names[j] == "ISZERO":
                break
            if names[j] == "SSTORE":
                out.append({
                    "kind": "envis_call_before_state_write",
                    "severity": "medium", "bytecode_only": True,
                    "detail": f"{name} at bytecode offset "
                              f"{ins[idx]['offset']} is followed "
                              f"by SSTORE at offset "
                              f"{ins[j]['offset']} with no call-"
                              "result check between them - state "
                              "is written after an external call "
                              "(CEI violation shape, sequence "
                              "heuristic)"})
                break
        break  # one call site characterizes the sequence surface

    try:
        info = cc.analyze_bytecode(code_hex)
        sels = {(s.get("selector") or "").lower().removeprefix("0x")
                for s in info.get("selectors") or []}
    except Exception:
        sels = set()
    if _MINT_SELECTOR in sels and _OWNER_SELECTOR not in sels:
        out.append({
            "kind": "envis_mint_surface_ungated_shape",
            "severity": "medium", "bytecode_only": True,
            "detail": "bytecode dispatcher exposes "
                      "mint(address,uint256) (0x40c10f19) but no "
                      "owner() selector (0x8da5cb5b) exists in the "
                      "bytecode - a mint surface with no owner "
                      "accessor (selector-combination heuristic; "
                      "a gate could still exist without an owner "
                      "getter, so this is a lead, not a verdict)"})
    return out


class EnvisBytecodePlugin(Plugin):
    id = "envis_bytecode"
    label = "4envis Bytecode Patterns"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Bytecode SEQUENCE pattern scanner for "
                   "unverified contracts: unchecked call results "
                   "(no ISZERO after CALL), call-before-state-write "
                   "CEI shapes, and mint-selector-without-owner "
                   "combinations. Presence-level bytecode lanes "
                   "already exist; sequence analysis is the "
                   "remainder.")
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
            for hit in analyze_envis_bytecode(code):
                ev = {"severity": hit["severity"],
                      "tool": "4envis", "bytecode_only": True,
                      "address": art.get("address", ""),
                      "remediation": REMEDIATION}
                findings.append(self._f(
                    "web3", hit["kind"],
                    f"{hit['severity'].upper()}: 4envis bytecode: "
                    f"{hit['detail']}",
                    source="envis_bytecode (native)",
                    confidence=55, passive=True, evidence=ev))
        if not used:
            res = self._skipped("no contract bytecode supplied or "
                                "found for 4envis patterns")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        res = self._ok(findings, f"4envis bytecode patterns over "
                                 f"{used} artifact(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
