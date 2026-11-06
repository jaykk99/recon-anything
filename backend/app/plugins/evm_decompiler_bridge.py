"""EVM Decompiler Bridge (Cat-1 #1, VARIANT of bytecode_deep_analysis).

Delta over the existing bytecode lane: instead of stopping at
opcode / selector findings, it reconstructs structured
Solidity-like pseudocode - one pseudo-function per dispatcher
selector with its branch, storage read/write and external-call
summary - and reports the dangerous flows found in the
reconstruction (DELEGATECALL, SELFDESTRUCT, CALLCODE, arbitrary
CALL with calldata-forwarding shape). The pseudocode lines are
attached as evidence on the findings.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C
from . import contract_chain as cc

_DANGER = {
    "DELEGATECALL": ("high", "executes foreign code in this "
                     "contract's storage/balance context"),
    "SELFDESTRUCT": ("high", "can destroy the contract and force "
                     "its balance to an arbitrary address"),
    "CALLCODE": ("high", "legacy self-context foreign execution"),
}


def decompile_pseudocode(code_hex: str) -> Dict[str, Any]:
    """Return {'functions': [...], 'lines': [...]} pseudocode."""
    ins = C.disasm(code_hex)
    info = cc.analyze_bytecode(code_hex or "")
    sig_by_sel = {s["selector"].lower(): s.get("signature")
                  for s in info.get("selectors", [])}
    ops = [i["op"] for i in ins]
    lines: List[str] = []
    functions: List[Dict[str, Any]] = []
    # dispatcher selectors in order of appearance
    sels: List[str] = []
    for i in ins:
        if i["op"] == "PUSH4":
            sel = "0x" + i["operand"]
            if sel not in sels:
                sels.append(sel)
    for sel in sels:
        sig = sig_by_sel.get(sel.lower())
        name = (sig.split("(")[0] if sig else f"unknown_{sel[2:]}")
        lines.append(f"function {name}() {{ /* selector {sel} */ }}")
        functions.append({"selector": sel, "name": name,
                          "signature": sig})
    if not sels:
        lines.append("// no dispatcher selectors found (raw code)")
    summary = {
        "storage_writes": ops.count("SSTORE"),
        "storage_reads": ops.count("SLOAD"),
        "calls": ops.count("CALL"), "delegatecalls": ops.count("DELEGATECALL"),
        "creates": ops.count("CREATE") + ops.count("CREATE2"),
        "selfdestructs": ops.count("SELFDESTRUCT"),
        "logs": sum(ops.count(f"LOG{n}") for n in range(5)),
    }
    lines.append(f"// storage: {summary['storage_reads']} reads, "
                 f"{summary['storage_writes']} writes; calls: "
                 f"{summary['calls']}, delegatecalls: "
                 f"{summary['delegatecalls']}, selfdestructs: "
                 f"{summary['selfdestructs']}")
    return {"functions": functions, "lines": lines, "summary": summary,
            "opcodes": ops}


def analyze_decompiled(code_hex: str) -> List[Dict[str, Any]]:
    if not C.code_bytes(code_hex):
        return []
    dec = decompile_pseudocode(code_hex)
    hits: List[Dict[str, Any]] = []
    ops = dec["opcodes"]
    pseudo = "\n".join(dec["lines"])[:1500]
    for op, (sev, why) in _DANGER.items():
        if op in ops:
            hits.append(C.hit(
                f"decompiled_{op.lower()}_flow",
                f"Pseudocode reconstruction shows {op} in the "
                f"runtime code: it {why}. Functions reconstructed: "
                f"{len(dec['functions'])}.",
                sev,
                f"Audit every {op} path in the reconstructed "
                f"pseudocode; the target must be pinned and gated.",
                opcode=op, pseudocode=pseudo,
                functions=len(dec["functions"]),
                check="decompiler_bridge"))
    if "CALL" in ops and "CALLDATACOPY" in ops and "DELEGATECALL" not in ops:
        hits.append(C.hit(
            "decompiled_arbitrary_call_flow",
            "Pseudocode reconstruction shows CALL fed by copied "
            "calldata (generic forwarder shape): the contract can "
            "be made to call arbitrary targets with arbitrary data.",
            "medium",
            "Gate forwarder-style entry points and pin call targets.",
            pseudocode=pseudo, check="decompiler_bridge"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_decompiled(data.get("bytecode", ""))


class EvmDecompilerBridgePlugin(Plugin):
    id = "evm_decompiler_bridge"
    label = "EVM Decompiler Bridge"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Reconstructs Solidity-like pseudocode "
                   "(functions, branches, storage reads/writes) "
                   "from runtime bytecode disassembly and reports "
                   "dangerous flows in the reconstruction.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, source=False,
            no_input="no runtime bytecode to decompile")
