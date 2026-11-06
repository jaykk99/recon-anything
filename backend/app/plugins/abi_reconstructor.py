"""ABI Reconstructor (Cat-1 #4, VARIANT of bytecode_deep_analysis).

Delta: assemble a clean ABI JSON artifact for bytecode-only
contracts - function entries for every dispatcher selector, with
signatures resolved from the known-selector table when possible,
and unknown selectors reported as unresolved entries (never
dropped). Event candidates are taken from LOG-heavy code paths
when topic hashes are supplied. Findings fire on unresolved
selectors (interface surface nobody can name) and on resolved
dangerous functions (delegatecall-style / selfdestruct-style
entry points) present in an unverified contract.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C
from . import contract_chain as cc

_DANGEROUS_WORDS = ("delegatecall", "selfdestruct", "sweep", "rescue",
                    "emergencywithdraw", "execute", "multicall")


def reconstruct_abi(code_hex: str) -> List[Dict[str, Any]]:
    info = cc.analyze_bytecode(code_hex or "")
    abi: List[Dict[str, Any]] = []
    for s in info.get("selectors", []):
        sig: Optional[str] = s.get("signature")
        if sig:
            name = sig.split("(")[0]
            inner = sig[sig.find("(") + 1:sig.rfind(")")]
            types = [t.strip() for t in inner.split(",") if t.strip()]
            abi.append({"type": "function", "name": name,
                        "selector": s["selector"],
                        "inputs": [{"name": f"arg{i}", "type": t}
                                   for i, t in enumerate(types)],
                        "outputs": [], "stateMutability": "nonpayable",
                        "resolved": True})
        else:
            abi.append({"type": "function",
                        "name": f"unknown_{s['selector'][2:]}",
                        "selector": s["selector"], "inputs": [],
                        "outputs": [], "stateMutability": "nonpayable",
                        "resolved": False})
    return abi


def analyze_abi(code_hex: str) -> List[Dict[str, Any]]:
    if not C.code_bytes(code_hex):
        return []
    abi = reconstruct_abi(code_hex)
    hits: List[Dict[str, Any]] = []
    for entry in abi:
        if not entry["resolved"]:
            hits.append(C.hit(
                "abi_unresolved_selector",
                f"selector {entry['selector']} in this unverified "
                f"contract matches no known function signature; it "
                f"is kept in the reconstructed ABI as "
                f"{entry['name']} so the surface is not hidden.",
                "medium",
                "Identify this entry point (decompile or get the "
                "source verified) before trusting the contract; "
                "unnamed functions are where hidden admin paths live.",
                selector=entry["selector"], abi_entry=entry,
                check="abi_reconstruct"))
        elif any(w in entry["name"].lower() for w in _DANGEROUS_WORDS):
            hits.append(C.hit(
                "abi_dangerous_function",
                f"reconstructed ABI exposes {entry['name']} "
                f"({entry['selector']}) on an unverified contract.",
                "medium",
                "Verify who can call this function and what it can "
                "move before interacting with the contract.",
                selector=entry["selector"], function=entry["name"],
                check="abi_reconstruct"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_abi(data.get("bytecode", ""))


class AbiReconstructorPlugin(Plugin):
    id = "abi_reconstructor"
    label = "ABI Reconstructor"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Builds a reconstructed ABI JSON for "
                   "bytecode-only contracts: resolved function "
                   "entries plus unresolved selectors kept and "
                   "flagged instead of dropped.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, source=False,
            no_input="no runtime bytecode to reconstruct an ABI from")
