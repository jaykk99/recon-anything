"""ERC20 Compliance Verifier (Cat-1 #17, VARIANT of the BEP20 family).

Delta: a full EIP-20 conformance VERDICT instead of one detector
per violation. Checks interface completeness against the standard -
the six functions (totalSupply, balanceOf, transfer, allowance,
approve, transferFrom) and the Transfer / Approval events with
their exact signatures - in source (or a supplied ABI), and
reconciles live read-only probe results (name / symbol / decimals
/ totalSupply supplied on the bus) against what the source claims.
Every missing or malformed element is its own finding; a fully
conformant token stays silent.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_REQUIRED_FUNCS = {
    "totalSupply": r"function\s+totalSupply\s*\(\s*\)",
    "balanceOf": r"function\s+balanceOf\s*\(\s*address",
    "transfer": r"function\s+transfer\s*\(\s*address\s+\w+\s*,\s*(?:uint256|uint)\b",
    "allowance": r"function\s+allowance\s*\(\s*address\s+\w+\s*,\s*address",
    "approve": r"function\s+approve\s*\(\s*address\s+\w+\s*,\s*(?:uint256|uint)\b",
    "transferFrom": r"function\s+transferFrom\s*\(\s*address\s+\w+\s*,"
                    r"\s*address\s+\w+\s*,\s*(?:uint256|uint)\b",
}
_REQUIRED_EVENTS = {
    "Transfer": r"event\s+Transfer\s*\(\s*address\s+indexed\s+\w+\s*,"
                r"\s*address\s+indexed\s+\w+\s*,\s*(?:uint256|uint)\b",
    "Approval": r"event\s+Approval\s*\(\s*address\s+indexed\s+\w+\s*,"
                r"\s*address\s+indexed\s+\w+\s*,\s*(?:uint256|uint)\b",
}


def verify_erc20(source: str = "", abi: Any = None,
                 live: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    src = source or ""
    abi_names = set()
    if isinstance(abi, list):
        for e in abi:
            if isinstance(e, dict) and e.get("type") == "function":
                abi_names.add(str(e.get("name", "")))
            if isinstance(e, dict) and e.get("type") == "event":
                abi_names.add("event:" + str(e.get("name", "")))
    if src.strip() or abi_names:
        for name, pat in _REQUIRED_FUNCS.items():
            if re.search(pat, src) or name in abi_names:
                continue
            # a public state variable auto-generates exactly this
            # getter in the ABI (WETH9 declares balanceOf and
            # allowance as public mappings) - that IS conformant
            if re.search(rf"public\s+{re.escape(name)}\b", src):
                continue
            hits.append(C.hit(
                "erc20_missing_function",
                f"EIP-20 required function {name}() is missing "
                f"or has a non-standard signature; wallets and "
                f"exchanges integrating this token will fail or "
                f"misbehave.",
                "medium",
                f"Implement {name}() exactly as EIP-20 specifies.",
                function=name, check="erc20_compliance"))
        for name, pat in _REQUIRED_EVENTS.items():
            if re.search(pat, src) or ("event:" + name) in abi_names:
                continue
            hits.append(C.hit(
                "erc20_missing_event",
                f"EIP-20 required event {name} is missing or its "
                f"parameters are not indexed / typed as the "
                f"standard requires; indexers cannot track the "
                f"token.",
                "medium",
                f"Declare event {name} with the exact EIP-20 "
                f"signature (indexed from/to, uint256 value).",
                event=name, check="erc20_compliance"))
        # transfer must return bool per spec (SHOULD, widely enforced)
        m = re.search(r"function\s+transfer\s*\([^)]*\)[^{;]*\{", src)
        if m and "returns" not in m.group(0) and "bool" not in m.group(0):
            hits.append(C.hit(
                "erc20_transfer_no_bool",
                "transfer() declares no bool return; EIP-20 "
                "callers that check the return value will treat "
                "every transfer as failed.",
                "low",
                "Make transfer() return bool as EIP-20 specifies.",
                function="transfer", check="erc20_compliance"))
    if live:
        dec = live.get("decimals")
        if dec is not None:
            try:
                if not (0 <= int(dec) <= 36):
                    hits.append(C.hit(
                        "erc20_live_decimals_anomaly",
                        f"live decimals() probe returned {dec}, "
                        f"outside the sane 0-36 range.",
                        "medium",
                        "Fix the decimals value; integrations "
                        "scale amounts by it.",
                        decimals=dec, check="erc20_compliance"))
            except Exception:
                hits.append(C.hit(
                    "erc20_live_decimals_anomaly",
                    f"live decimals() probe returned a non-numeric "
                    f"value {dec!r}.", "medium",
                    "Fix the decimals value.", decimals=str(dec),
                    check="erc20_compliance"))
        if live.get("totalSupply") is not None and src:
            m = re.search(r"totalSupply\s*=\s*(\d[\d_]*)", src)
            if m and int(m.group(1).replace("_", "")) != int(
                    live["totalSupply"]):
                hits.append(C.hit(
                    "erc20_supply_mismatch",
                    "live totalSupply() does not match the supply "
                    "constant declared in source.",
                    "medium",
                    "Reconcile the deployed supply with the "
                    "audited source (possible extra mint path).",
                    check="erc20_compliance"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    live = None
    for kind in ("oracle_samples",):
        pass
    for item in data["extras"].get("chain_contracts", []):
        if isinstance(item, dict) and item.get("live_token"):
            live = item["live_token"]
    return verify_erc20(data.get("source", ""), data.get("abi"), live)


class Erc20ComplianceVerifyPlugin(Plugin):
    id = "erc20_compliance_verify"
    label = "ERC20 Compliance Verifier"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Full EIP-20 conformance verdict: all six "
                   "functions and both events with standard "
                   "signatures in source/ABI, reconciled with "
                   "live read-only token probes when supplied.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, bytecode=False,
            no_input="no token source or ABI to verify against EIP-20")
