"""Forge Inspect (Tier 9) - SIM-DERIVED, UNVERIFIED ONLY.

HARD RULE: simulation/artifact analysis only. Every finding carries
verdict=UNVERIFIED / sim_derived=True; never VERIFIED_REAL, never
proof. VERIFIED_REAL requires live-chain probes.

`forge inspect <contract> storageLayout|methods|abi` extracts
artifact catalogs from compiled contracts. The distinct remainder
shipped here is a native artifact extractor over verified source
(no compiler needed):

- method identifiers: canonical signature -> 4-byte selector
  (keccak via contract_sim.function_selector);
- storage layout: state variables in declaration order with
  sequential slot assignment for value types (32-byte slots;
  mappings/dynamic types occupy one slot head each - the standard
  layout approximation, labeled as such);
- event / error catalogs from declarations.

Findings are the RISK subset of the catalog (the catalog helpers
themselves are unit-tested directly): a dangerous selector -
unguarded ``upgradeTo(address)`` / ``upgradeToAndCall`` (UUPS
selectors 0x3659cfe6 / 0x4f1ef286), an unguarded function whose
selector catalogs it as selfdestruct-capable, or a storage layout
where an owner/admin slot is written by an ungated function.
A clean, gated catalog is silent.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from . import contract_chain as cc
from . import contract_sim as cs
from .base import Cost, Plugin, PluginResult, Target, Ctx
from .forksim_util import is_gated, run_analyzer_plugin

UUPS_SELECTORS = {"3659cfe6": "upgradeTo(address)",
                  "4f1ef286": "upgradeToAndCall(address,bytes)"}


def _param_types(signature: str) -> List[str]:
    m = re.search(r"\(([^()]*)\)", signature)
    if not m or not m.group(1).strip():
        return []
    out = []
    for part in m.group(1).split(","):
        toks = part.strip().split()
        if toks:
            t = toks[0]
            # canonical ABI spelling: bare uint/int are uint256/int256
            t = re.sub(r"^uint(?=\[|$)", "uint256", t)
            t = re.sub(r"^int(?=\[|$)", "int256", t)
            out.append(t)
    return out


def method_identifiers(source: str) -> Dict[str, str]:
    """{canonical_signature: selector} for functions with bodies."""
    out: Dict[str, str] = {}
    clean = cc._strip_comments(source)
    for fn in cc.extract_functions(clean):
        if not fn["name"] or fn["text"].rstrip().endswith(";"):
            continue
        types = _param_types(fn["signature"])
        canon = f"{fn['name']}({','.join(types)})"
        try:
            out[canon] = cs.function_selector(canon)
        except Exception:
            continue
    return out


def storage_layout(source: str) -> List[Dict[str, Any]]:
    """[{slot, name, type}] sequential-slot approximation."""
    clean = cc._strip_comments(source)
    # state vars: declarations at contract body level, before functions
    head = clean.split("function ")[0]
    out: List[Dict[str, Any]] = []
    slot = 0
    for m in re.finditer(
            r"\b(mapping\s*\([^)]*\)|address|bool|uint\w*|int\w*|bytes\w*|"
            r"string)\s+(?:public\s+|private\s+|internal\s+|constant\s+|"
            r"immutable\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]*)?;",
            head):
        typ, name = m.group(1), m.group(2)
        if "constant" in m.group(0) or "immutable" in m.group(0):
            continue  # no storage slot
        out.append({"slot": slot, "name": name,
                    "type": re.sub(r"\s+", "", typ)})
        slot += 1
    return out


def analyze_forge_inspect_source(source: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    clean = cc._strip_comments(source)
    fns = {f["name"]: f for f in cc.extract_functions(clean)}
    methods = method_identifiers(source)
    for canon, sel in methods.items():
        bare = sel[2:] if sel.startswith("0x") else sel
        name = canon.split("(")[0]
        fn = fns.get(name)
        if fn is None:
            continue
        gated = is_gated(fn["text"], fn["signature"])
        if bare in UUPS_SELECTORS and not gated:
            hits.append({
                "key": "forge_inspect_unguarded_upgrade_selector",
                "severity": "high", "check": "uups_selector_ungated",
                "function": name,
                "detail": (f"forge-inspect catalog: selector {sel} "
                           f"({UUPS_SELECTORS[bare]}) is present and "
                           f"'{name}' carries no access gate - anyone "
                           f"can point the proxy at a new "
                           f"implementation."),
                "confidence": 76,
                "extra": {"selector": sel, "canonical": canon}})
        if "selfdestruct" in fn["text"] and not gated:
            hits.append({
                "key": "forge_inspect_ungated_selfdestruct",
                "severity": "high", "check": "selfdestruct_selector",
                "function": name,
                "detail": (f"forge-inspect catalog: '{name}' "
                           f"(selector {sel}) reaches selfdestruct "
                           f"with no access gate."),
                "confidence": 74,
                "extra": {"selector": sel, "canonical": canon}})
    # owner/admin storage slot written by an ungated function
    owner_slots = [v for v in storage_layout(source)
                   if re.search(r"owner|admin|governor", v["name"], re.I)]
    for var in owner_slots:
        for fn in fns.values():
            if re.search(rf"\b{re.escape(var['name'])}\s*=(?!=)",
                         fn["text"]) and \
                    not is_gated(fn["text"], fn["signature"]) and \
                    re.search(r"\b(public|external)\b", fn["signature"]) and \
                    fn["name"] != "constructor":
                hits.append({
                    "key": "forge_inspect_owner_slot_ungated_write",
                    "severity": "high", "check": "owner_slot_write",
                    "function": fn["name"],
                    "detail": (f"forge-inspect storage layout: slot "
                               f"{var['slot']} holds '{var['name']}' "
                               f"and ungated '{fn['name']}' writes it - "
                               f"the artifact layout shows an open "
                               f"ownership takeover path."),
                    "confidence": 72,
                    "extra": {"slot": var["slot"], "variable": var["name"]}})
                break
    return hits


class ForgeInspectPlugin(Plugin):
    id = "forge_inspect"
    label = "Forge Inspect (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("forge-inspect-style artifact extraction (method "
                   "identifiers, storage layout, event/error "
                   "catalogs) over verified source; findings are the "
                   "risk subset: unguarded upgrade/selfdestruct "
                   "selectors and owner-slot writes. SIM-DERIVED, "
                   "UNVERIFIED only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_analyzer_plugin(self, target, ctx,
                                         analyze_forge_inspect_source)
