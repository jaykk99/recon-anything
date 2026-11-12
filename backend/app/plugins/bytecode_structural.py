"""Bytecode structural analysis (Track 3: bytecode-only coverage).

Baseline fact (2026-11-08 Rust-engine parity work): on the cached
bytecode-only slice (3,089 contracts, no verified source) only 3 of
the 54 Tier-1 plugins emit any flags - constant_inliner_check,
abi_reconstructor and solc_version_matcher. Everything else in the
Tier-1 set needs source, storage reads or live chain data, so a
bytecode-only contract is almost invisible to the fast lane.

These two plugins close part of that gap with purely structural,
offline analysis of the runtime bytecode itself - no network fetch
at scan time, no source, no storage, no calls:

1. bytecode_dispatcher_recovery - function-selector recovery from
   the dispatcher itself. ``analyze_bytecode`` in contract_chain
   collects EVERY PUSH4 immediate (including constants buried in
   function bodies); a real entry point is a PUSH4 that the
   dispatcher actually compares calldata against, i.e. a PUSH4
   followed within a few instructions by EQ (the canonical
   ``DUP1 PUSH4 <sel> EQ PUSHn <dest> JUMPI`` shape, and the
   optimized ``CALLDATALOAD/SHR`` variant). Recovered selectors are
   resolved against an embedded curated offline selector table
   (contract_chain's known signatures plus the extra common
   signatures below - built at import time with the repo's own
   keccak, never fetched). Findings fire on dispatcher-exposed
   PRIVILEGED entry points (withdraw / mint / sweep / rescue /
   upgrade / ownership / initializer / aggregator shapes) and on
   dispatcher selectors nobody can name. Severity is capped at
   medium for privileged entries: bytecode alone cannot show
   whether an access gate exists in the body, so this is a
   detection surface, never a claim the function is ungated -
   and it never stamps VERIFIED_REAL.

2. bytecode_proxy_delegatecall_audit - proxy / delegatecall
   structure from raw bytecode:
   - a PUSH32 of an EIP-1967 slot constant (implementation /
     beacon / admin) means the code reads or writes the
     namespaced proxy slots - the upgradeable-proxy pattern,
     visible with no source and no storage read;
   - the EIP-1167 minimal-proxy runtime pattern (implementation
     baked into the code, whole contract is a forwarder);
   - DELEGATECALL with no address masking anywhere in the code:
     the canonical delegatecall target handling masks the loaded
     address with PUSH20 0xff..ff (or the equivalent 32-byte
     2**160-1 constant) ANDed before use. A DELEGATECALL whose
     code contains no such mask sequence takes its target word
     unmasked - the unmasked-delegatecall shape. Minimal proxies
     are exempt (their target is the baked-in implementation,
     already reported by the minimal-proxy finding).

Both follow the Cat-1 (_cat300_common) conventions exactly, like
abi_reconstructor: pure analyze functions over the bytecode plus a
thin Plugin wrapper served by C.finish(fetch=True, source=False),
so the Tier-1 lane (pre-seeded chain_data record / patched
rpc_get_code, network blocked) feeds them exactly like the other
bytecode plugins.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C
from . import contract_chain as cc
from .cryptopack_util import keccak256

# ---------------------------------------------------------------------------
# Curated offline selector table (extra signatures beyond
# contract_chain._KNOWN_SIGNATURES). Embedded in code, resolved at
# import time with the repo's own keccak - NO network fetch, ever.
# ---------------------------------------------------------------------------

_EXTRA_SIGNATURES = [
    # Money movement / vault / staking
    "withdraw(address,uint256)", "withdrawETH()", "withdrawAll(address)",
    "withdrawToken(address,address,uint256)", "withdrawTokens(address)",
    "deposit(uint256)", "depositETH()", "deposit(uint256,address)",
    "mint(uint256,address)", "redeem(uint256,address,address)",
    "withdraw(uint256,address,address)", "asset()", "totalAssets()",
    "stake(uint256)", "stake(uint256,address)", "unstake(uint256)",
    "claimRewards()", "claimReward()", "getReward()", "harvest()",
    "sendETH(address)", "sendValue(address,uint256)",
    "rescueETH()", "recover(address,uint256)", "recoverToken(address)",
    "emergencyWithdraw(uint256)", "sweepETH()",
    # Admin / ownership / roles
    "setAdmin(address)", "setImplementation(address)",
    "setBeacon(address)", "beacon()", "setMinter(address)",
    "addMinter(address)", "renounceMinter()",
    "setOwner(address)", "updateOwner(address)", "acceptOwnership()",
    "pendingOwner()", "setFee(uint256)", "setTax(uint256)",
    "setBlacklist(address,bool)", "blacklistAddress(address)",
    "unblacklist(address)", "freeze(address)", "unfreeze(address)",
    "setVault(address)", "setTreasury(address)",
    "setRoleAdmin(bytes32,bytes32)",
    # Initialization / upgrade (beyond contract_chain's set)
    "initialize(address,address)", "initialize(address,uint256)",
    "init(address)", "setup(address)",
    # Aggregators / generic execution
    "execute(address,bytes)", "execute(address,uint256,bytes)",
    "executeBatch(address[],bytes[])", "multicall(bytes[])",
    "call(address,bytes)",
    # ERC721 admin / minting
    "safeMint(address)", "safeMint(address,uint256)",
    "publicMint(uint256)", "whitelistMint(uint256)",
    "setBaseURI(string)", "tokenURI(uint256)", "contractURI()",
    "burnFrom(address,uint256)",
    # Governance execution
    "propose(address[],uint256[],bytes[])", "castVote(uint256,uint8)",
    "queue(uint256)", "execute(uint256)",
    # Distribution
    "airdrop(address[],uint256[])", "multisend(address[],uint256[])",
]

SELECTOR_TABLE: Dict[str, str] = dict(cc.SELECTOR_TABLE)
for _sig in _EXTRA_SIGNATURES:
    SELECTOR_TABLE.setdefault(keccak256(_sig.encode())[:4].hex(), _sig)

# Function names (lowercased, no arguments) whose exposure through a
# dispatcher is a privileged surface worth reporting from bytecode
# alone. Deliberately explicit - user functions (transfer, approve,
# setApprovalForAll, balanceOf, ...) are NOT in this set.
_PRIVILEGED_NAMES = {
    "withdraw", "withdrawall", "withdraweth", "withdrawtoken",
    "withdrawtokens", "mint", "safemint", "publicmint",
    "whitelistmint", "sweep", "sweepeth", "rescue", "rescuetokens",
    "rescueeth", "emergencywithdraw", "upgradeto",
    "upgradetoandcall", "setowner", "updateowner",
    "transferownership", "renounceownership", "changeadmin",
    "setadmin", "setimplementation", "setbeacon", "initialize",
    "init", "execute", "multicall", "delegatecall", "pause",
    "unpause", "setpaused", "blacklist", "blacklistaddress",
    "grantrole", "revokerole", "setminter", "addminter",
    "burnfrom", "recover", "recovertoken",
    "freeze", "unfreeze",
}


# ---------------------------------------------------------------------------
# Dispatcher recovery: PUSH4 + EQ entry points
# ---------------------------------------------------------------------------

def recover_dispatcher_selectors(code_hex: str) -> List[Dict[str, Any]]:
    """Enumerate exposed entry points from the dispatcher pattern.

    A selector counts as an entry point only when a PUSH4 carrying
    it is followed by an EQ within the next 4 instructions - the
    shape every Solidity/Vyper dispatcher uses to compare the
    calldata selector. PUSH4 constants that never reach an EQ
    (return values, masks, in-body constants) are not entry points
    and are not returned. Returns [{selector, signature}] in
    first-seen order; signature is None when the curated offline
    table cannot name it.
    """
    insns = C.disasm(code_hex or "")
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for i, ins in enumerate(insns):
        if ins["op"] != "PUSH4" or len(ins["operand"]) != 8:
            continue
        window = insns[i + 1:i + 5]
        if not any(w["op"] == "EQ" for w in window):
            continue
        sel = ins["operand"].lower()
        if sel in seen:
            continue
        seen.add(sel)
        out.append({"selector": "0x" + sel,
                    "signature": SELECTOR_TABLE.get(sel)})
    return out


def analyze_dispatcher(code_hex: str) -> List[Dict[str, Any]]:
    if not C.code_bytes(code_hex):
        return []
    hits: List[Dict[str, Any]] = []
    for entry in recover_dispatcher_selectors(code_hex):
        sig = entry["signature"]
        if sig is None:
            hits.append(C.hit(
                "bytecode_unknown_dispatcher_entry",
                f"dispatcher entry point {entry['selector']} "
                f"matches no known function signature in the "
                f"offline selector table; this bytecode-only "
                f"contract exposes a callable function nobody can "
                f"name from its code alone.",
                "low",
                "Identify this entry point (decompile or get the "
                "source verified) before trusting the contract; "
                "unnamed dispatcher entries are where hidden admin "
                "paths live.",
                selector=entry["selector"],
                check="bytecode_dispatcher_recovery"))
            continue
        name = sig.split("(")[0].lower()
        if name in _PRIVILEGED_NAMES:
            hits.append(C.hit(
                "bytecode_privileged_dispatcher_entry",
                f"dispatcher exposes privileged entry point "
                f"{sig} ({entry['selector']}) on a bytecode-only "
                f"contract with no verified source. Bytecode alone "
                f"cannot show whether an access gate protects it.",
                "medium",
                "Verify who can call this function and what it can "
                "move before interacting with the contract; confirm "
                "the access gate in the function body or via a "
                "live read-only probe before trusting it.",
                selector=entry["selector"], signature=sig,
                function=sig.split("(")[0],
                check="bytecode_dispatcher_recovery"))
    return hits


def analyze_dispatcher_data(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_dispatcher(data.get("bytecode", ""))


class BytecodeDispatcherRecoveryPlugin(Plugin):
    id = "bytecode_dispatcher_recovery"
    label = "Bytecode Dispatcher Recovery"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Recovers exposed entry points from raw "
                   "bytecode dispatcher patterns (PUSH4 + EQ), "
                   "resolves them against an embedded offline "
                   "selector table, and flags privileged and "
                   "unknown dispatcher entry points on "
                   "bytecode-only contracts.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze_dispatcher_data, fetch=True,
            source=False,
            no_input="no runtime bytecode to recover a dispatcher from")


# ---------------------------------------------------------------------------
# Proxy / DELEGATECALL structure
# ---------------------------------------------------------------------------

# EIP-1967 namespaced slots (values as PUSH32 operands, no 0x).
_EIP1967_SLOTS = {
    cc.EIP1967_IMPLEMENTATION_SLOT[2:]: "implementation",
    cc.EIP1967_BEACON_SLOT[2:]: "beacon",
    # keccak256("eip1967.proxy.admin") - 1
    "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103":
        "admin",
}

_ADDRESS_MASK = (1 << 160) - 1


def _has_address_mask(insns: List[Dict[str, Any]]) -> bool:
    """True when a PUSH of the 2**160-1 address mask is ANDed -
    the canonical masking of a loaded address word before a
    DELEGATECALL / CALL target is used."""
    for i, ins in enumerate(insns):
        if not ins["op"].startswith("PUSH") or not ins["operand"]:
            continue
        try:
            val = int(ins["operand"], 16)
        except ValueError:
            continue
        if val != _ADDRESS_MASK:
            continue
        if any(w["op"] == "AND" for w in insns[i + 1:i + 4]):
            return True
    return False


def analyze_proxy_delegatecall(code_hex: str) -> List[Dict[str, Any]]:
    code = C.code_bytes(code_hex)
    if not code:
        return []
    hits: List[Dict[str, Any]] = []
    insns = C.disasm(code_hex)
    info = cc.analyze_bytecode(code_hex)

    # EIP-1967 slot constants baked into the code.
    seen_slots: Set[str] = set()
    for ins in insns:
        if ins["op"] != "PUSH32":
            continue
        kind = _EIP1967_SLOTS.get(ins["operand"].lower())
        if kind and kind not in seen_slots:
            seen_slots.add(kind)
            hits.append(C.hit(
                "bytecode_eip1967_proxy_slot",
                f"bytecode embeds the EIP-1967 {kind} storage "
                f"slot constant (0x{ins['operand'].lower()}): "
                f"this bytecode-only contract reads or writes "
                f"the namespaced proxy {kind} slot - the "
                f"upgradeable-proxy pattern, with no verified "
                f"source to show who controls the upgrade path.",
                "medium",
                "Resolve the implementation/admin behind this "
                "proxy (storage read of the EIP-1967 slot) and "
                "verify who can upgrade it before trusting the "
                "contract.",
                slot_kind=kind, slot="0x" + ins["operand"].lower(),
                check="bytecode_proxy_delegatecall"))

    # EIP-1167 minimal proxy: the whole runtime is a forwarder.
    minimal_impl = info.get("minimal_proxy_impl")
    if minimal_impl:
        hits.append(C.hit(
            "bytecode_minimal_proxy",
            f"bytecode is an EIP-1167 minimal proxy: the entire "
            f"runtime forwards every call by DELEGATECALL to the "
            f"baked-in implementation {minimal_impl}. All logic "
            f"and risk live in that implementation.",
            "medium",
            "Audit the implementation contract, not this "
            "forwarder; confirm the clone was initialized.",
            implementation=minimal_impl,
            check="bytecode_proxy_delegatecall"))

    # Unmasked DELEGATECALL.
    delegatecalls = int((info.get("opcodes") or {}).get(
        "DELEGATECALL", 0))
    if delegatecalls and not minimal_impl \
            and not _has_address_mask(insns):
        hits.append(C.hit(
            "bytecode_unmasked_delegatecall",
            f"bytecode contains DELEGATECALL x{delegatecalls} "
            f"and no address-mask sequence anywhere in the code "
            f"(no PUSH of the 20-byte 0xff..ff mask ANDed before "
            f"use): the delegatecall target word is taken "
            f"unmasked, so whatever word reaches the call - a "
            f"storage slot, calldata, or a computed value - is "
            f"used as the code address verbatim in this "
            f"contract's storage context.",
            "medium",
            "Pin the delegatecall target to a known "
            "implementation, mask loaded addresses, and gate "
            "any path that can influence the target word.",
            delegatecall_count=delegatecalls,
            check="bytecode_proxy_delegatecall"))
    return hits


def analyze_proxy_data(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_proxy_delegatecall(data.get("bytecode", ""))


class BytecodeProxyDelegatecallAuditPlugin(Plugin):
    id = "bytecode_proxy_delegatecall_audit"
    label = "Bytecode Proxy / Delegatecall Audit"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Structural proxy and delegatecall audit of "
                   "raw bytecode: EIP-1967 proxy slot constants, "
                   "EIP-1167 minimal proxies, and DELEGATECALL "
                   "usage with no address masking - all visible "
                   "with no verified source.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze_proxy_data, fetch=True,
            source=False,
            no_input="no runtime bytecode to audit for proxy / "
                     "delegatecall structure")
