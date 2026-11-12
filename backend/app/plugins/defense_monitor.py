"""Defense-monitor detectors: the watch surface for a contract an
agent (or Jay) owns or guards.

These are NOT vulnerability detectors. They flag the control surface
a defender must watch - who can change the owner, the admin, or the
implementation, whether an upgrade window is open, whether allowances
can be granted by signature, whether one key can freeze the contract.
A fire means "put this on the watch list", not "this is exploitable".

Every detector is contract-scoped static analysis over verified
source, with a timelock / multisig exclusion: a control surface
behind a TimelockController or a multisig stays silent, because the
watch-worthy shape is single-key control with no delay.

The live half lives in app/defense_watch.py (read-only eth_call
snapshots: owner(), paused(), EIP-1967 implementation/admin/beacon
slots, allowance(owner, spender)) and in the agent_watch MCP tool.
Detection only, read-only live probes, never a transaction.
"""

from __future__ import annotations

from typing import List

from .bsc_common import S, register_family

FAMILY = "defense"

SPECS = [
    S("defense_upgrade_window_open", FAMILY, severity="high",
      scope="contract",
      contract_need_any=(
          r"function upgradeTo\s*\(",
          r"function upgradeToAndCall\s*\(",
          r"function _authorizeUpgrade\s*\(",
          r"function setImplementation\s*\(",
          r"function upgrade\s*\(",
      ),
      contract_forbid=(
          r"TimelockController",
          r"onlyTimelock",
          r"minDelay",
          r"GnosisSafe",
          r"MultiSigWallet",
          r"\bmultisig\b",
      ),
      detail="Open upgrade window: the contract can change its "
             "implementation (upgradeTo / _authorizeUpgrade / "
             "setImplementation) with no timelock or multisig gate "
             "in source. Whoever holds the admin key can swap the "
             "logic out from under every holder with no delay. "
             "Watch the EIP-1967 implementation slot and the admin "
             "slot; alert on any change.",
      fix="Put implementation changes behind a timelock plus a "
          "multisig, and monitor the EIP-1967 implementation slot "
          "so an unexpected swap pages the owner immediately."),
    S("defense_owner_single_point", FAMILY, severity="medium",
      scope="contract",
      contract_need=(r"Ownable",),
      contract_need_any=(
          r"function mint\s*\(",
          r"function pause\s*\(",
          r"function burn\s*\(",
          r"function withdraw\s*\(",
          r"function setFee",
          r"function rescue",
          r"function emergencyWithdraw",
      ),
      contract_forbid=(
          r"TimelockController",
          r"GnosisSafe",
          r"MultiSigWallet",
          r"\bmultisig\b",
          r"onlyTimelock",
      ),
      detail="Single-point owner control: an Ownable contract where "
             "one owner key controls value-moving admin functions "
             "(mint / pause / burn / withdraw / rescue) with no "
             "timelock or multisig in source. One compromised key "
             "is full control. Watch the owner() value; alert on "
             "any ownership transfer.",
      fix="Move admin control to a multisig behind a timelock, "
          "and alert on every OwnershipTransferred event."),
    S("defense_unbounded_allowance_surface", FAMILY,
      severity="medium",
      scope="contract",
      contract_need=(r"function permit\s*\(",),
      contract_need_any=(
          r"EIP712",
          r"DOMAIN_SEPARATOR",
          r"ecrecover",
      ),
      detail="Signature-granted allowance surface: permit() "
             "(EIP-2612) lets an allowance be granted by a signed "
             "message instead of an on-chain transaction, so a "
             "phished or leaked signature can open a large "
             "allowance without the owner ever sending a tx. "
             "Monitor allowance(owner, spender) for the big "
             "spenders and revoke stale approvals.",
      fix="Use short permit deadlines, monitor allowance(owner, "
          "spender) for every material spender, and revoke "
          "allowances that are no longer needed."),
    S("defense_pause_blacklist_centralized", FAMILY,
      severity="medium",
      scope="contract",
      contract_need_any=(
          r"function pause\s*\(",
          r"function blacklist\s*\(",
          r"function setBlacklist",
          r"blacklisted\s*\[",
      ),
      contract_forbid=(
          r"TimelockController",
          r"GnosisSafe",
          r"MultiSigWallet",
          r"\bmultisig\b",
          r"onlyTimelock",
      ),
      detail="Centralized freeze power: pause / blacklist "
             "functions controlled by a single admin with no "
             "timelock or multisig in source. One key can freeze "
             "transfers or blacklist holders instantly. Watch "
             "paused() and the blacklist state; alert on any flip.",
      fix="Put pause / blacklist behind a timelock plus a "
          "multisig, and alert the moment paused() or a "
          "blacklist entry changes."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}

register_family(globals(), SPECS)
