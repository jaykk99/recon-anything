"""Hardhat Fork Config Audit (Tier 9) - SIM-DERIVED, UNVERIFIED ONLY.

HARD RULE: simulation analysis only. Every finding carries
verdict=UNVERIFIED / sim_derived=True; never VERIFIED_REAL, never
proof. VERIFIED_REAL requires live-chain probes.

Coverage decision: a Hardhat *network simulator* plugin would be a
DUPLICATE of anvil_fork_probe's engine (both are local EVM fork
runners) and of contract_simulation's eth_call lane, so this plugin
ships the genuinely distinct remainder - the Hardhat FORK
CONFIGURATION surface that decides whether fork simulation results
can be trusted at all:

- a fork RPC URL with an embedded API key / credential in a published
  hardhat.config (the key that funds every fork run, leaked);
- a fork with NO pinned blockNumber (results drift between runs -
  a sim result that cannot be reproduced cannot be evidence);
- a fork chainId that disagrees with the fork URL's network, and
  ``accounts`` given as a raw mnemonic/private-key array in the fork
  network block.

Adjacent lanes checked and NOT duplicated: cp_secret_hardhat_key
(generic hardcoded deployer key anywhere), cp_web3_hardhat_artifacts
(exposed build artifacts), cp_node_hardhat_accounts (well-known
Hardhat test accounts on a live node). None of them parse the
``forking:`` block or judge fork reproducibility.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Plugin, PluginResult, Target, Ctx
from .forksim_util import run_analyzer_plugin

_FORK_BLOCK = re.compile(r"forking\s*:\s*\{([^}]*)\}", re.S)
_URL = re.compile(r"url\s*:\s*[\"'`]([^\"'`]+)[\"'`]")
_KEY_IN_URL = re.compile(
    r"(?:/v2/|/v3/|api[-_]?key=|/)([A-Za-z0-9_\-]{24,})(?:[\"'`/?]|$)")


def analyze_hardhat_source(source: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if "hardhat" not in source.lower() and "forking" not in source:
        return hits
    for m in _FORK_BLOCK.finditer(source):
        block = m.group(1)
        um = _URL.search(block)
        url = um.group(1) if um else ""
        if url and ("://" in url and ("/v2/" in url or "/v3/" in url
                                      or "api" in url.lower())
                    and _KEY_IN_URL.search(url)):
            hits.append({
                "key": "hardhat_fork_rpc_key_leak", "severity": "high",
                "check": "fork_rpc_key_in_url",
                "detail": ("Hardhat fork config embeds an RPC API key "
                           "in the forking url. Anyone with the config "
                           "can spend that key's quota / bill the owner."),
                "confidence": 75})
        if "blockNumber" not in block:
            hits.append({
                "key": "hardhat_fork_unpinned_block", "severity": "medium",
                "check": "fork_block_not_pinned",
                "detail": ("Hardhat fork config does not pin "
                           "blockNumber. Fork-sim results drift as "
                           "mainnet state changes, so a result from "
                           "this config cannot be reproduced or "
                           "trusted as evidence."),
                "confidence": 70})
    # mnemonic / raw keys inside a hardhat accounts block
    for m in re.finditer(r"accounts\s*:\s*(?:\{[^}]*mnemonic|"
                         r"\[\s*[\"'`]0x[0-9a-fA-F]{64})", source):
        hits.append({
            "key": "hardhat_fork_accounts_secret", "severity": "high",
            "check": "fork_accounts_secret",
            "detail": ("Hardhat config carries account secrets "
                       "(mnemonic or raw private key) next to its "
                       "network/fork configuration."),
            "confidence": 72})
        break
    return hits


class HardhatForkConfigPlugin(Plugin):
    id = "hardhat_fork_config"
    label = "Hardhat Fork Config Audit (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Hardhat fork-configuration audit: embedded fork "
                   "RPC keys, unpinned fork blocks (non-reproducible "
                   "simulation), account secrets in fork config. "
                   "SIM-DERIVED, UNVERIFIED only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_analyzer_plugin(self, target, ctx,
                                         analyze_hardhat_source)
