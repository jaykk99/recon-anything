"""Etherscan-family verified-source BUNDLE downloader (Tier-7).

Distinct remainder vs master (checked dee4763, 853 plugins):
- chain_osint / contract_audit / defi_risk call Etherscan
  getsourcecode for ONE chain (Ethereum) only to feed source-code
  analyzers; the bundle itself (ABI surface, constructor arguments,
  creation transaction, compiler settings) is discarded.
- This plugin is the downloader: for each Etherscan-family explorer
  (Ethereum, BSC, Polygon, Arbitrum, Base) it fetches the full
  verified bundle and reports it as inventory findings, including
  unverified-contract and constructor-args signals the analyzers
  never surface. Keyless public endpoint first; ETHERSCAN_API_KEY
  (ctx key "etherscan") only raises rate limits.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target

ADDR_RX = re.compile(r"0x[a-fA-F0-9]{40}")
# Etherscan API V2 (unified, chainid-addressed). V1 was deprecated by
# Etherscan (verified live 2026-11-05: V1 returns "deprecated V1
# endpoint", V2 without a key returns "Missing/Invalid API Key").
EXPLORERS_V2 = "https://api.etherscan.io/v2/api"
CHAIN_IDS = {"ethereum": 1, "bsc": 56, "polygon": 137,
             "arbitrum": 42161, "base": 8453}
# Keyless route: Blockscout instances expose an Etherscan-compatible
# ?module=contract&action=getsourcecode API with no key.
KEYLESS_COMPAT = {
    "ethereum": "https://eth.blockscout.com/api",
    "base": "https://base.blockscout.com/api",
    "gnosis": "https://gnosis.blockscout.com/api",
}


def extract_addresses(target: Target, ctx: Ctx) -> List[str]:
    out: List[str] = []
    for cand in [target.raw or "", target.normalized or ""]:
        out += ADDR_RX.findall(cand)
    for item in ctx.consume("contract_addresses"):
        s = item if isinstance(item, str) else str(
            item.get("address", "") if isinstance(item, dict) else item)
        out += ADDR_RX.findall(s)
    seen, uniq = set(), []
    for a in out:
        if a.lower() not in seen:
            seen.add(a.lower())
            uniq.append(a)
    return uniq[:4]


class EtherscanBundlePlugin(Plugin):
    id = "etherscan_bundle"
    label = "Etherscan Source Bundle Downloader"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = ("Downloads the full verified-source bundle (source, "
                   "ABI function surface, constructor arguments, "
                   "creation tx, compiler) for an address across "
                   "Etherscan-family explorers. Keyless; an Etherscan "
                   "key only raises rate limits.")
    phase = 2
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        addrs = extract_addresses(target, ctx)
        if not addrs:
            return self._skipped("no EVM address in target or bus")
        key = ctx.keys.get("etherscan") or os.environ.get(
            "ETHERSCAN_API_KEY") or ""
        findings = []
        routes = []
        if key:
            routes += [(c, EXPLORERS_V2, cid)
                       for c, cid in CHAIN_IDS.items()]
        routes += [(c, api, None) for c, api in KEYLESS_COMPAT.items()]
        for addr in addrs:
            for chain, api, cid in routes:
                try:
                    bundle = await self._fetch(ctx, api, addr, key, cid)
                except Exception:
                    bundle = None
                if bundle:
                    findings += self._findings(addr, chain, bundle)
                    break
        if not findings:
            return self._degraded(
                "no explorer returned a source bundle (unverified or "
                "unreachable explorers)")
        return self._ok(findings, f"{len(findings)} bundle findings")

    async def _fetch(self, ctx, api, addr, key, chain_id=None):
        params = {"module": "contract", "action": "getsourcecode",
                  "address": addr}
        if chain_id:
            params["chainid"] = chain_id
        if key:
            params["apikey"] = key
        resp = await ctx.http.get(api, params=params, timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        rows = data.get("result") if isinstance(data, dict) else None
        if not isinstance(rows, list) or not rows:
            return None
        return rows[0] if isinstance(rows[0], dict) else None

    def _findings(self, addr, chain, b):
        out = []
        src = b.get("SourceCode") or ""
        name = b.get("ContractName") or ""
        if not src:
            out.append(self._f(
                "web3", "unverified_contract", f"{addr} on {chain}",
                "EtherscanBundle", confidence=85,
                evidence={"severity": "medium", "chain": chain,
                          "address": addr,
                          "remediation": "Verify the contract source on "
                                         "the explorer so users and "
                                         "auditors can inspect it."}))
            return out
        abi_count = 0
        try:
            abi = json.loads(b.get("ABI") or "[]")
            abi_count = sum(1 for e in abi if isinstance(e, dict)
                            and e.get("type") == "function")
        except Exception:
            abi_count = 0
        ctor = b.get("ConstructorArguments") or ""
        out.append(self._f(
            "web3", "verified_source_bundle",
            f"{name or addr} on {chain}: {len(src)} chars, "
            f"{abi_count} ABI functions",
            "EtherscanBundle", confidence=90,
            evidence={"severity": "low", "chain": chain, "address": addr,
                      "contract_name": name,
                      "compiler": b.get("CompilerVersion", ""),
                      "abi_functions": abi_count,
                      "proxy": str(b.get("Proxy", "0")),
                      "remediation": "Keep the verified bundle in sync "
                                     "with deployed bytecode on upgrades."}))
        if ctor:
            out.append(self._f(
                "web3", "constructor_args_present",
                f"{addr} on {chain}: constructor args {len(ctor)//2} bytes",
                "EtherscanBundle", confidence=80,
                evidence={"severity": "low", "chain": chain,
                          "address": addr, "ctor_bytes": len(ctor) // 2,
                          "remediation": "Review constructor arguments: "
                                         "owner/admin addresses set here "
                                         "define the contract trust root."}))
        return out
