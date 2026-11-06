"""Sourcify repository fetch with match-quality reporting (Tier-7).

Distinct remainder vs master (dee4763): chain_osint checks Sourcify
v2 for a boolean verified flag; contract_audit/defi_risk/meme_coin
fetch Sourcify source TEXT to feed analyzers and discard everything
else. Nobody reports the verification QUALITY: full vs partial match
(a partial match means the deployed bytecode was matched with
different metadata/settings - materially weaker assurance), the
compiler/settings from metadata, or the source file inventory.
This plugin reports exactly that remainder. Keyless.
"""
from __future__ import annotations

import re
import time
from typing import List

from .base import Cost, Ctx, Plugin, PluginResult, Target

ADDR_RX = re.compile(r"0x[a-fA-F0-9]{40}")
SOURCIFY_V2 = "https://sourcify.dev/server/v2/contract"
CHAINS = [1, 56, 137, 42161, 8453]


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


class SourcifyFetchPlugin(Plugin):
    id = "sourcify_fetch"
    label = "Sourcify Fetch (Match Quality)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ("Fetches the Sourcify record for an address and "
                   "reports match quality (full vs partial), compiler "
                   "and settings from metadata, and the verified "
                   "source file inventory. Keyless.")
    phase = 2
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        addrs = extract_addresses(target, ctx)
        if not addrs:
            return self._skipped("no EVM address in target or bus")
        findings = []
        for addr in addrs:
            for chain in CHAINS:
                try:
                    rec = await self._fetch(ctx, chain, addr)
                except Exception:
                    rec = None
                if rec:
                    findings += self._findings(addr, chain, rec)
                    break
        if not findings:
            return self._degraded("Sourcify has no record for the "
                                   "address on checked chains")
        return self._ok(findings, f"{len(findings)} sourcify findings")

    async def _fetch(self, ctx, chain, addr):
        resp = await ctx.http.get(
            f"{SOURCIFY_V2}/{chain}/{addr}",
            params={"fields": "all"}, timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) and data else None

    def _findings(self, addr, chain, rec):
        out = []
        match = str(rec.get("match") or rec.get("matchType") or "")
        verified = rec.get("verified") or match
        # v2 live shape: runtimeMatch/creationMatch are "match" |
        # "partial_match" | null alongside the summary "match" field.
        runtime_match = str(rec.get("runtimeMatch") or "")
        if not verified and runtime_match:
            verified = runtime_match
        if not verified:
            return out
        is_partial = "partial" in str(verified).lower() or \
            "partial" in runtime_match.lower()
        comp = rec.get("compilation") or {}
        name = comp.get("name") or rec.get("name") or addr
        sources = rec.get("sources") or {}
        out.append(self._f(
            "web3", "sourcify_partial_match" if is_partial
            else "sourcify_full_match",
            f"{name} chain {chain}: {verified}, {len(sources)} files",
            "Sourcify", confidence=90 if not is_partial else 85,
            evidence={"severity": "medium" if is_partial else "low",
                      "chain": chain, "address": addr, "match": str(verified),
                      "compiler": comp.get("compilerVersion", ""),
                      "files": len(sources),
                      "remediation": ("A partial match is weaker than a "
                                      "full match: re-verify with exact "
                                      "metadata to reach full match."
                                      if is_partial else
                                      "Full Sourcify match: source and "
                                      "metadata reproduce the deployed "
                                      "bytecode.")}))
        return out
