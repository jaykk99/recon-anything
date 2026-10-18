"""DeFi risk scanner (defensive OSINT).

For pool/vault contract addresses discovered during a scan (published on
the "contract_addresses" discovery bus), this pulls the VERIFIED public
source from Etherscan and flags structural risk factors: upgradeable
proxy patterns (owner can swap the logic), owner-only privileged
functions, pause/emergency kill switches, and fee-on-transfer mechanics.
Public data only, read-only, no on-chain interaction.

Needs ETHERSCAN_API_KEY (ctx key "etherscan" or the ETHERSCAN_API_KEY
env var). Skips gracefully with a clear note when the key is missing.
"""
from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

ETH_API = "https://api.etherscan.io/api"
MAX_ADDR = 5  # contracts to scan per run (free-tier friendly)


def _key(ctx: Ctx) -> Optional[str]:
    return ctx.keys.get("etherscan") or os.environ.get("ETHERSCAN_API_KEY") or None


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def scan_defi_risks(src: str) -> List[Dict[str, str]]:
    """Static DeFi risk checks over verified Solidity source."""
    out: List[Dict[str, str]] = []
    clean = _strip_comments(src)

    # --- 1. verified or not is handled by caller; here: proxy detection ---
    proxy_hits = []
    if re.search(r"delegatecall", clean):
        proxy_hits.append("delegatecall in code")
    if re.search(r"TransparentUpgradeableProxy|ERC1967|UUPSUpgradeable|"
                 r"upgradeTo|implementation\(\)|beacon", clean):
        proxy_hits.append("upgradeable-proxy pattern (Transparent/UUPS/ERC1967/beacon)")
    if re.search(r"function\s+fallback\s*\([^)]*\)[^{]*\{[^}]*delegatecall", clean, re.S):
        proxy_hits.append("fallback delegates to implementation")
    if proxy_hits:
        out.append({
            "check": "proxy",
            "severity": "high",
            "detail": ("UPGRADEABLE PROXY: " + "; ".join(proxy_hits) + ". "
                       "The admin/owner can replace the implementation logic "
                       "at any time, so users trust the owner, not the code."),
            "remediation": ("Verify who holds the admin keys (multisig? timelock?). "
                            "Check the current implementation address and diff it "
                            "against what was audited. Prefer timelocked upgrades.")})

    # --- 2. owner-only privileged functions ---
    owner_fns = re.findall(
        r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)[^{;]*\bonlyOwner\b[^{;]*\{",
        clean)
    if owner_fns:
        shown = ", ".join(owner_fns[:10])
        extra = f" (+{len(owner_fns) - 10} more)" if len(owner_fns) > 10 else ""
        out.append({
            "check": "owner_only",
            "severity": "medium",
            "detail": (f"OWNER PRIVILEGES: {len(owner_fns)} owner-only function(s): "
                       f"{shown}{extra}. A single key controls them."),
            "remediation": ("Check who the owner is (EOA vs multisig vs timelock). "
                            "Prefer renounced ownership or DAO/multisig control for "
                            "pools holding user funds.")})

    # --- 3. pause / emergency functions ---
    fn_names = re.findall(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean)
    pause_hits = [n for n in fn_names
                  if any(k in n.lower() for k in ("pause", "emergency", "circuitbreaker"))]
    if pause_hits:
        out.append({
            "check": "pause",
            "severity": "medium",
            "detail": ("PAUSE/EMERGENCY: " + ", ".join(sorted(set(pause_hits))) +
                       " present. Centralized kill switch can freeze funds or "
                       "halt the protocol."),
            "remediation": ("Confirm pause authority is a multisig/timelock with a "
                            "published policy. Test that unpause paths work; a stuck "
                            "pause locks user funds.")})

    # --- 4. fee-on-transfer mechanics ---
    fee_hits = []
    for pat in (r"_taxFee", r"_liquidityFee", r"_burnFee", r"_takeFee",
                r"feeOnTransfer", r"transferFee", r"\bfee\s*=\s*\d",
                r"reflection", r"_reflectFee"):
        if re.search(pat, clean):
            fee_hits.append(pat.strip("\\b"))
    if fee_hits:
        out.append({
            "check": "fee_on_transfer",
            "severity": "medium",
            "detail": ("FEE-ON-TRANSFER mechanics detected (" +
                       ", ".join(sorted(set(fee_hits))) + "). Received amounts "
                       "differ from sent amounts; breaks routers/aggregators that "
                       "assume exact amounts."),
            "remediation": ("Disclose the exact fee schedule. Integrators must use "
                            "supportingFeeOnTransferTokens router variants and never "
                            "assume amountIn == amountOut.")})

    # --- 5. mint / unlimited supply levers ---
    mint_hits = [n for n in fn_names if "mint" in n.lower()]
    if mint_hits:
        guarded = bool(re.search(r"onlyOwner|onlyMinter|onlyRole", clean))
        out.append({
            "check": "mint",
            "severity": "high" if not guarded else "medium",
            "detail": ("MINT function(s): " + ", ".join(sorted(set(mint_hits))) +
                       (" WITHOUT visible access guard" if not guarded
                        else " (guarded by owner/role)") +
                       ". Unbounded minting can dilute holders to zero."),
            "remediation": ("Cap supply or burn mint keys. If minting is needed, "
                            "gate it behind a multisig + timelock with on-chain "
                            "limits.")})
    return out


EXPL = {
    "proxy": "theoretical",
    "owner_only": "theoretical",
    "pause": "theoretical",
    "fee_on_transfer": "theoretical",
    "mint": "public_poc",
}


class DefiRiskPlugin(Plugin):
    id = "defi_risk"
    label = "DeFi Risk Scanner"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = ["etherscan"]
    description = ("DeFi risk factors on discovered pool/vault contracts: "
                   "proxy/upgrades, owner functions, pause switches, "
                   "fee-on-transfer. Public data only.")
    phase = 2  # consumes addresses published by address miners
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = _key(ctx)
        if not key:
            return self._skipped(
                "ETHERSCAN_API_KEY not configured (set the 'etherscan' key or "
                "ETHERSCAN_API_KEY env var). DeFi risk scan skipped.")

        addrs = self._collect(ctx)
        if not addrs:
            res = self._skipped("no pool/vault contract addresses discovered "
                                "on this target; nothing to scan")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        scanned = 0
        no_source = 0
        for addr in addrs[:MAX_ADDR]:
            try:
                src = await self._source(ctx, key, addr)
                if not src:
                    no_source += 1
                    findings.append(self._f(
                        "web3", "defi_unverified",
                        f"HIGH: {addr} has no verified source on Etherscan. "
                        "DeFi positions in unverified contracts cannot be "
                        "risk-assessed; treat as dangerous.",
                        source="Etherscan", source_url=f"https://etherscan.io/address/{addr}",
                        confidence=90, passive=True,
                        evidence={
                            "severity": "high", "address": addr,
                            "exploitability": "unknown",
                            "remediation": ("Do not deposit into unverified contracts. "
                                            "Unverified code can hide backdoors, "
                                            "hidden mint, or upgrade traps.")}))
                    continue
                scanned += 1
                risks = scan_defi_risks(src)
                if not risks:
                    findings.append(self._f(
                        "web3", "defi_no_flags",
                        f"{addr}: verified source scanned; no proxy, owner-privilege, "
                        "pause, fee, or mint flags found. Not a proof of safety.",
                        source="Etherscan static scan",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=60, passive=True,
                        evidence={
                            "severity": "low", "address": addr,
                            "exploitability": "unknown",
                            "remediation": ("Static scan is a first pass only. Get a "
                                            "professional audit before depositing.")}))
                for r in risks:
                    findings.append(self._f(
                        "web3", f"defi_{r['check']}",
                        f"{r['severity'].upper()}: {r['detail']}",
                        source="Etherscan static scan",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=75, passive=True,
                        evidence={
                            "severity": r["severity"], "address": addr,
                            "check": r["check"],
                            "exploitability": EXPL.get(r["check"], "unknown"),
                            "remediation": r["remediation"],
                            "scope_note": ("Static analysis of published source only. "
                                           "Never interacted with the contract.")}))
            except Exception:
                continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"scanned {scanned} contract(s), "
                                 f"{no_source} unverified")
        res.duration_ms = dur
        return res

    def _collect(self, ctx: Ctx) -> List[str]:
        seen: List[str] = []
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else str(item.get("address", ""))
                a = a.strip()
                if re.fullmatch(r"0x[0-9a-fA-F]{40}", a) and a not in seen:
                    seen.append(a)
        return seen

    async def _source(self, ctx: Ctx, key: str, addr: str) -> Optional[str]:
        from urllib.parse import urlencode
        url = f"{ETH_API}?{urlencode({'module': 'contract', 'action': 'getsourcecode', 'address': addr, 'apikey': key})}"
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20,
                        max_retries=1)
        if r.status_code != 200:
            return None
        try:
            d = r.json()
        except Exception:
            return None
        res = d.get("result")
        if not res or not isinstance(res, list):
            return None
        src = (res[0] or {}).get("SourceCode") or ""
        if src.startswith("{{"):
            src = src.strip("{}")
        return src if len(src) > 100 else None
