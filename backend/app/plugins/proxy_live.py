"""Live proxy / upgrade-window plugin (Wave 1.3).

Static ``defense_upgrade_window_open`` describes an upgrade window in
source. This plugin reads the LIVE proxy: EIP-1967 implementation /
admin / beacon slots plus the ZeppelinOS implementation slot via
read-only ``eth_getStorageAt``, fetches the live implementation's
bytecode and verified source, and re-runs the repo's existing
contract analysis (defense family + fork-path) on that implementation.

A fire means the implementation the proxy points at RIGHT NOW has an
open upgrade window (or another defense/fork-path hit) - the shape
that precedes an upgrade takeover. Findings are candidates
(``report_class: "candidate"``) until the validator live-probes them;
never VERIFIED_REAL. No verified source for the implementation means
bytecode-only observation, reported as not-cleared, never clean.

Accepts a contract address target, optionally chain-prefixed
(``eth:0x...`` / ``bsc:0x...``); a bare address is probed across the
configured chains. Read-only: eth_getStorageAt / eth_getCode /
verified-source reads only, through the repo's shared chain readers.
"""
from __future__ import annotations

import time
from typing import List, Optional

from .. import proxy_bridge_live as pbl
from . import chain_data
from . import contract_chain as cc
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class _CtxReader(pbl.CtxReader):
    """Same protocol; subclassed here so the module stays
    self-contained for the registry import scan."""


class ProxyLiveUpgradeWindowPlugin(Plugin):
    id = "proxy_live_upgrade_window"
    label = "Live Proxy Upgrade Window"
    accepts = ["crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = (
        "LIVE proxy check: reads the EIP-1967 + ZeppelinOS proxy slots "
        "on-chain, resolves the current implementation, and re-runs "
        "the defense / fork-path analysis on that implementation's "
        "verified source. Fires (candidate) when the live "
        "implementation has an open upgrade window. Read-only.")
    phase = 2
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        chain_hint, addr = cc.parse_target_address(
            (target.raw or "") or (target.normalized or ""))
        if not addr:
            for item in ctx.consume("chain_contracts"):
                if isinstance(item, dict) and item.get("address"):
                    chain_hint = item.get("chain") or chain_hint
                    addr = str(item.get("address"))
                    break
        if not addr:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. "
                "eth:0x...)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        reader = _CtxReader(ctx)
        chain = chain_hint
        if not chain:
            for cid in cc.DEFAULT_CHAIN_ORDER:
                code = await cc.rpc_get_code(ctx, cc.CHAINS[cid], addr)
                if code and code != "0x" and len(code) >= 4:
                    chain = cid
                    break
        if not chain:
            res = self._degraded(
                f"proxy_live_upgrade_window: no chain answered "
                f"eth_getCode for {addr} - chain data unavailable, "
                "not cleared")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        slots = await pbl.read_proxy_slots(reader, chain, addr)
        impl = slots.get("implementation")
        if not impl:
            res = self._skipped(
                f"{addr} on {chain} is not an EIP-1967 / beacon / "
                "ZeppelinOS proxy (no implementation slot set)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        impl_code = await reader.aget_code(chain, impl)
        impl_hash = pbl.code_hash(impl_code)
        sel_count = len(pbl.extract_selectors(impl_code))
        url = cc.explorer_url(cc.CHAINS[chain], addr)
        base_ev = {
            "address": addr, "chain": chain,
            "chain_id": cc.CHAINS[chain].chain_id,
            "proxy_address": addr,
            "implementation_address": impl,
            "implementation_admin": slots.get("admin"),
            "implementation_beacon": slots.get("beacon"),
            "implementation_code_hash": impl_hash,
            "implementation_selectors": sel_count,
            "live": True,
            "report_class": "candidate",
            "remediation": (
                "Put implementation changes behind a timelock plus a "
                "multisig, and monitor the EIP-1967 implementation "
                "slot so an unexpected swap pages the owner "
                "immediately."),
        }
        src = None
        try:
            src = await chain_data.get_source(ctx, cc.CHAINS[chain],
                                              impl)
        except Exception:
            src = None
        dur = int((time.monotonic() - t0) * 1000)
        if not src:
            res = self._ok(
                [], f"proxy_live_upgrade_window: live implementation "
                f"{impl} (code {impl_hash}, {sel_count} selectors, "
                f"admin {slots.get('admin')}) has NO verified source "
                "- bytecode-only observation, not analyzed, not "
                "cleared")
            res.duration_ms = dur
            return res
        hits = pbl.analyze_implementation_source(
            src["source"], contract_name=src.get("contract_name", ""))
        findings: List[Finding] = []
        for h in hits:
            ev = dict(base_ev)
            ev.update({
                "severity": h.get("severity", "high"),
                "check": h.get("kind") or h.get("id"),
                "function": h.get("function", ""),
                "code": h.get("code", ""),
                "detail": h.get("detail", ""),
                "contract_name": src.get("contract_name", ""),
                "source_origin": src.get("origin", ""),
                "bytecode_only": False,
            })
            if h.get("report_class"):
                ev["report_class"] = h["report_class"]
            if h.get("recipient"):
                ev["recipient"] = h["recipient"]
            key = h.get("kind") or h.get("id") or self.id
            sev = str(h.get("severity", "high")).upper()
            fn_txt = (f"function '{h['function']}' "
                      if h.get("function") else "")
            findings.append(self._f(
                "web3", key,
                f"{sev}: live implementation {impl} behind proxy "
                f"{addr} on {cc.CHAINS[chain].name}: {fn_txt}"
                f"{h.get('detail', '')}\n\nCode:\n{h.get('code', '')}",
                source="proxy live check (verified source of the "
                       "live implementation)",
                source_url=url,
                confidence=80 if h.get("severity") == "high" else 65,
                passive=True, evidence=ev))
        res = self._ok(
            findings,
            f"proxy_live_upgrade_window: proxy {addr} -> live "
            f"implementation {impl} (code {impl_hash}, {sel_count} "
            f"selectors, admin {slots.get('admin')}); re-analysis "
            f"of the implementation source: {len(findings)} "
            f"finding(s)")
        res.duration_ms = dur
        return res
