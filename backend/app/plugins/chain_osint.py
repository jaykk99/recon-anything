"""Blockchain OSINT aggregator (defensive OSINT).

Works with ZERO API keys:
- Keyless: Blockchair API (no auth) for balances, tx counts, first/last
  activity. Sourcify (no auth) for verified-source checks.
- Enhanced: ETHERSCAN_API_KEY unlocks richer Etherscan enrichment
  (full tx history, counterparty analysis).

For wallet/contract addresses discovered during a scan (published on the
"contract_addresses" discovery bus by the address-mining plugins).
Read-only. It never signs, sends, or interacts with anything on-chain.
"""
from __future__ import annotations

import datetime as dt
import os
import time
from typing import Any, Dict, List, Optional

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

ETH_API = "https://api.etherscan.io/api"
BLOCKCHAIR_API = "https://api.blockchair.com/ethereum/dashboards/address"
SOURCIFY_V2 = "https://sourcify.dev/server/v2/contract/1"
MAX_ADDR = 8     # addresses to enrich per run (free-tier friendly)
TX_LIMIT = 20    # transactions per address


def _key(ctx: Ctx) -> Optional[str]:
    return ctx.keys.get("etherscan") or os.environ.get("ETHERSCAN_API_KEY") or None


def _wei_to_eth(wei: str) -> float:
    try:
        return int(wei) / 1e18
    except (TypeError, ValueError):
        return 0.0


class ChainOsintPlugin(Plugin):
    id = "chain_osint"
    label = "Blockchain OSINT"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # works keyless via Blockchair+Sourcify; etherscan key enhances
    description = ("Chain enrichment for discovered addresses: keyless "
                   "Blockchair balances/activity + Sourcify verified-source "
                   "checks always run; ETHERSCAN_API_KEY (optional) adds full "
                   "tx history and counterparties. Read-only.")
    phase = 2  # runs after address miners populate the discovery bus
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = _key(ctx)

        addrs = self._collect(ctx)
        if not addrs:
            res = self._skipped("no wallet/contract addresses discovered on "
                                "this target; nothing to enrich")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        enriched = 0
        keyless = 0
        for addr in addrs[:MAX_ADDR]:
            try:
                if key:
                    f = await self._enrich(ctx, key, addr)
                else:
                    f = await self._enrich_keyless(ctx, addr)
                    keyless += 1
                if f:
                    findings.extend(f)
                    enriched += 1
            except Exception:
                continue  # one bad address never kills the plugin

        dur = int((time.monotonic() - t0) * 1000)
        mode = (f"keyless (Blockchair+Sourcify); ETHERSCAN_API_KEY would add "
                f"full tx history") if not key else "etherscan"
        res = self._ok(findings, f"enriched {enriched}/{len(addrs)} address(es) "
                                 f"via {mode}")
        res.duration_ms = dur
        return res

    def _collect(self, ctx: Ctx) -> List[str]:
        seen: List[str] = []
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else str(item.get("address", ""))
                a = a.strip()
                if a and a not in seen:
                    seen.append(a)
        # only Ethereum-style addresses can be queried on Etherscan
        import re
        return [a for a in seen if re.fullmatch(r"0x[0-9a-fA-F]{40}", a)]

    async def _api(self, ctx: Ctx, key: str, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        from urllib.parse import urlencode
        url = f"{ETH_API}?{urlencode(params)}"
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20,
                        max_retries=1)
        if r.status_code != 200:
            return None
        try:
            d = r.json()
        except Exception:
            return None
        if str(d.get("status")) not in ("1", "0"):
            return None
        if str(d.get("message")) == "NOTOK" and str(d.get("status")) != "0":
            return None
        return d

    async def _enrich(self, ctx: Ctx, key: str, addr: str) -> List[Finding]:
        out: List[Finding] = []

        # 1. Is it a contract, and is its source verified?
        src = await self._api(ctx, key, {
            "module": "contract", "action": "getsourcecode",
            "address": addr, "apikey": key})
        is_contract = False
        verified = False
        contract_name = ""
        if src and isinstance(src.get("result"), list) and src["result"]:
            info = src["result"][0] or {}
            is_contract = bool(info.get("ABI") and info.get("ABI") != "Contract source code not verified")
            contract_name = info.get("ContractName") or ""
            verified = bool(is_contract and contract_name)
        ctx.publish("chain_contracts", {
            "address": addr, "is_contract": is_contract,
            "verified": verified, "name": contract_name})

        # 2. Balance + tx history (first 20 most recent)
        bal_d = await self._api(ctx, key, {
            "module": "account", "action": "balance",
            "address": addr, "tag": "latest", "apikey": key})
        balance = _wei_to_eth(bal_d.get("result") if bal_d else "")

        txs_d = await self._api(ctx, key, {
            "module": "account", "action": "txlist", "address": addr,
            "startblock": "0", "endblock": "99999999", "page": "1",
            "offset": str(TX_LIMIT), "sort": "desc", "apikey": key})
        txs = (txs_d or {}).get("result") or []
        txs = [t for t in txs if isinstance(t, dict)][:TX_LIMIT]

        first_seen = last_seen = ""
        in_eth = out_eth = 0.0
        parties: Dict[str, int] = {}
        failed = 0
        for t in txs:
            ts = int(t.get("timeStamp") or 0)
            if ts:
                s = dt.datetime.fromtimestamp(ts, dt.timezone.utc).date().isoformat()
                first_seen = first_seen or s
                last_seen = s
            val = _wei_to_eth(t.get("value"))
            if (t.get("to") or "").lower() == addr.lower():
                in_eth += val
            if (t.get("from") or "").lower() == addr.lower():
                out_eth += val
            other = t.get("from") if (t.get("to") or "").lower() == addr.lower() else t.get("to")
            if other:
                parties[other] = parties.get(other, 0) + 1
            if t.get("isError") == "1":
                failed += 1
        top_parties = sorted(parties.items(), key=lambda kv: kv[1], reverse=True)[:5]

        kind = "contract" if is_contract else "wallet/EOA"
        out.append(self._f(
            "identity", "chain_profile",
            f"Chain profile: {addr} ({kind}) - balance {balance:.4f} ETH, "
            f"{len(txs)} recent txns ({in_eth:.4f} ETH in / {out_eth:.4f} ETH out), "
            f"first seen {first_seen or 'n/a'}, last {last_seen or 'n/a'}, "
            f"{len(parties)} counterparties{', ' + str(failed) + ' failed txns' if failed else ''}.",
            source="Etherscan", source_url=f"https://etherscan.io/address/{addr}",
            confidence=90, passive=True,
            evidence={
                "severity": "low", "address": addr, "kind": kind,
                "balance_eth": round(balance, 6),
                "recent_txs": len(txs), "in_eth": round(in_eth, 6),
                "out_eth": round(out_eth, 6), "first_seen": first_seen,
                "last_seen": last_seen,
                "top_counterparties": [p[0] for p in top_parties],
                "failed_txs": failed,
                "verified_source": verified, "contract_name": contract_name,
                "exploitability": "unknown",
                "remediation": ("Public chain data: nothing to remediate. Use the "
                                "counterparty list and first/last activity to pivot "
                                "further (exchange deposits, mixer interaction, "
                                "linked identities).")}))

        if is_contract and not verified:
            out.append(self._f(
                "identity", "contract_unverified",
                f"MEDIUM: {addr} has deployed bytecode but no verified source "
                f"on Etherscan. Treat any interaction with it as high risk.",
                source="Etherscan", source_url=f"https://etherscan.io/address/{addr}",
                confidence=90, passive=True,
                evidence={
                    "severity": "medium", "address": addr,
                    "exploitability": "theoretical",
                    "remediation": ("Do not interact with unverified contracts. If "
                                    "this contract belongs to the target, publish "
                                    "verified source so users can audit what they "
                                    "approve.")}))
        return out

    async def _sourcify_verified(self, ctx: Ctx, addr: str):
        """Keyless verified-source check via Sourcify (no auth).

        Returns (is_contract, verified, contract_name). Sourcify v2 API
        returns 404 when the address is not a verified contract.
        """
        url = f"{SOURCIFY_V2}/{addr}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20,
                            max_retries=1)
        except Exception:
            return False, False, ""
        if r.status_code == 404:
            return False, False, ""
        if r.status_code != 200:
            return False, False, ""
        try:
            d = r.json()
        except Exception:
            return False, False, ""
        # v2 returns match info; presence of creationMatch/runtimeMatch
        # means verified bytecode on Sourcify.
        creation = d.get("creationMatch")
        runtime = d.get("runtimeMatch")
        verified = bool(creation or runtime)
        name = ""
        try:
            meta = (runtime or creation or {}).get("metadata") or {}
            settings = meta.get("settings") or {}
            targets = settings.get("compilationTarget") or {}
            if isinstance(targets, dict) and targets:
                first = next(iter(targets.values()))
                name = str(first).split(":")[-1] if isinstance(first, str) else ""
        except Exception:
            pass
        # Any 200 with match data implies contract bytecode exists.
        return True, verified, name

    async def _enrich_keyless(self, ctx: Ctx, addr: str) -> List[Finding]:
        """Keyless enrichment: Blockchair (balance/activity) + Sourcify
        (verified-source check). No API keys needed."""
        out: List[Finding] = []

        # 1. Blockchair dashboard: balance, tx counts, first/last seen.
        balance = 0.0
        tx_count = 0
        first_seen = last_seen = ""
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            f"{BLOCKCHAIR_API}/{addr}", timeout=20,
                            max_retries=1)
            data = safe_json_dict(r)
            info = ((data.get("data") or {}).get(addr) or {})
            address_info = info.get("address") or {}
            balance = _wei_to_eth(str(address_info.get("balance") or "0"))
            tx_count = int(address_info.get("transaction_count") or 0)
            first_seen = str(address_info.get("first_seen_receiving") or "")[:10]
            last_seen = str(address_info.get("last_seen_spending") or "")[:10]
        except Exception:
            pass

        # 2. Sourcify verified-source check.
        is_contract, verified, contract_name = await self._sourcify_verified(ctx, addr)
        ctx.publish("chain_contracts", {
            "address": addr, "is_contract": is_contract,
            "verified": verified, "name": contract_name})

        kind = "contract" if is_contract else "wallet/EOA"
        out.append(self._f(
            "identity", "chain_profile",
            f"Chain profile: {addr} ({kind}) - balance {balance:.4f} ETH, "
            f"{tx_count} total txns, first seen {first_seen or 'n/a'}, "
            f"last {last_seen or 'n/a'}"
            f"{', verified source on Sourcify' + (f' ({contract_name})' if contract_name else '') if verified else ''}.",
            source="Blockchair+Sourcify (keyless)",
            source_url=f"https://blockchair.com/ethereum/address/{addr}",
            confidence=85, passive=True,
            evidence={
                "severity": "low", "address": addr, "kind": kind,
                "balance_eth": round(balance, 6), "tx_count": tx_count,
                "first_seen": first_seen, "last_seen": last_seen,
                "verified_source": verified, "contract_name": contract_name,
                "exploitability": "unknown",
                "remediation": ("Public chain data: nothing to remediate. Add "
                                "ETHERSCAN_API_KEY for full tx history and "
                                "counterparty analysis.")}))

        if is_contract and not verified:
            out.append(self._f(
                "identity", "contract_unverified",
                f"MEDIUM: {addr} has deployed bytecode but no verified source "
                f"on Sourcify/Etherscan. Treat any interaction with it as high risk.",
                source="Sourcify (keyless)",
                source_url=f"https://blockchair.com/ethereum/address/{addr}",
                confidence=85, passive=True,
                evidence={
                    "severity": "medium", "address": addr,
                    "exploitability": "theoretical",
                    "remediation": ("Do not interact with unverified contracts. If "
                                    "this contract belongs to the target, publish "
                                    "verified source so users can audit what they "
                                    "approve.")}))
        return out
