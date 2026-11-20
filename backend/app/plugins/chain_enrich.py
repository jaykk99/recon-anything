"""Multi-chain address enrichment (keyless, read-only OSINT).

chain_osint enriches Ethereum 0x addresses. This plugin covers
everything else the address detectors find - Bitcoin, Litecoin,
Dogecoin, Bitcoin Cash, Dash, Zcash, Tron, XRP, Solana - and applies
public address labels (exchange / mixer / bridge / sanctioned / burn) to
EVERY discovered address, including Ethereum ones.

Before this, a target that published a BTC or SOL wallet got the address
detected but never enriched: no balance, no activity, no label. Now the
checksum-verified detectors feed the crypto_addresses bus (with a chain
tag) and this phase-2 plugin looks each one up on a keyless public
source.

All sources are no-auth public explorers/RPCs. Read-only: it never
signs, sends, or interacts on-chain - it reads what a block explorer
already shows. Pure parsers (parse_*) are module-level so they unit-test
without the network.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from ..chaindata import (APTOS_ACCOUNTS, BLOCKCHAIR, CHAINS, DASH_INSIGHT,
                         DOGECHAIN, KOIOS, SOLANA_RPC, SUI_COIN_TYPE,
                         SUI_GRAPHQL, TONCENTER, TRONGRID, TRONSCAN, XRPSCAN,
                         explorer_url, parse_aptos, parse_blockchair,
                         parse_dash_insight, parse_dogechain, parse_esplora,
                         parse_koios, parse_solana_balance, parse_sui,
                         parse_ton, parse_tron, parse_trongrid, parse_xrp)
from ..cryptolabels import labels_for, summarize_label
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

MAX_ADDR = 14          # addresses to enrich per run
PER_ADDR_TIMEOUT = 15


class ChainEnrichPlugin(Plugin):
    id = "chain_enrich"
    label = "Multi-chain OSINT"
    # Also runs when the scan target IS an address: the checksum
    # detectors publish it to crypto_addresses and this plugin is the
    # phase-2 consumer, so a pasted wallet gets a real lookup instead
    # of an empty run (chain-health fix 2026-11-14).
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ("Keyless balance/activity enrichment for discovered "
                   "Bitcoin, Litecoin, Dogecoin, BCH, Dash, Zcash, Tron, XRP "
                   "and Solana addresses, plus public address labels "
                   "(exchange/mixer/bridge/sanctioned/burn) on every address. "
                   "Read-only public-explorer data.")
    phase = 2
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        items = self._collect(ctx)
        if not items:
            res = self._skipped("no non-ETH crypto addresses discovered on "
                                "this target; nothing to enrich")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        enriched = 0
        labeled = 0
        attempts = 0
        refused = 0
        for addr, chain, key in items[:MAX_ADDR]:
            cfg = CHAINS.get(chain, {"kind": "label_only", "name": chain})
            enrichable = cfg.get("kind") not in (None, "label_only")
            if enrichable:
                attempts += 1
            # 1. labels on every address (keyless, local)
            try:
                labs = labels_for(addr, chain)
                if labs:
                    findings.append(self._label_finding(addr, chain, cfg, labs))
                    labeled += 1
            except Exception:
                pass
            # 2. balance/activity for enrichable chains
            try:
                prof = await self._enrich(ctx, addr, chain, cfg)
                if prof:
                    findings.append(self._profile_finding(addr, chain, cfg, prof))
                    enriched += 1
                elif enrichable:
                    refused += 1
            except Exception:
                if enrichable:
                    refused += 1
                continue
            self._checkpoint(findings)

        dur = int((time.monotonic() - t0) * 1000)
        note = (f"enriched {enriched}, labeled {labeled} of "
                f"{len(items)} non-ETH address(es), keyless")
        if refused:
            note += (f"; {refused}/{attempts} chain lookup(s) refused "
                     "upstream (no keyless source answered)")
        # A run that found nothing AND reached no source is degraded,
        # never a clean OK: silence must not read as "address is clean".
        if attempts and enriched == 0 and labeled == 0:
            res = self._degraded(f"DEGRADED: {note}")
        else:
            res = self._ok(findings, note)
        res.duration_ms = dur
        return res

    def _collect(self, ctx: Ctx) -> List[Tuple[str, str, str]]:
        out: List[Tuple[str, str, str]] = []
        seen = set()
        for item in ctx.consume("crypto_addresses"):
            if isinstance(item, dict):
                addr = str(item.get("address", "")).strip()
                chain = str(item.get("chain", "")).strip().lower()
                key = str(item.get("key", ""))
            else:
                addr, chain, key = str(item).strip(), "", ""
            if not addr or addr in seen:
                continue
            seen.add(addr)
            out.append((addr, chain, key))
        return out

    async def _enrich(self, ctx: Ctx, addr: str, chain: str,
                      cfg: Dict[str, str]) -> Dict[str, Any]:
        kind = cfg.get("kind")
        if kind == "blockchair":
            url = BLOCKCHAIR.format(slug=cfg["slug"], addr=addr)
            r = await fetch(ctx.http, ctx.limiter, "GET", url,
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_blockchair(safe_json_dict(r), addr)
        if kind == "esplora":
            url = f"{(cfg.get('base') or 'https://mempool.space/api').rstrip('/')}/address/{addr}"
            r = await fetch(ctx.http, ctx.limiter, "GET", url,
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_esplora(safe_json_dict(r), addr)
        if kind == "dogechain":
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            DOGECHAIN.format(addr=addr),
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_dogechain(safe_json_dict(r))
        if kind == "dash":
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            DASH_INSIGHT.format(addr=addr),
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_dash_insight(safe_json_dict(r))
        if kind == "tron":
            # TronGrid answers keyless; Tronscan is the fallback because
            # its anonymous quota is 3 rps (HTTP 429) on 2026-11-14.
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            TRONGRID.format(addr=addr),
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            prof = parse_trongrid(safe_json_dict(r))
            if prof:
                return prof
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            TRONSCAN.format(addr=addr),
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_tron(safe_json_dict(r))
        if kind == "cardano":
            r = await fetch(ctx.http, ctx.limiter, "POST", KOIOS,
                            timeout=PER_ADDR_TIMEOUT, max_retries=1,
                            headers={"Content-Type": "application/json"},
                            content=json.dumps({"_addresses": [addr]}))
            return parse_koios(safe_json_dict(r))
        if kind == "ton":
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            TONCENTER.format(addr=addr),
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_ton(safe_json_dict(r))
        if kind == "sui":
            query = ("query { address(address: \"%s\") { balance("
                     "coinType: \"%s\") { totalBalance } } }"
                     % (addr, SUI_COIN_TYPE))
            r = await fetch(ctx.http, ctx.limiter, "POST", SUI_GRAPHQL,
                            timeout=PER_ADDR_TIMEOUT, max_retries=1,
                            headers={"Content-Type": "application/json"},
                            content=json.dumps({"query": query}))
            return parse_sui(safe_json_dict(r))
        if kind == "aptos":
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            APTOS_ACCOUNTS.format(addr=addr),
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_aptos(safe_json_dict(r))
        if kind == "xrp":
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            XRPSCAN.format(addr=addr),
                            timeout=PER_ADDR_TIMEOUT, max_retries=1)
            return parse_xrp(safe_json_dict(r))
        if kind == "solana":
            body = json.dumps({"jsonrpc": "2.0", "id": 1,
                               "method": "getBalance", "params": [addr]})
            r = await fetch(ctx.http, ctx.limiter, "POST", SOLANA_RPC,
                            timeout=PER_ADDR_TIMEOUT, max_retries=1,
                            headers={"Content-Type": "application/json"},
                            content=body)
            return parse_solana_balance(safe_json_dict(r))
        return {}

    def _profile_finding(self, addr: str, chain: str, cfg: Dict[str, str],
                         prof: Dict[str, Any]) -> Finding:
        name = cfg.get("name", chain.upper())
        bal = prof.get("balance", 0.0)
        parts = [f"balance {bal}"]
        if prof.get("tx_count"):
            parts.append(f"{prof['tx_count']} txns")
        if prof.get("first_seen"):
            parts.append(f"first seen {prof['first_seen']}")
        if prof.get("last_seen"):
            parts.append(f"last {prof['last_seen']}")
        return self._f(
            "identity", "chain_profile",
            f"{name} address {addr}: " + ", ".join(parts) + ".",
            source=f"{name} explorer (keyless)",
            source_url=explorer_url(addr, chain),
            confidence=85, passive=True,
            evidence={"severity": "low", "address": addr, "chain": chain,
                      "exploitability": "unknown", **prof,
                      "remediation": ("Public chain data: nothing to "
                                      "remediate. Pivot on activity / "
                                      "counterparties to map linked wallets "
                                      "and exchange deposits.")})

    def _label_finding(self, addr: str, chain: str, cfg: Dict[str, str],
                       labs: List[Dict[str, Any]]) -> Finding:
        worst = max(labs, key=lambda l: {"high": 3, "medium": 2, "low": 1}
                    .get(l.get("severity", "low"), 1))
        sev = worst.get("severity", "low")
        cats = sorted({l.get("category", "") for l in labs if l.get("category")})
        summary = summarize_label(labs) or "labeled address"
        return self._f(
            "identity", "address_label",
            f"{cfg.get('name', chain.upper())} address {addr} is labeled: "
            f"{summary}. {worst.get('note', '')}",
            source=worst.get("source", "public label set"),
            source_url=explorer_url(addr, chain),
            confidence=88, passive=True,
            evidence={"severity": sev, "address": addr, "chain": chain,
                      "labels": labs, "categories": cats,
                      "exploitability": "unknown",
                      "remediation": (
                          "Analytical label from public data. A "
                          "sanctioned/mixer link is a compliance signal - "
                          "review exposure before interacting; nothing to "
                          "patch on the target itself.")})
