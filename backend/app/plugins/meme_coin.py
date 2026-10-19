"""Meme-coin / token risk scanner (defensive OSINT).

For token contract addresses discovered during a scan (published on the
"contract_addresses" discovery bus), this pulls the VERIFIED public source
from Etherscan and runs static honeypot / rug-pull checks: sell-blocking
transfer logic, owner mint levers, wallet blacklists, tax levers (buy vs
sell tax asymmetry), and unrenounced ownership. Detection only: pure
static source analysis, never interacts with the chain, never calls
contracts, never touches wallets.

Needs ETHERSCAN_API_KEY (ctx key "etherscan" or the ETHERSCAN_API_KEY
env var). Skips gracefully with a clear note when the key is missing.

Liquidity depth/locks cannot be checked statically; every finding's
remediation says to verify locks manually.
"""
from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional, Tuple

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

ETH_API = "https://api.etherscan.io/api"
MAX_ADDR = 5  # tokens to scan per run (free-tier friendly)


def _key(ctx: Ctx) -> Optional[str]:
    return ctx.keys.get("etherscan") or os.environ.get("ETHERSCAN_API_KEY") or None


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _func_body(clean: str, name: str) -> str:
    """Return the body of the first function named `name` (brace matched)."""
    m = re.search(r"function\s+" + re.escape(name) +
                  r"\s*\([^;{}]*\)[^{;]*\{", clean)
    if not m:
        return ""
    i = m.end() - 1
    depth = 0
    j = i
    while j < len(clean):
        if clean[j] == "{":
            depth += 1
        elif clean[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return clean[i:j + 1]


def _tax_values(clean: str) -> Tuple[List[int], List[int]]:
    """Extract declared buy/sell tax numbers from source."""
    buys: List[int] = []
    sells: List[int] = []
    for m in re.finditer(
            r"\b(_?(buy|sell)(tax|fee|liquidityfee|marketingfee|devfee\w*))\b"
            r"\s*=\s*(\d+)", clean, re.I):
        var, side, _kind, val = m.group(1), m.group(2), m.group(3), m.group(4)
        try:
            v = int(val)
        except ValueError:
            continue
        (buys if side.lower() == "buy" else sells).append(v)
    return buys, sells


def audit_meme_token(src: str) -> List[Dict[str, str]]:
    """Static meme-coin risk checks over verified Solidity source.

    Returns list of {"check":..., "severity":..., "detail":...,
    "remediation":...}.
    """
    out: List[Dict[str, str]] = []
    clean = _strip_comments(src)
    liq_note = (" Liquidity depth and locks cannot be verified statically: "
                "check a locker (Unicrypt, Team Finance) and the pair's "
                "reserves manually before interacting.")

    # --- 1. honeypot: transfer logic that blocks sells ---
    transfer = _func_body(clean, "_transfer")
    honey_hits = []
    if transfer:
        # buy-only gate: _transfer reverts unless the sender is the pair
        if re.search(r"require\s*\([^)]*from\s*==\s*\w*[Pp]air", transfer):
            honey_hits.append("transfer reverts unless sender is the pair "
                              "(buys only - sells blocked)")
        # sell path gated on an owner allowlist
        if re.search(r"require\s*\([^)]*to\s*!=\s*\w*[Pp]air", transfer):
            honey_hits.append("transfer reverts when sending TO the pair "
                              "(sell path blocked)")
        # blacklist enforced on the transfer path
        if re.search(r"[Bb]lacklist", transfer):
            honey_hits.append("blacklist mapping enforced inside _transfer "
                              "(wallets can be blocked from selling)")
        # DEX router blocked on the sell path
        if re.search(r"require\s*\([^)]*router", transfer, re.I):
            honey_hits.append("router-gated require() on the transfer path")
    if honey_hits:
        out.append({
            "check": "honeypot",
            "severity": "high",
            "detail": ("HONEYPOT SHAPE: " + "; ".join(honey_hits) + ". Holders "
                       "may be able to buy but not sell."),
            "remediation": ("Do not buy until sells are proven: simulate a "
                            "sell on a fork, or watch the pair for real sell "
                            "transactions from non-owner wallets." + liq_note)})

    # --- 2. rug-pull levers ---
    fn_names = re.findall(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean)

    # 2a. owner can mint unlimited
    mint_fns = [n for n in fn_names if n.lower() == "mint"]
    if mint_fns:
        capped = bool(re.search(r"maxSupply|MAX_SUPPLY|supply\s*\+\s*amount\s*<=|"
                                r"require\s*\(\s*totalSupply\s*\(\s*\)\s*\+",
                                clean, re.I))
        out.append({
            "check": "rug_mint",
            "severity": "high" if not capped else "medium",
            "detail": ("RUG LEVER: mint() present" +
                       (" with NO visible supply cap" if not capped
                        else " (a supply cap is visible)") +
                       ". Unbounded minting dilutes holders to zero."),
            "remediation": ("Require a hard supply cap or burned mint keys. "
                            "Until then, assume the owner can print at will."
                            + liq_note)})

    # 2b. owner can blacklist wallets
    bl_fns = [n for n in fn_names
              if re.search(r"blacklist", n, re.I)]
    if bl_fns:
        out.append({
            "check": "rug_blacklist",
            "severity": "high",
            "detail": ("RUG LEVER: blacklist setter(s) " +
                       ", ".join(sorted(set(bl_fns))) +
                       ". The owner can block any wallet from selling or "
                       "receiving - selective honeypot at will."),
            "remediation": ("Blacklists must be renounced or time-limited and "
                            "documented. Assume blacklisted-you until proven "
                            "otherwise." + liq_note)})

    # 2c. owner can set tax > 25% (or with no upper bound)
    tax_setters = [n for n in fn_names
                   if re.search(r"set(tax|fee)|update(tax|fee)", n, re.I)]
    buys, sells = _tax_values(clean)
    declared_high = [v for v in buys + sells if v > 25]
    capped_tax = bool(re.search(
        r"require\s*\([^)]*(_taxFee|_sellTax|_buyTax|taxFee|sellTax|buyTax)"
        r"[^)]*<=\s*(25|2[0-4]|\d{1,2})\b", clean))
    if tax_setters and not capped_tax:
        out.append({
            "check": "rug_tax",
            "severity": "high",
            "detail": ("RUG LEVER: tax setter(s) " +
                       ", ".join(sorted(set(tax_setters))) +
                       " with NO visible upper bound. The owner can raise "
                       "taxes to 100% (soft honeypot)."),
            "remediation": ("Taxes must be capped on-chain (e.g. "
                            "require(tax <= 25)). Until capped, any tax level "
                            "is possible." + liq_note)})
    if declared_high:
        out.append({
            "check": "rug_tax",
            "severity": "high",
            "detail": (f"RUG LEVER: declared tax value(s) above 25%: "
                       f"{sorted(set(declared_high))}. Confiscatory fees."),
            "remediation": ("Verify the live tax by simulating buy AND sell "
                            "on a fork. Fees above ~10% are a red flag."
                            + liq_note)})

    # 2d. owner can disable trading
    trade_fns = [n for n in fn_names
                 if re.search(r"trading", n, re.I)]
    if trade_fns:
        out.append({
            "check": "rug_trading",
            "severity": "medium",
            "detail": ("RUG LEVER: trading toggle(s) " +
                       ", ".join(sorted(set(trade_fns))) +
                       ". The owner can halt all trading (freeze exits)."),
            "remediation": ("Trading controls must be renounced after launch "
                            "or governed by timelock. A live toggle means "
                            "exits exist at the owner's pleasure." + liq_note)})

    # --- 3. tax analysis: asymmetric buy vs sell tax ---
    if buys or sells:
        bmax = max(buys) if buys else 0
        smax = max(sells) if sells else 0
        if smax > 0 and bmax >= 0 and smax > bmax * 1.5 and smax - bmax >= 5:
            out.append({
                "check": "asymmetric_tax",
                "severity": "medium",
                "detail": (f"ASYMMETRIC TAX (honeypot shape): max buy tax "
                           f"{bmax}% vs max sell tax {smax}%. Sellers pay "
                           f"far more - exiting is punished."),
                "remediation": ("Simulate a full buy-then-sell round trip on "
                                "a fork and measure the real haircut. "
                                "Asymmetric sell tax is a classic soft-rug."
                                + liq_note)})

    # --- 4. ownership not renounced ---
    if re.search(r"function\s+owner\s*\(", clean):
        if not re.search(r"renounceOwnership", clean):
            out.append({
                "check": "owner_not_renounced",
                "severity": "medium",
                "detail": ("OWNERSHIP NOT RENOUNCED: owner() exists but "
                           "renounceOwnership never appears in source. Every "
                           "owner lever above stays live."),
                "remediation": ("Prefer renounced ownership or a timelocked "
                                "multisig owner. Until then, the deployer "
                                "holds all levers." + liq_note)})

    # dedup by check
    seen = set()
    deduped = []
    for f in out:
        if f["check"] in seen:
            continue
        seen.add(f["check"])
        deduped.append(f)
    return deduped


EXPL = {
    "honeypot": "public_poc",
    "rug_mint": "public_poc",
    "rug_blacklist": "public_poc",
    "rug_tax": "theoretical",
    "rug_trading": "theoretical",
    "asymmetric_tax": "theoretical",
    "owner_not_renounced": "theoretical",
}


class MemeCoinPlugin(Plugin):
    id = "meme_coin"
    label = "Meme Coin Risk Scanner"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = ["etherscan"]
    description = ("Meme-coin / token risk scan on verified source: honeypot "
                   "shapes, rug-pull levers (mint, blacklist, taxes, trading "
                   "toggles), tax asymmetry, ownership. Static only, never "
                   "touches the chain.")
    phase = 2  # consumes addresses published by address miners
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = _key(ctx)
        if not key:
            return self._skipped(
                "ETHERSCAN_API_KEY not configured (set the 'etherscan' key or "
                "ETHERSCAN_API_KEY env var). Meme-coin scan skipped.")

        addrs = self._collect(ctx)
        if not addrs:
            res = self._skipped("no token contract addresses discovered on "
                                "this target; nothing to scan")
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
                        "web3", "meme_unverified",
                        f"{addr}: no verified source on Etherscan. Token "
                        "risk cannot be assessed statically; treat as "
                        "dangerous.",
                        source="Etherscan",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=90, passive=True,
                        evidence={
                            "severity": "medium", "address": addr,
                            "exploitability": "unknown",
                            "remediation": ("Do not buy unverified tokens. "
                                            "Unverified code hides honeypots, "
                                            "hidden mint, and tax traps.")}))
                    continue
                scanned += 1
                risks = audit_meme_token(src)
                if not risks:
                    findings.append(self._f(
                        "web3", "meme_no_flags",
                        f"{addr}: verified source scanned; no honeypot, "
                        "rug-lever, tax, or ownership flags found. Not a "
                        "proof of safety.",
                        source="Etherscan static scan",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=60, passive=True,
                        evidence={
                            "severity": "low", "address": addr,
                            "exploitability": "unknown",
                            "remediation": ("Static scan is a first pass only. "
                                            "Verify liquidity locks manually "
                                            "and get a real audit before "
                                            "buying.")}))
                for r in risks:
                    findings.append(self._f(
                        "web3", f"meme_{r['check']}",
                        f"{r['severity'].upper()}: {r['detail']}",
                        source="Etherscan static scan",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=75, passive=True,
                        evidence={
                            "severity": r["severity"], "address": addr,
                            "check": r["check"],
                            "exploitability": EXPL.get(r["check"], "unknown"),
                            "remediation": r["remediation"],
                            "scope_note": ("Static analysis of published source "
                                           "only. Never interacted with the "
                                           "contract or any wallet.")}))
            except Exception:
                continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"scanned {scanned} token(s), "
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
