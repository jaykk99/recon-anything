"""Token rug-check: scam-token safety signals (defensive, read-only).

Flags the classic rug-pull / scam-token patterns so a user can spot a
scam token BEFORE touching it:

  - holder concentration (a few wallets control most of the supply)
  - liquidity that is not locked or burned (can be pulled in one tx)
  - mint / freeze authority still active
  - honeypot + extreme buy/sell tax signals
  - unverified contract source
  - owner privileges that can move balances or rewrite the rules

Detection only. Every check is a read-only GET (or JSON-RPC read)
against public keyless sources: GoPlus Security (token security
metadata), DexScreener (market/liquidity), and the public Solana RPC
(supply, largest accounts, mint layout). It never creates tokens,
never creates or touches wallets, never signs anything, and never
moves money. There is deliberately no transaction code in this file.

Sources degrade independently: if one API is unreachable the rest
still run and the finding set simply shrinks. Checks with no data
never fabricate a flag.
"""
from __future__ import annotations

import asyncio
import base64
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   safe_json_dict, safe_json_list)

# --- sources (all keyless, read-only) ---------------------------------
GOPLUS_EVM = ("https://api.gopluslabs.io/api/v1/token_security/{chain}"
              "?contract_addresses={addr}")
GOPLUS_SOL = ("https://api.gopluslabs.io/api/v1/sol_token_security"
              "?contract_addresses={addr}")
HONEYPOT_IS = ("https://api.honeypot.is/v2/IsHoneypot"
               "?address={addr}&chainID={chain}")
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/{addr}"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# EVM chains probed (id -> name), most scam-heavy first.
EVM_CHAINS = [(1, "ethereum"), (56, "bsc"), (8453, "base"),
              (137, "polygon"), (42161, "arbitrum"), (43114, "avalanche"),
              (10, "optimism")]

MAX_TOKENS = 3            # tokens checked per run (keeps runs bounded)
EVM_RE = re.compile(r"0x[0-9a-fA-F]{40}")
SOL_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")
B58_CTX_RE = re.compile(r"(mint|token|contract|ca\b|address)", re.I)
ZERO_ADDR = "0x" + "0" * 40

# Well-known majors: checking them burns the per-run token budget and
# the answers are already known. Skipped silently.
KNOWN_MAJORS = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH (eth)
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC (eth)
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT (eth)
    "0x55d398326f99059ff775485246999027b3197955",  # USDT (bsc)
    "So11111111111111111111111111111111111111112",  # WSOL
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC (sol)
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",  # USDT (sol)
}

SCOPE_NOTE = ("Read-only public API lookups (GoPlus, DexScreener, "
              "public chain RPC). No transaction was simulated, signed "
              "or sent; nothing on-chain was touched.")

REMEDIATION = ("Do not buy or hold this token until the flags are "
               "resolved. Check the contract yourself on the chain "
               "explorer, confirm liquidity is locked or burned, and "
               "never connect a main wallet to an unknown token site.")


def _tax_pct(raw: Any) -> Optional[float]:
    """GoPlus taxes come as '0.05' (fraction) or occasionally '5'.
    Normalize to a percentage float; None when unparseable."""
    try:
        v = float(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if v < 0:
        return None
    return v * 100.0 if v <= 1.0 else v


def _f1(raw: Any) -> Optional[float]:
    """Loose '0'/'1' flag parser used by the GoPlus payload."""
    if raw is None:
        return None
    try:
        return 1.0 if float(str(raw).strip()) >= 1.0 else 0.0
    except (TypeError, ValueError):
        return None


def _looks_like_solana_mint(s: str) -> bool:
    s = (s or "").strip()
    if not SOL_RE.fullmatch(s):
        return False
    if EVM_RE.fullmatch(s) or s.lower().startswith("bc1"):
        return False
    # pure numbers / single-case strings are not mints in practice
    return any(c.isalpha() for c in s)


def _parse_solana_mint(raw: bytes) -> Dict[str, Optional[str]]:
    """SPL Token Mint account layout (82 bytes):
    mint_authority   COption<Pubkey>: tag u32 @0,  key @4..36
    supply           u64 @36
    decimals         u8  @44
    is_initialized   bool @45
    freeze_authority COption<Pubkey>: tag u32 @46, key @50..82
    Authorities are returned as hex (presence is what matters)."""
    out: Dict[str, Optional[str]] = {"mint_authority": None,
                                     "freeze_authority": None}
    if not raw or len(raw) < 82:
        return out
    if int.from_bytes(raw[0:4], "little") == 1:
        out["mint_authority"] = raw[4:36].hex()
    if int.from_bytes(raw[46:50], "little") == 1:
        out["freeze_authority"] = raw[50:82].hex()
    return out


class TokenRugcheckPlugin(Plugin):
    id = "token_rugcheck"
    label = "Token Rug-Check"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True  # read-only API lookups only; runs in both modes
    cost = Cost.FREE
    group = "web3"
    description = ("Scam-token safety check for a token contract (EVM) "
                   "or Solana mint: holder concentration, unlocked "
                   "liquidity, live mint/freeze authority, honeypot and "
                   "tax signals, unverified source, owner control. "
                   "Read-only via keyless GoPlus + DexScreener + public "
                   "RPC. Detection only - never trades or touches funds.")
    phase = 2  # also consumes addresses mined by phase-1 plugins
    timeout_s = 120

    # ------------------------------------------------------------------
    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            tokens = await self._collect(target, ctx)
        except Exception:
            tokens = []
        if not tokens:
            res = self._skipped("no token contract/mint address on this "
                                "target; nothing to rug-check")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        checked = 0
        for addr, kind in tokens[:MAX_TOKENS]:
            try:
                if kind == "solana":
                    got = await self._check_solana(ctx, addr, passive)
                else:
                    got = await self._check_evm(ctx, addr, passive)
                findings.extend(got)
                checked += 1
            except Exception:
                continue  # one bad token never kills the plugin
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"rug-checked {checked}/{min(len(tokens), MAX_TOKENS)}"
                       f" token(s); {len(findings)} finding(s)")
        res.duration_ms = dur
        return res

    # ------------------------------------------------------------------
    # Target collection: direct address, discovery bus, page content.
    # ------------------------------------------------------------------
    async def _collect(self, target: Target,
                       ctx: Ctx) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        seen = set()

        def add(addr: str, kind: str) -> None:
            key = addr.lower()
            if key in seen or addr in KNOWN_MAJORS or key in KNOWN_MAJORS:
                return
            seen.add(key)
            out.append((addr, kind))

        norm = (target.normalized or "").strip()
        if EVM_RE.fullmatch(norm):
            add(norm, "evm")
        elif _looks_like_solana_mint(norm):
            add(norm, "solana")

        for kind_name in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind_name):
                a = item if isinstance(item, str) else str(
                    item.get("address", "") if isinstance(item, dict) else item)
                a = (a or "").strip()
                if EVM_RE.fullmatch(a):
                    add(a, "evm")
                elif _looks_like_solana_mint(a):
                    add(a, "solana")

        # Page content: mine addresses out of the homepage itself.
        if target.type in ("domain", "url") and len(out) < MAX_TOKENS:
            domain = domain_from_target(target.type, target.normalized)
            if domain:
                from ..net import web_base
                base = (await web_base(ctx, target, domain)).rstrip("/")
                page = await ctx.fetch_page(base, timeout=20)
                if page:
                    html = page.get("text") or ""
                    for m in EVM_RE.finditer(html):
                        add(m.group(0), "evm")
                    for m in SOL_RE.finditer(html):
                        cand = m.group(0)
                        window = html[max(0, m.start() - 120):m.end() + 40]
                        if (B58_CTX_RE.search(window)
                                and _looks_like_solana_mint(cand)):
                            add(cand, "solana")
        return out

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _flag(self, key: str, severity: str, title: str, why: str,
              addr: str, chain: str, confidence: int = 85,
              extra: Optional[Dict[str, Any]] = None,
              passive: bool = True) -> Finding:
        ev: Dict[str, Any] = {
            "severity": severity,
            "title": title,
            "why_it_matters": why,
            "token_address": addr,
            "chain": chain,
            "remediation": REMEDIATION,
            "scope_note": SCOPE_NOTE,
        }
        if extra:
            ev.update(extra)
        return self._f("web3", key, f"{severity.upper()}: {title}. {why}",
                       source="Token rug-check", confidence=confidence,
                       evidence=ev, passive=passive)

    async def _dexscreener(self, ctx: Ctx, addr: str) -> Dict[str, Any]:
        """Best pair liquidity/market numbers from DexScreener."""
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            DEXSCREENER.format(addr=addr),
                            timeout=15, max_retries=1)
            if r.status_code != 200:
                return {}
            d = safe_json_dict(r)
        except Exception:
            return {}
        pairs = d.get("pairs")
        if not isinstance(pairs, list) or not pairs:
            return {}
        best: Dict[str, Any] = {}
        best_liq = -1.0
        for p in pairs:
            if not isinstance(p, dict):
                continue
            liq = ((p.get("liquidity") or {}).get("usd")
                   if isinstance(p.get("liquidity"), dict) else None)
            try:
                liq_f = float(liq) if liq is not None else 0.0
            except (TypeError, ValueError):
                liq_f = 0.0
            if liq_f > best_liq:
                best_liq = liq_f
                best = {"liquidity_usd": liq_f, "chain": p.get("chainId"),
                        "dex": p.get("dexId"),
                        "pair_created_at": p.get("pairCreatedAt"),
                        "fdv": p.get("fdv")}
        best["pairs"] = len(pairs)
        return best

    # ------------------------------------------------------------------
    # EVM token check
    # ------------------------------------------------------------------
    async def _goplus_evm(self, ctx: Ctx,
                          addr: str) -> Tuple[Optional[str], Dict[str, Any]]:
        reqs = [("GET", GOPLUS_EVM.format(chain=cid, addr=addr),
                 {"timeout": 15, "max_retries": 1})
                for cid, _name in EVM_CHAINS]
        try:
            resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                     concurrency=7, deadline=45)
        except Exception:
            return None, {}
        for (cid, cname), r in zip(EVM_CHAINS, resps or []):
            if r is None or getattr(r, "status_code", 0) != 200:
                continue
            d = safe_json_dict(r)
            result = d.get("result")
            if not isinstance(result, dict):
                continue
            info = result.get(addr.lower()) or result.get(addr) or {}
            if isinstance(info, dict) and info:
                return cname, info
        return None, {}

    async def _check_evm(self, ctx: Ctx, addr: str,
                         passive: bool) -> List[Finding]:
        findings: List[Finding] = []
        chain_name, info = await self._goplus_evm(ctx, addr)
        dex = await self._dexscreener(ctx, addr)
        chain = chain_name or str(dex.get("chain") or "evm")
        flags = 0
        score = 0
        checks: List[str] = []

        if not info:
            findings.append(self._flag(
                "rugcheck_no_data", "low",
                f"No security data found for token {addr[:10]}...",
                "No public security or market source recognizes this "
                "token. A token nobody can verify is a token you cannot "
                "check for scams - treat that as a warning by itself.",
                addr, chain, confidence=60, passive=passive))
            return findings

        # --- honeypot -------------------------------------------------
        checks.append("honeypot")
        if _f1(info.get("is_honeypot")) == 1.0:
            flags += 1
            score += 40
            findings.append(self._flag(
                "rugcheck_honeypot", "high",
                "Honeypot: buyers cannot sell this token",
                "A honeypot lets you buy but blocks you from selling, "
                "so every dollar you put in is trapped while the price "
                "chart keeps going up to lure the next victim.",
                addr, chain, confidence=90,
                extra={"is_honeypot": True}, passive=passive))

        # --- buy/sell tax ----------------------------------------------
        checks.append("tax")
        buy_tax = _tax_pct(info.get("buy_tax"))
        sell_tax = _tax_pct(info.get("sell_tax"))
        worst_tax = max([t for t in (buy_tax, sell_tax) if t is not None],
                        default=None)
        if worst_tax is not None and worst_tax > 10:
            flags += 1
            sev = "high" if worst_tax > 25 else "medium"
            score += 30 if worst_tax > 25 else 18
            findings.append(self._flag(
                "rugcheck_extreme_tax" if worst_tax > 25
                else "rugcheck_high_tax", sev,
                f"Extreme trading tax on this token ({worst_tax:.0f}%)",
                "Every trade hands a huge cut to the contract. High "
                "taxes are how scam tokens quietly drain buyers even "
                "when the price looks fine - a 25% sell tax means you "
                "lose a quarter of your money the moment you exit.",
                addr, chain, confidence=85,
                extra={"buy_tax_pct": buy_tax, "sell_tax_pct": sell_tax},
                passive=passive))

        # --- holder concentration (when the source exposes it) ---------
        holders = info.get("holders")
        if isinstance(holders, list) and holders:
            checks.append("holders")
            pcts = []
            for h in holders:
                if isinstance(h, dict):
                    try:
                        pcts.append(float(h.get("percent") or 0) * 100
                                    if float(h.get("percent") or 0) <= 1
                                    else float(h.get("percent") or 0))
                    except (TypeError, ValueError):
                        continue
            if pcts:
                top10 = sum(sorted(pcts, reverse=True)[:10])
                if top10 > 50:
                    flags += 1
                    score += 25 if top10 > 80 else 15
                    findings.append(self._flag(
                        "rugcheck_holder_concentration", "high",
                        f"Top 10 wallets hold {top10:.0f}% of this token",
                        "When a handful of wallets control most of the "
                        "supply, they can dump at any moment and crash "
                        "the price to zero while everyone else is left "
                        "holding worthless tokens.",
                        addr, chain, confidence=85,
                        extra={"top10_pct": round(top10, 1),
                               "top1_pct": round(max(pcts), 1),
                               "holder_count": info.get("holder_count")},
                        passive=passive))

        # --- liquidity lock --------------------------------------------
        checks.append("liquidity lock")
        lp_holders = info.get("lp_holders")
        if isinstance(lp_holders, list) and lp_holders:
            locked = 0.0
            total = 0.0
            for h in lp_holders:
                if not isinstance(h, dict):
                    continue
                try:
                    pct = float(h.get("percent") or 0)
                except (TypeError, ValueError):
                    continue
                pct = pct * 100 if pct <= 1 else pct
                total += pct
                tag = str(h.get("tag") or "").lower()
                if _f1(h.get("is_locked")) == 1.0 or "burn" in tag:
                    locked += pct
            if total > 0 and locked < 50:
                flags += 1
                score += 20
                findings.append(self._flag(
                    "rugcheck_liquidity_unlocked", "high",
                    f"Liquidity is NOT locked ({locked:.0f}% locked/burned)",
                    "The money in the trading pool can be withdrawn by "
                    "whoever controls it, instantly and without warning. "
                    "That one transaction is the rug pull: the pool "
                    "empties and the token becomes unsellable.",
                    addr, chain, confidence=85,
                    extra={"lp_locked_pct": round(locked, 1)},
                    passive=passive))

        # --- thin liquidity (DexScreener) -------------------------------
        if dex:
            checks.append("market liquidity")
            liq = float(dex.get("liquidity_usd") or 0)
            if 0 < liq < 10_000:
                flags += 1
                sev = "high" if liq < 1_000 else "medium"
                score += 15 if liq < 1_000 else 10
                findings.append(self._flag(
                    "rugcheck_liquidity_thin", sev,
                    f"Trading liquidity is only ${liq:,.0f}",
                    "A pool this small can be moved or drained with "
                    "very little money, and your sell order alone can "
                    "crash the price. Thin liquidity is where rug "
                    "pulls are cheapest to run.",
                    addr, chain, confidence=80,
                    extra={"liquidity_usd": liq, "dex": dex.get("dex")},
                    passive=passive))

        # --- mint authority ---------------------------------------------
        checks.append("mint authority")
        if _f1(info.get("is_mintable")) == 1.0:
            flags += 1
            score += 12
            findings.append(self._flag(
                "rugcheck_mint_authority", "medium",
                "Minting is still switched on for this token",
                "Whoever holds the mint power can print unlimited new "
                "tokens out of thin air and sell them, diluting your "
                "share of the supply toward zero.",
                addr, chain, confidence=85,
                extra={"mintable": True}, passive=passive))

        # --- owner control / freeze-style powers ------------------------
        checks.append("owner control")
        owner_sins = []
        if _f1(info.get("owner_change_balance")) == 1.0:
            owner_sins.append("owner can change holder balances")
        if _f1(info.get("can_take_back_ownership")) == 1.0:
            owner_sins.append("ownership can be taken back after "
                              "'renouncing'")
        if _f1(info.get("hidden_owner")) == 1.0:
            owner_sins.append("there is a hidden owner")
        if _f1(info.get("is_blacklisted")) == 1.0:
            owner_sins.append("a blacklist can freeze chosen wallets")
        if owner_sins:
            flags += 1
            score += 15
            key = ("rugcheck_freeze_authority"
                   if any("blacklist" in s or "balances" in s
                          for s in owner_sins)
                   else "rugcheck_owner_control")
            findings.append(self._flag(
                key, "high" if len(owner_sins) > 1 else "medium",
                "The contract owner has dangerous powers: "
                + "; ".join(owner_sins),
                "These powers mean the rules can change after you buy. "
                "A blacklisted wallet can never sell, and an owner who "
                "can edit balances can take tokens straight out of "
                "your wallet.",
                addr, chain, confidence=85,
                extra={"owner_powers": owner_sins}, passive=passive))

        # --- verified source --------------------------------------------
        checks.append("source verification")
        if _f1(info.get("is_open_source")) == 0.0:
            flags += 1
            score += 8
            findings.append(self._flag(
                "rugcheck_unverified_contract", "medium",
                "Contract source code is not verified",
                "Nobody outside the team can read what this contract "
                "actually does. Every other safety check is weaker "
                "when the code itself is a black box.",
                addr, chain, confidence=80,
                extra={"open_source": False}, passive=passive))

        findings.append(self._summary(addr, chain, score, flags, checks,
                                      info.get("holder_count"), passive))
        return findings

    # ------------------------------------------------------------------
    # Solana token check
    # ------------------------------------------------------------------
    async def _solana_rpc(self, ctx: Ctx, method: str,
                          params: list) -> Optional[Dict[str, Any]]:
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", SOLANA_RPC,
                            json={"jsonrpc": "2.0", "id": 1,
                                  "method": method, "params": params},
                            timeout=15, max_retries=1)
            if r.status_code != 200:
                return None
            d = safe_json_dict(r)
        except Exception:
            return None
        res = d.get("result")
        return res if isinstance(res, dict) else None

    async def _goplus_sol(self, ctx: Ctx, mint: str) -> Dict[str, Any]:
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            GOPLUS_SOL.format(addr=mint),
                            timeout=15, max_retries=1)
            if r.status_code != 200:
                return {}
            d = safe_json_dict(r)
        except Exception:
            return {}
        result = d.get("result")
        if not isinstance(result, dict):
            return {}
        info = result.get(mint) or {}
        return info if isinstance(info, dict) else {}

    async def _check_solana(self, ctx: Ctx, mint: str,
                            passive: bool) -> List[Finding]:
        findings: List[Finding] = []
        chain = "solana"
        flags = 0
        score = 0
        checks: List[str] = []

        supply_res, largest_res, acct_res, gp, dex = await asyncio.gather(
            self._solana_rpc(ctx, "getTokenSupply", [mint]),
            self._solana_rpc(ctx, "getTokenLargestAccounts",
                             [mint, {"commitment": "confirmed"}]),
            self._solana_rpc(ctx, "getAccountInfo",
                             [mint, {"encoding": "base64"}]),
            self._goplus_sol(ctx, mint),
            self._dexscreener(ctx, mint),
            return_exceptions=True)

        def _ok(res: Any) -> Optional[Dict[str, Any]]:
            return res if isinstance(res, dict) else None

        supply_res, largest_res = _ok(supply_res), _ok(largest_res)
        acct_res = _ok(acct_res)
        gp = gp if isinstance(gp, dict) else {}
        dex = dex if isinstance(dex, dict) else {}

        if not (supply_res or largest_res or acct_res or gp or dex):
            findings.append(self._flag(
                "rugcheck_no_data", "low",
                f"No data found for Solana mint {mint[:10]}...",
                "No public source recognizes this mint. A token "
                "nobody can verify is a token you cannot check for "
                "scams - treat that as a warning by itself.",
                mint, chain, confidence=60, passive=passive))
            return findings

        # --- holder concentration --------------------------------------
        checks.append("holders")
        supply_val = ((supply_res or {}).get("value") or {})
        try:
            supply = float(supply_val.get("uiAmount") or 0)
        except (TypeError, ValueError):
            supply = 0.0
        accounts = (largest_res or {}).get("value")
        if supply > 0 and isinstance(accounts, list) and accounts:
            amts = []
            for a in accounts:
                if isinstance(a, dict):
                    try:
                        amts.append(float(a.get("uiAmount") or 0))
                    except (TypeError, ValueError):
                        continue
            if amts:
                top10 = sum(sorted(amts, reverse=True)[:10]) / supply * 100
                if top10 > 50:
                    flags += 1
                    score += 25 if top10 > 80 else 15
                    findings.append(self._flag(
                        "rugcheck_holder_concentration", "high",
                        f"Top 10 wallets hold {top10:.0f}% of this token",
                        "When a handful of wallets control most of the "
                        "supply, they can dump at any moment and crash "
                        "the price to zero while everyone else is left "
                        "holding worthless tokens.",
                        mint, chain, confidence=88,
                        extra={"top10_pct": round(top10, 1),
                               "top1_pct": round(max(amts) / supply * 100, 1),
                               "supply": supply}, passive=passive))

        # --- mint / freeze authority (parsed from the mint account) -----
        checks.append("mint authority")
        checks.append("freeze authority")
        mint_auth: Optional[str] = None
        freeze_auth: Optional[str] = None
        data_list = ((acct_res or {}).get("value") or {}).get("data")
        if isinstance(data_list, list) and data_list:
            try:
                raw = base64.b64decode(data_list[0])
                parsed = _parse_solana_mint(raw)
                mint_auth = parsed["mint_authority"]
                freeze_auth = parsed["freeze_authority"]
            except Exception:
                pass
        if mint_auth is None and isinstance(gp.get("mintable"), dict):
            if str(gp["mintable"].get("status")) == "0":
                mint_auth = str(gp["mintable"].get("authority") or "active")
        if freeze_auth is None and isinstance(gp.get("freezable"), dict):
            if str(gp["freezable"].get("status")) == "0":
                freeze_auth = str(gp["freezable"].get("authority") or "active")
        if mint_auth:
            flags += 1
            score += 12
            findings.append(self._flag(
                "rugcheck_mint_authority", "medium",
                "Mint authority is still active on this token",
                "Whoever holds the mint authority can print unlimited "
                "new tokens out of thin air and sell them, diluting "
                "your share of the supply toward zero.",
                mint, chain, confidence=90,
                extra={"mint_authority_active": True}, passive=passive))
        if freeze_auth:
            flags += 1
            score += 12
            findings.append(self._flag(
                "rugcheck_freeze_authority", "medium",
                "Freeze authority is still active on this token",
                "Whoever holds the freeze authority can freeze any "
                "wallet's tokens, including yours, so they can never "
                "be sold or moved. That is the Solana version of a "
                "honeypot.",
                mint, chain, confidence=90,
                extra={"freeze_authority_active": True}, passive=passive))

        # --- thin liquidity ----------------------------------------------
        if dex:
            checks.append("market liquidity")
            liq = float(dex.get("liquidity_usd") or 0)
            if 0 < liq < 10_000:
                flags += 1
                sev = "high" if liq < 1_000 else "medium"
                score += 15 if liq < 1_000 else 10
                findings.append(self._flag(
                    "rugcheck_liquidity_thin", sev,
                    f"Trading liquidity is only ${liq:,.0f}",
                    "A pool this small can be moved or drained with "
                    "very little money, and your sell order alone can "
                    "crash the price. Thin liquidity is where rug "
                    "pulls are cheapest to run.",
                    mint, chain, confidence=80,
                    extra={"liquidity_usd": liq, "dex": dex.get("dex")},
                    passive=passive))

        holder_count = None
        if isinstance(gp.get("holder_count"), (int, float)):
            holder_count = gp["holder_count"]
        findings.append(self._summary(mint, chain, score, flags, checks,
                                      holder_count, passive))
        return findings

    # ------------------------------------------------------------------
    def _summary(self, addr: str, chain: str, score: int, flags: int,
                 checks: List[str], holder_count: Any,
                 passive: bool) -> Finding:
        score = min(score, 100)
        verdict = ("HIGH RISK" if score >= 60 else
                   "MEDIUM RISK" if score >= 30 else "LOW RISK")
        ev = {
            "severity": "low",
            "title": f"Token safety summary for {addr[:12]}...",
            "why_it_matters": (
                "This is the overall picture across every check that "
                "ran. A high score means several independent scam "
                "signals fired on the same token - real projects "
                "almost never trip more than one."),
            "token_address": addr,
            "chain": chain,
            "risk_score": score,
            "verdict": verdict,
            "flags": flags,
            "checks_run": checks,
            "holder_count": holder_count,
            "remediation": REMEDIATION,
            "scope_note": SCOPE_NOTE,
        }
        return self._f("web3", "rugcheck_token_summary",
                       f"LOW: Token safety summary: {verdict} "
                       f"({score}/100), {flags} flag(s) across "
                       f"{len(checks)} check(s) on {chain}.",
                       source="Token rug-check", confidence=85,
                       evidence=ev, passive=passive)
