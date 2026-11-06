"""CoinGecko price validator (Cat-4 SHIP).

Cross-checks prices a target page/bundle ASSERTS (displayed token
prices in the UI or supplied artifacts) against the keyless CoinGecko
public API reference price. A DApp showing a materially wrong price -
5%+ off the market - is either broken or is setting up a bad-faith
swap quote; either way the divergence is the finding.

Keyless: CoinGecko free API. Read-only. Detection only.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from ._cat4_common import artifact_dicts, fetch_json, all_texts
from .base import Cost, Ctx, Plugin, PluginResult, Target

COINGECKO = ("https://api.coingecko.com/api/v3/simple/price"
             "?ids={ids}&vs_currencies=usd")
KNOWN_IDS = {"eth": "ethereum", "ethereum": "ethereum",
             "btc": "bitcoin", "bitcoin": "bitcoin",
             "sol": "solana", "solana": "solana",
             "bnb": "binancecoin", "usdc": "usd-coin",
             "usdt": "tether", "matic": "matic-network"}
PRICE_HINT_RE = re.compile(
    r"(?i)(ethereum|bitcoin|solana|eth|btc|sol)\b[^$\n]{0,30}"
    r"\$\s*([0-9][0-9,]*\.?[0-9]*)")
MEDIUM_PCT = 5.0
HIGH_PCT = 20.0


def compare_prices(displayed: float, reference: float
                   ) -> Optional[Dict[str, Any]]:
    """Pure: divergence between a displayed and a reference price."""
    try:
        d, r = float(displayed), float(reference)
    except (TypeError, ValueError):
        return None
    if r <= 0 or d <= 0:
        return None
    pct = abs(d - r) / r * 100.0
    if pct < MEDIUM_PCT:
        return None
    return {"displayed": d, "reference": r,
            "divergence_pct": round(pct, 2),
            "severity": "high" if pct >= HIGH_PCT else "medium"}


def extract_displayed_prices(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for m in PRICE_HINT_RE.finditer(text or ""):
        token = m.group(1).lower()
        tid = KNOWN_IDS.get(token)
        if not tid:
            continue
        try:
            price = float(m.group(2).replace(",", ""))
        except ValueError:
            continue
        out.append({"token_id": tid, "displayed": price})
    return out


class CoingeckoPriceValidatorPlugin(Plugin):
    id = "coingecko_price_validator"
    label = "CoinGecko Price Validator"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Cross-check prices asserted by the target page "
                   "against the keyless CoinGecko reference price; "
                   "flag material divergence (5%+).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        notes = []
        try:
            claims: List[Dict[str, Any]] = []
            references: Dict[str, float] = {}
            for d in artifact_dicts(ctx):
                for c in d.get("price_claims") or []:
                    if isinstance(c, dict) and c.get("token_id"):
                        claims.append(c)
                for tid, price in (d.get("reference_prices") or {}).items():
                    try:
                        references[str(tid)] = float(price)
                    except (TypeError, ValueError):
                        continue
            for _w, text, _u in await all_texts(ctx, target):
                claims.extend(extract_displayed_prices(text))
            wanted = sorted({str(c["token_id"]) for c in claims
                             if str(c["token_id"]) not in references})
            if wanted:
                data = await fetch_json(
                    ctx, COINGECKO.format(ids=",".join(wanted[:10])))
                if isinstance(data, dict):
                    for tid, row in data.items():
                        if isinstance(row, dict) and row.get("usd"):
                            references[tid] = float(row["usd"])
                elif not references:
                    notes.append("CoinGecko reference unavailable")
            checked = 0
            for claim in claims[:20]:
                tid = str(claim.get("token_id"))
                ref = references.get(tid)
                if ref is None or claim.get("displayed") is None:
                    continue
                checked += 1
                hit = compare_prices(claim["displayed"], ref)
                if hit:
                    findings.append(self._f(
                        "web3", "displayed_price_divergence",
                        f"Target displays {tid} at ${hit['displayed']} "
                        f"vs reference ${hit['reference']} "
                        f"({hit['divergence_pct']}% divergence)",
                        source="coingecko price validator",
                        confidence=85,
                        evidence={
                            "severity": hit["severity"],
                            "hit": {**hit, "token_id": tid},
                            "remediation": "Fix the price feed or "
                            "remove the displayed price; a wrong "
                            "displayed price misleads users into bad "
                            "swaps."}))
            res = self._ok(findings,
                           "; ".join(notes) if notes and not findings
                           else f"{checked} prices cross-checked")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
