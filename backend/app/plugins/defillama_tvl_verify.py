"""DefiLlama TVL verify (Cat-4 SHIP).

Cross-checks a protocol's DefiLlama-reported TVL against an
independent on-chain sum (operator-supplied contract balance data,
or balances gathered from keyless public sources). Reported TVL that
materially exceeds what the protocol's contracts actually hold -
double counting, stale adapters, or invented numbers - is the
finding; the reverse gap flags under-reporting.

Keyless: DefiLlama public API + supplied balance evidence. Read-only.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from ._cat4_common import artifact_dicts, fetch_json, all_texts
from .base import Cost, Ctx, Plugin, PluginResult, Target

LLAMA = "https://api.llama.fi/protocol/{slug}"
SLUG_RE = re.compile(r"defillama\.com/protocol/([a-z0-9\-]+)", re.I)
MEDIUM_PCT = 10.0
HIGH_PCT = 25.0


def compare_tvl(reported: float, onchain: float
                ) -> Optional[Dict[str, Any]]:
    """Pure: reported TVL vs independently summed on-chain TVL."""
    try:
        rep, on = float(reported), float(onchain)
    except (TypeError, ValueError):
        return None
    if rep <= 0 or on < 0:
        return None
    base = max(rep, on)
    if base == 0:
        return None
    pct = abs(rep - on) / base * 100.0
    if pct < MEDIUM_PCT:
        return None
    return {"reported": rep, "onchain": on,
            "divergence_pct": round(pct, 2),
            "direction": "overstated" if rep > on else "understated",
            "severity": "high" if pct >= HIGH_PCT else "medium"}


def sum_balances(balances: Any) -> Optional[float]:
    """Sum a {address: usd_value} or [{usd_value}] balance set."""
    if isinstance(balances, dict):
        vals = balances.values()
    elif isinstance(balances, list):
        vals = [b.get("usd_value") if isinstance(b, dict) else b
                for b in balances]
    else:
        return None
    total = 0.0
    seen = False
    for v in vals:
        try:
            total += float(v)
            seen = True
        except (TypeError, ValueError):
            continue
    return total if seen else None


class DefillamaTvlVerifyPlugin(Plugin):
    id = "defillama_tvl_verify"
    label = "DefiLlama TVL Verifier"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Cross-check DefiLlama-reported TVL against an "
                   "independent on-chain balance sum; flag 10%+ "
                   "divergence either way.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        notes = []
        try:
            checks: List[Dict[str, Any]] = []
            for d in artifact_dicts(ctx):
                for c in d.get("tvl_checks") or []:
                    if isinstance(c, dict):
                        checks.append(c)
            slugs: List[str] = []
            for _w, text, _u in await all_texts(ctx, target):
                for m in SLUG_RE.finditer(text):
                    if m.group(1) not in slugs:
                        slugs.append(m.group(1))
            for slug in slugs[:3]:
                data = await fetch_json(ctx, LLAMA.format(slug=slug))
                if isinstance(data, dict) and data.get("tvl"):
                    try:
                        latest = data["tvl"][-1]
                        reported = float(latest["totalLiquidityUSD"])
                        checks.append({"protocol": slug,
                                       "reported_tvl": reported})
                    except Exception:
                        pass
            for check in checks[:10]:
                reported = check.get("reported_tvl",
                                     check.get("reported"))
                onchain = check.get("onchain_tvl", check.get("onchain"))
                if onchain is None and check.get("contract_balances"):
                    onchain = sum_balances(check["contract_balances"])
                if reported is None or onchain is None:
                    notes.append(f"{check.get('protocol', '?')}: "
                                 "missing on-chain sum, unverified")
                    continue
                hit = compare_tvl(reported, onchain)
                if hit:
                    findings.append(self._f(
                        "web3", "tvl_report_divergence",
                        f"TVL for {check.get('protocol', 'protocol')} "
                        f"is {hit['direction']}: DefiLlama reports "
                        f"${hit['reported']:,.0f} vs on-chain sum "
                        f"${hit['onchain']:,.0f} "
                        f"({hit['divergence_pct']}% gap)",
                        source="defillama tvl verify", confidence=80,
                        evidence={
                            "severity": hit["severity"], "hit": hit,
                            "remediation": "Reconcile the adapter with "
                            "the protocol's actual contract set; "
                            "unexplained TVL gaps mislead depositors."}))
            res = self._ok(findings,
                           "; ".join(notes) if notes and not findings
                           else f"{len(checks)} TVL checks run")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
