"""Certora-Style Rule Check (Tier 9) - SIM-DERIVED, UNVERIFIED ONLY.

HARD RULE: simulation/formal analysis only. Every finding carries
verdict=UNVERIFIED / sim_derived=True; never VERIFIED_REAL, never
proof. VERIFIED_REAL requires live-chain probes. Rules that need a
real prover (Certora Prover is a hosted, key-gated service) are NOT
claimed: this plugin implements only the CVL-style rules that ARE
statically evaluable, and says so.

The rules (Certora's classic ghost/sum and conservation rules,
evaluated over source):

- R1 sum-of-balances integrity: the contract declares BOTH a
  scalar supply/accounting variable (totalSupply / totalShares /
  totalDeposits) AND a per-account mapping (balances / shares /
  deposits). A state-changing function that updates one side
  without the other breaks the rule
  ``supply == sum of balances`` by construction.
- R2 transfer conservation: a function that debits one account
  (``balances[a] -= X`` / ``balances[a] = balances[a] - X``) and
  credits another with a DIFFERENT amount expression mints or
  burns value inside a transfer - conservation violated.

No other lane checks paired accounting updates: contract_audit and
contract_logic classify single functions; they never compare the
two sides of an accounting pair. Functions that update both sides
with the same amount expression do not flag.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from . import contract_chain as cc
from .base import Cost, Plugin, PluginResult, Target, Ctx
from .forksim_util import run_analyzer_plugin

_SUPPLY_VARS = ("totalSupply", "totalShares", "totalDeposits",
                "totalAssets", "_totalSupply")
_MAP_RE = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*uint\w*\s*\)\s*(?:public\s+|private\s+|"
    r"internal\s+)?([A-Za-z_][A-Za-z0-9_]*)")


def _norm(expr: str) -> str:
    return re.sub(r"\s+", "", expr or "")


def _updates(fn_text: str, var: str) -> bool:
    return bool(re.search(
        rf"\b{re.escape(var)}\s*(?:\+=|-=|\*=|=(?!=))", fn_text))


def _side_updates(fn_text: str, map_name: str) -> bool:
    return bool(re.search(
        rf"\b{re.escape(map_name)}\s*\[[^\]]+\]\s*(?:\+=|-=|=(?!=))",
        fn_text))


def analyze_certora_source(source: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    clean = cc._strip_comments(source)
    maps = _MAP_RE.findall(clean)
    supply = next((v for v in _SUPPLY_VARS
                   if re.search(rf"\b{re.escape(v)}\b", clean)), None)
    fns = [f for f in cc.extract_functions(clean)
           if f["name"] not in ("constructor",)]
    if supply and maps:
        map_name = maps[0]
        for fn in fns:
            if fn["text"].rstrip().endswith(";"):
                continue
            sup = _updates(fn["text"], supply)
            side = _side_updates(fn["text"], map_name)
            # Only creation/destruction functions must move both
            # sides: a plain transfer updates balances only, by
            # design, and must never flag (FP discipline).
            creation = bool(re.search(r"mint|burn|issue|destroy",
                                      fn["name"], re.I))
            if sup != side and (sup or creation):
                # view/pure helpers that merely compute are not writers
                if re.search(r"\b(view|pure)\b", fn["signature"]):
                    continue
                hits.append({
                    "key": "certora_rule_sum_of_balances",
                    "severity": "high", "check": "sum_of_balances",
                    "function": fn["name"],
                    "detail": (f"CVL rule 'supply == sum of balances' "
                               f"violated by construction: "
                               f"'{fn['name']}' updates "
                               f"{supply if sup else map_name} without "
                               f"updating {map_name if sup else supply}. "
                               f"Accounting can drift from the "
                               f"per-account ledger."),
                    "confidence": 72})
    # R2 conservation inside one function
    for fn in fns:
        for map_name in maps:
            debits = re.findall(
                rf"\b{re.escape(map_name)}\s*\[[^\]]+\]\s*-=\s*([^;]+);",
                fn["text"])
            credits = re.findall(
                rf"\b{re.escape(map_name)}\s*\[[^\]]+\]\s*\+=\s*([^;]+);",
                fn["text"])
            if debits and credits and \
                    _norm(debits[0]) != _norm(credits[0]):
                hits.append({
                    "key": "certora_rule_conservation",
                    "severity": "high", "check": "transfer_conservation",
                    "function": fn["name"],
                    "detail": (f"CVL conservation rule violated in "
                               f"'{fn['name']}': {map_name} is debited "
                               f"by '{debits[0].strip()[:60]}' but "
                               f"credited by '{credits[0].strip()[:60]}' "
                               f"- value is created or destroyed in "
                               f"the transfer."),
                    "confidence": 70})
                break
    return hits


class CertoraRulesPlugin(Plugin):
    id = "certora_rules"
    label = "Certora-Style Rules (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Certora CVL-style rules that are statically "
                   "evaluable (sum-of-balances integrity, transfer "
                   "conservation). Prover-only rules are not claimed. "
                   "SIM-DERIVED, UNVERIFIED only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_analyzer_plugin(self, target, ctx,
                                         analyze_certora_source)
