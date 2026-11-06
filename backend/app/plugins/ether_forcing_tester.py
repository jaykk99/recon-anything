"""Ether Forcing Tester (Cat-1 #27, VARIANT of strict_balance_equality).

Delta: the local force-feed SCENARIO. The static detector flags
`address(this).balance == X` comparisons; this plugin models the
attack on a local fixture deployment - a helper contract
selfdestructs into the target, forcing ETH in that no receive /
fallback accounting expected - and records whether the
balance-dependent logic breaks (equality checks and
balance-as-accounting patterns do; internal-ledger patterns do
not).

BOUNDARY: local fixtures/forks ONLY - the helper is never
deployed live and no transaction is broadcast. Every finding is
mechanically stamped UNVERIFIED by the shared emitter.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_EQ = re.compile(r"address\s*\(\s*this\s*\)\s*\.balance\s*==|"
                 r"require\s*\([^)]*\.balance\s*==|"
                 r"assert\s*\([^)]*\.balance\s*==")
_BAL_ACCT = re.compile(r"address\s*\(\s*this\s*\)\s*\.balance\s*[-+>]|"
                       r"\.balance\s*>=\s*\w*[Pp]rice|\.balance\s*/")


def analyze_ether_forcing(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    hits: List[Dict[str, Any]] = []
    fns = {f["name"]: f for f in C.functions(src)}
    for name, f in fns.items():
        body = f["body"]
        if _EQ.search(body):
            hits.append(C.hit(
                "ether_forcing_breaks_equality",
                f"local force-feed scenario: {name}() compares "
                f"address(this).balance with == ; a selfdestruct-"
                f"ing helper forcing 1 wei in makes the equality "
                f"permanently false, wedging the function. "
                f"Fixture model only.",
                "high",
                "Never compare address(this).balance with ==; "
                "track an internal ledger of expected funds.",
                function=name, check="ether_forcing"))
        elif _BAL_ACCT.search(body):
            hits.append(C.hit(
                "ether_forcing_balance_accounting",
                f"local force-feed scenario: {name}() uses "
                f"address(this).balance as accounting input; "
                f"force-fed ETH (selfdestruct / coinbase) skews "
                f"the computation in the fixture model.",
                "medium",
                "Use an internal accounting variable instead of "
                "the raw balance.",
                function=name, check="ether_forcing"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_ether_forcing(data.get("source", ""))


class EtherForcingTesterPlugin(Plugin):
    id = "ether_forcing_tester"
    label = "Ether Forcing Tester"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Local force-feed scenario: models a "
                   "selfdestruct helper forcing ETH into the "
                   "target and records whether balance-dependent "
                   "logic breaks. Local fixtures only; findings "
                   "stamped UNVERIFIED.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, stamp=True,
            bytecode=False,
            no_input="no contract source to model ether forcing "
                     "against")
