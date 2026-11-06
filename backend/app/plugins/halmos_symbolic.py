"""Halmos Symbolic Invariant Check (Tier 9) - SIM-DERIVED, UNVERIFIED.

HARD RULE: simulation analysis only. Every finding carries
verdict=UNVERIFIED / sim_derived=True; never VERIFIED_REAL, never
proof. VERIFIED_REAL requires live-chain probes.

Coverage decision: contract_simulation already runs Mythril
(symbolic *bug-pattern* search, opt-in). Halmos is a different
symbolic discipline: it checks ASSERTION-STYLE PROPERTIES
(`check_*` / `invariant_*` / prove functions and plain `assert(...)`
statements) for ALL inputs. The distinct remainder shipped here is
a native property checker over that property surface:

- a property/assert that is statically CONTRADICTED: an ungated
  public function can move the very state the property asserts is
  bounded (e.g. property asserts totalSupply <= CAP, a public mint
  grows totalSupply with no cap check in its body);
- an `assert(false)` / `assert(0 == 1)`-shaped statement reachable
  in a public function body (a property that can never hold);
- a declared property function that is VACUOUS: it asserts a
  tautology (`assert(x == x)` / `assert(true)`), giving false
  assurance of symbolic coverage.

When the real halmos binary is present (operator venv-halmos) it
can run the full solver pass; this native checker is the documented
substitution for the statically decidable subset, and properties
that need a solver are not claimed.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from . import contract_chain as cc
from .base import Cost, Plugin, PluginResult, Target, Ctx
from .forksim_util import is_gated, run_analyzer_plugin

_PROP_NAME = re.compile(r"^(check_|invariant_|prove_|test_.*invariant)",
                        re.I)
_ASSERT = re.compile(r"assert\s*\(([^;{}]+)\)")


def analyze_halmos_source(source: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    clean = cc._strip_comments(source)
    fns = cc.extract_functions(clean)
    by_name = {f["name"]: f for f in fns}

    # 1) reachable assert(false)-shaped statements in public functions
    for fn in fns:
        if not re.search(r"\b(public|external)\b", fn["signature"]):
            continue
        for m in _ASSERT.finditer(fn["text"]):
            expr = re.sub(r"\s+", "", m.group(1))
            if expr in ("false", "0==1", "1==0", "true==false"):
                hits.append({
                    "key": "halmos_assert_unreachable", "severity": "medium",
                    "check": "assert_false_reachable", "function": fn["name"],
                    "detail": (f"Symbolic property check: public function "
                               f"'{fn['name']}' contains assert({m.group(1).strip()}) "
                               f"- a property that can never hold when "
                               f"this path executes (Halmos would report "
                               f"this as a failed check for all inputs)."),
                    "confidence": 72})

    # 2) vacuous property functions
    props = [f for f in fns if _PROP_NAME.search(f["name"])]
    for fn in props:
        for m in _ASSERT.finditer(fn["text"]):
            expr = re.sub(r"\s+", "", m.group(1))
            if expr == "true" or re.fullmatch(r"(\w+)==\1", expr or ""):
                hits.append({
                    "key": "halmos_vacuous_property", "severity": "low",
                    "check": "vacuous_property", "function": fn["name"],
                    "detail": (f"Symbolic property '{fn['name']}' asserts "
                               f"a tautology (assert({m.group(1).strip()})). "
                               f"It passes for every input and proves "
                               f"nothing - false symbolic coverage."),
                    "confidence": 70})
                break

    # 3) property bounds contradicted by an ungated mover of same state
    for fn in props:
        for m in re.finditer(
                r"assert\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*<=\s*"
                r"([A-Za-z_][A-Za-z0-9_]*)\s*\)", fn["text"]):
            var, cap = m.group(1), m.group(2)
            for other in fns:
                if other["name"] == fn["name"]:
                    continue
                if not re.search(r"\b(public|external)\b", other["signature"]):
                    continue
                grows = re.search(
                    rf"\b{re.escape(var)}\s*\+=|\b{re.escape(var)}\s*=\s*"
                    rf"{re.escape(var)}\s*\+", other["text"])
                if not grows:
                    continue
                if is_gated(other["text"], other["signature"]):
                    continue
                if re.search(rf"{re.escape(cap)}", other["text"]):
                    continue  # mover enforces the cap itself
                hits.append({
                    "key": "halmos_invariant_contradicted",
                    "severity": "high", "check": "invariant_contradicted",
                    "function": other["name"],
                    "detail": (f"Symbolic property check: '{fn['name']}' "
                               f"asserts {var} <= {cap}, but public "
                               f"ungated '{other['name']}' grows {var} "
                               f"with no {cap} check - the asserted "
                               f"invariant is violated by construction "
                               f"(a Halmos counterexample exists)."),
                    "confidence": 74})
                break
    return hits


class HalmosSymbolicPlugin(Plugin):
    id = "halmos_symbolic"
    label = "Halmos Symbolic Invariants (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Halmos-style symbolic property checking (native "
                   "statically-decidable subset): contradicted, "
                   "unreachable and vacuous assert/invariant "
                   "properties. SIM-DERIVED, UNVERIFIED only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_analyzer_plugin(self, target, ctx,
                                         analyze_halmos_source)
