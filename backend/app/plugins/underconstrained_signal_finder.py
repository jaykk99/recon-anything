"""SHIP 62: static Circom source audit for witness tracks lacking enforcement."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    if "<--" not in text and "<==" not in text:
        return out
    assigned = re.findall(r"signal\s+(?:input\s+|output\s+)?(\w+)\s*<--", text)
    assigned += re.findall(r"(?<!\w)(\w+)\s*<--", text)
    constrained = set(re.findall(r"(\w+)\s*<==", text))
    constrained |= set(re.findall(r"(\w+)\s*===", text))
    seen = set()
    for name in assigned:
        if name in seen:
            continue
        seen.add(name)
        if name not in constrained:
            out.append(("underconstrained_signal",
                        f"Circom signal '{name}' is assigned with <-- but never constrained with <== or ===; a malicious prover can set it arbitrarily",
                        "high", f"Constrain '{name}' with <== (or add an explicit === constraint) so the witness value is enforced by the proof."))
    if rx(text, r"<--[^;\n]*/") and not has(text, "assert", "!= 0", "iszero"):
        out.append(("unconstrained_division_hint",
                    "Division result assigned via a <-- hint with no non-zero/assert guard visible; the divisor may be zero or the quotient unconstrained",
                    "medium", "Constrain the division (quotient * divisor === numerator) and assert the divisor is non-zero."))
    return out[:12]


class UnderconstrainedSignalFinder(Plugin):
    id = "underconstrained_signal_finder"
    label = "Underconstrained Signal Finder"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Finds Circom signals assigned with <-- that are never bound by a constraint (<== or ===), plus unconstrained division hints."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
