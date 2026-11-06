"""SHIP 63: static/artifact analysis of Halo2 lookup tables and arguments."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def _gap_check(table, out):
    try:
        vals = sorted({int(v) for v in table})
    except Exception:
        return
    if len(vals) >= 2:
        gaps = [v for v in range(vals[0], vals[-1] + 1) if v not in set(vals)]
        if gaps:
            out.append(("halo2_lookup_table_gap",
                        f"Lookup table covering {vals[0]}..{vals[-1]} has gaps at {gaps[:8]}; values in the gaps are claimed in range but absent from the table (or vice versa)",
                        "medium", "Make the lookup table contiguous over the claimed range or narrow the claimed range to the table contents."))

def analyze(text, objs):
    out = []
    for lk in find_values(objs, "lookups"):
        if isinstance(lk, list):
            for entry in lk:
                if isinstance(entry, dict):
                    _gap_check(entry.get("table") or [], out)
                    if str(entry.get("table_column") or entry.get("column_type") or "").lower() == "advice":
                        out.append(("halo2_lookup_table_advice_column",
                                    "Lookup table column is an advice column, so the prover controls the table contents",
                                    "high", "Use a fixed column for lookup tables so table contents are committed by the circuit, not the prover."))
                    if entry.get("constrained") is False:
                        out.append(("halo2_lookup_unconstrained_expr",
                                    f"Looked-up expression '{entry.get('expr')}' is not constrained to the declared table",
                                    "high", "Add the lookup argument constraint binding the expression to the table."))
    m = re.search(r"lookup_table\s*=\s*\[([0-9,\s\-]+)\]", text)
    if m:
        _gap_check([x for x in m.group(1).split(",") if x.strip()], out)
    if rx(text, r"table_column\s*[:=]\s*advice"):
        out.append(("halo2_lookup_table_advice_column",
                    "Lookup table column declared as advice in supplied Halo2 code/config",
                    "high", "Use a fixed column for lookup tables."))
    return out[:10]


class Halo2LookupVerifier(Plugin):
    id = "halo2_lookup_verifier"
    label = "Halo2 Lookup Verifier"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Validates Halo2 lookup arguments in supplied circuit artifacts: table gaps at range edges, advice-controlled table columns, unconstrained looked-up expressions."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
