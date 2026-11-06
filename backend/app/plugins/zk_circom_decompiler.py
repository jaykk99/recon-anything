"""SHIP 61: parse supplied R1CS (JSON form) and emit its constraints as readable equations. Local artifact parsing only."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def decompile_r1cs(data):
    """Pure: R1CS dict -> list of readable equation strings."""
    eqs = []
    if not isinstance(data, dict):
        return eqs
    cons = data.get("constraints")
    if not isinstance(cons, list):
        return eqs
    for c in cons:
        if isinstance(c, str) and "=" in c:
            eqs.append(c)
        elif isinstance(c, dict):
            def side(m):
                if not isinstance(m, dict):
                    return str(m)
                parts = [f"{coef}*{sig}" if coef not in (1, "1") else str(sig)
                         for sig, coef in m.items()]
                return " + ".join(parts) or "0"
            eqs.append(f"({side(c.get('A'))}) * ({side(c.get('B'))}) = ({side(c.get('C'))})")
    return eqs

def analyze(text, objs):
    out = []
    for o in objs if isinstance(objs, list) else []:
        eqs = decompile_r1cs(o)
        if eqs:
            n = first([o], "nConstraints") or len(eqs)
            out.append(("zk_r1cs_decompiled",
                        f"R1CS decompiled: {len(eqs)} constraint equation(s), nConstraints={n}; first: {eqs[0][:160]}",
                        "low", "Review the decompiled constraints against the circuit source; constraints that bind no output signal are audited by underconstrained_signal_finder."))
            return out
    if rx(text, r'"nConstraints"\s*:\s*\d+'):
        m = re.search(r'"nConstraints"\s*:\s*(\d+)', text)
        out.append(("zk_r1cs_decompiled",
                    f"R1CS artifact present: nConstraints={m.group(1)} (constraint bodies not in JSON form, equations unavailable)",
                    "low", "Supply the full R1CS JSON to recover per-constraint equations."))
    return out


class ZkCircomDecompiler(Plugin):
    id = "zk_circom_decompiler"
    label = "ZK Circom Decompiler"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Decompiles a supplied Circom R1CS artifact back into readable algebraic constraint equations grouped by signal."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
