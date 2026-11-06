"""SHIP 79: parameter-set analysis for TFHE/SEAL/OpenFHE-style configs."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


_QMAX = {2048: 54, 4096: 109, 8192: 218, 16384: 438, 32768: 881}

def analyze(text, objs):
    out = []
    deg = first(objs, "poly_degree", "polynomial_degree", "n")
    qbits = first(objs, "modulus_chain_bits", "q_bits", "total_modulus_bits")
    try:
        if deg is not None:
            d = int(deg)
            if d <= 2048:
                out.append(("fhe_parameters_below_128bit",
                            f"FHE polynomial degree {d} cannot reach ~128-bit security at usable modulus sizes (estimate from supplied parameters)",
                            "high", "Use parameter sets from the Homomorphic Encryption Standard tables targeting >= 128-bit security."))
            elif qbits is not None and d in _QMAX and int(qbits) > _QMAX[d]:
                out.append(("fhe_parameters_below_128bit",
                            f"FHE degree {d} with a {qbits}-bit modulus chain exceeds the ~128-bit security bound of { _QMAX[d] } bits for that degree (estimate from supplied parameters)",
                            "high", "Reduce the modulus chain or raise the polynomial degree to meet the 128-bit standard table."))
    except Exception:
        pass
    depth = first(objs, "multiplicative_depth", "depth")
    try:
        if depth is not None and int(depth) > 10 and first(objs, "bootstrapping") is False:
            out.append(("fhe_noise_budget_exhausted",
                        f"Evaluation depth {depth} with no bootstrapping placement; the noise budget is exhausted before evaluation completes",
                        "medium", "Insert bootstrapping or enlarge the modulus chain (within the security table) for the planned depth."))
    except Exception:
        pass
    return out[:8]


class FheCiphertextEval(Plugin):
    id = "fhe_ciphertext_eval"
    label = "FHE Ciphertext Parameter Evaluation"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Estimates the security/noise posture of supplied FHE parameter sets (polynomial degree, modulus chain, bootstrapping placement) against a local parameter table. Estimates are labeled as estimates."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
