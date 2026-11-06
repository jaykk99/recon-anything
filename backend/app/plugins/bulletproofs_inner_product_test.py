"""SHIP 75: static/artifact analysis of Bulletproofs parameters."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    gl = first(objs, "generator_length", "generators")
    try:
        if gl is not None:
            g = int(gl)
            if g <= 0 or (g & (g - 1)) != 0:
                out.append(("bulletproofs_generator_length_not_power_of_two",
                            f"Bulletproofs generator vector length {g} is not a power of two; the inner-product argument cannot fold correctly",
                            "high", "Use generator vectors whose length is exactly 2^n for the claimed bit range."))
    except Exception:
        pass
    exp = first(objs, "expected_generators")
    try:
        if exp is not None and gl is not None and int(exp) != int(gl):
            out.append(("bulletproofs_range_parameter_mismatch",
                        f"Claimed range parameters require {exp} generators but {gl} are used; aggregate (n, m) bounds do not match the proof parameters",
                        "medium", "Align the generator count with n*m for the aggregated range proof."))
    except Exception:
        pass
    if first(objs, "transcript_bound", "fiat_shamir_bound") is False:
        out.append(("bulletproofs_transcript_not_bound",
                    "The inner-product proof is not bound into the Fiat-Shamir transcript; proofs may be replayable/malleable across statements",
                    "high", "Append every inner-product round message to the transcript before deriving challenges."))
    if ("inner_product" in text.lower() or "inner-product" in text.lower()) and "bulletproof" in text.lower() and "transcript" not in text.lower():
        out.append(("bulletproofs_transcript_not_bound",
                    "Bulletproofs inner-product code shows no transcript binding",
                    "medium", "Bind the proof into the Fiat-Shamir transcript."))
    return out[:8]


class BulletproofsInnerProductTest(Plugin):
    id = "bulletproofs_inner_product_test"
    label = "Bulletproofs Inner-Product Test"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Validates supplied Bulletproofs setups: generator vector lengths are powers of two matching the claimed range, and the inner-product argument is bound into the Fiat-Shamir transcript."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
