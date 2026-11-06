"""SHIP 76: static source/artifact analysis of Groth16 verifiers."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    ic = first(objs, "ic_length", "gamma_abc_length")
    pi = first(objs, "public_inputs", "num_public_inputs")
    try:
        if ic is not None and pi is not None and int(ic) != int(pi) + 1:
            out.append(("groth16_ic_length_mismatch",
                        f"Verification key IC (gamma_abc) length is {ic} but there are {pi} public inputs (expected inputs + 1); verification is broken or inputs are silently dropped",
                        "high", "Regenerate the verification key so IC length equals public inputs + 1."))
    except Exception:
        pass
    pc = first(objs, "pairing_count", "pairings")
    try:
        if pc is not None and int(pc) < 4:
            out.append(("groth16_incomplete_pairing_check",
                        f"Verifier performs only {pc} pairings (< 4); the full Groth16 pairing equation is not checked",
                        "high", "Check the complete pairing product equation (all four pairings)."))
    except Exception:
        pass
    t = text.lower()
    if has(text, "groth16", "verifyingkey", "verifyproof", "verify_proof"):
        if not has(text, "input < r", "input >= r", "< r)", "field modulus", "modulus check", "r - 1", "checkinput"):
            out.append(("groth16_input_not_range_checked",
                        "Groth16 verifier does not range-check public inputs against the field modulus; out-of-field inputs can alias valid ones",
                        "medium", "Require every public input to be < the BN254 scalar field modulus before verification."))
        if rx(text, r"function\s+(setvk|updateverifyingkey|set_verifying_key)") or rx(text, r"verifyingkey\s+public\b"):
            out.append(("groth16_vk_mutable",
                        "The Groth16 verification key is mutable after deployment; whoever can update it can make any proof verify",
                        "high", "Make the verification key immutable after deployment."))
    return out[:8]


class Groth16VerifierChecker(Plugin):
    id = "groth16_verifier_checker"
    label = "Groth16 Verifier Checker"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Reviews supplied Groth16 verifier source / verification-key JSON: pairing completeness, IC length vs public inputs, input field-range checks, and vk mutability."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
