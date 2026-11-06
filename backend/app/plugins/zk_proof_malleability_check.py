"""VARIANT 74: ZK-verifier binding and consumption checks."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    if first(objs, "proof_bound_to_inputs") is False:
        out.append(("zk_proof_not_bound_to_inputs",
                    "ZK proof is not bound to its public inputs; proof elements or instance data can be swapped and the proof still verifies in a new context",
                    "high", "Bind the proof to the public inputs (Fiat-Shamir over the full instance) inside the verifier."))
    if first(objs, "proof_consumed", "nullified") is False:
        out.append(("zk_proof_not_consumed",
                    "A verified ZK proof is not consumed/nullified; the same proof can be replayed in a new context",
                    "high", "Record a nullifier/consumed marker for every verified proof before value moves."))
    t = text.lower()
    if has(text, "groth16", "plonk", "verifyproof", "verify_proof", "zk proof", "zkproof"):
        if "publicinput" not in t.replace(" ", "").replace("_", "") and "public_input" not in t and "instance" not in t:
            out.append(("zk_proof_not_bound_to_inputs",
                        "ZK verifier code shows no public-input binding in the verification call",
                        "medium", "Pass and bind all public inputs in verification."))
        if not has(text, "nullifier", "consumed", "spent", "usedproof", "used_proof"):
            out.append(("zk_proof_not_consumed",
                        "ZK verifier code records no nullifier/consumed marker after verification",
                        "medium", "Nullify each verified proof before its effect executes."))
        if rx(text, r"proof\.[a-z]\s*=[^=]"):
            out.append(("zk_proof_elements_mutable",
                        "Proof elements are assignable in the verifier path; a mutated proof may still verify if the equation is under-bound",
                        "medium", "Treat proof data as immutable calldata and bind every element into the verification equation."))
    return out[:8]


class ZkProofMalleabilityCheck(Plugin):
    id = "zk_proof_malleability_check"
    label = "ZK Proof Malleability Check"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Checks supplied ZK verifier code that proofs are bound to their public inputs and consumed/nullified after verification, so a proof cannot be mutated or replayed in a new context."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
