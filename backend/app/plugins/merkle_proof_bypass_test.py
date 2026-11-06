"""VARIANT 68: general Merkle bypass matrix over supplied verifier code/config."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    if first(objs, "accepts_empty_proof") is True or rx(text, r"proof\.length\s*==\s*0[^;\n]{0,60}return\s+true"):
        out.append(("merkle_empty_proof_accepted",
                    "Merkle verifier accepts an empty proof (fixture result UNVERIFIED for any live claim)",
                    "high", "Reject empty proofs unless the leaf is the root itself and that case is explicitly intended."))
    if first(objs, "allows_zero_leaf") is True:
        out.append(("merkle_zero_leaf_accepted",
                    "Merkle verifier accepts the zero leaf/zero node, enabling substitution with uninitialized storage values",
                    "medium", "Reject zero leaves and zero intermediate nodes."))
    if first(objs, "validates_proof_length") is False:
        out.append(("merkle_proof_length_unvalidated",
                    "Merkle verifier does not validate the proof length against the tree depth",
                    "medium", "Check proof length equals the expected tree depth before verification."))
    t = text.lower()
    if "merkle" in t and ("verify" in t or "proof" in t):
        if "proof.length" not in t and "proof length" not in t and first(objs, "validates_proof_length") is None:
            out.append(("merkle_proof_length_unvalidated",
                        "Supplied Merkle verifier shows no proof-length validation",
                        "medium", "Validate proof length against tree depth."))
        if rx(text, r"leaf\s*=\s*keccak256\(abi\.encodePacked\([a-z0-9_]+\)\)"):
            out.append(("merkle_single_hash_leaf",
                        "Leaf is a single packed hash of one variable-length argument; second-preimage shapes can reinterpret internal nodes as leaves",
                        "medium", "Hash leaves twice or domain-separate leaf and node hashing."))
    return out[:8]


class MerkleProofBypassTest(Plugin):
    id = "merkle_proof_bypass_test"
    label = "Merkle Proof Bypass Test"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Tests a supplied Merkle verifier against the general bypass matrix: empty-proof acceptance, zero-leaf/zero-node substitution, single-hash leaves, and missing proof-length/index validation. Active leg is local-fixture only, stamped UNVERIFIED."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
