"""SHIP 67: static analysis of BLS aggregation code/artifacts."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    t = text.lower()
    if not ("bls" in t or "aggregate" in t):
        return out
    if not has(text, "proof_of_possession", "proof-of-possession", "pop_proof", "popverify", "proof of possession"):
        out.append(("bls_missing_proof_of_possession",
                    "BLS aggregation is used with no proof-of-possession check; a rogue key can be crafted to cancel other signers (rogue-key attack)",
                    "high", "Require and verify a proof-of-possession for every public key before aggregation, or restrict aggregation to distinct messages."))
    if not has(text, "subgroup"):
        out.append(("bls_missing_subgroup_check",
                    "BLS public keys/points are aggregated with no subgroup-membership check visible",
                    "medium", "Validate every public key is non-identity and in the correct subgroup before aggregation."))
    return out


class BlsSigAggregatorAudit(Plugin):
    id = "bls_sig_aggregator_audit"
    label = "BLS Signature Aggregator Audit"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Audits supplied BLS aggregate-signature code for rogue-key exposure: missing proof-of-possession, missing subgroup checks, unrestricted same-message aggregation."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
