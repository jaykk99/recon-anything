"""VARIANT 90: ZK-pool nullifier/double-spend scope (not bridge message proofs)."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    if first(objs, "nullifier_in_circuit") is False:
        out.append(("zk_nullifier_missing_in_circuit",
                    "The circuit has no nullifier signal; notes can be spent repeatedly (double-spend)",
                    "high", "Derive a unique nullifier inside the circuit from the note secret and include it as a public output."))
    if first(objs, "spent_mapping", "nullifier_stored") is False:
        out.append(("zk_nullifier_not_stored",
                    "The contract does not store spent nullifiers, so a presented nullifier is never marked used",
                    "high", "Store every spent nullifier in a mapping and reject repeats."))
    if first(objs, "checked_before_transfer") is False:
        out.append(("zk_nullifier_checked_after_transfer",
                    "The nullifier is not checked before value moves; the spend ordering allows double-spend races",
                    "high", "Check and record the nullifier before any transfer/withdrawal executes."))
    if out:
        return out[:8]
    t = text.lower()
    zk_ctx = has(text, "shielded", "zk", "nullifier", "withdraw", "note commitment")
    if zk_ctx and ("withdraw" in t or "spend" in t or "shielded" in t):
        if "nullifier" not in t:
            out.append(("zk_nullifier_missing",
                        "ZK withdrawal/spend path has no nullifier at all; the same note/proof can be spent twice",
                        "high", "Add a circuit-derived nullifier, store spent nullifiers, and check before value moves."))
        elif not has(text, "spent", "nullifiers[", "isspent", "nullifierused", "usednullifier"):
            out.append(("zk_nullifier_not_stored",
                        "A nullifier is referenced but no spent-nullifier storage/check is visible in the supplied contract",
                        "high", "Persist spent nullifiers and reject any repeat presentation."))
    return out[:8]


class ZeroKnowledgeNullifierAudit(Plugin):
    id = "zero_knowledge_nullifier_audit"
    label = "Zero-Knowledge Nullifier Audit"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Audits supplied ZK shielded-pool/withdrawal contracts and circuits for a unique nullifier that is derived, stored, and checked before value moves, so the same note cannot be spent twice."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
