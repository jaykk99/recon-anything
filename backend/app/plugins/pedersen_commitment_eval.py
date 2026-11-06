"""SHIP 69: static analysis of Pedersen commitment implementations."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    t = text.lower()
    if "pedersen" not in t and "commitment" not in t:
        return out
    if rx(text, r"\bH\s*=\s*[A-Za-z0-9_]+\s*\*\s*G\b") or has(text, "same seed for both generators", "h derived from g"):
        out.append(("pedersen_known_generator_relation",
                    "Pedersen generators G and H have a known discrete-log relation in the derivation, so commitments are not binding",
                    "high", "Derive G and H independently (e.g. hash-to-curve with distinct domain separators) so no party knows log_G(H)."))
    if rx(text, r"blind\w*\s*=\s*(math\.random|rand\(|random\.random|time\()"):
        out.append(("pedersen_weak_blinding",
                    "Pedersen blinding factor comes from a predictable PRNG/time source, so commitments are not hiding",
                    "high", "Draw blinding factors from a CSPRNG (os.urandom / crypto random)."))
    if not has(text, "range_proof", "range proof", "rangeproof", "bulletproof"):
        out.append(("pedersen_no_range_enforcement",
                    "Pedersen commitment is used with no range proof/enforcement visible; negative or overflowing values can be committed",
                    "medium", "Pair every commitment with a range proof over the claimed value bounds."))
    return out


class PedersenCommitmentEval(Plugin):
    id = "pedersen_commitment_eval"
    label = "Pedersen Commitment Evaluation"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Audits supplied Pedersen commitment code: generator independence, blinding-factor entropy, and whether a value range is actually enforced alongside the commitment."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
