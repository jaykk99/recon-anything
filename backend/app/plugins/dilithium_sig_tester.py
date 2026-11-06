"""SHIP 81: static/config analysis of Dilithium integrations. No signatures are forged or submitted."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


_LEVELS = {"44": 2, "65": 3, "87": 5, "dilithium2": 2, "dilithium3": 3, "dilithium5": 5, "2": 2, "3": 3, "5": 5}

def analyze(text, objs):
    out = []
    var = first(objs, "parameter_set", "variant", "dilithium_variant")
    claimed = first(objs, "claimed_level", "claimed_security_level")
    if var is not None and claimed is not None:
        key = re.search(r"(44|65|87)", str(var))
        lvl = _LEVELS.get(key.group(1)) if key else _LEVELS.get(str(var).lower().replace("ml-dsa-", "").replace("dilithium", "dilithium"))
        try:
            if lvl is not None and int(claimed) > lvl:
                out.append(("dilithium_claimed_level_mismatch",
                            f"Dilithium/ML-DSA variant {var} provides level {lvl} but level {claimed} is claimed",
                            "medium", "Claim only the level of the deployed parameter set."))
        except Exception:
            pass
    sc, vc = first(objs, "sign_context"), first(objs, "verify_context")
    if sc is not None and vc is not None and sc != vc:
        out.append(("dilithium_context_mismatch",
                    "Sign and verify paths use different context strings; signatures will fail or, worse, cross-context replay is possible where contexts were meant to separate domains",
                    "medium", "Use one consistent context string and pre-hash mode on sign and verify paths."))
    sp, vp = first(objs, "sign_prehash"), first(objs, "verify_prehash")
    if sp is not None and vp is not None and sp != vp:
        out.append(("dilithium_prehash_mismatch",
                    "Pre-hash mode differs between sign and verify paths",
                    "medium", "Align the pre-hash mode on both paths."))
    if first(objs, "key_zeroized", "zeroize") is False:
        out.append(("dilithium_key_not_zeroized",
                    "Private-key buffers are not zeroized after use in the supplied integration",
                    "low", "Zeroize private-key buffers immediately after signing operations."))
    return out[:8]


class DilithiumSigTester(Plugin):
    id = "dilithium_sig_tester"
    label = "Dilithium / ML-DSA Tester"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Reviews supplied Dilithium/ML-DSA integrations: parameter set vs claimed level, sign/verify context and pre-hash consistency, and private-key buffer zeroization."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
