"""SHIP 80: static/config analysis of Kyber integrations."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


_LEVELS = {"512": 1, "768": 3, "1024": 5}

def analyze(text, objs):
    out = []
    var = first(objs, "parameter_set", "variant", "kyber_variant")
    claimed = first(objs, "claimed_level", "claimed_security_level")
    if var is not None:
        m = re.search(r"(512|768|1024)", str(var))
        if m and claimed is not None:
            try:
                if int(claimed) > _LEVELS[m.group(1)]:
                    out.append(("kyber_claimed_level_mismatch",
                                f"Kyber/ML-KEM-{m.group(1)} provides NIST level {_LEVELS[m.group(1)]} but level {claimed} is claimed",
                                "medium", "Claim only the security level of the deployed parameter set, or deploy the larger parameter set."))
            except Exception:
                pass
    if first(objs, "implicit_rejection") is False:
        out.append(("kyber_no_implicit_rejection",
                    "Kyber decapsulation lacks implicit rejection; explicit failure lets an attacker distinguish invalid ciphertexts (key-recovery oracle)",
                    "high", "Implement implicit rejection: return a pseudorandom key on decapsulation failure."))
    if first(objs, "decaps_error_distinct", "distinct_error") is True or has(text, "return err_invalid_ciphertext", "distinct decapsulation error"):
        out.append(("kyber_decapsulation_error_leak",
                    "Decapsulation failures are distinguishable (error/timing), leaking validity information",
                    "medium", "Make decapsulation failures indistinguishable and constant-time."))
    if first(objs, "key_reused", "ephemeral") is False and first(objs, "key_reused") is not True:
        pass
    if first(objs, "key_reused") is True:
        out.append(("kyber_key_reuse",
                    "KEM keypair is reused across sessions where ephemeral keys are required; forward secrecy is lost",
                    "medium", "Generate an ephemeral KEM keypair per session."))
    if rx(text, r"kyber\s*512") and rx(text, r"level\s*5|nist level 5"):
        out.append(("kyber_claimed_level_mismatch",
                    "Kyber-512 (level 1) is described as level 5 in supplied material",
                    "medium", "Correct the claimed level or deploy ML-KEM-1024."))
    return out[:8]


class KyberPqcVerifier(Plugin):
    id = "kyber_pqc_verifier"
    label = "Kyber / ML-KEM Verifier"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Validates supplied Kyber/ML-KEM integrations: parameter set vs claimed security level, implicit rejection, decapsulation error leakage, and ephemeral vs reused KEM keys."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
