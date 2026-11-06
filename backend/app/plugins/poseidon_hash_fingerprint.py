"""SHIP 77: parameter extraction vs a local reference table."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def _check(full, partial, out, src):
    try:
        if full is not None and int(full) < 8:
            out.append(("poseidon_low_full_rounds",
                        f"Poseidon full rounds = {full} (< 8) in {src}; below the reference security margin",
                        "high", "Use the reference Poseidon round numbers for the field/width (at least 8 full rounds)."))
        if partial is not None and int(partial) < 50:
            out.append(("poseidon_low_partial_rounds",
                        f"Poseidon partial rounds = {partial} in {src}; below the reference margin (~57 for BN254 t=3)",
                        "high", "Use the reference Poseidon partial-round count for the chosen field and state width."))
    except Exception:
        pass

def analyze(text, objs):
    out = []
    _check(first(objs, "full_rounds"), first(objs, "partial_rounds"), out, "supplied parameters")
    ob, fb = first(objs, "output_bits"), first(objs, "field_bits")
    try:
        if ob is not None and int(ob) < 128:
            out.append(("poseidon_truncated_output",
                        f"Poseidon output is truncated to {ob} bits and used as a full hash; collision resistance is capped at about {int(ob)//2} bits",
                        "medium", "Do not truncate Poseidon outputs used as hashes/commitments below the security target."))
    except Exception:
        pass
    mds = first(objs, "mds_source", "mds")
    if mds is not None and str(mds).lower() in ("custom", "ad-hoc", "adhoc", "hand-made", "unknown"):
        out.append(("poseidon_adhoc_mds",
                    "Poseidon MDS matrix is ad-hoc with no derivation record; its diffusion/security is unvetted",
                    "medium", "Use the reference MDS matrix (Cauchy construction) for the Poseidon instance and record its derivation."))
    mf = re.search(r"full_rounds\s*[:=]\s*(\d+)", text)
    mp = re.search(r"partial_rounds\s*[:=]\s*(\d+)", text)
    if mf or mp:
        _check(mf.group(1) if mf else None, mp.group(1) if mp else None, out, "supplied config")
    return out[:8]


class PoseidonHashFingerprint(Plugin):
    id = "poseidon_hash_fingerprint"
    label = "Poseidon Hash Fingerprint"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Fingerprints supplied Poseidon instances (field, width, exponent, rounds, MDS source) and flags round counts below reference margins, truncated outputs, and ad-hoc MDS matrices."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
