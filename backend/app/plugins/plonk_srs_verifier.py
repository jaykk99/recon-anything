"""SHIP 64: structural integrity checks on supplied PLONK setup artifacts."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    deg = first(objs, "circuit_degree", "degree")
    srs_len = first(objs, "srs_length", "srs_len")
    try:
        if deg is not None and srs_len is not None and int(srs_len) < int(deg):
            out.append(("plonk_srs_too_short",
                        f"SRS length {srs_len} is shorter than the circuit degree {deg}; polynomials of that degree cannot be committed",
                        "high", "Regenerate or supply an SRS with at least as many powers as the circuit degree."))
    except Exception:
        pass
    for pt in find_values(objs, "points"):
        if isinstance(pt, list):
            for p in pt:
                if isinstance(p, dict) and (p.get("on_curve") is False or p.get("in_subgroup") is False):
                    out.append(("plonk_srs_invalid_point",
                                "An SRS/key point is off-curve or outside the correct subgroup",
                                "high", "Reject the setup artifact; regenerate keys from a validated SRS and verify subgroup membership on load."))
                    break
    if first(objs, "vk_matches_srs", "vk_srs_match") is False:
        out.append(("plonk_vk_srs_mismatch",
                    "Verification-key commitments do not correspond to the supplied SRS; the vk may come from an unknown setup (toxic-waste provenance cannot be verified from artifacts alone)",
                    "high", "Use the verification key generated from the attested SRS ceremony and pin its fingerprint."))
    md = re.search(r"srs_length\s*[:=]\s*(\d+)", text)
    me = re.search(r"(?:circuit_degree|degree)\s*[:=]\s*(\d+)", text)
    if md and me and int(md.group(1)) < int(me.group(1)):
        out.append(("plonk_srs_too_short",
                    f"SRS length {md.group(1)} shorter than circuit degree {me.group(1)} in supplied config",
                    "high", "Supply an SRS covering the full circuit degree."))
    return out[:8]


class PlonkSrsVerifier(Plugin):
    id = "plonk_srs_verifier"
    label = "PLONK SRS Verifier"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Checks supplied PLONK SRS/setup artifacts: SRS length vs circuit degree, curve-point subgroup membership, verification-key to SRS correspondence. Never claims a setup was honest."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
