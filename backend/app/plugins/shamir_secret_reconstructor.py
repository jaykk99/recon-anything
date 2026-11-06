"""SHIP 73: configuration/logic audit of Shamir implementations."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    thr = first(objs, "threshold")
    shares = first(objs, "total_shares", "shares", "num_shares")
    try:
        if thr is not None and int(thr) <= 1:
            out.append(("shamir_threshold_one",
                        f"Shamir threshold is {thr}; any single share holder can reconstruct the secret",
                        "high", "Set a threshold of at least 2 (typically a majority of shares)."))
        if thr is not None and shares is not None and int(thr) > int(shares):
            out.append(("shamir_threshold_exceeds_shares",
                        f"Shamir threshold {thr} exceeds the total share count {shares}; the secret can never be reconstructed",
                        "medium", "Set threshold <= total shares."))
    except Exception:
        pass
    if first(objs, "share_mac", "mac", "integrity") is False:
        out.append(("shamir_shares_no_integrity",
                    "Shamir shares are distributed without integrity/MACs; a tampered share silently corrupts reconstruction",
                    "medium", "Authenticate each share (MAC or signature) and verify before interpolation."))
    pb, sb = first(objs, "prime_bits"), first(objs, "secret_bits")
    try:
        if pb is not None and sb is not None and int(pb) < int(sb):
            out.append(("shamir_field_smaller_than_secret",
                        f"Shamir field prime is {pb} bits, smaller than the {sb}-bit secret; shares leak/corrupt the secret",
                        "high", "Use a prime field larger than the secret."))
    except Exception:
        pass
    if first(objs, "eval_at_zero_unchecked") is True or has(text, "attacker-controlled share coordinate", "unvalidated x coordinate"):
        out.append(("shamir_unchecked_share_coordinates",
                    "Lagrange interpolation at x=0 accepts attacker-controlled/unvalidated share coordinates",
                    "medium", "Validate share coordinates (non-zero, unique, issued set) before interpolation."))
    if rx(text, r"threshold\s*[:=]\s*1\b"):
        out.append(("shamir_threshold_one",
                    "Shamir threshold configured as 1 in supplied config/code",
                    "high", "Set a threshold of at least 2."))
    return out[:8]


class ShamirSecretReconstructor(Plugin):
    id = "shamir_secret_reconstructor"
    label = "Shamir Secret Sharing Auditor"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Audits supplied Shamir secret-sharing implementations/configs: threshold sanity, interpolation-at-zero handling, share integrity, and field size. Never collects or reconstructs a real secret."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
