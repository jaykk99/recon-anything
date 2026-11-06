"""VARIANT 86: crypto-specific differential posture over supplied samples/code only."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze_samples(samples):
    out = []
    valid = [s for s in samples if isinstance(s, dict) and s.get("padding_valid") is True]
    invalid = [s for s in samples if isinstance(s, dict) and s.get("padding_valid") is False]
    if valid and invalid:
        ve = {str(s.get("error") or s.get("status") or "") for s in valid}
        ie = {str(s.get("error") or s.get("status") or "") for s in invalid}
        if ve != ie:
            out.append(("cbc_padding_oracle_candidate",
                        "Supplied differential samples return distinguishable responses for valid vs invalid CBC padding (padding-oracle candidate, UNVERIFIED, no decryption attempted)",
                        "medium", "Return one generic decryption error, verify a MAC (Encrypt-then-MAC/AEAD) before padding is checked, and make the path constant-time."))
        vt = [float(s["timing_ms"]) for s in valid if isinstance(s.get("timing_ms"), (int, float))]
        it = [float(s["timing_ms"]) for s in invalid if isinstance(s.get("timing_ms"), (int, float))]
        if vt and it and abs(sum(vt)/len(vt) - sum(it)/len(it)) > 20:
            out.append(("cbc_padding_timing_candidate",
                        "Supplied samples show a >20ms average timing delta between valid and invalid padding (padding-oracle candidate, UNVERIFIED)",
                        "medium", "Authenticate ciphertext before decryption and keep the error path constant-time."))
    return out

def analyze(text, objs):
    samples = []
    for v in find_values(objs, "samples"):
        if isinstance(v, list):
            samples.extend(v)
    out = analyze_samples(samples)
    if rx(text, r"(invalid|bad|incorrect)\s+padding") or has(text, "paddingerror", "badpaddingexception"):
        out.append(("cbc_padding_error_distinguishable",
                    "Supplied code/responses expose a distinct padding error, the classic padding-oracle signal (candidate, UNVERIFIED)",
                    "medium", "Collapse all decryption failures into one generic error and authenticate before decrypting."))
    return out[:6]


class CbcPaddingProbe(Plugin):
    id = "cbc_padding_probe"
    label = "CBC Padding Probe (Pattern + Supplied Differentials)"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Detects CBC padding-oracle signals from operator-supplied differential samples and code patterns: distinct padding errors or timing deltas that separate valid from invalid padding. Candidate only, UNVERIFIED; it never decrypts anything and performs no live oracle attack."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
