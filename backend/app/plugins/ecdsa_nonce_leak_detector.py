"""VARIANT 65: cryptographic k-nonce analysis over supplied signature corpora."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def _norm(v):
    return str(v).strip().lower()

def analyze(text, objs):
    sigs = []
    for v in find_values(objs, "signatures"):
        if isinstance(v, list):
            sigs.extend([s for s in v if isinstance(s, dict)])
    if isinstance(objs, list):
        sigs.extend([o for o in objs if isinstance(o, dict) and "r" in o])
    out = []
    by_r = {}
    for s in sigs:
        if s.get("r") is None:
            continue
        by_r.setdefault(_norm(s["r"]), []).append(str(s.get("signer") or s.get("address") or "unknown"))
    for r, signers in by_r.items():
        uniq = set(signers)
        if len(signers) > 1 and len(uniq) == 1:
            out.append(("ecdsa_nonce_reuse",
                        f"ECDSA nonce reuse: {len(signers)} signatures from signer {signers[0]} share the same r value ({r[:18]}...); the signer's private key is recoverable from any two of them",
                        "high", "Rotate the exposed key immediately and use deterministic nonces (RFC 6979) with a CSPRNG."))
        elif len(signers) > 1 and len(uniq) > 1:
            out.append(("ecdsa_r_shared_across_signers",
                        f"The same ECDSA r value ({r[:18]}...) appears under {len(uniq)} different signers, indicating a shared/broken nonce generator",
                        "medium", "Audit the nonce generation of every affected signer; rotate keys whose nonce source is shared."))
    return out[:8]


class EcdsaNonceLeakDetector(Plugin):
    id = "ecdsa_nonce_leak_detector"
    label = "ECDSA Nonce Leak Detector"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Detects ECDSA ephemeral-nonce (k) reuse over supplied signature sets: signatures grouped by r per signer; a repeated r exposes the private key. Not contract replay nonces."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
