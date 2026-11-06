"""SHIP 70: static AEAD call-site scanning."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    if "chacha" not in text.lower():
        return out
    if rx(text, r"nonce\s*[:=]\s*b?[\"\'](?:\\x00|0{4,}|.{0,3}[\"\'])") or has(text, "static nonce", "fixed nonce", "zero nonce"):
        out.append(("chacha_static_nonce",
                    "ChaCha20-Poly1305 is used with a static, zero, or hardcoded nonce; nonce reuse under one key destroys Poly1305 authenticity",
                    "high", "Use a fresh random (or safely counted, never-repeating) 12-byte nonce per message and transmit it with the ciphertext."))
    if rx(text, r"nonce\s*[:=]\s*b[\"\'][^\"\']{4,}[\"\']"):
        out.append(("chacha_hardcoded_nonce",
                    "ChaCha20-Poly1305 nonce is a hardcoded literal in the supplied code",
                    "high", "Generate the nonce per message from a CSPRNG or a persistent monotonic counter."))
    return out[:6]


class ChaCha20Poly1305Inspector(Plugin):
    id = "chacha20_poly1305_inspector"
    label = "ChaCha20-Poly1305 Inspector"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Finds ChaCha20-Poly1305 call sites in supplied code and flags static/zero/hardcoded nonces and key+nonce pairs hardcoded together."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
