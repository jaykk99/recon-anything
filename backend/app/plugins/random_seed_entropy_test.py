"""VARIANT 84: general-application predictable-randomness scan of supplied code."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


_SEC = ("token", "key", "nonce", "secret", "session", "otp", "password", "seed", "salt")

def analyze(text, objs):
    out = []
    t = text.lower()
    sec_context = any(s in t for s in _SEC)
    if "math.random" in t and sec_context:
        out.append(("predictable_prng_security_value",
                    "Math.random() is used in code that produces a security value (token/key/nonce/session); Math.random is predictable",
                    "high", "Use a CSPRNG (crypto.randomBytes / crypto.getRandomValues / secrets module) for security values."))
    if rx(text, r"(seed|srand|random\.seed)\s*\(\s*[^)]*(time|timestamp|pid|date\.now|currenttimemillis)"):
        out.append(("prng_seeded_from_time_or_pid",
                    "A PRNG is seeded from the current time or process ID; its output stream is guessable",
                    "high", "Seed from the OS CSPRNG, or use the CSPRNG directly."))
    if rx(text, r"new\s+random\s*\(\s*system\.currenttimemillis") :
        out.append(("prng_seeded_from_time_or_pid",
                    "java.util.Random is seeded from the current time in supplied code",
                    "high", "Use SecureRandom for security values."))
    if rx(text, r"\brand\s*\(\s*\)") and sec_context and "crypto" not in t:
        out.append(("predictable_prng_security_value",
                    "rand() is used in code producing a security value; the C PRNG is predictable",
                    "medium", "Use the OS CSPRNG (getrandom / arc4random_buf) for security values."))
    return out[:6]


class RandomSeedEntropyTest(Plugin):
    id = "random_seed_entropy_test"
    label = "Random Seed Entropy Test"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Scans supplied application code for predictable PRNG inputs to security values: Math.random/rand() for tokens or keys, and PRNGs seeded from timestamps or PIDs."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
