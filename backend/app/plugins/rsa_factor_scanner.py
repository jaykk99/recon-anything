"""SHIP 72: pure number theory over supplied public keys."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


import math

def _small_primes(limit=1000):
    sieve = [True] * (limit + 1)
    primes = []
    for i in range(2, limit + 1):
        if sieve[i]:
            primes.append(i)
            for j in range(i * i, limit + 1, i):
                sieve[j] = False
    return primes
_SMALL = _small_primes()

def _fp(n):
    return f"{n.bit_length()}bit sha256:{__import__('hashlib').sha256(str(n).encode()).hexdigest()[:16]}"

def analyze_moduli(moduli):
    out = []
    mods = [int(m) for m in moduli if isinstance(m, int) or str(m).isdigit()]
    mods = [m for m in mods if m > 3]
    for i in range(len(mods)):
        for j in range(i + 1, len(mods)):
            g = math.gcd(mods[i], mods[j])
            if 1 < g < min(mods[i], mods[j]):
                out.append(("rsa_shared_prime_factor",
                            f"Two supplied RSA moduli ({_fp(mods[i])}, {_fp(mods[j])}) share a common prime factor; both private keys are recoverable by GCD",
                            "high", "Revoke both keys and regenerate with independent, high-entropy prime generation."))
                return out
    for n in mods:
        if n.bit_length() < 2048:
            out.append(("rsa_weak_key_size",
                        f"Supplied RSA modulus is only {n.bit_length()} bits ({_fp(n)})",
                        "medium", "Use RSA keys of at least 2048 bits (3072 preferred)."))
        for p in _SMALL:
            if n % p == 0 and p < n:
                out.append(("rsa_small_factor",
                            f"Supplied RSA modulus ({_fp(n)}) has the small prime factor {p}",
                            "high", "Revoke the key; its primes were generated with dangerously low entropy."))
                break
        if n.bit_length() <= 512:
            r = math.isqrt(n)
            if r * r < n:
                r += 1
            for k in range(0, 20000):
                a = r + k
                b2 = a * a - n
                b = math.isqrt(b2)
                if b * b == b2 and a - b not in (1, n):
                    out.append(("rsa_fermat_close_primes",
                                f"Supplied RSA modulus ({_fp(n)}) factors by Fermat's method; its primes are too close together",
                                "high", "Revoke the key and generate primes independently."))
                    break
    return out[:8]

def analyze(text, objs):
    moduli = []
    for k in ("moduli", "modulus", "n"):
        for v in find_values(objs, k):
            if isinstance(v, list):
                moduli.extend([x for x in v if isinstance(x, int)])
            elif isinstance(v, int):
                moduli.append(v)
    if isinstance(objs, list):
        moduli.extend([o for o in objs if isinstance(o, int)])
    return analyze_moduli(moduli)


class RsaFactorScanner(Plugin):
    id = "rsa_factor_scanner"
    label = "RSA Factor Scanner"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Runs batch-GCD shared-factor, small-factor, Fermat close-prime, and key-size checks over supplied RSA public moduli. Fingerprints only in findings."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
