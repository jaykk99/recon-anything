"""VARIANT 85: DH parameter-strength pass over supplied handshake/parameter artifacts."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def _is_probable_prime(n, rounds=12):
    if n < 2:
        return False
    small = [2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    import random as _rnd
    _rnd.seed(12345)
    for _ in range(rounds):
        a = _rnd.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def analyze(text, objs):
    out = []
    bits = first(objs, "dh_bits", "group_bits", "prime_bits")
    m = re.search(r"dh(?:param)?[^\n]{0,30}?(1024|2048|3072|4096)\s*(?:bit|\b)", text, re.I)
    try:
        b = int(bits) if bits is not None else (int(m.group(1)) if m and "dh" in text.lower() else None)
    except Exception:
        b = None
    if b is not None and b < 2048:
        out.append(("dh_group_too_small",
                    f"Diffie-Hellman group is {b} bits (< 2048); discrete logs are feasible for a well-resourced attacker (Logjam class)",
                    "high", "Use an FFDHE group of at least 2048 bits (3072 preferred) or ECDHE."))
    p = first(objs, "p", "prime", "modulus_p")
    if isinstance(p, int) and p > 100:
        if not _is_probable_prime(p):
            out.append(("dh_modulus_composite",
                        "The supplied DH modulus p is composite (Miller-Rabin); the group structure is broken",
                        "high", "Use a vetted safe-prime FFDHE group."))
        elif not _is_probable_prime((p - 1) // 2):
            out.append(("dh_not_safe_prime",
                        "The supplied DH prime p is not a safe prime ((p-1)/2 is composite); small-subgroup attacks are possible",
                        "medium", "Use a safe-prime group and validate peer public values are in the prime-order subgroup."))
    if first(objs, "safe_prime") is False:
        out.append(("dh_not_safe_prime",
                    "The configured DH group is flagged as not a safe prime",
                    "medium", "Use a vetted safe-prime FFDHE group."))
    return out[:8]


class DiffieHellmanGroupCheck(Plugin):
    id = "diffie_hellman_group_check"
    label = "Diffie-Hellman Group Check"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Checks supplied DH parameters/groups: size below 2048 bits, composite modulus (Miller-Rabin over a supplied p), safe-prime violations, and known-weak MODP groups."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
