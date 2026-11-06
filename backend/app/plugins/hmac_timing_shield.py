"""SHIP 83: static code scanning only."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


_SECRETY = ("mac", "tag", "digest", "hmac", "signature", "hash", "token", "secret")

def analyze(text, objs):
    out = []
    for line in text.splitlines():
        low = line.lower()
        if any(s in low for s in ("compare_digest", "constanttimecompare", "consttime", "isEqual".lower(), "timingsafeequal", "subtle.compare")):
            continue
        if not any(s in low for s in _SECRETY):
            continue
        if "==" in line or ".equals(" in low or re.search(r"\bmemcmp\s*\(", low) or "===" in line:
            out.append(("non_constant_time_mac_compare",
                        f"Secret-derived value compared with non-constant-time equality: {line.strip()[:140]}",
                        "medium", "Compare MACs/digests with a constant-time comparator (hmac.compare_digest, subtle.ConstantTimeCompare, MessageDigest.isEqual, crypto.timingSafeEqual)."))
            if len(out) >= 5:
                break
    return out


class HmacTimingShield(Plugin):
    id = "hmac_timing_shield"
    label = "HMAC Timing Shield"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Finds MAC/digest/signature comparisons in supplied code that use non-constant-time equality (==, equals, memcmp) instead of a constant-time comparator."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
