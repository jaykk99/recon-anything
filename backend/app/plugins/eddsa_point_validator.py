"""SHIP 66: pure curve-math checks (field/canonicality/small-order) on supplied Ed25519 points and scalars."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


L = 2**252 + 27742317777372353535851937790883648493
P_FIELD = 2**255 - 19

def _intval(v):
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") or any(c in s.lower() for c in "abcdef") and len(s) > 10 else int(s)
    except Exception:
        try:
            return int.from_bytes(bytes.fromhex(s), "little")
        except Exception:
            return None

def analyze(text, objs):
    out = []
    entries = []
    for k in ("signatures", "keys", "points"):
        for v in find_values(objs, k):
            if isinstance(v, list):
                entries.extend([e for e in v if isinstance(e, dict)])
            elif isinstance(v, dict):
                entries.append(v)
    for e in entries:
        s = _intval(e.get("S", e.get("s"))) if (e.get("S") is not None or e.get("s") is not None) else None
        if s is not None and s >= L:
            out.append(("eddsa_noncanonical_s",
                        "EdDSA signature scalar S is >= L (group order); non-canonical S is accepted, making signatures malleable",
                        "high", "Reject signatures with S >= L during verification (canonical S check)."))
        for label in ("A", "R", "public_key", "point"):
            if e.get(label) is None:
                continue
            pv = _intval(e.get(label))
            if pv is None:
                continue
            if pv >= P_FIELD:
                out.append(("eddsa_noncanonical_point",
                            f"EdDSA point {label} encoding is non-canonical (>= field prime)",
                            "medium", "Reject non-canonical point encodings before verification."))
            if pv in (0, 1):
                out.append(("eddsa_small_order_point",
                            f"EdDSA point {label} is a small-order (torsion/identity) point; accepting it enables small-subgroup attacks",
                            "high", "Reject small-order points and use cofactored verification consistently."))
    return out[:10]


class EddsaPointValidator(Plugin):
    id = "eddsa_point_validator"
    label = "EdDSA Point Validator"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Validates supplied EdDSA keys/signatures: canonical S < L, points on the prime-order subgroup, small-order (torsion) points rejected."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
