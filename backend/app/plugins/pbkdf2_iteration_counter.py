"""VARIANT 82: PBKDF2-specific iteration-count pass over supplied code/config."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


_THRESH = {"sha1": 1300000, "sha256": 600000, "sha512": 210000, "sha384": 210000}

def analyze(text, objs):
    out = []
    t = text.lower()
    counts = []
    for m in re.finditer(r"pbkdf2[^\n;]{0,140}?(\d[\d_]{2,})\s*[,)]", text, re.I):
        counts.append(int(m.group(1).replace("_", "")))
    for m in re.finditer(r"(?:pbkdf2_)?iterations?\s*[:=]\s*(\d[\d_]*)", text, re.I):
        if "pbkdf2" in t:
            counts.append(int(m.group(1).replace("_", "")))
    for v in find_values(objs, "iterations"):
        if isinstance(v, int) and "pbkdf2" in t:
            counts.append(v)
    if not counts:
        return out
    hashname = "sha256"
    for h in _THRESH:
        if h in t:
            hashname = h
            break
    thr = _THRESH[hashname]
    low = min(counts)
    if low < thr:
        out.append(("pbkdf2_low_iterations",
                    f"PBKDF2 iteration count {low} is below current OWASP guidance for HMAC-{hashname.upper()} ({thr})",
                    "medium", f"Raise PBKDF2 iterations to at least {thr} for HMAC-{hashname.upper()} (or migrate to Argon2id)."))
    return out


class Pbkdf2IterationCounter(Plugin):
    id = "pbkdf2_iteration_counter"
    label = "PBKDF2 Iteration Counter"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Finds PBKDF2 call sites in supplied code/config and flags iteration counts below current OWASP guidance for the hash in use (600k for HMAC-SHA256)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
