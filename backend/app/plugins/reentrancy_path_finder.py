"""Reentrancy Path Finder (Cat-1 #6, VARIANT of contract_logic).

Delta: explicit reentrancy PATH enumeration. contract_logic flags
CEI violations in one function; this plugin builds the concrete
path - entry function -> external call -> shared state variable ->
a second function that reads/writes that same variable before its
own external call - and emits each full path as one finding.

BOUNDARY: any simulation of a flagged path runs on local
fixtures/forks ONLY (no live transaction, ever). Every finding
this plugin emits is mechanically stamped UNVERIFIED by the
shared emitter (evidence unverified/sim_derived/not_verified_real
plus the 'UNVERIFIED (sim): ' value prefix).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_CALL_RE = re.compile(
    r"(\.call\s*\{|\.call\s*\(|\.transfer\s*\(|\.send\s*\(|"
    r"\.safeTransfer|\.transferFrom\s*\(|\w+\.transfer\s*\()")
_WRITE_RE = re.compile(r"([A-Za-z_][\w]*)\s*(?:\[|\+\+|--|\+=|-=|=(?!=))")


def _guarded(fn: Dict[str, str], source: str) -> bool:
    return "nonReentrant" in fn.get("mods", "") or \
        "ReentrancyGuard" in source


def find_reentrancy_paths(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    state = {v["name"] for v in C.state_vars(src)}
    fns = [f for f in C.functions(src)
           if f["name"] not in ("constructor",)]
    # per-function: external call position, state writes after it,
    # state reads/writes anywhere
    info: Dict[str, Dict[str, Any]] = {}
    for f in fns:
        body = f["body"]
        m = _CALL_RE.search(body)
        if not m:
            info[f["name"]] = {"call_at": None, "writes_after": set(),
                               "writes": set(), "reads": set()}
            continue
        after = body[m.start():]
        writes_after = {w for w in _WRITE_RE.findall(after)
                        if w in state}
        writes = {w for w in _WRITE_RE.findall(body) if w in state}
        reads = {w for w in re.findall(r"\b([A-Za-z_]\w*)\b", body)
                 if w in state}
        info[f["name"]] = {"call_at": m.start(),
                           "writes_after": writes_after,
                           "writes": writes, "reads": reads}
    hits: List[Dict[str, Any]] = []
    for f in fns:
        if _guarded(f, src):
            continue
        inf = info[f["name"]]
        if inf["call_at"] is None or not inf["writes_after"]:
            continue
        for var in sorted(inf["writes_after"]):
            # second function touching the same var = the re-entry leg
            partners = [g["name"] for g in fns
                        if g["name"] != f["name"]
                        and (var in info[g["name"]]["writes"]
                             or var in info[g["name"]]["reads"])]
            path = f"{f['name']}() -> external call -> re-enter " \
                   + (f"{partners[0]}()" if partners else f"{f['name']}()") \
                   + f" over shared state '{var}'"
            hits.append(C.hit(
                "reentrancy_path",
                f"reentrancy path enumerated: {path}. The entry "
                f"function writes '{var}' only AFTER its external "
                f"call, so a re-entrant call observes the stale "
                f"value"
                + (f"; {len(partners)} other function(s) also touch "
                   f"'{var}' ({', '.join(partners[:3])})"
                   if partners else "")
                + ". Local-fixture simulation only.",
                "high",
                "Apply checks-effects-interactions on this path "
                "and add a reentrancy guard; the shared variable "
                "must be updated before any external call.",
                path=path, entry=f["name"], variable=var,
                partners=partners, check="reentrancy_path_finder"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return find_reentrancy_paths(data.get("source", ""))


class ReentrancyPathFinderPlugin(Plugin):
    id = "reentrancy_path_finder"
    label = "Reentrancy Path Finder"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Enumerates concrete reentrancy paths "
                   "(entry -> external call -> shared state -> "
                   "re-entry function). Simulation is local "
                   "fixtures/forks only; every finding is stamped "
                   "UNVERIFIED.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, stamp=True,
            bytecode=False,
            no_input="no contract source to enumerate reentrancy "
                     "paths from")
