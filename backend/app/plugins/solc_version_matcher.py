"""Solc Version Matcher (Cat-1 #9, VARIANT of contract_recon).

Delta: contract_recon extracts the compiler version (pragma /
bytecode CBOR metadata); nobody mapped that version against the
known compiler-bug record. This plugin carries a local table of
documented solc bug ranges (from the Solidity team's published
bug list - the entries below are the widely-hit families) and
reports exactly which known bugs a target's compiler version is
exposed to. A current compiler (no table hit) stays silent.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C
from . import contract_chain as cc

# (low_inclusive, high_inclusive, bug_name, severity, note)
BUG_TABLE: List[Tuple[Tuple[int, int, int], Tuple[int, int, int],
                      str, str, str]] = [
    ((0, 4, 0), (0, 4, 26), "legacy_compiler_bugs", "medium",
     "pre-0.5 compiler line: uninitialized storage pointers, "
     "complex expression evaluation-order and optimizer bugs from "
     "the published bug list apply to this whole range"),
    ((0, 5, 0), (0, 5, 17), "abi_encoder_v2_optimizer_bugs", "medium",
     "0.5.x line carries published ABIEncoderV2 and optimizer "
     "bugs (incl. the 0.5.5-0.5.12 encoder and clearing bugs)"),
    ((0, 6, 0), (0, 6, 11), "optimizer_and_abi_bugs_0_6", "low",
     "0.6.x early line: published optimizer full-inliner and "
     "ABI-encoder bugs fixed in later 0.6 patches"),
    ((0, 7, 0), (0, 7, 5), "optimizer_bugs_0_7", "low",
     "0.7.x early line: published optimizer bugs fixed in 0.7.6"),
    ((0, 8, 0), (0, 8, 3), "early_0_8_compiler_bugs", "low",
     "0.8.0-0.8.3: published signed-immutable and ABI re-encoding "
     "bugs fixed in later 0.8 patches"),
    ((0, 8, 13), (0, 8, 14), "yul_optimizer_absence_0_8_13", "low",
     "0.8.13/0.8.14 era: yul optimizer issues from the published "
     "list (fixed in 0.8.15+)"),
]


def parse_version(text: str) -> Optional[Tuple[int, int, int]]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def version_of(source: str = "", bytecode: str = "",
               explicit: str = "") -> Optional[Tuple[int, int, int]]:
    if explicit:
        v = parse_version(explicit)
        if v:
            return v
    if source:
        m = re.search(r"pragma\s+solidity\s+[^;]*?(\d+\.\d+\.\d+)",
                      source)
        if m:
            return parse_version(m.group(1))
    if bytecode:
        solc = cc.analyze_bytecode(bytecode).get("metadata", {}) \
            .get("solc")
        if solc:
            return parse_version(solc)
    return None


def match_solc_version(version) -> List[Dict[str, Any]]:
    if not version:
        return []
    if isinstance(version, str):
        version = parse_version(version)
        if not version:
            return []
    ver = tuple(int(x) for x in version)
    hits: List[Dict[str, Any]] = []
    for lo, hi, name, sev, note in BUG_TABLE:
        if lo <= ver <= hi:
            vs = ".".join(map(str, ver))
            hits.append(C.hit(
                "solc_known_compiler_bug",
                f"compiler solc {vs} is inside the published bug "
                f"range for '{name}': {note}.",
                sev,
                "Recompile with a current solc release and "
                "redeploy; compiler bugs are in the deployed "
                "bytecode and cannot be patched in place.",
                solc_version=vs, bug=name,
                range=f"{'.'.join(map(str, lo))}-"
                      f"{'.'.join(map(str, hi))}",
                check="solc_version_match"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    ver = version_of(data.get("source", ""), data.get("bytecode", ""))
    return match_solc_version(ver) if ver else []


class SolcVersionMatcherPlugin(Plugin):
    id = "solc_version_matcher"
    label = "Solc Version Matcher"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Maps the identified solc compiler version "
                   "(pragma or bytecode CBOR metadata) against a "
                   "local known-compiler-bug table and reports "
                   "which published bugs the version is exposed to.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True,
            no_input="no source or bytecode to read a compiler "
                     "version from")
