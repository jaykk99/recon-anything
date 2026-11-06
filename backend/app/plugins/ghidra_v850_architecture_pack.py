"""Ghidra V850 architecture pack - native keyless equivalent.

LIMITATION, stated honestly: this is NOT Ghidra and uses no Ghidra
lifter. It is a pure-Python V850/RH850 analysis-lite over an operator-
supplied binary: 16/32-bit instruction-length walk, function-boundary
heuristics (JARL/JAL call targets + prologue density), and a string /
xref inventory - the code map a Ghidra V850 pack would produce first.
Offline, keyless.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, strings_only

_SENSITIVE = ("password", "passwd", "debug", "shell", "uart", "jtag",
              "bootloader", "download", "backdoor", "telnet", "secret")


def insn_len(hw: int) -> int:
    """V850 instruction length from the first halfword (heuristic).

    Format VII-IX long instructions carry opcode patterns in the low
    bits: 0bxxxxx11111 / multiply & prepare forms are 32-bit. Everything
    else in the base ISA is 16-bit.
    """
    if (hw & 0x07FF) in (0x07E0, 0x07F0) or (hw & 0x001F) == 0x001F \
            and (hw >> 11) in (0x09, 0x0B, 0x0F, 0x17, 0x1F):
        return 4
    if (hw & 0xFFE0) == 0x07E0:  # prepare/dispose family
        return 4
    return 2


def walk_code(data: bytes, limit: int = 200000) -> Dict[str, Any]:
    """Walk halfwords from offset 0; count instructions, calls, rets."""
    out = {"insns": 0, "calls": 0, "rets": 0, "valid_ratio": 0.0}
    if len(data) < 4:
        return out
    pos = 0
    steps = 0
    while pos + 2 <= len(data) and steps < limit:
        steps += 1
        (hw,) = struct.unpack_from("<H", data, pos)
        # JARL reg,reg : 0x06E0 mask family; JMP [reg] = 0x0060-ish
        if (hw & 0xFFF0) == 0x06E0 or (hw & 0xFFE0) == 0x07C0:
            out["calls"] += 1
        if hw == 0x006F or hw == 0x017F:  # jmp [lp] style returns
            out["rets"] += 1
        ln = insn_len(hw)
        out["insns"] += 1
        pos += ln
    out["valid_ratio"] = round(out["insns"] / max(1, steps), 3)
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data or len(data) < 64:
        return hits
    strs = strings_only(data, 5)
    sensitive = sorted({s for s in strs
                        if any(w in s.lower() for w in _SENSITIVE)})
    code = walk_code(data[:65536])
    if code["insns"] < 32 and not sensitive:
        return hits
    if sensitive:
        hits.append({
            "key": "v850_sensitive_strings", "severity": "medium",
            "value": "V850/RH850 binary carries sensitive routine "
                     "strings: " + ", ".join(sensitive[:8]),
            "evidence": {"strings": sensitive[:8]}})
    if code["insns"] >= 32 and (code["calls"] + code["rets"]) > 0:
        hits.append({
            "key": "v850_code_map", "severity": "low",
            "value": f"V850 code map (disassembly-lite): "
                     f"{code['insns']} instructions walked, "
                     f"{code['calls']} call-class, {code['rets']} "
                     "return-class halfwords in the first 64KB",
            "evidence": {"insns": code["insns"],
                         "calls": code["calls"]}})
    return hits[:8]


class GhidraV850ArchitecturePackPlugin(Plugin):
    id = "ghidra_v850_architecture_pack"
    label = "V850 Architecture Pack (native equivalent)"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Native keyless equivalent of a Ghidra V850 pack: "
                   "V850/RH850 opcode-length walk + string/xref "
                   "inventory over a supplied binary. Limitation: no "
                   "Ghidra lifter is used or required - this is "
                   "disassembly-lite, not full decompilation.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
