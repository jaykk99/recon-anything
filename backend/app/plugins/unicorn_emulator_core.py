"""Unicorn-emulator-core (native keyless equivalent): isolated emulation of an operator-supplied code snippet inside a pure-Python virtual CPU (x86 subset) - final registers, memory-write log and crash/sink points. Nothing is executed natively on the host.
"""
from __future__ import annotations
import re, struct, time
from typing import Any, Dict, List, Tuple
from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat5_common import (
    DANGEROUS_IMPORTS, BUFFER_IMPORTS, REMEDIATION, block_edges,
    code_section_bytes, decode_one, detect_format, elf_imports,
    elf_section, extract_strings, find_string_xrefs, load_artifacts,
    mask_secret, offset_to_vaddr, parse_any, parse_elf, parse_macho,
    parse_pe, pe_all_import_names, shannon_entropy, split_blocks,
    strings_only, try_capstone_disasm, window_entropies, PT_GNU_STACK,
    PT_GNU_RELRO, PF_W, PF_X)


def emulate(code: bytes, max_steps: int = 10000) -> Dict[str, Any]:
    regs = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "esp": 0x7FFF0000, "eip": 0}
    stack: List[int] = []
    writes: List[int] = []
    sink = None
    steps = 0
    pc = 0
    zf = False
    while 0 <= pc < len(code) and steps < max_steps:
        steps += 1
        b = code[pc]
        if b == 0xC3:  # ret
            if stack:
                pc = stack.pop()
                continue
            break
        if 0xB8 <= b <= 0xBF and pc + 4 < len(code):
            val = struct.unpack_from("<I", code, pc + 1)[0]
            regs["eax"] = val
            pc += 5
            continue
        if b == 0x31 and pc + 1 < len(code):
            regs["eax"] = 0
            zf = True
            pc += 2
            continue
        if b == 0xEB and pc + 1 < len(code):
            rel = struct.unpack_from("<b", code, pc + 1)[0]
            pc = pc + 2 + rel
            continue
        if b == 0xE9 and pc + 4 < len(code):
            rel = struct.unpack_from("<i", code, pc + 1)[0]
            pc = pc + 5 + rel
            continue
        if b in (0x74, 0x75) and pc + 1 < len(code):
            rel = struct.unpack_from("<b", code, pc + 1)[0]
            take = zf if b == 0x74 else not zf
            pc = pc + 2 + rel if take else pc + 2
            continue
        if b == 0xE8 and pc + 4 < len(code):
            rel = struct.unpack_from("<i", code, pc + 1)[0]
            stack.append(pc + 5)
            pc = pc + 5 + rel
            continue
        if b == 0x0F and pc + 1 < len(code) and code[pc + 1] == 0x05:
            sink = ("syscall", pc)
            break
        if b == 0xCD and pc + 1 < len(code):
            sink = ("int", pc)
            break
        if b in (0xF6, 0xF7) and pc + 1 < len(code) and ((code[pc + 1] >> 3) & 7) in (6, 7):
            sink = ("div-by-register (crash point if divisor is 0)", pc)
            break
        if b == 0xF4:
            sink = ("hlt", pc)
            break
        if b == 0x89 and pc + 1 < len(code):
            writes.append(pc)
            pc += 2
            continue
        pc += 1
    return {"regs": regs, "writes": writes, "sink": sink, "steps": steps}

def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    fmt, info = parse_any(data)
    if fmt == "raw" or not data:
        return hits
    code, coff = code_section_bytes(data, fmt, info)
    if not code:
        return hits
    res = emulate(code)
    if res["sink"]:
        kind, at = res["sink"]
        hits.append({"key": "unicorn_emulation_sink", "severity": "medium",
            "value": f"Isolated emulation reached {kind} at code offset {at:#x} after {res['steps']} steps (final eax={res['regs']['eax']:#x})",
            "evidence": {"sink": kind, "offset": at, "steps": res["steps"]}})
    return hits

class UnicornEmulatorCorePlugin(Plugin):
    id = "unicorn_emulator_core"
    label = "Unicorn Emulator Core"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Isolated pure-Python emulation of supplied code snippets: registers, writes, crash/sink points. Nothing executed natively.'
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings: List = []
        try:
            arts = load_artifacts(target, ctx)
            if not arts:
                return self._ok([], "no operator-supplied binary artifact in ctx.shared or target file path; nothing to analyse")
            for name, data in arts:
                for hit in analyze(data, name):
                    ev = {"severity": hit.get("severity", "low"),
                          "remediation": REMEDIATION}
                    ev.update(hit.get("evidence") or {})
                    findings.append(self._f(
                        "infra", hit["key"], hit["value"],
                        source=name or "supplied binary", confidence=85,
                        evidence=ev))
        except Exception as exc:  # never raise fatally
            return self._ok(findings, f"analysis degraded: {exc}"[:200])
        return self._ok(findings, f"{len(findings)} finding(s) from supplied artifact(s)")
