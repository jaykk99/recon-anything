"""Capstone-disasm-engine (VARIANT of EVM-only bytecode_deep_analysis): the same disassembly job for native ISAs - variable-length x86/x64 opcodes from an operator-supplied binary translated into listings, flagging privileged/dangerous instructions (syscall, int 0x80, hlt) in executable sections. Capstone is used when importable, with a pure-Python decoder fallback.
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


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    fmt, info = parse_any(data)
    if fmt == "raw" or not data:
        return hits
    code, coff = code_section_bytes(data, fmt, info)
    if not code:
        return hits
    listing = try_capstone_disasm(code, coff)
    kinds = []
    if listing is not None:
        for ins in listing:
            if ins["mnemonic"] in ("syscall", "sysenter"):
                kinds.append(("syscall", ins["address"]))
            elif ins["mnemonic"] == "int" and "0x80" in ins["op_str"]:
                kinds.append(("int80", ins["address"]))
            elif ins["mnemonic"] == "hlt":
                kinds.append(("hlt", ins["address"]))
    else:
        i = 0
        while i < len(code):
            ln, kind, _t = decode_one(code, i)
            if kind in ("syscall", "int", "hlt"):
                kinds.append((kind, coff + i))
            i += max(ln, 1)
    for kind, addr in kinds[:8]:
        hits.append({"key": "capstone_privileged_instruction", "severity": "low",
            "value": f"Disassembly: privileged/dangerous instruction {kind} at file offset {addr:#x}",
            "evidence": {"instruction": kind, "offset": addr, "engine": "capstone" if listing is not None else "pure-python-fallback"}})
    return hits

class CapstoneDisasmEnginePlugin(Plugin):
    id = "capstone_disasm_engine"
    label = "Capstone Disasm Engine"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Native-ISA disassembly of supplied binaries (variant of EVM bytecode_deep_analysis): privileged instruction audit.'
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
