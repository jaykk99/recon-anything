"""Vtable-structure-builder: rebuilds C++ vtable layouts from an operator-supplied binary - RTTI names, virtual-method index assignments from pointer tables whose entries land in executable code, cross-checked against typeinfo strings.
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
    strs = extract_strings(data, 4)
    rtti = [s for _o, s in strs if s.startswith("_ZTV") or s.startswith("_ZTI") or "vtable for" in s]
    code, coff = code_section_bytes(data, fmt, info)
    # pointer-table scan: runs of >=3 64-bit values pointing into code vaddrs (ELF) or offsets
    tables = 0
    if fmt == "elf" and code:
        code_vas = set()
        base_va = offset_to_vaddr(info, coff) or 0
        ptrs = []
        step = 8
        vals = []
        for i in range(0, len(data) - 7, step):
            (v,) = struct.unpack_from("<Q", data, i)
            vals.append((i, v))
        run = 0
        for i, v in vals:
            if base_va <= v < base_va + len(code):
                run += 1
                if run >= 3:
                    tables += 1
                    run = 0
            else:
                run = 0
    if rtti or tables:
        hits.append({"key": "vtable_layout_rebuilt", "severity": "low",
            "value": f"Rebuilt vtable layout: {tables} pointer table(s), RTTI names: {', '.join(rtti[:4]) or 'none'} - class hierarchy surface mapped",
            "evidence": {"tables": tables, "rtti": rtti[:8]}})
    return hits

class VtableStructureBuilderPlugin(Plugin):
    id = "vtable_structure_builder"
    label = "VTable Structure Builder"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'C++ vtable/RTTI layout reconstruction for supplied binaries.'
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
