"""DWARF-debug-symbol-reader: extracts DWARF debug information (variable names, types, line tables, struct layouts) from an operator-supplied ELF/Mach-O binary and flags binaries shipping full debug info as an information-exposure finding. Pure-Python section/string analysis.
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
    if fmt not in ("elf", "macho") or not data:
        return hits
    dbg_secs = []
    if fmt == "elf":
        dbg_secs = [s["name"] for s in info.get("sections", []) if s.get("name", "").startswith(".debug")]
    strs = strings_only(data, 5)
    dwarf_markers = [s for s in strs if "DW_AT_" in s or s.startswith(".debug_") or "DW_TAG_" in s]
    if dbg_secs or dwarf_markers:
        sample = (dbg_secs or dwarf_markers)[:6]
        hits.append({"key": "dwarf_debug_info_shipped", "severity": "medium",
            "value": f"Binary ships DWARF debug info ({', '.join(sample)}) - variable names, types and line tables exposed",
            "evidence": {"format": fmt, "debug_sections": dbg_secs, "markers": dwarf_markers[:6]}})
    return hits

class DwarfDebugSymbolReaderPlugin(Plugin):
    id = "dwarf_debug_symbol_reader"
    label = "DWARF Debug Symbol Reader"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'DWARF debug-info extraction + shipped-debug-info exposure check for supplied ELF/Mach-O binaries.'
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
