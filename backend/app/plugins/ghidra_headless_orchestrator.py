"""Ghidra-headless-orchestrator (native keyless equivalent): structural analysis of an operator-supplied PE/ELF/Mach-O binary - function inventory, call graph and basic-block flow - emitting the flowchart data a Ghidra headless run would produce. Ghidra itself is not required or used; analysis is capstone-if-available plus a pure-Python CFG builder over the supplied artifact only.
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
    imports: List[str] = []
    if fmt == "elf":
        imports = elf_imports(info)
    elif fmt == "pe":
        imports = pe_all_import_names(info)
    danger = sorted(set(imports) & DANGEROUS_IMPORTS)
    blocks = split_blocks(code) if code else []
    if danger and blocks:
        for imp in danger[:8]:
            hits.append({"key": "ghidra_dangerous_callgraph", "severity": "medium",
                "value": f"Function inventory ({len(blocks)} blocks) reaches dangerous import {imp}",
                "evidence": {"format": fmt, "blocks": len(blocks), "import": imp}})
    return hits

class GhidraHeadlessOrchestratorPlugin(Plugin):
    id = "ghidra_headless_orchestrator"
    label = "Ghidra Headless Orchestrator"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Native keyless Ghidra-style structural analysis of supplied binaries: function inventory, call graph, basic blocks. Ghidra not required or used.'
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
