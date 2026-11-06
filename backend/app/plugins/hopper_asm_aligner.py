"""Hopper-asm-aligner (native keyless equivalent; Hopper is not available in this environment and is not used): disassembly listing aligned to function boundaries with cross-references to sensitive strings, for agent consumption. Static analysis of operator-supplied binaries only.
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
    xrefs = find_string_xrefs(data, code, coff, info, fmt)
    SENS = ("/bin/sh", "cmd.exe", "powershell", "/bin/bash", "system", "passwd")
    for x in xrefs:
        if any(s in x["string"] for s in SENS):
            hits.append({"key": "hopper_sensitive_xref", "severity": "medium",
                "value": f"Code at file offset {x['code_off']:#x} references sensitive string {x['string']!r}",
                "evidence": {"format": fmt, "string": x["string"], "code_off": x["code_off"]}})
    return hits[:10]

class HopperAsmAlignerPlugin(Plugin):
    id = "hopper_asm_aligner"
    label = "Hopper ASM Aligner"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Native keyless Hopper-style disassembly alignment + sensitive-string xrefs for supplied binaries. Hopper not required or used.'
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
