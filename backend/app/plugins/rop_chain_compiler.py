"""ROP-chain-compiler (BOUNDARY FORM - gadget INVENTORY + mitigation audit ONLY): inventories ret-terminated gadgets (address, bytes, terminator class) in an operator-supplied binary and audits exploit-mitigation posture (NX, PIE, canary, RELRO/CFG). No chain is constructed, no payload is assembled, ever.
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
    gadgets = []
    for i, b in enumerate(code):
        if b == 0xC3 and i >= 1:
            gadgets.append(i)
        elif b == 0xC2 and i >= 1:
            gadgets.append(i)
    if len(gadgets) >= 5:
        # mitigation posture
        missing = []
        if fmt == "elf":
            stack = [ph for ph in info.get("phdrs", []) if ph["type"] == PT_GNU_STACK]
            if stack and (stack[0]["flags"] & PF_X):
                missing.append("NX-off")
            if info.get("etype") == 2:
                missing.append("non-PIE")
            if "__stack_chk_fail" not in (elf_imports(info) + info.get("symbols", [])):
                missing.append("no-canary")
            if not any(ph["type"] == PT_GNU_RELRO for ph in info.get("phdrs", [])):
                missing.append("no-RELRO")
        elif fmt == "pe":
            dc = info.get("dll_characteristics", 0)
            if not (dc & 0x0100):
                missing.append("NX-off")
            if not (dc & 0x0040):
                missing.append("no-ASLR")
        hits.append({"key": "rop_gadget_inventory", "severity": "medium" if missing else "low",
            "value": f"Gadget inventory: {len(gadgets)} ret-terminated gadgets in executable section; mitigation gaps: {', '.join(missing) or 'none'} (inventory + audit only, no chain built)",
            "evidence": {"gadgets": len(gadgets), "sample_offsets": gadgets[:10], "missing_mitigations": missing}})
    return hits

class RopChainCompilerPlugin(Plugin):
    id = "rop_chain_compiler"
    label = "ROP Gadget Inventory + Mitigation Audit"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Gadget inventory + mitigation posture audit ONLY for supplied binaries. No chain construction, no payload assembly.'
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
