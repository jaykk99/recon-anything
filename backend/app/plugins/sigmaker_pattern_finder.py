"""Sigmaker-pattern-finder: generates resilient byte-signature patterns (wildcarding relocatable bytes - rel32 call/jump displacements and absolute pointers) for a target function in an operator-supplied binary, so the feature can be tracked across product versions.
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


def make_signature(code: bytes, start: int = 0, length: int = 32) -> str:
    out = []
    i = start
    end = min(len(code), start + length)
    while i < end:
        b = code[i]
        if b in (0xE8, 0xE9) and i + 4 < end:  # rel32 call/jmp: wildcard displacement
            out.append(f"{b:02X}")
            out.extend(["??"] * 4)
            i += 5
            continue
        if b == 0xEB and i + 1 < end:
            out.append(f"{b:02X}")
            out.append("??")
            i += 2
            continue
        if b == 0x48 and i + 9 < end and code[i + 1] in (0xB8, 0xBB, 0xB9, 0xBA):
            out.append("48")
            out.append(f"{code[i+1]:02X}")
            out.extend(["??"] * 8)
            i += 10
            continue
        out.append(f"{b:02X}")
        i += 1
    return " ".join(out)

def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    fmt, info = parse_any(data)
    if fmt == "raw" or not data:
        return hits
    code, coff = code_section_bytes(data, fmt, info)
    if len(code) < 16:
        return hits
    has_reloc = any(code[i] in (0xE8, 0xE9) for i in range(len(code) - 5)) or b"\x48\xb8" in code
    if has_reloc:
        sig = make_signature(code, 0, 32)
        hits.append({"key": "sigmaker_resilient_pattern", "severity": "low",
            "value": f"Resilient byte signature for function at code offset 0: {sig}",
            "evidence": {"signature": sig, "wildcards": sig.count("??")}})
    return hits

class SigmakerPatternFinderPlugin(Plugin):
    id = "sigmaker_pattern_finder"
    label = "Sigmaker Pattern Finder"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Resilient wildcarded byte-signature generation for functions in supplied binaries.'
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
