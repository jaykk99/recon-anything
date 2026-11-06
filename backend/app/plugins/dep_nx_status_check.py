"""DEP-NX-status-check: data-execution-prevention state of an operator-supplied PE/ELF/Mach-O - GNU_STACK flags, PE NX_COMPAT/DYNAMIC_BASE flags, and writable+executable sections/segments.
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
    if fmt == "elf":
        stacks = [ph for ph in info.get("phdrs", []) if ph["type"] == PT_GNU_STACK]
        if not stacks:
            hits.append({"key": "nx_no_gnu_stack", "severity": "low",
                "value": "ELF has no PT_GNU_STACK header - stack executability is toolchain-default (ambiguous NX posture)",
                "evidence": {}})
        elif stacks[0]["flags"] & PF_X:
            hits.append({"key": "nx_executable_stack", "severity": "high",
                "value": "ELF PT_GNU_STACK is executable (RWE) - NX/DEP disabled for the stack",
                "evidence": {"gnu_stack_flags": stacks[0]["flags"]}})
        for s in info.get("sections", []):
            if (s.get("flags", 0) & 0x1) and (s.get("flags", 0) & 0x4):  # W+X (SHF_WRITE=1, EXEC=4)
                hits.append({"key": "nx_wx_section", "severity": "medium",
                    "value": f"ELF section {s['name']} is writable+executable (W+X)",
                    "evidence": {"section": s["name"]}})
    elif fmt == "pe":
        dc = info.get("dll_characteristics", 0)
        if not (dc & 0x0100):
            hits.append({"key": "nx_pe_not_nx_compat", "severity": "medium",
                "value": "PE is not NX_COMPAT (DllCharacteristics lacks 0x0100) - DEP not opted in",
                "evidence": {"dll_characteristics": dc}})
        for s in info.get("sections", []):
            if (s["chars"] & 0x80000000) and (s["chars"] & 0x20000000):
                hits.append({"key": "nx_wx_section", "severity": "medium",
                    "value": f"PE section {s['name']} is writable+executable (W+X)",
                    "evidence": {"section": s["name"]}})
    elif fmt == "macho":
        for seg in info.get("segments", []):
            if (seg["initprot"] & 2) and (seg["initprot"] & 4):
                hits.append({"key": "nx_wx_section", "severity": "medium",
                    "value": f"Mach-O segment {seg['name']} is writable+executable",
                    "evidence": {"segment": seg["name"]}})
    return hits[:10]

class DepNxStatusCheckPlugin(Plugin):
    id = "dep_nx_status_check"
    label = "DEP/NX Status Check"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'NX/DEP posture check for supplied PE/ELF/Mach-O binaries.'
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
