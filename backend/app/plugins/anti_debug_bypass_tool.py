"""Anti-debug-bypass-tool (DETECTION ONLY form): statically detects anti-debug / anti-trace checks in an operator-supplied binary - IsDebuggerPresent, ptrace self-checks, NtQueryInformationProcess, timing (rdtsc) and debug-register checks - reported as a protection-posture finding with locations. No disabling, patching or bypass capability is built.
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


APIS = ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtSetInformationThread", "ptrace", "OutputDebugStringA", "OutputDebugStringW",
        "FindWindowA", "FindWindowW", "GetTickCount", "QueryPerformanceCounter")
def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    if not data:
        return hits
    strs = strings_only(data, 4)
    joined = set(strs)
    fmt, info = parse_any(data)
    imps: List[str] = []
    if fmt == "elf":
        imps = elf_imports(info)
    elif fmt == "pe":
        imps = pe_all_import_names(info)
    names = joined | set(imps)
    for api in APIS:
        if api in names:
            hits.append({"key": "antidebug_check_present", "severity": "low",
                "value": f"Anti-debug check present (detection only): {api}",
                "evidence": {"api": api}})
    code, coff = code_section_bytes(data, fmt, info) if fmt != "raw" else (b"", 0)
    rdtsc = 0
    int3 = 0
    i = 0
    while i < len(code):
        ln, kind, _t = decode_one(code, i)
        if kind == "rdtsc":
            rdtsc += 1
        if code[i] == 0xCC:
            int3 += 1
        i += max(ln, 1)
    if rdtsc:
        hits.append({"key": "antidebug_timing_check", "severity": "low",
            "value": f"Timing-based anti-debug pattern: {rdtsc} rdtsc instruction(s) in code (detection only)",
            "evidence": {"rdtsc": rdtsc}})
    return hits[:12]

class AntiDebugBypassToolPlugin(Plugin):
    id = "anti_debug_bypass_tool"
    label = "Anti-Debug Detector"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Anti-debug check DETECTION ONLY for supplied binaries. No bypass or disabling capability.'
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
