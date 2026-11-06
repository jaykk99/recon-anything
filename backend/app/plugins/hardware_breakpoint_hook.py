"""Hardware-breakpoint-hook (STATIC detector): detects use of hardware-breakpoint / debug-register machinery in an operator-supplied binary - DR0-DR7 references, context-thread calls used to arm debug registers, and vectored exception handlers keyed to debug exceptions. No live hooking of any process is built.
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
    if not data:
        return hits
    strs = strings_only(data, 3)
    names = set(strs)
    fmt, info = parse_any(data)
    if fmt == "elf":
        names |= set(elf_imports(info))
    elif fmt == "pe":
        names |= set(pe_all_import_names(info))
    dr_refs = sorted(s for s in names if re.fullmatch(r"DR[0-7]", s or "") or "Dr0" in (s or "") or "CONTEXT_DEBUG_REGISTERS" in (s or ""))
    # string scan is noisy alone: require a context API alongside DR names, or explicit debug-register wording
    ctx_apis = [a for a in ("SetThreadContext", "GetThreadContext", "NtSetContextThread", "AddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler") if a in names]
    wording = [s for s in strs if "debug register" in s.lower() or "hardware breakpoint" in s.lower()]
    if wording:
        hits.append({"key": "hw_breakpoint_machinery_reference", "severity": "medium",
            "value": f"Hardware-breakpoint/debug-register machinery referenced: {wording[0][:80]!r} (static detection only)",
            "evidence": {"reference": wording[0][:120]}})
    if dr_refs and ctx_apis:
        hits.append({"key": "hw_breakpoint_dr_context_pattern", "severity": "high",
            "value": f"Debug-register names ({', '.join(dr_refs[:4])}) combined with thread-context API ({ctx_apis[0]}) - hardware-breakpoint arming pattern (static detection only)",
            "evidence": {"dr": dr_refs, "apis": ctx_apis}})
    elif "AddVectoredExceptionHandler" in ctx_apis:
        hits.append({"key": "hw_breakpoint_veh_debug_handler", "severity": "low",
            "value": "Vectored exception handler present (AddVectoredExceptionHandler) - debug-exception hooking surface (static detection only)",
            "evidence": {"api": "AddVectoredExceptionHandler"}})
    return hits[:8]

class HardwareBreakpointHookPlugin(Plugin):
    id = "hardware_breakpoint_hook"
    label = "Hardware Breakpoint Hook Detector"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Static detection of hardware-breakpoint/debug-register machinery in supplied binaries. No live hooking.'
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
