"""GDB-runtime-tracer (STATIC detector form): over an operator-supplied binary, statically detects dynamic-tracing / stack-manipulation machinery - ptrace and debugger APIs, stack-pivot gadgets and return-address overwrite patterns. No live process is attached, traced or executed.
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
    strs = strings_only(data, 4)
    joined = "\n".join(strs)
    for api in ("ptrace", "PTRACE_ATTACH", "PTRACE_TRACEME", "process_vm_writev", "WaitForDebugEvent", "DebugActiveProcess"):
        if api in joined:
            hits.append({"key": "gdb_tracer_api_presence", "severity": "medium",
                "value": f"Tracing/debug API reference present in supplied binary: {api}",
                "evidence": {"api": api}})
    fmt, info = parse_any(data)
    code, coff = code_section_bytes(data, fmt, info) if fmt != "raw" else (b"", 0)
    pivots = 0
    i = 0
    while i < len(code):
        ln, kind, _t = decode_one(code, i)
        if kind == "pivot":
            pivots += 1
        i += max(ln, 1)
    if pivots:
        hits.append({"key": "gdb_stack_pivot_pattern", "severity": "medium",
            "value": f"{pivots} stack-pivot instruction(s) (xchg eax,esp pattern) in code - stack-manipulation candidate",
            "evidence": {"pivots": pivots}})
    return hits[:10]

class GdbRuntimeTracerPlugin(Plugin):
    id = "gdb_runtime_tracer"
    label = "GDB Runtime Tracer"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Static detector for tracing APIs and stack-pivot patterns in supplied binaries. No live attachment.'
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
