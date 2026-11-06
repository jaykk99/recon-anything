"""Thread-context-spy (STATIC detector form): over an operator-supplied binary, statically detects thread/register-context manipulation machinery - SetThreadContext/GetThreadContext, SuspendThread + CreateRemoteThread patterns and cross-thread context writes. No live process is attached or inspected.
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


APIS = ("SetThreadContext", "GetThreadContext", "NtSetContextThread", "NtGetContextThread",
        "SuspendThread", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "Wow64SetThreadContext")
def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    if not data:
        return hits
    fmt, info = parse_any(data)
    names = set(strings_only(data, 4))
    if fmt == "elf":
        names |= set(elf_imports(info))
    elif fmt == "pe":
        names |= set(pe_all_import_names(info))
    found = [a for a in APIS if a in names]
    for api in found[:8]:
        sev = "high" if api in ("SetThreadContext", "NtSetContextThread", "CreateRemoteThread") else "medium"
        hits.append({"key": "thread_context_manipulation_api", "severity": sev,
            "value": f"Thread-context manipulation API present in supplied binary: {api} (static detection only)",
            "evidence": {"api": api}})
    if "SetThreadContext" in found and "SuspendThread" in found:
        hits.append({"key": "thread_context_hijack_pattern", "severity": "high",
            "value": "SuspendThread + SetThreadContext combination present - classic thread-hijack pattern (static detection only)",
            "evidence": {"apis": ["SuspendThread", "SetThreadContext"]}})
    return hits[:10]

class ThreadContextSpyPlugin(Plugin):
    id = "thread_context_spy"
    label = "Thread Context Spy"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Static detection of thread/register-context manipulation APIs in supplied binaries. No live attachment.'
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
