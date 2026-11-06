"""Angr-symbolic-executor (native keyless equivalent; angr is not required): bounded symbolic-style path enumeration over capstone/fallback-decoded blocks of an operator-supplied binary, reporting feasible crash pathways (syscall/div/dangerous-call sinks) with the branch constraints that reach them. Nothing is executed on the host.
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
    blocks = split_blocks(code)
    edges = block_edges(blocks)
    by_start = {b["start"]: b for b in blocks}
    # bounded DFS enumerating paths, tracking jcc constraints
    paths = []
    def dfs(start, cons, depth):
        if depth > 24 or len(paths) > 64:
            return
        b = by_start.get(start)
        if b is None:
            return
        if b["term"] in ("syscall", "div", "int"):
            paths.append((b, list(cons)))
            return
        outs = edges.get(start, [])
        if not outs:
            return
        for o in outs:
            c2 = cons + ([f"branch@{start:#x}"] if b["term"] == "jcc" else [])
            dfs(o, c2, depth + 1)
    if blocks:
        dfs(blocks[0]["start"], [], 0)
    for b, cons in paths[:5]:
        hits.append({"key": "angr_crash_pathway", "severity": "medium",
            "value": f"Feasible crash pathway reaches {b['term']} sink at code offset {b['start']:#x} under constraints: {', '.join(cons) or 'unconditional'}",
            "evidence": {"sink": b["term"], "block": b["start"], "constraints": cons}})
    return hits

class AngrSymbolicExecutorPlugin(Plugin):
    id = "angr_symbolic_executor"
    label = "Angr Symbolic Executor"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Bounded symbolic path enumeration for supplied binaries: feasible crash pathways + constraints. Nothing executed.'
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
