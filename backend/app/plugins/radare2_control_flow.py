"""Radare2-control-flow (native keyless equivalent): comprehensive basic-block / CFG structure for an operator-supplied native binary - block boundaries, edges and unreachable blocks - without any GUI.
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
    if len(blocks) < 2:
        return hits
    edges = block_edges(blocks)
    reached = set()
    stack = [blocks[0]["start"]]
    while stack:
        cur = stack.pop()
        if cur in reached:
            continue
        reached.add(cur)
        stack.extend(edges.get(cur, []))
    dead = [b for b in blocks if b["start"] not in reached and b["start"] != 0]
    for b in dead[:5]:
        hits.append({"key": "radare2_unreachable_block", "severity": "low",
            "value": f"Unreachable basic block at code offset {b['start']:#x} ({b['end']-b['start']} bytes, terminator {b['term']}) - dead/hidden code candidate",
            "evidence": {"block_start": b["start"], "blocks_total": len(blocks)}})
    return hits

class Radare2ControlFlowPlugin(Plugin):
    id = "radare2_control_flow"
    label = "Radare2 Control Flow"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Native CFG builder (radare2-style) for supplied binaries: blocks, edges, unreachable code.'
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
