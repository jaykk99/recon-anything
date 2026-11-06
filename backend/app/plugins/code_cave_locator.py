"""Code-cave-locator: finds unused execution gaps in an operator-supplied binary - slack space, oversized alignment padding and zero-filled section tails - sized and located, and flagged as injection-footprint indicators when a cave contains non-zero anomalous content.
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
    caves = []  # (where, size, anomalous_bytes)
    if fmt == "pe":
        for s in info.get("sections", []):
            if s["vsize"] and s["raw_size"] > s["vsize"] and (s["chars"] & 0x20000000):
                tail = data[s["raw_off"] + s["vsize"]:s["raw_off"] + s["raw_size"]]
                caves.append((f"section {s['name']} tail", len(tail), sum(1 for b in tail if b not in (0, 0xCC))))
    elif fmt == "elf":
        for s in info.get("sections", []):
            if (s.get("flags", 0) & 0x4) and s.get("size", 0) >= 64:
                blob = data[s["offset"]:s["offset"] + s["size"]]
                run = 0
                best = 0
                best_anom = 0
                cur_anom = 0
                for b in blob:
                    if b == 0:
                        run += 1
                    else:
                        if run >= 64:
                            best = max(best, run)
                            best_anom = cur_anom
                        run = 0
                        cur_anom = 0
                if run >= 64:
                    best = max(best, run)
    # generic zero-run scan for both formats (also catches padding caves)
    run = 0
    start = 0
    generic = []
    for i, b in enumerate(data):
        if b == 0:
            if run == 0:
                start = i
            run += 1
        else:
            if run >= 256:
                generic.append((start, run))
            run = 0
    if run >= 256:
        generic.append((start, run))
    for where, size, anom in caves:
        if size >= 128:
            hits.append({"key": "code_cave_found", "severity": "medium" if anom else "low",
                "value": f"Code cave: {size} unused bytes at {where}" + (f" containing {anom} non-zero anomalous bytes (injection footprint indicator)" if anom else ""),
                "evidence": {"size": size, "where": where, "anomalous": anom}})
    for off, size in generic[:3]:
        hits.append({"key": "code_cave_found", "severity": "low",
            "value": f"Code cave: {size} zero-filled bytes at file offset {off:#x} (alignment/slack space)",
            "evidence": {"size": size, "offset": off, "anomalous": 0}})
    return hits[:8]

class CodeCaveLocatorPlugin(Plugin):
    id = "code_cave_locator"
    label = "Code Cave Locator"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Unused execution-gap (code cave) location + sizing for supplied binaries, with injection-footprint flagging.'
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
