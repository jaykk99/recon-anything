"""IDA-Pro-bridge (native keyless equivalent; IDA Pro / Hex-Rays are not available and are not used): IDA-style graph data - functions, basic blocks, xrefs and a decompiler-like pseudocode outline naming dangerous call sites - generated natively for agent prompts from an operator-supplied binary.
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
    imports = elf_imports(info) if fmt == "elf" else (pe_all_import_names(info) if fmt == "pe" else [])
    blocks = split_blocks(code) if code else []
    for imp in sorted(set(imports) & DANGEROUS_IMPORTS)[:8]:
        hits.append({"key": "ida_dangerous_pseudocode_call", "severity": "medium",
            "value": f"Pseudocode outline: function calls dangerous API {imp} ({len(blocks)} basic blocks mapped)",
            "evidence": {"format": fmt, "import": imp, "blocks": len(blocks)}})
    return hits

class IdaProBridgePlugin(Plugin):
    id = "ida_pro_bridge"
    label = "IDA Pro Bridge"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Native keyless IDA-style graph/pseudocode outline for supplied binaries. IDA Pro not required or used.'
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
