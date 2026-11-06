"""String-xref-mapper (VARIANT of binex strings extraction, which has no xref mapping): for each extracted string in an operator-supplied native binary, maps the code locations that reference it (absolute-VA pointer search over the executable section).
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
    xrefs = find_string_xrefs(data, code, coff, info, fmt)
    for x in xrefs[:10]:
        sev = "medium" if any(k in x["string"] for k in ("password", "/bin/sh", "token", "secret", "http")) else "low"
        hits.append({"key": "string_xref_entry", "severity": sev,
            "value": f"String {x['string'][:60]!r} (offset {x['string_off']:#x}) is referenced by code at file offset {x['code_off']:#x}",
            "evidence": {"string": x["string"][:120], "string_off": x["string_off"], "code_off": x["code_off"]}})
    return hits

class StringXrefMapperPlugin(Plugin):
    id = "string_xref_mapper"
    label = "String Xref Mapper"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'String-to-code cross-reference mapping for supplied native binaries (variant of binex strings).'
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
