"""Obfuscation-entropy-calc: per-section/per-region entropy and structural distribution metrics over an operator-supplied native binary, grading packing/obfuscation boundaries against known packer profiles (e.g. UPX-style section layouts). Distinct from the binwalk carver: this grades obfuscation in the binary itself.
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


PACKER_SECTIONS = ("UPX0", "UPX1", "UPX2", ".aspack", ".adata", "MEW", ".petite", ".nsp0", ".nsp1", "Themida", ".vmp0", ".vmp1")
def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    fmt, info = parse_any(data)
    if fmt == "raw" or not data:
        return hits
    sections = []
    if fmt == "elf":
        sections = [(s["name"], data[s["offset"]:s["offset"] + s["size"]]) for s in info.get("sections", [])]
    elif fmt == "pe":
        sections = [(s["name"], data[s["raw_off"]:s["raw_off"] + s["raw_size"]]) for s in info.get("sections", [])]
    for sname, blob in sections:
        if sname in PACKER_SECTIONS:
            hits.append({"key": "obfuscation_packer_section", "severity": "medium",
                "value": f"Known packer section name present: {sname}",
                "evidence": {"section": sname}})
        if blob and len(blob) >= 256:
            ent = shannon_entropy(blob)
            if ent >= 7.2:
                hits.append({"key": "obfuscation_high_entropy_section", "severity": "medium",
                    "value": f"Section {sname or '(unnamed)'} entropy {ent:.2f} - packed/obfuscated content boundary",
                    "evidence": {"section": sname, "entropy": round(ent, 3), "size": len(blob)}})
    return hits[:10]

class ObfuscationEntropyCalcPlugin(Plugin):
    id = "obfuscation_entropy_calc"
    label = "Obfuscation Entropy Calc"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Per-section entropy grading + packer-profile matching for supplied native binaries.'
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
