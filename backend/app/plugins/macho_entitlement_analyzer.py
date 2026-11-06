"""Mach-O-entitlement-analyzer (VARIANT of binex, whose iOS lane is App Store metadata only): parses embedded entitlements / code-signature blobs from an operator-supplied Mach-O binary or IPA payload and flags dangerous entitlements.
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


DANGEROUS_ENT = ("get-task-allow", "com.apple.security.cs.allow-unsigned-executable-memory",
                 "com.apple.security.cs.allow-jit", "com.apple.security.cs.disable-library-validation",
                 "com.apple.security.get-task-allow", "allow-dyld-environment-variables")
def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    if detect_format(data) != "macho":
        # IPA is a zip: accept supplied bytes containing a Mach-O + plist
        if b"\xcf\xfa\xed\xfe" not in data and b"get-task-allow" not in data:
            return hits
    text = data.decode("utf-8", "ignore")
    for ent in DANGEROUS_ENT:
        if ent in text:
            # require the entitlement to be enabled (<true/>) nearby when plist-shaped
            idx = text.find(ent)
            window = text[idx:idx + 200]
            enabled = ("<true" in window) or ("get-task-allow" == ent)
            hits.append({"key": "macho_dangerous_entitlement", "severity": "high" if ent == "get-task-allow" else "medium",
                "value": f"Dangerous Mach-O entitlement present: {ent}" + (" (enabled)" if enabled else ""),
                "evidence": {"entitlement": ent, "enabled_hint": enabled}})
    info = parse_macho(data)
    for seg in info.get("segments", []):
        if (seg["initprot"] & 2) and (seg["initprot"] & 4):
            hits.append({"key": "macho_wx_segment", "severity": "medium",
                "value": f"Mach-O segment {seg['name']} is writable+executable (initprot={seg['initprot']})",
                "evidence": {"segment": seg["name"]}})
    return hits[:10]

class MachoEntitlementAnalyzerPlugin(Plugin):
    id = "macho_entitlement_analyzer"
    label = "Mach-O Entitlement Analyzer"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Mach-O entitlement + code-signature review for supplied macOS binaries/IPAs (variant of metadata-only binex iOS lane).'
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
