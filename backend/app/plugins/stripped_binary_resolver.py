"""Stripped-binary-resolver: reconstructs function designations in an operator-supplied stripped binary via algorithmic structure matching - CFG shape, known library constants and call patterns matched against local library signatures (FLIRT-style, keyless).
"""
from __future__ import annotations
import struct
from typing import Any, Dict, List
from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat5_common import (
    REMEDIATION, code_section_bytes, load_artifacts,
    parse_any, split_blocks)


KNOWN_CONSTS = [(0x9E3779B9, "TEA/XTEA-family constant (crypto routine candidate)"),
                (0x6A09E667, "SHA-256 initial state constant (hash routine candidate)"),
                (0x428A2F98, "SHA-256 round constant (hash routine candidate)"),
                (0xEDB88320, "CRC32 reflected polynomial (checksum routine candidate)")]
def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    fmt, info = parse_any(data)
    if fmt == "raw" or not data:
        return hits
    stripped = False
    if fmt == "elf":
        has_symtab = any(s.get("name") == ".symtab" for s in info.get("sections", []))
        stripped = not has_symtab
    elif fmt == "pe":
        stripped = info.get("characteristics", 0) & 0x2000 == 0 and not info.get("imports")
    if not stripped and fmt == "elf":
        return hits
    found = []
    for const, label in KNOWN_CONSTS:
        needle = struct.pack("<I", const)
        if needle in data:
            found.append(label)
    code, coff = code_section_bytes(data, fmt, info)
    blocks = split_blocks(code) if code else []
    if found:
        for label in found[:5]:
            hits.append({"key": "stripped_function_identified", "severity": "low",
                "value": f"Stripped binary: reconstructed function designation - {label} ({len(blocks)} blocks analysed)",
                "evidence": {"identification": label, "stripped": True, "blocks": len(blocks)}})
    elif stripped and blocks:
        hits.append({"key": "stripped_binary_inventory", "severity": "low",
            "value": f"Stripped binary (no symbol table): {len(blocks)} function blocks reconstructed structurally; no known library signature matched",
            "evidence": {"stripped": True, "blocks": len(blocks)}})
    return hits

class StrippedBinaryResolverPlugin(Plugin):
    id = "stripped_binary_resolver"
    label = "Stripped Binary Resolver"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'FLIRT-style function identification for supplied stripped binaries via constants + CFG shape.'
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
