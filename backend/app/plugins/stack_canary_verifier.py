"""Stack-canary-verifier: grades stack-canary presence/coverage in an operator-supplied binary - __stack_chk_fail/__security_cookie references versus buffer-risk imports that need them.
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
    imps: List[str] = []
    if fmt == "elf":
        imps = elf_imports(info) + info.get("symbols", [])
    elif fmt == "pe":
        imps = pe_all_import_names(info)
    strs = strings_only(data, 4)
    allnames = set(imps) | set(strs)
    has_canary = any(c in allnames for c in ("__stack_chk_fail", "__stack_chk_guard", "__security_cookie", "__security_check_cookie"))
    risky = sorted(set(imps) & BUFFER_IMPORTS)
    if risky and not has_canary:
        hits.append({"key": "canary_missing_with_buffer_funcs", "severity": "high",
            "value": f"Buffer-risk functions present ({', '.join(risky[:6])}) but NO stack canary (__stack_chk_fail/__security_cookie absent) - uninstrumented stack buffers",
            "evidence": {"risky_imports": risky, "canary": False}})
    elif risky and has_canary:
        pass  # covered: silent by design (coverage present)
    return hits

class StackCanaryVerifierPlugin(Plugin):
    id = "stack_canary_verifier"
    label = "Stack Canary Verifier"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Stack-canary presence/coverage verification for supplied binaries.'
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
