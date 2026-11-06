"""Memory-dump-analyzer (VARIANT of signature-only da_crash_dump/da_heap_dump): content analysis of an operator-supplied dump - plaintext remnants (URLs, commands, config strings) extracted, with any secret-shaped material reported MASKED + fingerprinted only. Operator-supplied artifacts only; full secrets never appear in findings.
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


SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*(\S{4,})"), "password assignment"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{10,}"), "bearer token"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GitHub token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
]
def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    if not data:
        return hits
    strs = extract_strings(data, 5)
    text = "\n".join(s for _o, s in strs)
    urls = sorted(set(re.findall(r"https?://[A-Za-z0-9.\-]+(?:/[^\s\"'<>]*)?", text)))[:10]
    if urls:
        hits.append({"key": "dump_plaintext_urls", "severity": "low",
            "value": f"Dump contains {len(urls)} plaintext URL remnant(s): {', '.join(urls[:3])}",
            "evidence": {"urls": urls}})
    for pat, label in SECRET_PATTERNS:
        for m in pat.finditer(text):
            secret = m.group(1) if m.groups() else m.group(0)
            masked, fp = mask_secret(secret)
            hits.append({"key": "dump_secret_remnant_masked", "severity": "high",
                "value": f"Dump contains a {label} remnant (masked {masked}, sha256:{fp}) - full value withheld",
                "evidence": {"kind": label, "masked": masked, "fingerprint": fp}})
            break
    cmds = [s for _o, s in strs if any(c in s for c in ("cmd.exe /c", "/bin/sh -c", "powershell -", "curl ", "wget "))]
    if cmds:
        hits.append({"key": "dump_command_remnant", "severity": "medium",
            "value": f"Dump contains command-line remnant(s): {cmds[0][:80]!r}",
            "evidence": {"commands": [c[:120] for c in cmds[:5]]}})
    return hits[:12]

class MemoryDumpAnalyzerPlugin(Plugin):
    id = "memory_dump_analyzer"
    label = "Memory Dump Analyzer"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Content analysis of supplied dumps: URL/command remnants, secret-shaped material masked + fingerprinted only.'
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
