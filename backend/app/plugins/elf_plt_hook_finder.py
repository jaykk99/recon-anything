"""ELF-PLT-hook-finder: static PLT/GOT configuration audit of an operator-supplied ELF - writable GOT (no GNU_RELRO), missing BIND_NOW, and LD_PRELOAD-style hooking symbols in the import surface.
"""
from __future__ import annotations
from typing import Any, Dict, List
from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat5_common import (
    REMEDIATION, detect_format, elf_imports,
    elf_section, load_artifacts,
    parse_elf, strings_only, PT_GNU_RELRO)


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    if detect_format(data) != "elf":
        return hits
    info = parse_elf(data)
    if not info.get("ok"):
        return hits
    has_relro = any(ph["type"] == PT_GNU_RELRO for ph in info.get("phdrs", []))
    bind_now = 24 in info.get("dynamic", {}) or 30 in info.get("dynamic", {})  # DT_BIND_NOW / DT_FLAGS BIND_NOW approx via FLAGS presence refined below
    flags = info.get("dynamic", {}).get(30, 0)
    bind_now = bool(flags & 0x8) or 24 in info.get("dynamic", {})
    got = elf_section(info, ".got") or elf_section(info, ".got.plt")
    if got and not has_relro:
        hits.append({"key": "elf_writable_got", "severity": "medium",
            "value": "ELF has a GOT section but no GNU_RELRO segment - GOT is writable at runtime (PLT/GOT overwrite risk)",
            "evidence": {"relro": has_relro, "bind_now": bind_now}})
    if has_relro and not bind_now:
        hits.append({"key": "elf_partial_relro", "severity": "low",
            "value": "ELF has partial RELRO only (no BIND_NOW) - .got.plt stays writable under lazy binding",
            "evidence": {"relro": True, "bind_now": False}})
    imps = elf_imports(info) + info.get("symbols", [])
    for sym in imps:
        if sym in ("__libc_dlopen_mode", "dlopen", "dlsym") or "LD_PRELOAD" in sym:
            hits.append({"key": "elf_preload_hook_surface", "severity": "low",
                "value": f"Dynamic-loading / preload hook surface in import table: {sym}",
                "evidence": {"symbol": sym}})
            break
    strs = strings_only(data, 4)
    if any("LD_PRELOAD" in s for s in strs):
        hits.append({"key": "elf_ld_preload_reference", "severity": "medium",
            "value": "Binary references LD_PRELOAD - preloading hook indicator",
            "evidence": {}})
    return hits[:10]

class ElfPltHookFinderPlugin(Plugin):
    id = "elf_plt_hook_finder"
    label = "ELF PLT Hook Finder"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'ELF PLT/GOT static configuration audit: writable GOT, RELRO/BIND_NOW posture, preload hook surface.'
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
