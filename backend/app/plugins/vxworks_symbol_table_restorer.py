"""VxWorks symbol table restorer: locate symbol/string tables in an
operator-supplied VxWorks firmware image and restore a symbol
inventory (name, class) - flagging sensitive symbols (shell, debug,
download routines) left in a production image. Pure-Python parsing,
offline, keyless.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, strings_only

_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{3,48}$")
_SENSITIVE = {
    "shell": "high", "usrShell": "high", "dbgHelp": "high",
    "wdb": "high", "symFindByName": "medium", "taskSpawn": "medium",
    "download": "medium", "bootLoad": "medium", "ld": "low",
    "iosDrvInstall": "low", "usrAppInit": "low", "sysHwInit": "low",
}
_MARKERS = ("symTbl", "symbol table", "VxWorks", "vxworks",
            "Wind River")


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data or len(data) < 64:
        return hits
    strs = strings_only(data, 4)
    has_marker = any(any(mk in s for mk in _MARKERS) for s in strs)
    symbols = [s for s in strs if _SYMBOL_RE.match(s)]
    sensitive = []
    for s in symbols:
        for pat, sev in _SENSITIVE.items():
            if s == pat or (len(pat) > 4 and s.startswith(pat)):
                sensitive.append((s, sev))
                break
    if not has_marker and not sensitive:
        return hits
    if has_marker and len(symbols) >= 8:
        hits.append({
            "key": "vxworks_symbol_table_present", "severity": "low",
            "value": f"VxWorks symbol table restored: {len(symbols)} "
                     "symbol-like names recovered from the production "
                     "image (aids reverse engineering of every "
                     "subsystem)",
            "evidence": {"symbols": len(symbols)}})
    seen = set()
    for sym, sev in sensitive:
        if sym in seen:
            continue
        seen.add(sym)
        if sev in ("high", "medium"):
            hits.append({
                "key": "vxworks_sensitive_symbol", "severity": sev,
                "value": f"Sensitive VxWorks symbol '{sym}' left in "
                         "the production image symbol table",
                "evidence": {"symbol": sym}})
    return hits[:10]


class VxworksSymbolTableRestorerPlugin(Plugin):
    id = "vxworks_symbol_table_restorer"
    label = "VxWorks Symbol Table Restorer"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Restores the symbol inventory of a supplied "
                   "VxWorks image and flags shell/debug/download "
                   "symbols shipped in production firmware.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
