"""Swift name demangler (Cat-7 #189, SHIP).

Finds $s/$S mangled Swift symbols in an operator-supplied IPA/Mach-O
(or string dump) and demangles them with a pure-python SUBSET
demangler (length-prefixed identifiers + common type codes), grouping
the readable inventory by module. Falls back to a bundled
swift-demangle binary when present. Keyless.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Dict, List, Optional

from ._cat7_common import Cat7Plugin, finding

TYPE_CODES = {"Si": "Int", "SS": "String", "Sb": "Bool", "Sf": "Float",
              "Sd": "Double", "Su": "UInt", "SQ": "Optional",
              "Sg": "Optional", "Sp": "UnsafePointer"}
MANGLED_RE = re.compile(r"\$[sS][A-Za-z0-9_$]{4,120}")


def demangle_swift(sym: str) -> Optional[str]:
    """Subset demangler: length-prefixed identifiers + suffix codes."""
    if not sym or not sym.startswith(("$s", "$S")):
        return None
    body = sym[2:]
    parts: List[str] = []
    i = 0
    while i < len(body):
        if body[i].isdigit():
            j = i
            while j < len(body) and body[j].isdigit():
                j += 1
            try:
                n = int(body[i:j])
            except ValueError:
                break
            ident = body[j:j + n]
            if len(ident) < n:
                break
            parts.append(ident)
            i = j + n
        else:
            break
    if not parts:
        return None
    rest = body[i:]
    readable = ".".join(parts)
    for code, name in TYPE_CODES.items():
        rest = rest.replace(code, f" {name}")
    if "F" in rest or sym.endswith("F"):
        readable += "()"
    return readable


def find_swift_symbols(strings: List[str]) -> List[str]:
    out = set()
    for s in strings or []:
        for m in MANGLED_RE.finditer(s or ""):
            out.add(m.group(0))
    return sorted(out)


def analyze_swift(strings: List[str]) -> List[Dict]:
    syms = find_swift_symbols(strings)
    if not syms:
        return []
    demangled = []
    # Optional external fallback for symbols the subset parser misses.
    use_ext = shutil.which("swift-demangle") is not None
    for sym in syms[:200]:
        readable = demangle_swift(sym)
        if readable is None and use_ext:
            try:
                r = subprocess.run(["swift-demangle", sym],
                                   capture_output=True, text=True,
                                   timeout=5)
                readable = (r.stdout or "").strip() or None
            except Exception:
                readable = None
        if readable:
            demangled.append(readable)
    if not demangled:
        return []
    modules = sorted({d.split(".")[0] for d in demangled})
    return [finding(
        "swift_demangled_inventory",
        f"{len(demangled)} Swift symbols demangled across modules: "
        f"{', '.join(modules[:5])}",
        "low", source="Mach-O strings", confidence=75,
        symbols=demangled[:25], modules=modules[:10])]


class SwiftNameDemanglerPlugin(Cat7Plugin):
    id = "swift_name_demangler"
    label = "Swift Name Demangler"
    description = ("Demangles $s/$S Swift symbols found in an "
                   "operator-supplied IPA/Mach-O with a pure-python "
                   "subset demangler; readable function inventory "
                   "grouped by module.")

    def analyze(self, art: Dict) -> List[Dict]:
        pool = list(art.get("strings") or [])
        for t in (art.get("texts") or {}).values():
            pool.extend(t.split())
        return analyze_swift(pool)
