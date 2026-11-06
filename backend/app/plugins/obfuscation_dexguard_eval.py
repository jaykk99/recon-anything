"""Obfuscation / DexGuard evaluation (Cat-7 #193, VARIANT of binex).

Metrics pass over the same APK binex reads: identifier-length /
mangling ratio, class-name readability, string-encryption
indicators, DexGuard/R8 marker strings. Scores the unobfuscated
attack surface (readable sensitive class/method names).
"""
from __future__ import annotations

import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

CLASS_RE = re.compile(r"L([a-zA-Z][a-zA-Z0-9_/]*);")
SENSITIVE_NAME = re.compile(
    r"(login|password|auth|token|crypto|secret|payment|billing|"
    r"session|account|admin)", re.I)
MARKERS = ("DexGuard", "dexguard", "R8", "ProGuard", "proguard")


def obfuscation_metrics(dex_text: str) -> Dict:
    classes = CLASS_RE.findall(dex_text or "")
    total = len(classes)
    mangled = 0
    readable_sensitive: List[str] = []
    for c in classes:
        segs = [s for s in c.split("/") if s]
        if segs and all(len(s) <= 2 for s in segs[-1:]):
            mangled += 1
        if SENSITIVE_NAME.search(c):
            last = segs[-1] if segs else c
            if len(last) > 3:
                readable_sensitive.append(c.replace("/", "."))
    return {"total": total, "mangled": mangled,
            "ratio": (mangled / total) if total else 0.0,
            "readable_sensitive": sorted(set(readable_sensitive))}


def analyze_obfuscation(art: Dict) -> List[Dict]:
    dex = art.get("dex_text") or ""
    text = dex + "\n" + (art.get("all_text") or "")
    m = obfuscation_metrics(dex)
    out: List[Dict] = []
    markers = sorted(x for x in MARKERS if x in text)
    if m["readable_sensitive"]:
        out.append(finding(
            "obfuscation_readable_sensitive_names",
            f"{len(m['readable_sensitive'])} sensitive class names are "
            f"READABLE (unobfuscated attack surface): "
            f"{', '.join(m['readable_sensitive'][:5])}",
            "medium", source="DEX class strings", confidence=82,
            classes=m["readable_sensitive"][:15],
            mangled_ratio=round(m["ratio"], 3), markers=markers))
    elif m["total"] >= 10 and m["ratio"] < 0.3 and not markers:
        out.append(finding(
            "obfuscation_absent",
            f"DEX classes are essentially unobfuscated "
            f"(mangled ratio {m['ratio']:.0%}, no DexGuard/R8/ProGuard "
            f"markers) - reverse engineering is trivial",
            "medium", source="DEX class strings", confidence=75,
            mangled_ratio=round(m["ratio"], 3)))
    return out


class ObfuscationDexguardEvalPlugin(Cat7Plugin):
    id = "obfuscation_dexguard_eval"
    label = "Obfuscation / DexGuard Evaluation"
    description = ("Obfuscation-metrics pass over an operator-"
                   "supplied APK: mangling ratio, readable sensitive "
                   "names, DexGuard/R8 markers.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_obfuscation(art)
