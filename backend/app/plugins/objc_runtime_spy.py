"""Objective-C runtime surface audit (Cat-7 #188, SHIP).

STATIC equivalent of a runtime spy: extracts the ObjC class/method
string inventory from an operator-supplied IPA/Mach-O and flags the
instrumentation-sensitive surface (method swizzling helpers, sensitive
selectors, dynamic loaders). No live runtime logging or tracing.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

SWIZZLE_MARKERS = ("method_exchangeImplementations", "class_replaceMethod",
                   "method_setImplementation", "class_addMethod",
                   "objc_msgSend", "imp_implementationWithBlock")
SENSITIVE_SELECTORS = ("canEvaluatePolicy", "evaluatePolicy",
                       "authenticateWithLocalAuth", "loadRequest",
                       "setAllowsAnyHTTPSCertificate", "allowsAnyHTTPS",
                       "jailbreak", "isJailbroken")
CLASS_RE = re.compile(r"^[A-Z][A-Za-z0-9_]{2,60}$")


def analyze_objc_strings(strings: List[str]) -> List[Dict]:
    out: List[Dict] = []
    pool = set(strings or [])
    text = "\n".join(strings or [])
    swizzle = sorted(m for m in SWIZZLE_MARKERS if m in text)
    if swizzle:
        out.append(finding(
            "objc_swizzling_surface",
            f"Method-swizzling / runtime-manipulation helpers present: "
            f"{', '.join(swizzle[:6])}",
            "medium", source="Mach-O strings", confidence=80,
            helpers=swizzle[:10]))
    sensitive = sorted(s for s in SENSITIVE_SELECTORS if s in text)
    if sensitive:
        out.append(finding(
            "objc_sensitive_selectors",
            f"Instrumentation-sensitive selectors present: "
            f"{', '.join(sensitive[:6])}",
            "medium", source="Mach-O strings", confidence=80,
            selectors=sensitive[:10]))
    classes = sorted(c for c in pool if CLASS_RE.match(c or ""))
    if classes:
        out.append(finding(
            "objc_class_inventory",
            f"{len(classes)} ObjC-style class names visible in strings "
            f"(sample: {', '.join(classes[:5])})",
            "low", source="Mach-O strings", confidence=70,
            sample=classes[:20]))
    return out


class ObjcRuntimeSpyPlugin(Cat7Plugin):
    id = "objc_runtime_spy"
    label = "Objective-C Runtime Spy (static)"
    description = ("Static ObjC class/selector inventory of an "
                   "operator-supplied IPA/Mach-O; flags swizzling "
                   "helpers and sensitive selectors. No live tracing.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_objc_strings(art.get("strings") or [])
