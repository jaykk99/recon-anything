"""Frida instrumentation-surface audit (Cat-7 #183, VARIANT of binex).

STATIC equivalent only - no live injection, no hooks into any app.
Audits an operator-supplied APK for the instrumentation surface:
Frida gadget/config presence, hook-framework libraries, debuggable
flag, and ptrace/anti-tamper call sites.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, application_attrs, finding

HOOK_LIBS = ("frida", "substrate", "xposed", "gadget", "objection",
             "libhook", "sandhook", "whale")
ANTI_TAMPER = ("ptrace", "TracerPid", "isDebuggerConnected",
               "waitingForDebugger")


def analyze_frida_surface(art: Dict) -> List[Dict]:
    out: List[Dict] = []
    names = list((art.get("files") or {}).keys())
    hook = sorted({n for n in names
                   if any(h in n.lower() for h in HOOK_LIBS)})
    gadget_cfg = [n for n in names if "gadget" in n.lower()
                  and n.endswith((".config", ".json"))]
    if hook:
        out.append(finding(
            "frida_hook_framework_present",
            f"Hook/instrumentation framework artifacts inside the APK: "
            f"{', '.join(hook[:6])}",
            "high", source="APK contents", confidence=88,
            artifacts=hook[:12]))
    if gadget_cfg:
        out.append(finding(
            "frida_gadget_config",
            f"Frida Gadget configuration shipped in the APK: "
            f"{', '.join(gadget_cfg[:4])}",
            "high", source="APK contents", confidence=90,
            artifacts=gadget_cfg[:8]))
    text = art.get("all_text") or ""
    for marker, key, label in (
            ("frida-server", "frida_server_strings",
             "frida-server strings present in code"),
            ("REJECT", "frida_reject_strings", "")):
        if marker in text and key == "frida_server_strings":
            out.append(finding(
                key, f"Instrumentation surface: {label}", "medium",
                source="DEX strings", confidence=75))
    attrs = application_attrs(art.get("manifest") or "")
    if str(attrs.get("android:debuggable", "")).lower() == "true":
        out.append(finding(
            "frida_debuggable_build",
            "android:debuggable=true - the app is trivially "
            "instrumentable at runtime",
            "high", source="AndroidManifest.xml", confidence=92))
    tamper = sorted(m for m in ANTI_TAMPER if m in text)
    if tamper and not hook:
        out.append(finding(
            "frida_anti_tamper_weak",
            f"Anti-tamper hooks rely on string-visible checks only: "
            f"{', '.join(tamper[:4])}",
            "low", source="DEX strings", confidence=65,
            markers=tamper[:6]))
    return out


class FridaRuntimeScriptInjectorPlugin(Cat7Plugin):
    id = "frida_runtime_script_injector"
    label = "Frida Runtime Script Injector (static audit)"
    description = ("Static instrumentation-surface audit of an "
                   "operator-supplied APK: Frida gadget/config, hook "
                   "libraries, debuggable posture. No live injection.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_frida_surface(art)
