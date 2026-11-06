"""Android intent surface audit (Cat-7 #194, VARIANT of binex).

STATIC analysis only - no broadcasts are ever sent. Parses intent-
filters (actions, data schemes/hosts/paths, categories) per exported
component and classifies malformed-intent risk: unvalidated extras
surface, exported receivers for system-like actions, deep-link +
exported overlap.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding, intent_filters, \
    manifest_components

SYSTEM_ACTIONS = ("android.intent.action.BOOT_COMPLETED",
                  "android.intent.action.PACKAGE_ADDED",
                  "android.provider.Telephony.SMS_RECEIVED",
                  "android.intent.action.TIME_SET")


def analyze_intents(manifest: str) -> List[Dict]:
    out: List[Dict] = []
    for comp in manifest_components(manifest or ""):
        attrs = comp["attrs"]
        name = attrs.get("android:name", "?")
        exported = str(attrs.get("android:exported", "")).lower() == "true"
        filters = intent_filters(comp["segment"])
        if not exported or not filters:
            continue
        has_permission = bool(attrs.get("android:permission"))
        for f in filters:
            actions = [a for a in f["actions"]]
            sys_hits = [a for a in actions if a in SYSTEM_ACTIONS]
            if comp["tag"] == "receiver" and sys_hits and not has_permission:
                out.append(finding(
                    "intent_exported_system_receiver",
                    f"Exported receiver {name} handles system action "
                    f"{sys_hits[0]} with no permission gate - any app "
                    f"can spoof the broadcast",
                    "high", source="AndroidManifest.xml", confidence=85,
                    component=name, actions=sys_hits))
            if f["browsable"] and f["schemes"]:
                out.append(finding(
                    "intent_deeplink_exported_overlap",
                    f"Exported {comp['tag']} {name} is BROWSABLE for "
                    f"schemes {', '.join(f['schemes'][:4])} - deep-link "
                    f"extras reach it unvalidated",
                    "medium", source="AndroidManifest.xml",
                    confidence=82, component=name,
                    schemes=f["schemes"][:8]))
            if f["actions"] and not has_permission and \
                    comp["tag"] in ("activity", "service"):
                out.append(finding(
                    "intent_exported_no_permission",
                    f"Exported {comp['tag']} {name} has intent-filters "
                    f"and no android:permission - arbitrary intent "
                    f"extras accepted from any app",
                    "medium", source="AndroidManifest.xml",
                    confidence=78, component=name,
                    actions=f["actions"][:6]))
                break
    return out[:30]


class AndroidIntentFuzzerPlugin(Cat7Plugin):
    id = "android_intent_fuzzer"
    label = "Android Intent Fuzzer (static)"
    description = ("Static intent-surface audit of an operator-"
                   "supplied APK manifest: exported components, "
                   "intent-filters, spoofable receivers. No broadcasts "
                   "are sent.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_intents(art.get("manifest") or "")
