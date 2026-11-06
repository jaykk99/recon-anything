"""IPA entitlement audit (Cat-7 #187, SHIP).

Input: operator-supplied IPA. Unzips in memory, extracts the plist
embedded in embedded.mobileprovision (and any loose .plist
entitlements), and flags debug / dev-distribution entitlements and
wildcard app IDs. Pure plistlib parsing, keyless, offline.
"""
from __future__ import annotations

import plistlib
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding


def parse_mobileprovision(blob: bytes) -> Dict:
    """Pull the plist XML out of a (CMS-wrapped) .mobileprovision."""
    if not blob:
        return {}
    try:
        return plistlib.loads(blob) or {}
    except Exception:
        pass
    start = blob.find(b"<?xml")
    end = blob.rfind(b"</plist>")
    if start >= 0 and end > start:
        try:
            return plistlib.loads(blob[start:end + 8]) or {}
        except Exception:
            return {}
    return {}


def analyze_entitlements(prov: Dict) -> List[Dict]:
    out: List[Dict] = []
    if not isinstance(prov, dict):
        return out
    ent = prov.get("Entitlements") or {}
    if not isinstance(ent, dict):
        return out
    if ent.get("get-task-allow") is True:
        out.append(finding(
            "ipa_get_task_allow",
            "Provisioning profile allows get-task-allow (debugger "
            "attach) - development/debug distribution entitlement",
            "high", source="embedded.mobileprovision", confidence=90))
    aps = str(ent.get("aps-environment", ""))
    if aps == "development":
        out.append(finding(
            "ipa_aps_development",
            "aps-environment=development in a distributed IPA",
            "medium", source="embedded.mobileprovision", confidence=85))
    app_id = str(ent.get("application-identifier", ""))
    if app_id.endswith(".*") or app_id == "*" or ".*" in app_id:
        out.append(finding(
            "ipa_wildcard_app_id",
            f"Wildcard application-identifier entitlement: {app_id}",
            "medium", source="embedded.mobileprovision", confidence=85))
    groups = ent.get("keychain-access-groups") or []
    if any(isinstance(g, str) and g.endswith(".*") for g in groups):
        out.append(finding(
            "ipa_keychain_wildcard_group",
            "Wildcard keychain-access-group entitlement present",
            "medium", source="embedded.mobileprovision", confidence=80))
    if prov.get("ProvisionsAllDevices"):
        out.append(finding(
            "ipa_all_devices",
            "Profile provisions ALL devices (enterprise/dev profile "
            "shipping in the IPA)", "medium",
            source="embedded.mobileprovision", confidence=80))
    return out


def analyze_ipa(art: Dict) -> List[Dict]:
    out: List[Dict] = []
    for name, blob in (art.get("files") or {}).items():
        if name.endswith(".mobileprovision"):
            out.extend(analyze_entitlements(parse_mobileprovision(blob)))
    if art.get("kind") == "file" and art.get("data"):
        out.extend(analyze_entitlements(parse_mobileprovision(art["data"])))
    return out


class IpaEntitlementPlisterPlugin(Cat7Plugin):
    id = "ipa_entitlement_plister"
    label = "IPA Entitlement Plister"
    description = ("Parses embedded.mobileprovision entitlements in an "
                   "operator-supplied IPA; flags debug/dev entitlements "
                   "and wildcard app IDs.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_ipa(art)
