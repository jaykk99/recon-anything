"""Android backup/debuggable flag check (Cat-7 #200, VARIANT).

binex's manifest parser never reads allowBackup or debuggable.
Delta: parse android:allowBackup, fullBackupContent /
dataExtractionRules presence, and android:debuggable from the
manifest of an operator-supplied APK.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, application_attrs, finding


def analyze_backup_flags(manifest: str, names: List[str]) -> List[Dict]:
    out: List[Dict] = []
    attrs = application_attrs(manifest or "")
    if str(attrs.get("android:debuggable", "")).lower() == "true":
        out.append(finding(
            "android_debuggable_true",
            "android:debuggable=true in the shipped manifest - "
            "anyone with USB access can attach a debugger and read "
            "app-private data",
            "high", source="AndroidManifest.xml", confidence=95))
    allow_backup = attrs.get("android:allowBackup")
    has_rules = bool(attrs.get("android:fullBackupContent") or
                     attrs.get("android:dataExtractionRules")) or \
        any("backup_rules" in n or "data_extraction_rules" in n
            for n in (names or []))
    if str(allow_backup).lower() == "true" and not has_rules:
        out.append(finding(
            "android_allow_backup_no_rules",
            "android:allowBackup=true with NO fullBackupContent / "
            "dataExtractionRules exclusions - app-private data is "
            "extractable via adb backup / device transfer",
            "medium", source="AndroidManifest.xml", confidence=88))
    return out


class AndroidBackupFlagCheckPlugin(Cat7Plugin):
    id = "android_backup_flag_check"
    label = "Android Backup Flag Check"
    description = ("Reads allowBackup/debuggable and backup-rule "
                   "presence from an operator-supplied APK manifest.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_backup_flags(
            art.get("manifest") or "",
            list((art.get("files") or {}).keys()))
