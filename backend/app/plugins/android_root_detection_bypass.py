"""Android root-detection posture (Cat-7 #185, VARIANT of binex).

DETECTION ONLY - reports whether root checks exist in an operator-
supplied APK and whether they look weak or absent. No bypass code,
no circumvention of any kind.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

STRONG = ("com.scottyab.rootbeer", "RootBeer", "PlayIntegrity",
          "IntegrityManager", "SafetyNet", "attest")
WEAK_ONLY = ("/system/xbin/su", "/system/bin/su", "Superuser.apk",
             "which su", "\"su\"", "magisk", "Magisk", "test-keys")


def root_posture(text: str) -> str:
    if not text:
        return "unknown"
    if any(s in text for s in STRONG):
        return "strong"
    if any(w in text for w in WEAK_ONLY):
        return "weak"
    return "absent"


def analyze_root_posture(text: str) -> List[Dict]:
    posture = root_posture(text or "")
    if posture == "absent":
        return [finding(
            "root_detection_absent",
            "No root/jailbreak detection found (no RootBeer, Play "
            "Integrity, SafetyNet, or su-path checks) - the app runs "
            "on rooted devices without complaint",
            "medium", source="DEX/manifest strings", confidence=75,
            posture="absent")]
    if posture == "weak":
        hits = sorted(w for w in WEAK_ONLY if w in text)
        return [finding(
            "root_detection_weak",
            f"Root detection is weak string/path checks only: "
            f"{', '.join(hits[:5])} (no RootBeer / Play Integrity)",
            "medium", source="DEX strings", confidence=80,
            posture="weak-string-only", markers=hits[:8])]
    return []  # strong: silent


class AndroidRootDetectionBypassPlugin(Cat7Plugin):
    id = "android_root_detection_bypass"
    label = "Android Root Detection (posture only)"
    description = ("DETECTION ONLY: reports root-check posture "
                   "(strong / weak-string-only / absent) in an "
                   "operator-supplied APK. No bypass code.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_root_posture(art.get("all_text") or "")
