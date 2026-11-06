"""DEX bytecode pattern matcher (Cat-7 #184, VARIANT of binex).

binex inventories DEX files but never identifies SDKs. Delta: a
signature database of known tracker/analytics SDK class-path
prefixes matched against DEX class strings, reported as a per-APK
tracker inventory.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

TRACKER_SDKS = {
    "com.google.android.gms.analytics": "Google Analytics",
    "com.google.firebase.analytics": "Firebase Analytics",
    "com.facebook.ads": "Meta Audience Network",
    "com.facebook.appevents": "Meta App Events",
    "com.appsflyer": "AppsFlyer",
    "com.amplitude": "Amplitude",
    "com.mixpanel": "Mixpanel",
    "com.flurry": "Flurry",
    "com.adjust": "Adjust",
    "io.branch": "Branch",
    "com.segment.analytics": "Segment",
    "com.kochava": "Kochava",
    "com.singular": "Singular",
    "com.localytics": "Localytics",
    "io.sentry": "Sentry (crash reporting)",
    "com.google.android.gms.ads": "AdMob",
    "com.applovin": "AppLovin",
    "com.unity3d.ads": "Unity Ads",
}
CLASS_RE = re.compile(r"L([a-z][a-z0-9_/]*)/")


def analyze_dex_trackers(dex_text: str) -> List[Dict]:
    if not dex_text:
        return []
    paths = set()
    for m in CLASS_RE.finditer(dex_text):
        paths.add(m.group(1).replace("/", "."))
    hits = {}
    for prefix, label in TRACKER_SDKS.items():
        if any(p == prefix or p.startswith(prefix + ".") for p in paths) \
                or prefix.replace(".", "/") in dex_text:
            hits[prefix] = label
    if not hits:
        return []
    labels = sorted(hits.values())
    return [finding(
        "dex_tracker_inventory",
        f"{len(labels)} tracker/analytics SDKs in DEX: "
        f"{', '.join(labels[:8])}",
        "medium", source="DEX class strings", confidence=85,
        trackers=labels, prefixes=sorted(hits))]


class DexBytecodePatternMatcherPlugin(Cat7Plugin):
    id = "dex_bytecode_pattern_matcher"
    label = "DEX Bytecode Pattern Matcher"
    description = ("Matches DEX class strings against a tracker/"
                   "analytics SDK signature database; per-APK tracker "
                   "inventory (variant of binex).")

    def analyze(self, art: Dict) -> List[Dict]:
        text = art.get("dex_text") or ""
        if not text and art.get("strings"):
            text = "\n".join(art["strings"])
        return analyze_dex_trackers(text)
