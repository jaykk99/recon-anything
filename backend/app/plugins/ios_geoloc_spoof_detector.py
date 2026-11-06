"""Geolocation spoofing-posture detector (Cat-7 #206, SHIP).

Input: operator-supplied APK/IPA. Statically detects location
consumption (CLLocationManager / FusedLocationProvider) and whether
any authenticity check accompanies it (isFromMockProvider, iOS
CLLocation sourceInformation). Verdict: accepts location with no
integrity check / check present / no location use. Keyless.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

LOCATION_APIS = ("CLLocationManager", "FusedLocationProvider",
                 "FusedLocationProviderClient", "getLastLocation",
                 "requestLocationUpdates", "LocationManager",
                 "onLocationChanged")
INTEGRITY_MARKERS = ("isFromMockProvider", "isMock", "mockLocation",
                     "sourceInformation", "isSimulatedBySoftware",
                     "CLLocationSourceInformation")


def analyze_geoloc(text: str) -> List[Dict]:
    if not text:
        return []
    used = sorted(a for a in LOCATION_APIS if a in text)
    if not used:
        return []
    checks = sorted(m for m in INTEGRITY_MARKERS if m in text)
    if checks:
        return []  # integrity check present: posture OK, silent
    return [finding(
        "geoloc_no_integrity_check",
        f"App consumes location via {', '.join(used[:4])} with NO "
        f"mock/spoof integrity check (no isFromMockProvider / "
        f"sourceInformation) - spoofed GPS is accepted at face value",
        "medium", source="DEX/Mach-O strings", confidence=80,
        location_apis=used[:8], integrity_checks=[])]


class IosGeolocSpoofDetectorPlugin(Cat7Plugin):
    id = "ios_geoloc_spoof_detector"
    label = "Geolocation Spoof Detector"
    description = ("Static scan of an operator-supplied APK/IPA for "
                   "location use without mock-location integrity "
                   "checks.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_geoloc(art.get("all_text") or "")
