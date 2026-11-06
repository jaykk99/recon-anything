"""Mobile device-ID collection inventory (Cat-7 #210, VARIANT).

DETECTS collection routines in an operator-supplied package - it
does NOT harvest identifiers from any device. DEX/Mach-O string scan
for telephony IDs, ANDROID_ID, advertising IDs, MAC/serial APIs;
reports which persistent identifiers the app collects and whether
telephony collection happens without a permission gate.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

ID_APIS = {
    "getDeviceId": "IMEI (getDeviceId)",
    "getImei": "IMEI (getImei)",
    "getSubscriberId": "IMSI (getSubscriberId)",
    "getSimSerialNumber": "SIM serial",
    "getLine1Number": "phone number",
    "ANDROID_ID": "ANDROID_ID",
    "android_id": "ANDROID_ID",
    "AdvertisingIdClient": "Google Advertising ID",
    "getAdvertisingId": "advertising ID",
    "advertisingIdentifier": "Apple IDFA",
    "identifierForVendor": "Apple IDFV",
    "getMacAddress": "Wi-Fi MAC address",
    "getSerial": "device serial",
    "Build.SERIAL": "device serial",
}
TELEPHONY = {"getDeviceId", "getImei", "getSubscriberId",
             "getSimSerialNumber", "getLine1Number"}


def analyze_device_ids(text: str, manifest: str) -> List[Dict]:
    if not text:
        return []
    found = {}
    for api, label in ID_APIS.items():
        if api in text:
            found[api] = label
    if not found:
        return []
    labels = sorted(set(found.values()))
    has_perm = "READ_PHONE_STATE" in (manifest or "") or \
        "READ_PHONE_STATE" in text
    telephony = sorted(a for a in found if a in TELEPHONY)
    sev = "medium"
    note = ""
    if telephony and not has_perm:
        sev = "high"
        note = (" Telephony identifiers are collected WITHOUT the "
                "READ_PHONE_STATE permission declared.")
    return [finding(
        "device_id_collection_inventory",
        f"App collects {len(labels)} persistent device identifiers: "
        f"{', '.join(labels[:8])}.{note}",
        sev, source="DEX/Mach-O strings", confidence=83,
        identifiers=labels, telephony_ungated=bool(telephony
                                                   and not has_perm))]


class MobileDeviceIdHarvesterPlugin(Cat7Plugin):
    id = "mobile_device_id_harvester"
    label = "Mobile Device ID Harvester (detection)"
    description = ("Detects device-ID collection routines (IMEI, "
                   "ANDROID_ID, IDFA/IDFV, MAC, serial) inside an "
                   "operator-supplied package. Harvests nothing.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_device_ids(art.get("all_text") or "",
                                  art.get("manifest") or "")
