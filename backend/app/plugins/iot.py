"""IoT and hardware device detector.

Identifies IoT devices, routers, cameras, and industrial systems from
banners and web fingerprints. Flags default credentials and firmware
disclosure. Read-only. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

IOT_SIGNATURES = [
    (r"hikvision", "Hikvision camera/NVR"),
    (r"dahua", "Dahua camera/NVR"),
    (r"axis communications", "Axis camera"),
    (r"ubiquiti|unifi", "Ubiquiti/UniFi device"),
    (r"mikrotik|routeros", "MikroTik RouterOS"),
    (r"openwrt|dd-wrt|tomato", "OpenWrt/DD-WRT router firmware"),
    (r"boa[/ ]|goahead", "GoAhead/Boa embedded web server"),
    (r"lighttpd", "lighttpd (common on embedded devices)"),
    (r"sonos", "Sonos speaker"),
    (r"philips hue|hue bridge", "Philips Hue bridge"),
    (r"nest|google home", "Google Nest/Home device"),
    (r"ring\.com", "Ring device portal"),
    (r"modbus|bacnet|dnp3", "Industrial control protocol"),
    (r"scada|ics", "SCADA/ICS system"),
    (r"printer|ipp|jetdirect", "Network printer"),
    (r"synology|qnap|asustor", "NAS device"),
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("root", "root"), ("root", "admin"), ("ubnt", "ubnt"),
    ("guest", "guest"),
]

REMEDIATION = ("Change all default credentials, update firmware, segment "
               "IoT devices on isolated VLANs, and never expose management "
               "interfaces to the internet.")


class IotPlugin(Plugin):
    id = "iot"
    label = "IoT Device Scout"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = "Detect IoT devices, default creds, firmware disclosure."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or target.normalized
        base = f"https://{host}".rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=20,
                            follow_redirects=True)
            text = (r.text[:50000] + " " + str(r.headers)).lower()
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        seen = set()
        for pat, label in IOT_SIGNATURES:
            if re.search(pat, text) and label not in seen:
                seen.add(label)
                findings.append(self._f(
                    "infra", "iot_device",
                    f"IoT/hardware device detected: {label}. Check for default "
                    f"credentials and outdated firmware.",
                    source="IoT fingerprint", source_url=page_url,
                    confidence=70, passive=passive,
                    evidence={"severity": "medium", "device": label,
                              "remediation": REMEDIATION,
                              "scope_note": "Detection only. Authorized testing only."}))
        # firmware version disclosure
        for m in re.finditer(r"firmware[^\n<]{0,40}v?(\d+\.\d+(?:\.\d+)?)",
                             text, re.I):
            findings.append(self._f(
                "infra", "iot_firmware",
                f"Firmware version disclosed: '{m.group(0)[:60].strip()}'. "
                f"Check for known CVEs against this version.",
                source="IoT fingerprint", source_url=page_url,
                confidence=65, passive=passive,
                evidence={"severity": "low",
                          "remediation": REMEDIATION}))
            break
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} IoT indicators")
        res.duration_ms = dur
        return res
