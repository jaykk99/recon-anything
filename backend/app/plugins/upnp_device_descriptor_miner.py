"""UPnP device descriptor miner: analyse an operator-supplied UPnP
device descriptor XML (or fetch it read-only from an operator-owned
LAN target after SSDP discovery) - parse device/service/action lists,
flag WAN-hostile actions (port mapping, admin/config services) and
descriptor fields leaking firmware/model/internal IPs. Read-only
discovery, keyless.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List
from xml.etree import ElementTree

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, host_of, load_artifacts

_WAN_SERVICES = ("wanipconnection", "wanpppconnection",
                 "wancablelinkconfig")
_ADMIN_HINTS = ("addportmapping", "deleteportmapping", "setconfig",
                "factoryreset", "reboot", "setadmin", "upgrade",
                "setpassword")


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = data.decode("utf-8", "ignore")
    if "<device" not in text.lower() and "upnp" not in text.lower():
        return hits
    services = re.findall(r"<serviceType>([^<]+)</serviceType>", text)
    actions = re.findall(r"<name>([A-Za-z][\w]{2,40})</name>", text)
    model = re.search(r"<modelName>([^<]+)</modelName>", text)
    fw = re.search(r"<modelDescription>([^<]*)</modelDescription>",
                   text)
    hits.append({
        "key": "upnp_descriptor_inventory", "severity": "low",
        "value": f"UPnP descriptor mined: "
                 f"{model.group(1) if model else 'unknown model'}, "
                 f"{len(services)} services, {len(actions)} actions "
                 "in supplied descriptors",
        "evidence": {"services": len(services),
                     "model": model.group(1)[:60] if model else ""}})
    for svc in services:
        if any(w in svc.lower() for w in _WAN_SERVICES):
            hits.append({
                "key": "upnp_wan_port_mapping", "severity": "high",
                "value": f"UPnP WAN service exposed in descriptor: "
                         f"{svc} - port-mapping control reachable "
                         "from the LAN (and historically beyond)",
                "evidence": {"service": svc[:80]}})
            break
    bad_actions = [a for a in actions
                   if any(h in a.lower() for h in _ADMIN_HINTS)]
    if bad_actions:
        hits.append({
            "key": "upnp_admin_actions", "severity": "medium",
            "value": "UPnP admin-class actions present in descriptor: "
                     + ", ".join(sorted(set(bad_actions))[:8]),
            "evidence": {"actions": sorted(set(bad_actions))[:8]}})
    ips = sorted(set(re.findall(
        r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\."
        r"\d{1,3}\.\d{1,3}\b", text)))
    if ips and fw:
        hits.append({
            "key": "upnp_info_leak", "severity": "low",
            "value": f"Descriptor leaks internal IPs {ips[:3]} and "
                     f"firmware detail '{fw.group(1)[:60]}'",
            "evidence": {"ips": ips[:3]}})
    if len(hits) == 1 and not bad_actions:
        return []  # bare inventory with nothing hostile = clean
    return hits[:10]


class UpnpDeviceDescriptorMinerPlugin(Plugin):
    id = "upnp_device_descriptor_miner"
    label = "UPnP Device Descriptor Miner"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Mines UPnP descriptors (supplied XML, or read-only "
                   "fetch from an operator-owned LAN target): WAN "
                   "port-mapping and admin actions flagged, firmware/"
                   "internal-IP leaks inventoried.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            if load_artifacts(target, ctx):
                return collect(self, target, ctx, analyze)
            host = host_of(target)
            if ctx.mode != "active":
                return self._ok(
                    [], "supply a UPnP descriptor artifact, or run "
                    "active against an operator-owned LAN target")
            # Read-only: try the common descriptor locations directly.
            from ..ratelimit import fetch
            findings: List = []
            for port, path in ((49152, "/rootDesc.xml"),
                               (1900, "/rootDesc.xml"),
                               (8080, "/upnp/IGD.xml"),
                               (80, "/rootDesc.xml")):
                try:
                    resp = await fetch(
                        ctx.http, ctx.limiter, "GET",
                        f"http://{host}:{port}{path}", timeout=5,
                        max_retries=0, follow_redirects=True)
                except Exception:
                    continue
                if resp is not None and resp.status_code == 200 \
                        and "<device" in resp.text.lower():
                    for hit in analyze(resp.text.encode(), host):
                        ev = {"severity": hit.get("severity", "low")}
                        ev.update(hit.get("evidence") or {})
                        findings.append(self._f(
                            "infra", hit["key"], hit["value"],
                            source=host, confidence=85, evidence=ev,
                            passive=False))
                    break
            return self._ok(findings,
                            "live UPnP descriptor fetch (owned target)")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
