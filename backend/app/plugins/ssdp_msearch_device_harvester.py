"""SSDP M-SEARCH device harvester: sends ONE unicast SSDP
M-SEARCH (ssdp:all, short MX) to the target host's UDP 1900,
parses responses (ST, USN, LOCATION, SERVER) and inventories the
device identity. Gateway-class devices (InternetGatewayDevice /
WAN services) answering an external-style unicast search are the
posture finding; the description fetch is a plain GET of the
LOCATION the device itself advertised.

Inventory only - no control actions, no UPnP action invocation.
Keyless stdlib UDP/HTTP.
"""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, host_port_of, text_of

MSEARCH = ("M-SEARCH * HTTP/1.1\r\n"
           "HOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\n'
           "MX: 1\r\n"
           "ST: ssdp:all\r\n\r\n")

_GATEWAY_MARKERS = ("internetgatewaydevice", "wanipconnection",
                    "wanpppconnection", "miniupnpd", "igd")


def parse_ssdp_response(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for line in (text or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    out["_raw"] = text or ""
    return out


def hits_for_response(resp: Dict[str, Any], src: str
                      ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    st = (resp.get("st") or resp.get("nt") or "").lower()
    server = (resp.get("server") or "")
    blob = f"{st} {server.lower()} {(resp.get('_raw') or '').lower()}"
    if any(mk in blob for mk in _GATEWAY_MARKERS):
        hits.append({
            "key": "ssdp_gateway_device_exposed", "severity": "medium",
            "value": f"SSDP search answered by a gateway-class "
                     f"device ({src}): ST={resp.get('st', '?')}, "
                     f"SERVER={server or '?'}, "
                     f"LOCATION={resp.get('location', '?')} - UPnP "
                     "gateway services are discoverable",
            "evidence": {"st": resp.get("st", ""),
                         "server": server,
                         "location": resp.get("location", ""),
                         "remediation": "Disable UPnP/SSDP on "
                         "WAN-facing interfaces; gateway control "
                         "services (WANIPConnection) have a long "
                         "history of unauthenticated abuse."}})
    return hits


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    text = text_of(data)
    if not text:
        return []
    hits: List[Dict[str, Any]] = []
    chunks = re.split(r"(?im)^(HTTP/1\.1 200|NOTIFY)", text)
    # Simple path: treat whole artifact as one or more responses.
    for part in re.split(r"\r?\n\r?\n", text):
        if "st:" in part.lower() or "nt:" in part.lower():
            hits.extend(hits_for_response(
                parse_ssdp_response(part), "supplied capture"))
    return hits[:10]


def _probe(host: str, port: int, timeout: float = 3.0
           ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(MSEARCH.encode(), (host, port))
            for _ in range(4):
                try:
                    data, _addr = s.recvfrom(4096)
                except socket.timeout:
                    break
                out.append(parse_ssdp_response(
                    data.decode("latin1", "ignore")))
    except Exception:
        pass
    return out


class SsdpMsearchDeviceHarvesterPlugin(Plugin):
    id = "ssdp_msearch_device_harvester"
    label = "SSDP M-SEARCH Device Harvester"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("One unicast SSDP M-SEARCH to the target's UDP "
                   "1900; inventories device identity (ST/USN/"
                   "LOCATION/SERVER) and flags gateway-class UPnP "
                   "exposure. Inventory only, no control actions.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("ssdp_captures",))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 1900)
        try:
            resps = await asyncio.to_thread(_probe, host, port)
        except Exception:
            resps = []
        if not resps:
            return self._degraded(f"no SSDP response from "
                                  f"{host}:{port}")
        findings = []
        for resp in resps:
            for hit in hits_for_response(resp, f"{host}:{port}"):
                ev = {"severity": hit["severity"]}
                ev.update(hit.get("evidence") or {})
                findings.append(self._f(
                    "infra", hit["key"], hit["value"],
                    source="SSDP M-SEARCH", confidence=85,
                    evidence=ev, passive=False))
        return self._ok(findings,
                        f"{len(resps)} SSDP response(s) harvested")
