"""Hypervisor management interface detector.

Detects exposed VMware vSphere/ESXi, Proxmox VE, and Hyper-V management
interfaces. Flags version disclosure and default credential risk.
Read-only. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

HYPERVISOR_PATHS = [
    ("/ui/", "VMware vSphere Client"),
    ("/vsphere-client/", "vSphere Web Client (legacy)"),
    ("/sdk/vimServiceVersions.xml", "VMware SDK endpoint (version disclosure)"),
    ("/pve/", "Proxmox VE web interface"),
    ("/api2/json/version", "Proxmox API version endpoint"),
]

HYPERVISOR_SIGS = [
    (r"vmware|vsphere|esxi", "VMware hypervisor"),
    (r"proxmox", "Proxmox VE"),
    (r"hyper-v|hyperv", "Microsoft Hyper-V"),
    (r"xenserver|xcp-ng|citrix", "XenServer/XCP-ng"),
    (r"nutanix|ahv", "Nutanix AHV"),
]

REMEDIATION = ("Never expose hypervisor management to the internet. Use VPN "
               "or jump hosts, enforce MFA, and patch promptly.")


class HypervisorPlugin(Plugin):
    id = "hypervisor"
    label = "Hypervisor Scout"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = "Detect exposed hypervisor management interfaces."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or target.normalized
        base = f"https://{host}".rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        # signature scan on main page
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=20,
                            follow_redirects=True)
            text = (r.text[:50000] + " " + str(r.headers)).lower()
            page_url = str(r.url)
            for pat, label in HYPERVISOR_SIGS:
                if re.search(pat, text):
                    findings.append(self._f(
                        "infra", "hypervisor_detected",
                        f"Hypervisor detected: {label}. Management interfaces "
                        f"must not be internet-facing.",
                        source="Hypervisor fingerprint", source_url=page_url,
                        confidence=70, passive=passive,
                        evidence={"severity": "high",
                                  "remediation": REMEDIATION,
                                  "scope_note": "Detection only. Authorized testing only."}))
                    break
        except Exception:
            pass
        # path probes
        for path, label in HYPERVISOR_PATHS:
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12,
                                follow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    body = r.text[:1500].lower()
                    if any(k in body for k in ("vmware", "proxmox", "vsphere",
                                               "pve", "esxi")) or r.status_code == 401:
                        findings.append(self._f(
                            "infra", "hypervisor_exposed",
                            f"Exposed hypervisor interface: {label} at {url} "
                            f"(HTTP {r.status_code}).",
                            source="Hypervisor probe", source_url=url,
                            confidence=75, passive=passive,
                            evidence={"severity": "critical", "path": path,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Read-only probe. Authorized testing only."}))
            except Exception:
                continue
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} hypervisor findings")
        res.duration_ms = dur
        return res
