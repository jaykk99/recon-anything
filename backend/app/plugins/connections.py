"""Connection mapper (phase 2).

Maps everything connected to everything: target -> subdomains -> IPs ->
services -> accounts -> financial. Consumes the discovery bus populated
by phase-1 plugins and produces relationship findings.

This is OSINT-style relationship mapping from scan data.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Set
from urllib.parse import urlparse

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class ConnectionsPlugin(Plugin):
    id = "connections"
    label = "Connection Mapper"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    description = "Map every relationship: devices, accounts, services, financial."
    phase = 2  # runs after phase-1 populates the discovery bus

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings: List[Finding] = []
        target_label = target.normalized

        # Gather everything from the discovery bus
        subdomains = ctx.consume("subdomains")
        endpoints = ctx.consume("endpoints")
        js_files = ctx.consume("js_files")
        techs = ctx.consume("tech")
        emails = ctx.consume("emails")
        ips = ctx.consume("ips")
        processors = ctx.consume("financial_processors")

        # Also pull from shared as raw strings (some plugins publish dicts)
        def strs(items):
            return [i for i in items if isinstance(i, str)]

        subdomains = strs(subdomains)
        endpoints = strs(endpoints)
        emails = strs(emails)
        ips = strs(ips)
        processors = strs(processors)
        techs = strs(techs)

        # -- devices: IPs and subdomains are "devices" in the map ------------
        devices: Set[str] = set()
        for ip in ips:
            devices.add(f"ip:{ip}")
            findings.append(self._f(
                "graph", "connected_device", ip,
                f"connections: IP {ip} linked to target",
                confidence=85,
                evidence={"type": "device", "relation": "resolves_to"}))
        for sub in subdomains:
            devices.add(f"subdomain:{sub}")
            findings.append(self._f(
                "graph", "connected_device", sub,
                f"connections: subdomain {sub} linked to target",
                confidence=85,
                evidence={"type": "device", "relation": "subdomain_of"}))

        # -- services: tech stack + endpoints are "services" -------------------
        services: Set[str] = set()
        for t in techs:
            services.add(f"tech:{t}")
            findings.append(self._f(
                "graph", "connected_service", t,
                f"connections: {t} runs on target",
                confidence=80,
                evidence={"type": "service", "relation": "powered_by"}))
        # Group endpoints by path prefix as services
        ep_groups: Dict[str, int] = {}
        for ep in endpoints:
            try:
                path = urlparse(ep).path if "://" in ep else ep
                parts = [p for p in path.split("/") if p]
                if parts:
                    prefix = "/" + parts[0]
                    ep_groups[prefix] = ep_groups.get(prefix, 0) + 1
            except Exception:
                continue
        for prefix, count in sorted(ep_groups.items(), key=lambda x: -x[1])[:20]:
            services.add(f"api:{prefix}")
            findings.append(self._f(
                "graph", "connected_service", f"{prefix} ({count} endpoints)",
                f"connections: API group {prefix} with {count} endpoints",
                confidence=75,
                evidence={"type": "service", "relation": "exposes"}))

        # -- accounts: emails found -------------------------------------------
        for email in emails[:30]:
            findings.append(self._f(
                "graph", "connected_account", email,
                f"connections: email {email} associated with target",
                confidence=70,
                evidence={"type": "account", "relation": "associated_with"}))

        # -- financial connections ----------------------------------------------
        for proc in processors:
            findings.append(self._f(
                "graph", "connected_financial", proc,
                f"connections: {proc} processes payments for target",
                confidence=90,
                evidence={"type": "financial", "relation": "payment_processor"}))

        # -- relationship summary -------------------------------------------------
        total = len(devices) + len(services) + len(emails) + len(processors)
        findings.append(self._f(
            "graph", "connection_summary",
            f"{len(devices)} devices, {len(services)} services, "
            f"{len(emails)} accounts, {len(processors)} financial links",
            "connections: full relationship map built",
            confidence=95,
            evidence={"severity": "info",
                      "why": "Everything connected to the target, mapped"}))

        return self._ok(findings, f"mapped {total} connections")
