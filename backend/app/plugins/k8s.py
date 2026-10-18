"""Kubernetes misconfiguration detector.

Checks for exposed Kubernetes dashboards, API servers, and etcd.
Read-only probes only. Authorized testing only.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

K8S_PATHS = [
    ("/api/v1/namespaces", "Kubernetes API server (unauthenticated access?)"),
    ("/api/", "Kubernetes API root"),
    ("/version", "Kubernetes version endpoint"),
    ("/metrics", "Kubernetes metrics (may leak internal data)"),
]

K8S_PORTS = [6443, 10250, 10255, 2379, 2380, 8443]

REMEDIATION = ("Never expose the Kubernetes API or dashboard to the internet. "
               "Use RBAC, network policies, and private clusters.")


class K8sPlugin(Plugin):
    id = "k8s"
    label = "Kubernetes Misconfig"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = "Detect exposed Kubernetes API and dashboard."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or target.normalized
        base = f"https://{host}".rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        for path, label in K8S_PATHS:
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15,
                                follow_redirects=False)
                body = r.text[:2000].lower()
                if r.status_code in (200, 401, 403) and (
                        "kubernetes" in body or "kind" in body or "apiVersion" in body):
                    findings.append(self._f(
                        "infra", "k8s_exposed",
                        f"Exposed Kubernetes surface: {label} at {url} "
                        f"(HTTP {r.status_code}).",
                        source="K8s probe", source_url=url, confidence=75,
                        passive=passive,
                        evidence={"severity": "high", "path": path,
                                  "status": r.status_code,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Read-only probe. Authorized testing only."}))
            except Exception:
                continue
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} k8s exposures")
        res.duration_ms = dur
        return res
