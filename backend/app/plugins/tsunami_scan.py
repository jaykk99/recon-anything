"""Tsunami-style exposed service console detection (Tier-4 Vuln/CVE).

Google's Tsunami scanner model: a detector is a strict fingerprint
(service-specific path + response signature) for a service that is
dangerous when exposed. This plugin applies detector fingerprints
for well-known admin / service consoles on the target's OWN host -
same-origin paths plus the services' canonical ports:

  Jenkins (X-Jenkins header / login fingerprint), Consul (UI + agent
  API), etcd (/version), Docker API (/version on 2375/2379-style
  ports), Kubelet (10250 /healthz + /pods signature), Jupyter
  (/login fingerprint), Grafana (/login fingerprint), phpMyAdmin.

Detection only: fingerprints are matched, no login is attempted,
no API command is issued (Docker/Kubelet checks are version/health
GETs only).
"""
from __future__ import annotations

import json
import time
from typing import List, Tuple
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (service, severity, remediation)
SVC_INFO = {
    "jenkins": ("high", "Put Jenkins behind SSO/VPN and require auth; "
                        "an exposed controller is unauth RCE risk."),
    "consul": ("high", "Bind Consul to localhost/private nets and "
                       "enable ACLs; the agent API is cluster control."),
    "etcd": ("high", "Require client-cert auth on etcd and firewall "
                     "2379; it stores cluster secrets."),
    "docker_api": ("high", "Never expose the Docker API over TCP "
                           "without mTLS; it is root-equivalent."),
    "kubelet": ("high", "Require Kubelet auth (webhook) and firewall "
                        "10250; anonymous mode allows pod exec."),
    "jupyter": ("medium", "Require a token/password on Jupyter and "
                          "bind it privately; open notebooks are RCE."),
    "grafana": ("low", "Keep Grafana patched and disable anonymous "
                       "access unless intended."),
    "phpmyadmin": ("medium", "Restrict phpMyAdmin by IP/VPN and keep "
                           "it patched; it is a prime brute-force "
                           "target."),
}


def fingerprint(service: str, status: int, headers, text: str) -> bool:
    """Strict per-service response fingerprint (pure, testable)."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    body = text or ""
    low = body.lower()
    if status == 0:
        return False
    if service == "jenkins":
        return (status in (200, 403) and ("x-jenkins" in h or
                ("jenkins" in low and ("login" in low or
                                       "dashboard" in low))))
    if service == "consul":
        return status == 200 and ("consul" in low or
                                  '"agent"' in low or "serf" in low)
    if service == "etcd":
        if status != 200:
            return False
        try:
            d = json.loads(body)
            return isinstance(d, dict) and "etcdserver" in d
        except Exception:
            return "etcdserver" in low
    if service == "docker_api":
        if status != 200:
            return False
        try:
            d = json.loads(body)
            return isinstance(d, dict) and ("ApiVersion" in d or
                                            "apiVersion" in d) and \
                ("Version" in d or "Os" in d)
        except Exception:
            return False
    if service == "kubelet":
        return status == 200 and (body.strip() == "ok" or
                                  '"kind":"podlist"' in low.replace(
                                      " ", "") or "podlist" in low)
    if service == "jupyter":
        return status in (200, 302) and "jupyter" in low
    if service == "grafana":
        return status in (200, 302) and "grafana" in low
    if service == "phpmyadmin":
        return status in (200, 401) and "phpmyadmin" in low
    return False


# (service, path) probes on the target's own base origin
PATH_PROBES: List[Tuple[str, str]] = [
    ("jenkins", "/login"),
    ("jenkins", "/"),
    ("consul", "/ui/"),
    ("consul", "/v1/agent/self"),
    ("etcd", "/version"),
    ("docker_api", "/version"),
    ("jupyter", "/login"),
    ("grafana", "/login"),
    ("phpmyadmin", "/phpmyadmin/"),
    ("phpmyadmin", "/phpMyAdmin/"),
]

# (service, port, path, scheme) canonical-port probes on the same host
PORT_PROBES: List[Tuple[str, int, str, str]] = [
    ("docker_api", 2375, "/version", "http"),
    ("etcd", 2379, "/version", "http"),
    ("consul", 8500, "/v1/agent/self", "http"),
    ("kubelet", 10250, "/healthz", "https"),
    ("kubelet", 10255, "/pods", "http"),
    ("jenkins", 8080, "/login", "http"),
    ("grafana", 3000, "/login", "http"),
    ("jupyter", 8888, "/login", "http"),
]


class TsunamiScanPlugin(Plugin):
    id = "tsunami_scan"
    label = "Tsunami Console Detection"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = ("Tsunami-style detector fingerprints for exposed "
                   "admin/service consoles: Jenkins, Consul, etcd, "
                   "Docker API, Kubelet, Jupyter, Grafana, phpMyAdmin "
                   "on the target host's paths and canonical ports.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        found = set()

        def add(service: str, url: str, status: int):
            if service in found:
                return
            found.add(service)
            sev, rem = SVC_INFO[service]
            findings.append(self._f(
                "infra", "exposed_service_console",
                f"Exposed {service} console/API fingerprinted at "
                f"{url} (HTTP {status})",
                source="tsunami detector fingerprint", source_url=url,
                confidence=90, passive=False,
                evidence={"severity": sev, "service": service,
                          "remediation": rem}))

        for service, path in PATH_PROBES:
            if service in found:
                continue
            r = await ctx.probe(base + path, timeout=8)
            if fingerprint(service, int(r.get("status") or 0),
                           r.get("headers") or {}, r.get("text") or ""):
                add(service, base + path, int(r.get("status") or 0))

        host = urlparse(base).hostname or domain
        for service, port, path, scheme in PORT_PROBES:
            if service in found:
                continue
            url = f"{scheme}://{host}:{port}{path}"
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                   timeout=5, max_retries=1,
                                   follow_redirects=True)
                status, text = resp.status_code, (resp.text or "")[:4000]
                headers = dict(resp.headers)
            except Exception:
                continue
            if fingerprint(service, status, headers, text):
                add(service, url, status)
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"tsunami detectors run for {len(SVC_INFO)} "
                   f"services: {len(findings)} exposed "
                   f"({', '.join(sorted(found)) or 'none'})")
