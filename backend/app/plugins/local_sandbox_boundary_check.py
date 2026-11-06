"""Local sandbox boundary check (variant of app modes.py).

modes.py gates scan TARGETS. This plugin's delta: a component
capability boundary audit. It reads a component's declared execution
needs (manifest/config: network egress hosts, file paths, env vars,
subprocess use) and audits them against sandbox policy before the
component runs: egress outside the allowlist, paths outside sandbox
roots, secret-shaped env vars, undeclared subprocess use. Pure
analysis of supplied manifests, keyless; nothing is executed.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

ALLOWED_EGRESS_SUFFIXES = (".pypi.org", ".github.com", ".githubusercontent.com")
SANDBOX_ROOTS = ("/tmp", "/workspace", "./", "workspace/")
SECRET_ENV_RX = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)", re.I)
SENSITIVE_PATH_RX = re.compile(r"(^|/)(\.ssh|\.aws|\.gnupg|\.env|id_rsa|/etc/|/root/)", re.I)


def analyze_boundary(manifests: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(manifests, list):
        return rows
    for man in manifests:
        if not isinstance(man, dict):
            continue
        name = str(man.get("name") or "component")
        for host in man.get("network_egress") or []:
            h = str(host).lower()
            if not any(h == s.lstrip(".") or h.endswith(s) for s in ALLOWED_EGRESS_SUFFIXES):
                rows.append({"key": "sandbox_egress_violation",
                             "value": f"Component '{name}' declares network "
                                      f"egress to '{h}', outside the sandbox "
                                      f"egress allowlist",
                             "severity": "high",
                             "evidence": {"component": name, "host": h}})
        for p in man.get("file_paths") or []:
            ps = str(p)
            if SENSITIVE_PATH_RX.search(ps):
                rows.append({"key": "sandbox_sensitive_path",
                             "value": f"Component '{name}' declares access to "
                                      f"sensitive path '{ps}'",
                             "severity": "high",
                             "evidence": {"component": name, "path": ps}})
            elif not any(ps.startswith(r) or ps.startswith("/home/") and "/workspace/" in ps
                         for r in SANDBOX_ROOTS):
                rows.append({"key": "sandbox_path_outside_roots",
                             "value": f"Component '{name}' declares file path "
                                      f"'{ps}' outside the sandbox roots",
                             "severity": "medium",
                             "evidence": {"component": name, "path": ps}})
        for var in man.get("env_vars") or []:
            if SECRET_ENV_RX.search(str(var)):
                rows.append({"key": "sandbox_secret_env",
                             "value": f"Component '{name}' requests env var "
                                      f"'{var}', which is secret-shaped: "
                                      f"components must not receive raw secrets",
                             "severity": "high",
                             "evidence": {"component": name, "env_var": str(var)}})
        if man.get("subprocess") and not man.get("subprocess_declared"):
            rows.append({"key": "sandbox_undeclared_subprocess",
                         "value": f"Component '{name}' uses subprocesses "
                                  f"without declaring it in its manifest",
                         "severity": "medium", "evidence": {"component": name}})
    return rows


class LocalSandboxBoundaryCheckPlugin(Plugin):
    id = "local_sandbox_boundary_check"
    label = "Local Sandbox Boundary Check"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Audit a component's declared capabilities (egress, "
                   "paths, env, subprocess) against sandbox policy.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_boundary(ctx.consume("component_manifests"))
        except Exception as exc:
            return self._degraded(f"boundary check failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Sandbox boundary",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Remove the capability or get "
                                             "it explicitly approved and added "
                                             "to the sandbox policy.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"boundary rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
