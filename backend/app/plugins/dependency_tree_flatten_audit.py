"""Dependency tree flatten audit (variant of dependency_conf).

dependency_conf parses DIRECT deps from exposed manifests. This
plugin's delta: lockfile-driven transitive tree audit over supplied
lockfile data: depth and fan-out metrics, duplicate major versions of
one package, known-bad/abandoned transitive packages, and excessively
deep chains where flattening hides risk. Pure parsing, keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

KNOWN_BAD = {"event-stream": "compromised in 2018 (flatmap-stream incident)",
             "node-ipc": "protestware versions sabotaged consumers",
             "ua-parser-js": "hijacked releases shipped malware",
             "colors": "intentionally broken loop in 1.4.1",
             "faker": "intentionally broken release 6.6.6"}
DEPTH_LIMIT = 4


def parse_tree(data: Any) -> List[Dict[str, Any]]:
    """Normalize lockfile data into [{name, version, depth}]."""
    out: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        pkgs = data.get("packages") or data.get("dependencies") or {}
        if isinstance(pkgs, dict):
            for path, meta in pkgs.items():
                if not path:
                    continue
                name = str(path).split("node_modules/")[-1]
                depth = str(path).count("node_modules/")
                ver = meta.get("version") if isinstance(meta, dict) else ""
                out.append({"name": name, "version": str(ver or ""), "depth": depth})
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("name"):
                out.append({"name": str(item["name"]),
                            "version": str(item.get("version") or ""),
                            "depth": int(item.get("depth") or 0)})
            elif isinstance(item, str):
                m = re.match(r"([\w@./\-]+)@(\d[^\s]*)", item.strip())
                if m:
                    out.append({"name": m.group(1), "version": m.group(2), "depth": 1})
    elif isinstance(data, str):
        for line in data.splitlines():
            indent = len(line) - len(line.lstrip())
            m = re.search(r"([\w@./\-]+)@(\d[^\s]*)", line)
            if m:
                out.append({"name": m.group(1), "version": m.group(2),
                            "depth": max(1, indent // 2)})
    return out


def analyze_dependency_tree(data: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    tree = parse_tree(data)
    majors: Dict[str, set] = {}
    for p in tree:
        base = p["name"].split("/")[-1]
        if base in KNOWN_BAD:
            rows.append({"key": "dep_known_bad_transitive",
                         "value": f"Package '{p['name']}'@{p['version']} sits "
                                  f"at depth {p['depth']} in the tree: "
                                  f"{KNOWN_BAD[base]}",
                         "severity": "high",
                         "evidence": {"package": p["name"], "depth": p["depth"]}})
        if p["depth"] > DEPTH_LIMIT:
            rows.append({"key": "dep_excessive_depth",
                         "value": f"Package '{p['name']}' is buried at depth "
                                  f"{p['depth']} (> {DEPTH_LIMIT}): hidden "
                                  f"transitive risk that flattening conceals",
                         "severity": "medium",
                         "evidence": {"package": p["name"], "depth": p["depth"]}})
        major = p["version"].split(".")[0] if p["version"] else ""
        if major:
            majors.setdefault(p["name"], set()).add(major)
    for name, ms in majors.items():
        if len(ms) > 1:
            rows.append({"key": "dep_duplicate_major_versions",
                         "value": f"Package '{name}' appears with multiple "
                                  f"major versions {sorted(ms)} in one tree: "
                                  f"duplicate-major bloat and patch skew",
                         "severity": "medium",
                         "evidence": {"package": name, "majors": sorted(ms)}})
    return rows


class DependencyTreeFlattenAuditPlugin(Plugin):
    id = "dependency_tree_flatten_audit"
    label = "Dependency Tree Flatten Audit"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Transitive dependency-tree audit over supplied lockfile "
                   "data: depth, duplicate majors, known-bad packages.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            data: Any = ctx.consume("lockfile")
            if data and len(data) == 1:
                data = data[0]
            rows = analyze_dependency_tree(data)
        except Exception as exc:
            return self._degraded(f"dependency audit failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Dependency tree audit",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Pin, replace or remove the "
                                             "named package and regenerate "
                                             "the lockfile.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"dependency rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
