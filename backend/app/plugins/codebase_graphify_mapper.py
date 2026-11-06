"""Codebase graphify mapper (variant of assetgraph).

assetgraph graphs infrastructure assets. This plugin's delta: a
code-structure graph over supplied source artifacts: file/module nodes
with import edges and function nodes. Structural anomalies are the
findings: orphan modules nothing imports, circular imports, and hub
modules with extreme fan-in. Emitted in graph finding format. Pure
static parsing, keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Set

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_IMPORT_RES = [
    re.compile(r"^\s*import\s+([\w\.]+)", re.M),
    re.compile(r"^\s*from\s+([\w\.]+)\s+import", re.M),
    re.compile(r"(?:import|from)\s+['\"]([^'\"]+)['\"]"),
    re.compile(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    re.compile(r"^\s*import\s+['\"]([^'\"]+)['\"]", re.M),
]


def parse_imports(text: str) -> List[str]:
    out: List[str] = []
    for rx in _IMPORT_RES:
        out.extend(m.group(1) for m in rx.finditer(text or ""))
    return out


def _stem(name: str) -> str:
    base = str(name).replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[0]


def build_code_graph(files: Any) -> Dict[str, Any]:
    nodes: Set[str] = set()
    edges: Dict[str, Set[str]] = {}
    if isinstance(files, list):
        for f in files:
            if not isinstance(f, dict):
                continue
            name = str(f.get("name") or f.get("path") or "")
            if not name:
                continue
            stem = _stem(name)
            nodes.add(stem)
            deps = {_stem(d) for d in parse_imports(str(f.get("text") or f.get("content") or ""))}
            edges[stem] = {d for d in deps if d and d != stem}
    return {"nodes": nodes, "edges": edges}


def analyze_code_graph(files: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    g = build_code_graph(files)
    nodes, edges = g["nodes"], g["edges"]
    if not nodes:
        return rows
    # The first supplied file is the entry point: nothing imports it by
    # design, so it is never an orphan.
    entry = None
    if isinstance(files, list):
        for f in files:
            if isinstance(f, dict) and (f.get("name") or f.get("path")):
                entry = _stem(str(f.get("name") or f.get("path")))
                break
    imported = set()
    for deps in edges.values():
        imported.update(deps & nodes)
    for n in sorted(nodes):
        if n == entry:
            continue
        if n not in imported and not edges.get(n):
            continue  # fully isolated single file: not evidence of an orphan in a set
        if n not in imported and len(nodes) > 2:
            rows.append({"key": "code_orphan_module",
                         "value": f"Module '{n}' is imported by nothing in "
                                  f"the supplied set (orphan/dead module)",
                         "severity": "low", "evidence": {"module": n}})
    # circular imports: a -> b -> a (direct pairs and self-chains)
    for a, deps in edges.items():
        for b in deps:
            if b in edges and a in edges[b]:
                rows.append({"key": "code_circular_import",
                             "value": f"Circular import between '{a}' and '{b}'",
                             "severity": "medium",
                             "evidence": {"modules": [a, b]}})
                break
    fanin: Dict[str, int] = {}
    for deps in edges.values():
        for d in deps & nodes:
            fanin[d] = fanin.get(d, 0) + 1
    for mod, n in fanin.items():
        if n >= 5:
            rows.append({"key": "code_hub_module",
                         "value": f"Module '{mod}' has fan-in {n}: a change "
                                  f"there ripples across the codebase graph",
                         "severity": "low",
                         "evidence": {"module": mod, "fan_in": n}})
    return rows


class CodebaseGraphifyMapperPlugin(Plugin):
    id = "codebase_graphify_mapper"
    label = "Codebase Graphify Mapper"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    description = ("Code-structure graph over supplied source files: flag "
                   "orphan modules, circular imports, extreme fan-in hubs.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            files = ctx.consume("source_files") or ctx.consume("artifacts")
            rows = analyze_code_graph(files)
        except Exception as exc:
            return self._degraded(f"code graph failed: {exc}")
        findings: List[Finding] = [
            self._f("graph", r["key"], r["value"], source="Codebase graph",
                    confidence=80,
                    evidence={"severity": r["severity"],
                              "remediation": "Review the module structure: "
                                             "remove or wire in orphans, "
                                             "break import cycles, split hubs.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"code-graph rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
