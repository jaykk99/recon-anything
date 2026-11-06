"""Obsidian vault export (over supplied run data).

Generates an Obsidian vault structure from supplied assets + findings:
one Markdown note per asset and per finding, YAML frontmatter
(severity, plugin, target) and wikilinks mirroring asset relationships.
The vault manifest (note names + contents) rides in the finding's
evidence as the export artifact. Pure local generation, keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9\-]+", "-", str(text).lower()).strip("-")[:60] or "note"


def build_vault(assets: Any, findings: Any, target: str = "") -> List[Dict[str, str]]:
    notes: List[Dict[str, str]] = []
    asset_names: List[str] = []
    if isinstance(assets, list):
        for a in assets:
            name = str(a.get("value") if isinstance(a, dict) else a)
            slug = _slug(name)
            asset_names.append(slug)
            notes.append({"name": f"asset-{slug}.md",
                          "content": f"---\ntype: asset\ntarget: {target}\n---\n"
                                     f"# {name}\n"})
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
            sev = str(ev.get("severity") or f.get("severity") or "low")
            title = str(f.get("key") or "finding")
            links = " ".join(f"[[{n}]]" for n in asset_names[:3])
            notes.append({"name": f"finding-{_slug(title)}.md",
                          "content": f"---\nseverity: {sev}\nplugin: "
                                     f"{f.get('plugin_id', '')}\ntarget: {target}\n"
                                     f"---\n# {title}\n{str(f.get('value', ''))[:300]}\n{links}\n"})
    return notes


def analyze_vault_export(assets: Any, findings: Any,
                         target: str = "") -> List[Dict[str, Any]]:
    notes = build_vault(assets, findings, target)
    if not notes:
        return []
    return [{"key": "obsidian_vault_export",
             "value": f"Obsidian vault generated: {len(notes)} notes "
                      f"(frontmatter + wikilinks) ready as an export artifact",
             "severity": "low",
             "evidence": {"note_count": len(notes),
                          "notes": [n["name"] for n in notes][:50],
                          "vault": notes[:20]}}]


class ObsidianVaultVaultExportPlugin(Plugin):
    id = "obsidian_vault_vault_export"
    label = "Obsidian Vault Export"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    description = ("Export supplied assets/findings as an Obsidian vault: "
                   "Markdown notes, YAML frontmatter, wikilinks.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            assets = ctx.consume("subdomains") + ctx.consume("endpoints")
            rows = analyze_vault_export(assets, ctx.consume("findings"),
                                        target.normalized)
        except Exception as exc:
            return self._degraded(f"vault export failed: {exc}")
        findings: List[Finding] = [
            self._f("graph", r["key"], r["value"], source="Vault export",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Download the vault artifact "
                                             "and open it in Obsidian.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"vault notes: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
