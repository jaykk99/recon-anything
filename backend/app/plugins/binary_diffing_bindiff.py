"""Binary-diffing-bindiff: function-level diff of two versions of an operator-supplied binary (old + new supplied as the first two artifacts) - changed/new/removed function blocks by instruction hashing, highlighting newly patched sites.
"""
from __future__ import annotations
from typing import Any, Dict, List
from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat5_common import (
    REMEDIATION, code_section_bytes, load_artifacts,
    parse_any, split_blocks)


def function_hashes(code: bytes) -> Dict[str, Dict[str, Any]]:
    blocks = split_blocks(code)
    out: Dict[str, Dict[str, Any]] = {}
    import hashlib as _h
    for idx, b in enumerate(blocks):
        digest = _h.sha256(code[b["start"]:b["end"]]).hexdigest()[:12]
        out[digest] = {"index": idx, "start": b["start"], "size": b["end"] - b["start"]}
    return out

def analyze_pair(old: bytes, new: bytes) -> List[Dict[str, Any]]:
    hits = []
    fo, io = parse_any(old)
    fn, inew = parse_any(new)
    co, _ = code_section_bytes(old, fo, io) if fo != "raw" else (old, 0)
    cn, _ = code_section_bytes(new, fn, inew) if fn != "raw" else (new, 0)
    ho, hn = function_hashes(co), function_hashes(cn)
    changed_new = sorted(set(hn) - set(ho))
    removed = sorted(set(ho) - set(hn))
    for d in changed_new[:6]:
        hits.append({"key": "bindiff_new_or_changed_function", "severity": "medium",
            "value": f"Function block changed/new in new version (hash {d}, {hn[d]['size']} bytes at code offset {hn[d]['start']:#x}) - patched-site candidate",
            "evidence": {"hash": d, "size": hn[d]["size"], "start": hn[d]["start"]}})
    for d in removed[:3]:
        hits.append({"key": "bindiff_removed_function", "severity": "low",
            "value": f"Function block removed in new version (hash {d})",
            "evidence": {"hash": d}})
    return hits

def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    return []  # pair analysis lives in analyze_pair / run()

class BinaryDiffingBindiffPlugin(Plugin):
    id = "binary_diffing_bindiff"
    label = "Binary Diffing (BinDiff)"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Function-level diff of two supplied binary versions: changed/new/removed blocks, patched sites.'
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings: List = []
        try:
            arts = load_artifacts(target, ctx)
            if len(arts) < 2:
                return self._ok([], "bindiff needs two supplied binary versions (old + new) as artifacts")
            for hit in analyze_pair(arts[0][1], arts[1][1]):
                ev = {"severity": hit.get("severity", "low"), "remediation": REMEDIATION}
                ev.update(hit.get("evidence") or {})
                findings.append(self._f("infra", hit["key"], hit["value"],
                    source=f"{arts[0][0]} vs {arts[1][0]}", confidence=85, evidence=ev))
        except Exception as exc:
            return self._ok(findings, f"analysis degraded: {exc}"[:200])
        return self._ok(findings, f"{len(findings)} diff finding(s)")
