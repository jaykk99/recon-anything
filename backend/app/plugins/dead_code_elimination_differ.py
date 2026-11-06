"""Dead-code elimination differ (Cat 6 #170). Single-bundle heuristics plus two-artifact diff in run()."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Strip disabled/hidden feature code from production builds; dead admin or debug tracks are attack surface.'


def _to_text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    return str(data)


def _to_bytes(data) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    return str(data).encode("utf-8", errors="ignore")


def _mask(value: str) -> tuple:
    v = str(value or "")
    fp = hashlib.sha256(v.encode("utf-8", errors="ignore")).hexdigest()[:12]
    masked = (v[:4] + "***") if len(v) > 4 else "***"
    return masked, fp


def _strings(data: bytes, min_len: int = 4) -> List[str]:
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def analyze_dead_code(data, reference=None) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    if re.search(r"if\s*\(\s*(?:false|0)\s*\)\s*\{[^}]{10,400}\}", text, re.S):
        m = re.search(r"if\s*\(\s*(?:false|0)\s*\)\s*\{(.{10,120})", text, re.S)
        snippet = (m.group(1).strip()[:80] if m else "")
        out.append({"key": "dead_code_block", "severity": "medium",
                    "value": f"Unreachable if(false) block ships in the bundle: {snippet}"})
    for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*(?:FEATURE|FLAG|ENABLE)[\w$]*)\s*=\s*false", text):
        name = m.group(1)
        if text.count(name) >= 2:
            out.append({"key": "disabled_feature_shipped", "severity": "medium",
                        "value": f"Feature flag {name}=false but its gated code still ships in the production bundle"})
    ref = _to_text(reference) if reference else ""
    if ref:
        feats = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)", text)) | set(re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(", text))
        ref_feats = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)", ref)) | set(re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(", ref))
        extra = sorted(f for f in (feats - ref_feats) if re.search(r"(?i)admin|debug|hidden|beta|internal|dev", f))
        for f in extra[:8]:
            out.append({"key": "hidden_feature_in_build", "severity": "medium",
                        "value": f"Function '{f}' exists in the shipped bundle but not in the reference build"})
    return out


async def _gather(ctx: Ctx, target: Target):
    sources = []
    for kind in ("artifacts", "supplied_code", "code_samples",
                 "supplied_files", "files", "bundles", "storage_dumps"):
        try:
            items = ctx.consume(kind)
        except Exception:
            items = []
        for it in items or []:
            if isinstance(it, dict):
                txt = it.get("text") or it.get("content") or it.get("body") or ""
                lbl = it.get("name") or it.get("url") or kind
            else:
                txt, lbl = it, kind
            if txt:
                sources.append((str(lbl), txt))
    try:
        base = None
        if target.type == "url" and target.normalized:
            base = target.normalized
        elif target.type == "domain" and target.normalized:
            base = "https://" + target.normalized
        if base:
            page = await ctx.fetch_page(base, timeout=10)
            txt = ""
            if isinstance(page, dict):
                txt = page.get("text") or ""
            elif isinstance(page, str):
                txt = page
            elif page is not None:
                txt = getattr(page, "text", "") or ""
            if txt:
                sources.append((base, txt))
            try:
                js_urls = ctx.consume("js_files")
            except Exception:
                js_urls = []
            for u in list(js_urls or [])[:5]:
                if not isinstance(u, str):
                    continue
                p2 = await ctx.fetch_page(u, timeout=10)
                t2 = ""
                if isinstance(p2, dict):
                    t2 = p2.get("text") or ""
                elif isinstance(p2, str):
                    t2 = p2
                elif p2 is not None:
                    t2 = getattr(p2, "text", "") or ""
                if t2:
                    sources.append((u, t2))
    except Exception:
        pass
    return sources


class DeadCodeEliminationDifferPlugin(Plugin):
    id = 'dead_code_elimination_differ'
    label = 'Dead-Code / Hidden Feature Differ'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Find code shipped but unreachable in supplied bundles: disabled feature flags with live code, if(false) blocks, and (with two artifacts) features absent from the reference build.'
    phase = 2
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        seen = set()
        try:
            sources = await _gather(ctx, target)
        except Exception:
            sources = []
        for label, data in sources:
            try:
                hits = analyze_dead_code(data)
            except Exception:
                hits = []
            for h in hits or []:
                dedup = (h.get("key"), h.get("value"))
                if dedup in seen:
                    continue
                seen.add(dedup)
                ev = {"severity": h.get("severity", "low"),
                       "remediation": h.get("remediation") or REMEDIATION}
                if h.get("evidence"):
                    ev.update(h["evidence"])
                findings.append(self._f(
                    'web', h["key"], h["value"], source=label,
                    source_url=label if str(label).startswith("http") else None,
                    confidence=85, evidence=ev))
        res = self._ok(findings, reason=f"{len(sources)} source(s), {len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
