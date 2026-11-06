"""Global scope pollution checker (Cat 6 #167). Static scan."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Declare every variable, stop writing to window/global from libraries, and bundle with modules or strict mode.'


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


def analyze_globals(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    for m in re.finditer(r"\b(?:window|globalThis|global)\.([A-Za-z_$][\w$]*)\s*=(?!=)", text):
        out.append({"key": "global_window_write", "severity": "low",
                    "value": f"Code writes window/global property '{m.group(1)}' - global namespace pollution other scripts can collide with or abuse"})
        if len(out) >= 5:
            break
    declared = set(re.findall(r"(?:var|let|const|function)\s+([A-Za-z_$][\w$]*)", text))
    declared |= set(re.findall(r"function\s*\(([^)]*)\)", text))
    for m in re.finditer(r"(?m)^\s{0,3}([A-Za-z_$][\w$]*)\s*=(?!=|>)", text):
        name = m.group(1)
        if name in declared or name in ("module", "exports", "require"):
            continue
        ctx_before = text[max(0, m.start() - 200):m.start()]
        if re.search(r"(?:var|let|const)[^;]*$", ctx_before):
            continue
        out.append({"key": "implicit_global", "severity": "medium",
                    "value": f"Implicit global assignment '{name} = ...' with no declaration - leaks state onto the global object"})
        break
    for m in re.finditer(r"for\s*\(\s*([A-Za-z_$][\w$]*)\s+(?:in|of)\b", text):
        if m.group(1) not in declared:
            out.append({"key": "leaked_loop_variable", "severity": "low",
                        "value": f"Loop variable '{m.group(1)}' is never declared - it leaks as an implicit global"})
            break
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


class GlobalScopePollutionCheckerPlugin(Plugin):
    id = 'global_scope_pollution_checker'
    label = 'Global Scope Pollution Checker'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Inventory unintended global mutations in supplied JS: implicit globals, window/global writes from library code, leaked loop variables.'
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
                hits = analyze_globals(data)
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
