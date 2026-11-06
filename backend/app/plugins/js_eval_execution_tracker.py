"""Eval execution tracker (Cat 6 #168). Static sink inventory - not a runtime logger."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Remove eval-style sinks; where dynamic behavior is required, use a parser or allowlisted dispatch instead of executing strings.'


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


def analyze_eval_sinks(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    sinks = [
        (r"\beval\s*\(\s*([A-Za-z_$][\w$.]*)", "eval_tainted", "high", "eval() called with a variable/expression argument"),
        (r"\beval\s*\(\s*['\"`]", "eval_literal", "medium", "eval() called with a string literal"),
        (r"new\s+Function\s*\(\s*([A-Za-z_$][\w$.]*)", "function_ctor_tainted", "high", "Function constructor called with a variable argument"),
        (r"new\s+Function\s*\(\s*['\"`]", "function_ctor_literal", "medium", "Function constructor called with string arguments"),
        (r"set(?:Timeout|Interval)\s*\(\s*['\"`]", "string_timer", "medium", "setTimeout/setInterval called with a string (implicit eval)"),
        (r"document\.write\s*\([^)]*(?:<script|\+)", "document_write_script", "medium", "document.write() emits script markup or concatenated content"),
    ]
    seen_keys = set()
    for pat, key, sev, msg in sinks:
        if key in seen_keys:
            continue
        if re.search(pat, text):
            seen_keys.add(key)
            out.append({"key": key, "severity": sev, "value": msg + " - dynamic execution sink in supplied bundle"})
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


class JsEvalExecutionTrackerPlugin(Plugin):
    id = 'js_eval_execution_tracker'
    label = 'JS Eval Execution Tracker (Static)'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Locate dynamic code-execution sinks in supplied JS (eval, Function constructor, string timers, document.write) and grade them by input reachability.'
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
                hits = analyze_eval_sinks(data)
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
