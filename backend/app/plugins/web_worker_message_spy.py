"""Web worker message spy (Cat 6 #173). STATIC detector - no live worker monitoring."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Validate worker message shape and origin, never eval or inject message data, and keep credentials out of worker messages.'


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


def analyze_worker_messages(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    has_worker = bool(re.search(r"new\s+(?:Shared)?Worker\s*\(|onmessage\s*=|addEventListener\s*\(\s*['\"]message['\"]", text))
    if not has_worker:
        return out
    handlers = re.findall(r"(?:onmessage\s*=|addEventListener\s*\(\s*['\"]message['\"]\s*,)\s*(?:async\s*)?(?:function\s*)?\(([^)]*)\)\s*(?:=>)?\s*\{(.{0,600}?)\n\s*\}", text, re.S)
    for _params, body in handlers:
        if re.search(r"\beval\s*\(|innerHTML\s*=|document\.write|Function\s*\(", body) and re.search(r"\.data\b", body):
            out.append({"key": "worker_message_to_sink", "severity": "high",
                        "value": "Worker message handler feeds message data into eval/innerHTML-style sinks without validation"})
        elif not re.search(r"origin|typeof |instanceof|validate|schema", body) and re.search(r"\.data\b", body):
            out.append({"key": "worker_message_unvalidated", "severity": "medium",
                        "value": "Worker message handler consumes event.data with no origin or shape validation visible"})
    if re.search(r"postMessage\s*\([^)]*(?:token|password|secret|credential|api[_-]?key)", text, re.I):
        out.append({"key": "worker_credential_message", "severity": "high",
                    "value": "Credential-shaped data is sent through a worker postMessage channel"})
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


class WebWorkerMessageSpyPlugin(Plugin):
    id = 'web_worker_message_spy'
    label = 'Web Worker Message Surface (Static)'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Static audit of Web Worker message surfaces in supplied bundles: unvalidated onmessage handlers, workers fed credential-shaped data, missing origin checks.'
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
                hits = analyze_worker_messages(data)
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
