"""localStorage credential harvester (Cat 6 #163, VARIANT of jwt). Operator-supplied dumps ONLY, evidence masked."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Never persist credentials or session tokens in web storage; move sessions to HttpOnly cookies and purge stored tokens.'


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


CRED_KEY = re.compile(r"(?i)token|password|passwd|secret|api[_-]?key|session|auth|jwt|credential|refresh|bearer")

def _dump_pairs(text: str):
    pairs = []
    import json as _json
    t = text.strip()
    if t.startswith("{"):
        try:
            obj = _json.loads(t)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    pairs.append((str(k), str(v)))
                return pairs
        except Exception:
            pass
    for line in t.splitlines():
        m = re.match(r"\s*\"?([^\"=:]{1,80})\"?\s*[=:]\s*\"?(.{1,500})\"?\s*$", line)
        if m:
            pairs.append((m.group(1).strip(), m.group(2).strip()))
    for m in re.finditer(r"localStorage\.(?:getItem|setItem)\s*\(\s*['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", text):
        pairs.append((m.group(1), m.group(2) or ""))
    return pairs

def analyze_storage_dump(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    seen = set()
    for key, val in _dump_pairs(text):
        if key in seen:
            continue
        seen.add(key)
        jwt_like = bool(re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", (val or "").strip()))
        if CRED_KEY.search(key) or jwt_like:
            masked, fp = _mask(val or key)
            out.append({"key": "storage_credential_key", "severity": "high",
                        "value": f"Storage dump persists credential-shaped key '{key}' (value masked {masked}, sha256:{fp})",
                        "evidence": {"storage_key": key, "masked": masked, "fingerprint": fp}})
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


class LocalstorageCredentialHarvesterPlugin(Plugin):
    id = 'localstorage_credential_harvester'
    label = 'localStorage Credential Audit (Supplied Dumps)'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Audit operator-supplied localStorage/sessionStorage dumps: inventory credential-shaped persisted keys with masked, fingerprinted evidence only.'
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
                hits = analyze_storage_dump(data)
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
                    'leak', h["key"], h["value"], source=label,
                    source_url=label if str(label).startswith("http") else None,
                    confidence=85, evidence=ev))
        res = self._ok(findings, reason=f"{len(sources)} source(s), {len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
