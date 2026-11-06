"""ASAR unpacker (Cat 6 #151). Static, operator-supplied artifacts only; secrets masked."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Remove secrets, .env files and private keys from the packaged app; rebuild the ASAR without development artifacts.'


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


def analyze_asar(data) -> List[dict]:
    out = []
    raw = _to_bytes(data)
    text = _to_text(data)
    if not raw:
        return out
    import json as _json
    header = None
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, min(len(text), start + 200000)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        header = _json.loads(text[start:i + 1])
                    except Exception:
                        header = None
                    break
    names: List[str] = []
    def _walk(node, prefix=""):
        if isinstance(node, dict):
            files = node.get("files")
            if isinstance(files, dict):
                for name, child in files.items():
                    _walk(child, prefix + "/" + str(name))
                    if isinstance(child, dict) and ("size" in child or "offset" in child):
                        names.append(prefix + "/" + str(name))
            else:
                for k, v in node.items():
                    _walk(v, prefix)
    if isinstance(header, dict):
        _walk(header)
    risky_ext = (".env", ".pem", ".key", ".p12", ".node")
    for n in names:
        low = n.lower()
        if any(low.endswith(e) or ("/" + e.strip(".")) in low for e in risky_ext) or low.endswith(".env"):
            out.append({"key": "asar_risky_file", "severity": "medium",
                        "value": f"ASAR archive packages a sensitive/binary file: {n}"})
    secret_res = [
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"ghp_[A-Za-z0-9]{20,}", "GitHub token"),
        (r"sk-(?:live|test)?[_-]?[A-Za-z0-9]{16,}", "API secret key"),
        (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private key block"),
        (r"(?i)(?:password|passwd|api[_-]?key|secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "hardcoded credential assignment"),
    ]
    body = text
    for pat, what in secret_res:
        for m in re.finditer(pat, body):
            masked, fp = _mask(m.group(0))
            out.append({"key": "asar_embedded_secret", "severity": "high",
                        "value": f"ASAR content contains a {what} (masked {masked}, sha256:{fp})",
                        "evidence": {"masked": masked, "fingerprint": fp}})
            break
    for m in re.finditer(r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'\"`]*", body):
        out.append({"key": "asar_internal_endpoint", "severity": "low",
                    "value": f"ASAR content references an internal endpoint: {m.group(0)[:120]}"})
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


class AsarUnpackerStreamPlugin(Plugin):
    id = 'asar_unpacker_stream'
    label = 'ASAR Archive Unpacker'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Stream-parse operator-supplied Electron .asar archives: file inventory plus masked secret/endpoint flags in extracted JS.'
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
                hits = analyze_asar(data)
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
