"""Shared helpers for the Cat-7 (300-expansion) mobile plugins.

STATIC analysis of OPERATOR-SUPPLIED artifacts only: APK/IPA zip files,
extracted package trees, single files (plists, prefs XML, SQLite DBs,
Mach-O/ELF binaries, logs). Nothing here touches a device, a network,
or a third-party system. Secret-shaped values are only ever reported
MASKED (sha256 fingerprint + length), never in full.

Artifact dict shape (built by load_artifact / build_*):
  kind:     "zip" | "dir" | "file"
  name:     display name of the artifact
  path:     local path it came from (may be "")
  data:     raw bytes for single-file / zip artifacts (else b"")
  files:    {relpath: bytes} for zip/dir artifacts (size-capped)
  texts:    {relpath: str} decoded text for text-ish members
  manifest: decoded AndroidManifest.xml text ("" when absent)
  dex_text: concatenated DEX string content + smali/java text
  all_text: every decoded text + extracted binary strings (bounded)
  strings:  extracted printable strings (bounded list)
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile
from typing import Dict, List, Optional

from .base import Cost, Plugin, PluginResult, Target

MAX_FILE_BYTES = 96 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_TEXT = 6 * 1024 * 1024

TEXT_EXTS = (".xml", ".json", ".txt", ".plist", ".smali", ".java", ".kt",
             ".js", ".log", ".cfg", ".ini", ".properties", ".html", ".csv")

REMEDIATION = ("Review this mobile finding. Remove hardcoded secrets, "
               "minimize exported surface, enable pinning / attestation, "
               "and encrypt local storage with strong accessibility "
               "classes.")


def fingerprint(value) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8", errors="ignore")
    return hashlib.sha256(value or b"").hexdigest()


def mask_value(value) -> str:
    """Masked evidence: fingerprint + length only, never the value."""
    if isinstance(value, str):
        raw = value.encode("utf-8", errors="ignore")
    else:
        raw = value or b""
    return f"***[sha256:{fingerprint(raw)[:16]} len={len(raw)}]"


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    out, cur = [], []
    for b in data or b"":
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def _decode(data: bytes) -> str:
    return (data or b"")[:MAX_MEMBER_BYTES].decode("utf-8", errors="ignore")


def _finalize(art: Dict) -> Dict:
    files: Dict[str, bytes] = art.get("files") or {}
    texts: Dict[str, str] = {}
    strings: List[str] = []
    dex_parts: List[str] = []
    total = 0
    for name, blob in files.items():
        blob = blob or b""
        low = name.lower()
        if low.endswith(TEXT_EXTS) or low.endswith(".dex"):
            t = _decode(blob)
            texts[name] = t
            total += len(t)
            if low.endswith(".dex") or low.endswith(".smali"):
                dex_parts.append(t)
        if total < MAX_TOTAL_TEXT and (
                low.endswith((".dex", ".so")) or low.endswith(".app/app")
                or "/app.framework/" in low or low.endswith("app")):
            strings.extend(extract_strings(blob[:MAX_MEMBER_BYTES]))
    # Mach-O / loose binaries handed in as a single file.
    if art.get("kind") == "file" and art.get("data"):
        strings.extend(extract_strings(art["data"][:MAX_MEMBER_BYTES]))
        if (art.get("name") or "").lower().endswith(TEXT_EXTS):
            texts[art["name"]] = _decode(art["data"])
    manifest = ""
    for name, blob in files.items():
        if name.endswith("AndroidManifest.xml"):
            manifest = _decode(blob)
            break
    art["texts"] = texts
    art["manifest"] = manifest
    art["dex_text"] = "\n".join(dex_parts)
    art["strings"] = strings[:60000]
    parts = list(texts.values()) + strings
    art["all_text"] = "\n".join(parts)[:MAX_TOTAL_TEXT]
    return art


def build_from_files(files: Dict[str, bytes], name: str = "artifact",
                     data: bytes = b"", kind: str = "zip",
                     path: str = "") -> Dict:
    capped = {}
    for k, v in (files or {}).items():
        capped[k] = (v or b"")[:MAX_MEMBER_BYTES]
    return _finalize({"kind": kind, "name": name, "path": path,
                      "data": data, "files": capped})


def build_from_zip_bytes(data: bytes, name: str = "package.zip",
                         path: str = "") -> Dict:
    files: Dict[str, bytes] = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        for info in zf.infolist():
            if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
                continue
            try:
                files[info.filename] = zf.read(info.filename)
            except Exception:
                continue
    except Exception:
        files = {}
    return build_from_files(files, name=name, data=data, kind="zip",
                            path=path)


def build_from_dir(path: str) -> Dict:
    files: Dict[str, bytes] = {}
    for root, _dirs, fnames in os.walk(path):
        for fn in fnames:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, path)
            try:
                if os.path.getsize(full) > MAX_MEMBER_BYTES:
                    continue
                with open(full, "rb") as fh:
                    files[rel] = fh.read()
            except Exception:
                continue
            if len(files) > 4000:
                break
    return build_from_files(files, name=os.path.basename(path),
                            kind="dir", path=path)


def load_artifact(target: Target) -> Optional[Dict]:
    """Resolve an operator-supplied local artifact from the target.

    The target's normalized value is a local file or directory path.
    Returns None when it does not resolve to a local artifact (the
    plugin then reports ok(0) with an explanatory note, never a crash).
    """
    raw = (getattr(target, "normalized", "") or
           getattr(target, "raw", "") or "").strip()
    if not raw or raw.startswith(("http://", "https://")):
        return None
    raw = raw[7:] if raw.startswith("file://") else raw
    try:
        if os.path.isfile(raw):
            if os.path.getsize(raw) > MAX_FILE_BYTES:
                return None
            with open(raw, "rb") as fh:
                data = fh.read()
            name = os.path.basename(raw)
            if zipfile.is_zipfile(io.BytesIO(data)):
                return build_from_zip_bytes(data, name=name, path=raw)
            return _finalize({"kind": "file", "name": name, "path": raw,
                              "data": data, "files": {name: data}})
        if os.path.isdir(raw):
            return build_from_dir(raw)
    except Exception:
        return None
    return None


# -- AndroidManifest.xml helpers (regex-based; works on plain XML and
#    on the string-visible form of binary AXML, like binex) -----------

_ATTR_RE = re.compile(r'([\w:.-]+)\s*=\s*"([^"]*)"')
_TAG_RE = re.compile(r"<(activity|activity-alias|service|receiver|"
                     r"provider|application)\b([^>]*)>", re.S)


def manifest_attrs(tag_text: str) -> Dict[str, str]:
    return {m.group(1): m.group(2) for m in _ATTR_RE.finditer(tag_text)}


def manifest_components(manifest: str) -> List[Dict]:
    """Components with their attrs + the segment up to the next
    component (where that component's intent-filters live)."""
    if not manifest:
        return []
    matches = list(_TAG_RE.finditer(manifest))
    out = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(manifest)
        out.append({"tag": m.group(1), "attrs": manifest_attrs(m.group(0)),
                    "segment": manifest[m.start():end]})
    return out


def intent_filters(segment: str) -> List[Dict]:
    out = []
    for m in re.finditer(r"<intent-filter\b([^>]*)>(.*?)</intent-filter>",
                         segment or "", re.S):
        body = m.group(2)
        out.append({
            "attrs": manifest_attrs(m.group(1)),
            "actions": re.findall(r'android:name="([^"]+)"', body),
            "schemes": re.findall(r'android:scheme="([^"]*)"', body),
            "hosts": re.findall(r'android:host="([^"]*)"', body),
            "paths": re.findall(r'android:(?:path|pathPrefix|pathPattern)'
                                r'="([^"]*)"', body),
            "categories": re.findall(r'android:name="([^"]+)"', body),
            "browsable": "BROWSABLE" in body,
        })
    return out


def application_attrs(manifest: str) -> Dict[str, str]:
    m = re.search(r"<application\b([^>]*)>", manifest or "", re.S)
    return manifest_attrs(m.group(1)) if m else {}


def finding(key: str, value: str, severity: str = "low",
            source: str = "artifact", confidence: int = 80,
            **evidence) -> Dict:
    ev = {"severity": severity, "remediation": REMEDIATION}
    ev.update(evidence)
    return {"key": key, "value": value, "severity": severity,
            "source": source, "confidence": confidence, "evidence": ev}


class Cat7Plugin(Plugin):
    """Base for Cat-7 artifact plugins. id=None keeps this base itself
    out of the registry; each concrete plugin sets its own id."""
    id = None
    group = "mobile"
    passive = True
    cost = Cost.FREE
    accepts = ["apk", "ipa", "apk_url", "file", "local_file", "artifact",
               "play_store", "app_store"]
    timeout_s = 60

    def analyze(self, art: Dict) -> List[Dict]:  # overridden per plugin
        return []

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            art = load_artifact(target)
            if art is None:
                return self._ok(
                    [], "no operator-supplied local artifact at the "
                        "target path; this static analyzer needs a "
                        "local APK/IPA/extracted-artifact path")
            raw = self.analyze(art) or []
            findings = []
            for d in raw:
                ev = dict(d.get("evidence") or {})
                ev.setdefault("severity", d.get("severity", "low"))
                findings.append(self._f(
                    "mobile", d["key"], d["value"],
                    source=d.get("source", self.id),
                    confidence=d.get("confidence", 80), evidence=ev))
            return self._ok(findings,
                            f"{self.id}: {len(findings)} findings")
        except Exception as e:  # never raise fatally
            return self._ok([], f"{self.id} degraded: {e}"[:200])
