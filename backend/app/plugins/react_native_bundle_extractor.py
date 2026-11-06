"""React Native bundle extractor (Cat-7 #203, SHIP).

Input: operator-supplied APK/IPA. Locates the RN bundle
(assets/index.android.bundle, main.jsbundle), detects Hermes bytecode
vs plain JS, notes an embedded source map, and scans the bundle text
for secrets/endpoints with MASKED findings. Keyless.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ._cat7_common import Cat7Plugin, finding, mask_value

HERMES_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
BUNDLE_NAMES = ("index.android.bundle", "main.jsbundle",
                "index.bundle", "main.bundle")
SECRET_RES = [
    ("firebase_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic_assignment", re.compile(
        r"(?i)(api[_-]?key|secret|auth[_-]?token|access[_-]?token)"
        r"\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{16,})[\"']")),
]
URL_RE = re.compile(r"https?://[a-zA-Z0-9.\-]+\.[a-z]{2,24}(?:/[^\s\"'<>]*)?")


def find_bundle(art: Dict) -> Optional[Tuple[str, bytes]]:
    for name, blob in (art.get("files") or {}).items():
        base = name.rsplit("/", 1)[-1].lower()
        if base in BUNDLE_NAMES:
            return name, blob
    return None


def analyze_bundle(name: str, blob: bytes) -> List[Dict]:
    out: List[Dict] = []
    if not blob:
        return out
    hermes = blob[:8] == HERMES_MAGIC
    text = blob.decode("utf-8", errors="ignore")
    has_map = "sourceMappingURL" in text or blob.rstrip().endswith(b".map")
    if hermes:
        out.append(finding(
            "rn_hermes_bytecode",
            f"React Native bundle {name} is Hermes bytecode "
            f"(strings still recoverable statically)",
            "low", source=name, confidence=85, hermes=True,
            source_map=has_map))
    for kind, rx in SECRET_RES:
        for m in rx.finditer(text):
            val = m.group(2) if m.lastindex and m.lastindex >= 2 \
                else m.group(0)
            out.append(finding(
                "rn_bundle_secret",
                f"Hardcoded {kind} in React Native bundle {name}: "
                f"{mask_value(val)}",
                "high", source=name, confidence=88, kind=kind,
                masked_value=mask_value(val)))
            break  # one finding per kind per bundle is enough signal
    urls = sorted(set(URL_RE.findall(text)))[:25]
    backend = [u for u in urls if "api" in u or "backend" in u]
    if backend:
        out.append(finding(
            "rn_bundle_endpoints",
            f"{len(backend)} backend endpoints embedded in RN bundle "
            f"{name}", "low", source=name, confidence=75,
            endpoints=backend))
    return out


class ReactNativeBundleExtractorPlugin(Cat7Plugin):
    id = "react_native_bundle_extractor"
    label = "React Native Bundle Extractor"
    description = ("Extracts the RN bundle from an operator-supplied "
                   "APK/IPA, detects Hermes vs plain JS, and scans it "
                   "for secrets/endpoints (masked).")

    def analyze(self, art: Dict) -> List[Dict]:
        hit = find_bundle(art)
        if hit is None:
            # Loose bundle handed in directly as a single file.
            if art.get("kind") == "file" and art.get("data") and \
                    (art.get("name") or "").endswith(".bundle"):
                return analyze_bundle(art["name"], art["data"])
            return []
        return analyze_bundle(hit[0], hit[1])
