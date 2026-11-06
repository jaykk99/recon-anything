"""NSUserDefaults leak scanner (Cat-7 #201, SHIP).

Input: operator-supplied iOS artifacts (IPA data container, .plist
files, backup). Parses preference plists and flags plaintext
tokens/passwords/session keys - MASKED + fingerprinted only.
plistlib only, keyless, offline.
"""
from __future__ import annotations

import plistlib
import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding, mask_value

SENSITIVE_KEY = re.compile(
    r"(token|password|passwd|secret|session|auth|api[_-]?key|"
    r"access[_-]?key|refresh|credential|private)", re.I)


def analyze_defaults(obj, prefix: str = "") -> List[Dict]:
    out: List[Dict] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{k}"
            if isinstance(v, (dict, list)):
                out.extend(analyze_defaults(v, key + "."))
            elif isinstance(v, str) and v and SENSITIVE_KEY.search(str(k)):
                out.append(finding(
                    "nsuserdefaults_plaintext_secret",
                    f"Plaintext sensitive value in NSUserDefaults: "
                    f"key '{key}' = {mask_value(v)}",
                    "high", source="NSUserDefaults plist",
                    confidence=90, plist_key=key,
                    masked_value=mask_value(v)))
            if len(out) >= 40:
                return out
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(analyze_defaults(v, f"{prefix}{i}."))
    return out


def analyze_plist_bytes(data: bytes) -> List[Dict]:
    if not data:
        return []
    try:
        obj = plistlib.loads(data)
    except Exception:
        return []
    return analyze_defaults(obj)


class NsuserdefaultsLeakScannerPlugin(Cat7Plugin):
    id = "nsuserdefaults_leak_scanner"
    label = "NSUserDefaults Leak Scanner (masked)"
    description = ("Parses operator-supplied iOS preference plists; "
                   "flags plaintext tokens/passwords, masked only.")

    def analyze(self, art: Dict) -> List[Dict]:
        out: List[Dict] = []
        for name, blob in (art.get("files") or {}).items():
            if name.endswith(".plist"):
                out.extend(analyze_plist_bytes(blob))
        if art.get("kind") == "file" and art.get("data"):
            out.extend(analyze_plist_bytes(art["data"]))
        return out
