"""SharedPreferences leak scan (Cat-7 #191, SHIP).

Input: operator-supplied extracted Android app data (shared_prefs
XML, backup tar contents). Parses key/value pairs and flags plaintext
tokens/passwords/session values. Reports key names + MASKED value
fingerprints only - never a full secret, no device access.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding, mask_value

SENSITIVE_KEY = re.compile(
    r"(token|password|passwd|secret|session|auth|api[_-]?key|access[_-]?key|"
    r"refresh|credential|private|pin\b|otp)", re.I)
ENTRY_RE = re.compile(
    r"<(string|int|long|boolean|float|set)\s+name=\"([^\"]+)\"[^>]*>"
    r"(.*?)</\1>", re.S)


def analyze_prefs_xml(text: str) -> List[Dict]:
    out: List[Dict] = []
    if not text:
        return out
    for m in ENTRY_RE.finditer(text):
        key, value = m.group(2), (m.group(3) or "").strip()
        if value and SENSITIVE_KEY.search(key):
            out.append(finding(
                "shared_prefs_plaintext_secret",
                f"Plaintext sensitive value in SharedPreferences: "
                f"key '{key}' = {mask_value(value)}",
                "high", source="shared_prefs XML", confidence=90,
                pref_key=key, masked_value=mask_value(value)))
        if len(out) >= 40:
            break
    return out


class SharedPreferencesDumpPlugin(Cat7Plugin):
    id = "shared_preferences_dump"
    label = "Shared Preferences Dump (masked)"
    description = ("Parses operator-supplied shared_prefs XML / backup "
                   "artifacts; flags plaintext tokens and passwords "
                   "with masked fingerprints only.")

    def analyze(self, art: Dict) -> List[Dict]:
        out: List[Dict] = []
        for name, text in (art.get("texts") or {}).items():
            if name.endswith(".xml"):
                out.extend(analyze_prefs_xml(text))
        return out
