"""FCM push-token leak scan (Cat-7 #209, SHIP).

Input: operator-supplied artifacts - extracted app caches/logs/logcat
files plus APK strings. Matches FCM registration-token patterns and
Firebase config values reused as live keys. Reports token type +
MASKED fingerprint and where it leaked. Keyless, offline.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding, mask_value

FCM_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{10,30}:APA91b[A-Za-z0-9_-]{80,}")
LABELLED_RE = re.compile(
    r"(?:fcm(?:\s*registration)?\s*token|registration\s*token|"
    r"push\s*token)[\"'\s:=]+([A-Za-z0-9_:\-]{100,220})", re.I)
FIREBASE_KEY_RE = re.compile(r"AIza[0-9A-Za-z_\-]{35}")


def analyze_fcm_texts(texts: Dict[str, str]) -> List[Dict]:
    out: List[Dict] = []
    seen = set()
    for name, text in (texts or {}).items():
        if not text:
            continue
        hits = []
        for m in FCM_TOKEN_RE.finditer(text):
            hits.append(("FCM registration token", m.group(0)))
        for m in LABELLED_RE.finditer(text):
            hits.append(("labelled push token", m.group(1)))
        is_fb_config = "google-services" in name or "firebase" in name.lower()
        for m in FIREBASE_KEY_RE.finditer(text):
            hits.append(("Firebase API key (live config value)",
                         m.group(0)))
        for kind, token in hits:
            masked = mask_value(token)
            if masked in seen:
                continue
            seen.add(masked)
            where = ("committed Firebase config" if is_fb_config
                     else "app log/cache artifact")
            out.append(finding(
                "fcm_token_leak",
                f"{kind} leaked in {where} ({name}): {masked}",
                "high" if "token" in kind else "medium",
                source=name, confidence=85, token_type=kind,
                masked_value=masked, leaked_in=name))
            if len(out) >= 40:
                return out
    return out


class FcmPushTokenLeakPlugin(Cat7Plugin):
    id = "fcm_push_token_leak"
    label = "FCM Push Token Leak (masked)"
    description = ("Scans operator-supplied logs/caches/configs and "
                   "APK strings for leaked FCM registration tokens and "
                   "live Firebase keys; masked fingerprints only.")

    def analyze(self, art: Dict) -> List[Dict]:
        texts = dict(art.get("texts") or {})
        if art.get("dex_text"):
            texts["<dex strings>"] = art["dex_text"]
        if art.get("strings"):
            texts["<binary strings>"] = "\n".join(art["strings"])
        return analyze_fcm_texts(texts)
