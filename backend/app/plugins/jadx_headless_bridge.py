"""JADX headless bridge (Cat-7 #181, VARIANT of binex).

binex does strings/permissions only - no decompiled-code review.
Delta: when a local jadx binary is present it is noted, and the
decompiled-code review layer runs over the operator-supplied APK's
code-bearing text (DEX strings, smali, decompiled Java when the
operator extracted it): sensitive API call sites, insecure crypto,
cleartext endpoints, unsafe storage modes. Clean skip when there is
no code text. Keyless, offline.
"""
from __future__ import annotations

import shutil
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

PATTERNS = [
    ("weak_crypto_des", "high",
     ("Cipher.getInstance(\"DES", "Cipher.getInstance('DES", '"DES/ECB'),
     "DES encryption used in decompiled code"),
    ("weak_hash_md5", "medium",
     ("MessageDigest.getInstance(\"MD5", "getInstance(\"SHA-1"),
     "MD5/SHA-1 used for security purposes"),
    ("insecure_random", "medium",
     ("java.util.Random", "Math.random"),
     "Non-cryptographic random used (java.util.Random/Math.random)"),
    ("world_readable_storage", "high",
     ("MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE"),
     "World-readable/writable app storage mode"),
    ("trust_all_certs_code", "high",
     ("X509TrustManager", "checkServerTrusted", "ALLOW_ALL_HOSTNAME_VERIFIER"),
     "Custom TrustManager / hostname-verifier code in decompiled source"),
    ("exec_calls", "medium",
     ("Runtime.getRuntime().exec", "ProcessBuilder"),
     "Shell command execution call sites"),
    ("sqlite_raw_secrets", "medium",
     ("SQLiteDatabase.openDatabase", "rawQuery"),
     "Raw SQLite access call sites (review for injection/plaintext)"),
]


def analyze_code_review(dex_text: str, jadx_available: bool) -> List[Dict]:
    out: List[Dict] = []
    if not dex_text:
        return out
    for key, sev, needles, label in PATTERNS:
        hits = sorted(n for n in needles if n in dex_text)
        if hits:
            out.append(finding(
                f"jadx_{key}",
                f"Decompiled-code review: {label} "
                f"({', '.join(hits[:3])})",
                sev, source="DEX/smali/Java (jadx review layer)",
                confidence=78, jadx_binary=jadx_available,
                markers=hits[:5]))
    return out


class JadxHeadlessBridgePlugin(Cat7Plugin):
    id = "jadx_headless_bridge"
    label = "JADX Headless Bridge"
    description = ("Decompiled-code review layer over binex's APK "
                   "input: sensitive API call sites, insecure crypto "
                   "and storage modes (local jadx used when present).")

    def analyze(self, art: Dict) -> List[Dict]:
        code = "\n".join([art.get("dex_text") or ""] +
                         [t for n, t in (art.get("texts") or {}).items()
                          if n.endswith((".java", ".smali", ".kt"))])
        return analyze_code_review(code, shutil.which("jadx") is not None)
