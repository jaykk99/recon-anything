"""App tampering self-check scan (Cat-7 #208, VARIANT of binex).

Distinct from signature-format verification (#199): this checks
whether the APP verifies ITSELF - signature self-verification APIs,
Play Integrity / App Attest references, APK checksum / DEX-hash
comparison strings. Verdict: self-check present / partial / absent.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

STRONG = ("PlayIntegrity", "IntegrityManager", "SafetyNet", "App Attest",
          "AppAttest", "verifySignature")
SELF_CHECK = ("getPackageInfo", "signingInfo", "GET_SIGNATURES",
              "GET_SIGNING_CERTIFICATES", "MessageDigest",
              "apkChecksum", "verifyAppSignature", "signatureHash")
HASH_ONLY = ("classes.dex", "CRC32", "Adler32", "checksum")


def analyze_tamper_checks(text: str) -> List[Dict]:
    if text is None:
        text = ""
    strong = sorted(s for s in STRONG if s in text)
    if strong:
        return []  # real attestation/self-check present: silent
    partial = sorted(s for s in SELF_CHECK if s in text)
    if partial:
        return [finding(
            "tamper_self_check_partial",
            f"Tamper self-check is PARTIAL: local signature/hash "
            f"comparison strings only ({', '.join(partial[:4])}), no "
            f"Play Integrity / attestation - a patched app can patch "
            f"the check itself",
            "low", source="DEX strings", confidence=70,
            verdict="partial", markers=partial[:8])]
    return [finding(
        "tamper_self_check_absent",
        "Tamper self-check ABSENT: no signature self-verification, "
        "no Play Integrity/App Attest, no APK/DEX hash comparison - "
        "a repackaged build is indistinguishable to the app/backend",
        "medium", source="DEX strings", confidence=72,
        verdict="absent")]


class AppTamperingHashVerifyPlugin(Cat7Plugin):
    id = "app_tampering_hash_verify"
    label = "App Tampering Hash Verify"
    description = ("Scans an operator-supplied package for in-app "
                   "tamper self-checks (signature verification, Play "
                   "Integrity, hash comparison); verdict present / "
                   "partial / absent.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_tamper_checks(art.get("all_text") or "")
