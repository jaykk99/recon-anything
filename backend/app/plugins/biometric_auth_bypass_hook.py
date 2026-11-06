"""Biometric auth posture audit (Cat-7 #190, VARIANT of binex).

DETECTION ONLY - reports whether biometric checks exist in an
operator-supplied package and whether they are weak. No simulated-
positive hook, no bypass of any kind. Weak patterns: crypto-less
success callback, device-credential-only fallback, deprecated
FingerprintManager, LAContext device-owner fallback.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

USAGE = ("BiometricPrompt", "FingerprintManager", "LAContext",
         "canEvaluatePolicy", "evaluatePolicy")
CRYPTO_BINDING = ("CryptoObject", "Cipher", "Mac", "Signature")


def analyze_biometric(text: str) -> List[Dict]:
    out: List[Dict] = []
    if not text:
        return out
    used = sorted(u for u in USAGE if u in text)
    if not used:
        return out
    if "FingerprintManager" in text and "BiometricPrompt" not in text:
        out.append(finding(
            "biometric_deprecated_api",
            "Deprecated FingerprintManager used without "
            "BiometricPrompt (no unified weak/strong authenticator "
            "model)", "medium", source="DEX/Mach-O strings",
            confidence=80))
    success_cb = "onAuthenticationSucceeded" in text or \
        "evaluatePolicy" in text
    bound = "CryptoObject" in text and \
        any(c in text for c in CRYPTO_BINDING)
    if success_cb and not bound and "LAContext" not in text:
        out.append(finding(
            "biometric_no_crypto_binding",
            "Biometric success callback is NOT bound to a "
            "BiometricPrompt.CryptoObject - a positive result unlocks "
            "nothing cryptographic and can be spoofed locally",
            "high", source="DEX strings", confidence=78))
    if "DEVICE_CREDENTIAL" in text and "BIOMETRIC_STRONG" not in text:
        out.append(finding(
            "biometric_credential_only_fallback",
            "Biometric prompt allows DEVICE_CREDENTIAL without "
            "requiring BIOMETRIC_STRONG authenticators",
            "medium", source="DEX strings", confidence=75))
    if "deviceOwnerAuthentication" in text or \
            "LAPolicyDeviceOwnerAuthentication" in text:
        out.append(finding(
            "biometric_device_owner_fallback",
            "LAContext policy is deviceOwnerAuthentication (passcode "
            "fallback counts as biometric success)",
            "medium", source="Mach-O strings", confidence=75))
    return out


class BiometricAuthBypassHookPlugin(Cat7Plugin):
    id = "biometric_auth_bypass_hook"
    label = "Biometric Auth Bypass Hook (posture only)"
    description = ("DETECTION ONLY: biometric-posture audit of an "
                   "operator-supplied package (weak patterns, missing "
                   "CryptoObject binding). No bypass hook.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_biometric(art.get("all_text") or "")
