"""Attestation posture scan (Cat-7 #198, VARIANT of binex).

Posture DETECTION only - no simulated or spoofed attestation
responses are generated. Scans DEX for SafetyNet / Play Integrity
references and for signs the verdict is trusted client-side only
(no nonce / server-verification markers), plus basicIntegrity /
ctsProfile reliance patterns.
"""
from __future__ import annotations

from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

ATTEST = ("SafetyNet", "SafetyNetClient", "attest", "PlayIntegrity",
          "IntegrityManager", "IntegrityTokenRequest")
SERVER_MARKERS = ("nonce", "verifyAttestation", "serverVerify",
                  "checkIntegrityToken", "backend", "/verify")
CLIENT_ONLY = ("basicIntegrity", "ctsProfileMatch")


def analyze_attestation(text: str) -> List[Dict]:
    if not text:
        return []
    used = sorted(a for a in ATTEST if a in text)
    if not used:
        return [finding(
            "attestation_absent",
            "No SafetyNet / Play Integrity attestation references in "
            "the app - the backend cannot distinguish a genuine app "
            "on a genuine device from a script",
            "medium", source="DEX strings", confidence=72,
            posture="absent")]
    out: List[Dict] = []
    server = sorted(m for m in SERVER_MARKERS if m in text)
    client = sorted(c for c in CLIENT_ONLY if c in text)
    if client and not server:
        out.append(finding(
            "attestation_client_only_trust",
            f"Attestation verdict appears trusted CLIENT-side only "
            f"({', '.join(client[:3])} checked locally, no nonce / "
            f"server-verification markers) - verdicts can be forged "
            f"by a patched client",
            "high", source="DEX strings", confidence=76,
            posture="client-only-trust", apis=used[:6]))
    return out


class SafetynetAttestationSimulatorPlugin(Cat7Plugin):
    id = "safetynet_attestation_simulator"
    label = "SafetyNet Attestation Simulator (posture only)"
    description = ("Posture-only attestation scan of an operator-"
                   "supplied APK: API presence and client-only trust "
                   "patterns. No spoofed attestations are generated.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_attestation(art.get("all_text") or "")
