"""SHIP 87: static code scanning only."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    t = text.lower()
    if has(text, "mac-then-encrypt", "mac_then_encrypt", "mac then encrypt"):
        out.append(("mac_then_encrypt_composition",
                    "MAC-then-Encrypt composition is used; the ciphertext is unauthenticated, exposing a padding-oracle / ciphertext-malleability surface",
                    "high", "Use an AEAD mode (AES-GCM, ChaCha20-Poly1305), or Encrypt-then-MAC with independent keys."))
        return out
    m_mac = re.search(r"(?:hmac|mac)\s*\([^)]*plain", text, re.I)
    m_enc = re.search(r"encrypt\s*\(", text, re.I)
    if m_mac and m_enc and m_mac.start() < m_enc.start() and ("cbc" in t or "ctr" in t):
        out.append(("mac_then_encrypt_composition",
                    "A MAC is computed over the plaintext before CBC/CTR encryption in the supplied code (MAC-then-Encrypt); decryption must process unauthenticated ciphertext first",
                    "high", "Switch to an AEAD mode or Encrypt-then-MAC."))
    elif ("cbc" in t and "hmac" in t and not has(text, "encrypt-then-mac", "encrypt_then_mac", "aead", "gcm")):
        if rx(text, r"hmac[^;\n]{0,80}plaintext"):
            out.append(("mac_then_encrypt_composition",
                        "CBC encryption is combined with an HMAC over the plaintext (MAC-then-Encrypt shape)",
                        "medium", "Switch to an AEAD mode or Encrypt-then-MAC."))
    return out[:6]


class MacThenEncryptDetector(Plugin):
    id = "mac_then_encrypt_detector"
    label = "MAC-then-Encrypt Detector"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Detects MAC-then-Encrypt composition in supplied code: a MAC over the plaintext applied before CBC/CTR encryption, and hand-rolled compositions where an AEAD mode was available."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
