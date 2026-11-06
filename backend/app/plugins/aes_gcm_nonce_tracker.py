"""SHIP 71: static scanning plus supplied-record IV set comparison. Never attempts decryption."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


def analyze(text, objs):
    out = []
    seen = {}
    records = []
    for v in find_values(objs, "records"):
        if isinstance(v, list):
            records.extend([r for r in v if isinstance(r, dict)])
    if isinstance(objs, list):
        records.extend([o for o in objs if isinstance(o, dict) and ("iv" in o or "nonce" in o)])
    for r in records:
        iv = str(r.get("iv") or r.get("nonce") or "").lower()
        if iv:
            seen[iv] = seen.get(iv, 0) + 1
    for iv, n in seen.items():
        if n > 1:
            out.append(("aes_gcm_iv_reuse",
                        f"AES-GCM IV {iv[:8]}... (masked) is reused across {n} supplied ciphertext records under one key context; GCM IV reuse breaks confidentiality and the GHASH key",
                        "high", "Use a unique 12-byte IV per encryption under a key (random with a strict record cap, or a persistent counter)."))
            break
    if "gcm" in text.lower() or "aesgcm" in text.lower():
        m = re.search(r"urandom\((\d+)\)|randombytes\((\d+)\)|getrandbits\((\d+)\)", text)
        if m:
            bits = int(next(g for g in m.groups() if g))
            nbytes = bits // 8 if bits > 32 else bits
            if nbytes < 12:
                out.append(("aes_gcm_short_iv",
                            f"AES-GCM IV is generated with only {nbytes} bytes (< 12); short IVs raise collision/reuse risk",
                            "medium", "Generate a full 12-byte (96-bit) IV per message."))
        mt = re.search(r"tag_(?:length|bits)\s*[:=]\s*(\d+)", text)
        if mt and int(mt.group(1)) < 96:
            out.append(("aes_gcm_truncated_tag",
                        f"AES-GCM authentication tag is truncated to {mt.group(1)} bits (< 96)",
                        "medium", "Use a full 128-bit GCM tag, or at minimum 96 bits."))
        if rx(text, r"\biv\s*=\s*b[\"\'][^\"\']+[\"\']"):
            out.append(("aes_gcm_hardcoded_iv",
                        "AES-GCM IV is a hardcoded literal in the supplied code",
                        "high", "Generate a fresh unique IV per encryption and store/transmit it with the ciphertext."))
    return out[:8]


class AesGcmNonceTracker(Plugin):
    id = "aes_gcm_nonce_tracker"
    label = "AES-GCM Nonce Tracker"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Flags AES-GCM nonce hazards in supplied code (short/random-repeating IVs, truncated tags) and literal IV reuse across supplied ciphertext records."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
