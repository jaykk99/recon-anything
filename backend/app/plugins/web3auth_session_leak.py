"""Web3Auth session leak audit (Cat-4 variant of jwt).

Web3Auth/Torus-specific audit of OPERATOR-SUPPLIED storage dumps and
served bundles: Web3Auth key shares and session material persisted in
localStorage/sessionStorage (share keys, tss shares, oauth-derived
keys, session ids) mean anyone with the dump - or any XSS on the
origin - can reconstruct the user's wallet key.

BOUNDARY: operator-supplied artifacts only. Evidence is MASKED
(short prefix + length + SHA-256 fingerprint); full secret values
are never copied into findings. No third-party system access.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts, fingerprint, mask_value
from .base import Cost, Ctx, Plugin, PluginResult, Target

# "key": "value" pairs in storage dumps / bundle constants.
PAIR_RE = re.compile(r"""['"]([^'"]{2,80})['"]\s*:\s*['"]([^'"]{8,600})['"]""")
CONTEXT_HINTS = ("web3auth", "torus", "openlogin", "tss", "web3 auth")
KEY_MATERIAL = ("privkey", "private_key", "share", "sharekey",
                "oauth_key", "oauthkey", "sessionkey", "session_key",
                "seed", "mnemonic", "key_material", "combinedkey")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def scan_web3auth_material(text: str) -> List[Dict[str, Any]]:
    """Pure: one dump/bundle text -> MASKED key-material hits."""
    hits: List[Dict[str, Any]] = []
    if not isinstance(text, str) or not text:
        return hits
    low = text.lower()
    has_context = any(h in low for h in CONTEXT_HINTS)
    for m in PAIR_RE.finditer(text):
        key, value = m.group(1), m.group(2)
        kl = key.lower()
        is_material = any(k in kl for k in KEY_MATERIAL)
        looks_secret = bool(HEX64_RE.match(value.strip())) \
            or len(value) >= 43
        if is_material and (has_context or "web3auth" in kl
                            or "torus" in kl) and looks_secret:
            hits.append({
                "key_name": key,
                "context": "web3auth" if ("web3auth" in kl
                                          or has_context) else "torus",
                "masked": mask_value(value),
                "fingerprint": fingerprint(value),
                "storage_hint": "localStorage"
                if "localstorage" in low else "artifact"})
    # dedupe by key name + fingerprint
    seen, out = set(), []
    for h in hits:
        k = (h["key_name"], h["fingerprint"])
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


class Web3authSessionLeakPlugin(Plugin):
    id = "web3auth_session_leak"
    label = "Web3Auth Session/Share Leak Audit"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Web3Auth/Torus share and session material in "
                   "supplied storage dumps/bundles, reported masked "
                   "with fingerprint only. Operator artifacts only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            for where, text, url in await all_texts(ctx, target):
                for hit in scan_web3auth_material(text):
                    findings.append(self._f(
                        "leak", "web3auth_key_material_stored",
                        f"Web3Auth key material '{hit['key_name']}' "
                        f"persisted in {hit['storage_hint']}: "
                        f"{hit['masked']} (sha256 fp "
                        f"{hit['fingerprint']})",
                        source=f"web3auth session audit: {where}",
                        source_url=url or None, confidence=90,
                        evidence={
                            "severity": "high", "hit": hit,
                            "remediation": "Never persist assembled key "
                            "material or long-lived shares in web "
                            "storage; keep shares in memory only and "
                            "rotate the affected wallet's shares."}))
            res = self._ok(findings,
                           f"{len(findings)} Web3Auth leaks found"
                           if findings else "no Web3Auth key material")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
