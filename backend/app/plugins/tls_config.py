"""TLS protocol + cipher configuration audit plugin.

tls.py covers certificates; this plugin covers the *configuration*:
- which TLS versions the server negotiates (1.0/1.1 = deprecated),
- weak cipher suites (RC4, 3DES, export, NULL, anon),
- TLS compression (CRIME),
- missing forward secrecy on the negotiated cipher.

Detection only: TLS handshakes with version/cipher offers. Runs in
threads (blocking sockets).
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

WEAK_CIPHER_FRAGS = ("RC4", "DES", "3DES", "EXPORT", "NULL", "anon",
                     "MD5", "IDEA", "SEED", "CAMELLIA-128")


def _probe(host: str, versions: Tuple) -> Tuple[Optional[str], str, bool]:
    """Try handshakes restricted to `versions`. Returns (negotiated, cipher,
    compression_on)."""
    for ver in versions:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ver
        ctx.maximum_version = ver
        # include a weak cipher so we can observe if the server picks one
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            pass
        try:
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher() or ("", "", 0)
                    comp = bool(getattr(ssock, "compression", lambda: None)())
                    return ssock.version(), cipher[0], comp
        except Exception:
            continue
    return None, "", False


class TlsConfigPlugin(Plugin):
    id = "tls_config"
    label = "TLS Config Audit"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Audit TLS versions, weak ciphers, compression (CRIME) "
                   "and forward secrecy.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        order = [ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2,
                 ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1]
        # Filter versions the local OpenSSL still allows (some builds drop
        # 1.0/1.1 entirely - then "not offered by us" != "not supported").
        usable = []
        for ver in order:
            try:
                c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c.minimum_version = c.maximum_version = ver
                usable.append(ver)
            except Exception:
                pass
        if not usable:
            return self._degraded("local OpenSSL cannot do version probes")

        probes = await asyncio.gather(
            *(asyncio.to_thread(_probe, domain, (ver,)) for ver in usable))
        supported = {str(ver): res for ver, res in zip(usable, probes)
                     if res[0]}
        findings: List = []
        if not supported:
            return self._degraded("no TLS handshake succeeded")
        best = max(supported, key=lambda v: usable.index(
            next(x for x in usable if str(x) == v)))
        best_cipher = supported[best][1]

        for ver in ("TLSv1", "TLSv1.1"):
            if ver in supported:
                findings.append(self._f(
                    "web", "tls_deprecated_version",
                    f"{domain} negotiates deprecated {ver}",
                    source="TLS config audit", confidence=90, passive=True,
                    evidence={"severity": "medium", "version": ver,
                              "remediation": ("Disable TLS 1.0/1.1; require "
                                              "TLS 1.2+ (PCI DSS and all "
                                              "modern browsers agree).")}))
        weak = [f for f in WEAK_CIPHER_FRAGS
                if f in best_cipher.upper().replace("_", "")]
        # 3DES appears as DES in OpenSSL names; match carefully.
        if any(w in best_cipher for w in ("RC4", "EXP", "NULL", "aNULL")):
            weak = list(dict.fromkeys(weak + ["explicit"]))
        if weak and weak != ["explicit"]:
            findings.append(self._f(
                "web", "tls_weak_cipher",
                f"{domain} negotiates weak cipher {best_cipher} ({best})",
                source="TLS config audit", confidence=85, passive=True,
                evidence={"severity": "medium", "cipher": best_cipher,
                          "version": best,
                          "remediation": ("Restrict ciphers to "
                                          "ECDHE+AESGCM / ChaCha20 suites; "
                                          "drop RC4/3DES/export/NULL.")}))
        cipher_up = best_cipher.upper()
        if ("ECDHE" not in cipher_up and "DHE" not in cipher_up
                and "TLS_AES" not in cipher_up and "TLS_CHACHA" not in cipher_up
                and best_cipher):
            findings.append(self._f(
                "web", "tls_no_forward_secrecy",
                f"{domain} negotiates {best_cipher} without forward secrecy",
                source="TLS config audit", confidence=80, passive=True,
                evidence={"severity": "low", "cipher": best_cipher,
                          "remediation": ("Prefer ECDHE/DHE suites so a "
                                          "future key compromise cannot "
                                          "decrypt past traffic.")}))
        if any(res[2] for res in supported.values()):
            findings.append(self._f(
                "web", "tls_compression",
                f"{domain} negotiates TLS compression (CRIME risk)",
                source="TLS config audit", confidence=90, passive=True,
                evidence={"severity": "medium",
                          "remediation": ("Disable TLS compression "
                                          "server-side.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"TLS versions offered: {sorted(supported)}, "
                   f"{len(findings)} config issues")
