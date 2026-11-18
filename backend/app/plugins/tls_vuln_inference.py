"""TLS vulnerability-inference plugin (ported from ARTEX ssl_scanner.py).

Maps a live TLS handshake + the server certificate onto named
vulnerabilities: POODLE, BEAST, FREAK, Sweet32, Logjam, DROWN, weak RSA
keys, weak signature algorithms, and OCSP/CRL posture. Read-only: one
TLS handshake, no payloads, no oracles, no exploitation.

Ported from ARTEX `_check_vulnerabilities` + the cert checks in
`_get_certificate_info`, with corrections where ARTEX was wrong:
- ARTEX mapped TLS 1.1 -> Heartbleed. That is false (Heartbleed is
  CVE-2014-0160, an OpenSSL bug, not a protocol version) and is NOT
  ported. No Heartbleed finding exists in this plugin.
- ARTEX mapped RC4 -> CRIME. CRIME needs TLS compression, not RC4; RC4
  is already covered by ReconAnything's tls_config.py weak-cipher
  checks, so it is not re-emitted here.
- ARTEX's `_check_ocsp_stapling` never worked (TypeError: it passed an
  `ocsp_callback` kwarg that `SSLContext.wrap_socket` does not accept).
  OCSP is done properly here: AIA responder presence from the cert +
  the stapled response stdlib exposes as `SSLSocket.ocsp_response`.
- ARTEX's CRL check never downloaded the CRL, so it could never say
  "revoked". This port only reports CRL-distribution-point presence,
  never a revocation verdict.
- JA3/JA3S is not ported: ARTEX fabricated it with placeholder strings.
- ROBOT, CCS injection, Ticketbleed, Lucky13 need active oracle probing
  beyond a read-only handshake and are out of scope for this plugin.

Cert parsing uses `cryptography` (already a backend dependency).
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import Any, Dict, List, Optional

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Finding spec: (key, severity, human description). Severity is the
# evidence severity; Plugin._f normalizes it to low|medium|high.
_VULNS = {
    "poodle": ("tls_poodle", "high",
               "SSLv3 negotiated: POODLE (CVE-2014-3566) — CBC padding "
               "oracle, plaintext recovery."),
    "drown": ("tls_drown", "high",
              "SSLv2 negotiated: DROWN (CVE-2016-0800) — SSLv2 oracle "
              "decrypts modern TLS sessions."),
    "beast": ("tls_beast", "high",
              "TLS 1.0 negotiated: BEAST (CVE-2011-3389) — CBC IV "
              "predictability in TLS 1.0."),
    "sweet32": ("tls_sweet32", "high",
                "3DES/DES cipher negotiated: Sweet32 (CVE-2016-2183) — "
                "64-bit block ciphers leak plaintext after ~32GB."),
    "freak": ("tls_freak", "high",
              "EXPORT cipher negotiated: FREAK (CVE-2015-0204) — server "
              "accepts export-grade crypto, downgradeable."),
    "logjam": ("tls_logjam", "high",
               "EXPORT cipher negotiated: Logjam (CVE-2015-4000) — weak "
               "Diffie-Hellman, downgradeable."),
    "weak_rsa_key": ("tls_weak_rsa_key", "high",
                     "RSA public key under 1024 bits: factorable, and a "
                     "FREAK vector."),
    "weak_key": ("tls_weak_key", "medium",
                 "RSA public key under 2048 bits: below current minimum."),
    "weak_signature": ("tls_weak_signature", "medium",
                       "Certificate signed with a weak hash (SHA-1/MD5): "
                       "collision-forgable."),
}


def analyze_cert(der: bytes) -> Dict[str, Any]:
    """Parse a DER certificate into the facts the inference needs.

    Pure function (unit-tested with generated certs): key type/size,
    signature algorithm, OCSP responder URLs from AIA, and whether a CRL
    distribution point is present. Returns {} when the DER is unparsable.
    """
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return {}
    info: Dict[str, Any] = {}
    try:
        pub = cert.public_key()
        info["key_type"] = type(pub).__name__
        info["key_size"] = getattr(pub, "key_size", None)
    except Exception:
        info["key_type"] = None
        info["key_size"] = None
    try:
        info["sig_alg"] = cert.signature_algorithm_oid._name
    except Exception:
        info["sig_alg"] = ""
    ocsp_urls: List[str] = []
    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess).value
        for desc in aia:
            if desc.access_method == x509.OID_OCSP:
                ocsp_urls.append(desc.access_location.value)
    except Exception:
        pass
    info["ocsp_urls"] = ocsp_urls
    try:
        cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints)
        info["has_crl_dp"] = True
    except Exception:
        info["has_crl_dp"] = False
    return info


def infer_vulns(version: str, cipher: str, cert: Dict[str, Any],
                ocsp_response: Optional[bytes]) -> List[Dict[str, Any]]:
    """Map handshake + cert facts onto named-vuln finding specs.

    Pure function (unit-tested). Each item: {"name", "key", "severity",
    "detail"} where detail is the human-readable evidence string.
    """
    out: List[Dict[str, Any]] = []

    def _add(name: str, detail: str = "") -> None:
        key, sev, desc = _VULNS[name]
        out.append({"name": name, "key": key, "severity": sev,
                    "detail": f"{desc} {detail}".strip()})

    ver = (version or "").upper()
    if ver in ("SSLV3", "SSLV3.0"):
        _add("poodle", f"Negotiated version: {version}.")
        _add("drown", f"Negotiated version: {version}.")
    if ver in ("SSLV2", "SSLV2.0"):
        _add("drown", f"Negotiated version: {version}.")
    if ver in ("TLSV1", "TLS 1.0", "TLSV1.0"):
        _add("beast", f"Negotiated version: {version}.")
    ciph = (cipher or "").upper()
    if "3DES" in ciph or "DES" in ciph:
        _add("sweet32", f"Negotiated cipher: {cipher}.")
    # Export ciphers appear as IANA names (TLS_RSA_EXPORT_WITH_...) or
    # OpenSSL short names (EXP-RC4-MD5); ARTEX only matched "EXPORT".
    if "EXPORT" in ciph or ciph.startswith("EXP-") or ciph.startswith("EXP_"):
        _add("freak", f"Negotiated cipher: {cipher}.")
        _add("logjam", f"Negotiated cipher: {cipher}.")

    key_size = cert.get("key_size")
    key_type = (cert.get("key_type") or "").upper()
    if key_size is not None and "RSA" in key_type:
        if key_size < 1024:
            _add("weak_rsa_key", f"RSA key size: {key_size} bits.")
        elif key_size < 2048:
            _add("weak_key", f"RSA key size: {key_size} bits.")
    sig = (cert.get("sig_alg") or "").lower()
    if "sha1" in sig or "md5" in sig:
        _add("weak_signature", f"Signature algorithm: {cert.get('sig_alg')}.")

    ocsp_urls = cert.get("ocsp_urls") or []
    if ocsp_response:
        pass  # stapled response present: OCSP is working, no finding.
    elif ocsp_urls:
        out.append({"name": "ocsp_not_stapled", "key": "tls_ocsp_not_stapled",
                    "severity": "low",
                    "detail": "Certificate names an OCSP responder "
                              f"({ocsp_urls[0]}) but the server did not "
                              "staple an OCSP response; clients must make "
                              "a separate revocation check."})
    else:
        out.append({"name": "ocsp_missing", "key": "tls_ocsp_missing",
                    "severity": "low",
                    "detail": "Certificate carries no OCSP responder in "
                              "its Authority Information Access extension "
                              "and no stapled response was served; "
                              "revocation status cannot be checked "
                              "efficiently."})
    if not cert.get("has_crl_dp"):
        out.append({"name": "crl_dp_missing", "key": "tls_crl_dp_missing",
                    "severity": "low",
                    "detail": "Certificate carries no CRL distribution "
                              "point; revocation can only be checked via "
                              "OCSP, if at all."})
    return out


class TlsVulnInferencePlugin(Plugin):
    id = "tls_vuln_inference"
    label = "TLS Vuln Inference"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Named TLS vulnerabilities from the handshake + cert: "
                   "POODLE, BEAST, FREAK, Sweet32, Logjam, DROWN, weak "
                   "keys/signatures, OCSP/CRL posture.")
    phase = 1

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        try:
            hs = await asyncio.get_event_loop().run_in_executor(
                None, self._handshake, domain)
        except Exception as e:
            return self._degraded(f"TLS handshake failed: {e}" if str(e)
                                  else "TLS handshake failed")
        if not hs:
            return self._degraded("TLS handshake returned nothing")
        cert = analyze_cert(hs.get("der") or b"")
        specs = infer_vulns(hs.get("version") or "",
                            hs.get("cipher") or "", cert,
                            hs.get("ocsp_response"))
        findings: List[Finding] = []
        for spec in specs:
            findings.append(self._f(
                "web", spec["key"],
                f"{spec['detail']} ({domain}, negotiated "
                f"{hs.get('version') or 'unknown'} / "
                f"{hs.get('cipher') or 'unknown cipher'})",
                source="TLS handshake + certificate analysis",
                confidence=85, passive=True,
                evidence={"severity": spec["severity"],
                          "vuln": spec["name"],
                          "version": hs.get("version") or "",
                          "cipher": hs.get("cipher") or "",
                          "key_size": cert.get("key_size"),
                          "sig_alg": cert.get("sig_alg") or "",
                          "why": "A named TLS weakness is a concrete, "
                                 "checkable misconfiguration: disable the "
                                 "old protocol/cipher, replace the weak "
                                 "key or signature, or enable OCSP "
                                 "stapling, then re-scan."}))
        res = self._ok(findings,
                       f"analyzed TLS for {domain}: "
                       f"{len(findings)} named vuln finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    # -- helper (seam: tests monkeypatch _handshake) ----------------------

    def _handshake(self, host: str) -> Dict[str, Any]:
        """One TLS handshake; returns version/cipher/DER cert/OCSP.

        Same shape as tls.py's _get_cert (socket + wrap_socket in the
        executor). Raises on failure; the caller degrades.
        """
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return {
                    "version": ssock.version() or "",
                    "cipher": cipher[0] if cipher else "",
                    "der": ssock.getpeercert(binary_form=True) or b"",
                    "ocsp_response": getattr(ssock, "ocsp_response", None),
                }
