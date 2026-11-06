"""A2SV-style SSL/TLS vulnerability scanner (Tier-4 Vuln/CVE).

Protocol-level DETECTION only:
  * protocol support matrix - a completed handshake pinned to
    SSLv3 / TLS 1.0 / TLS 1.1 is a finding (deprecated protocols),
  * weak cipher suites - a handshake that succeeds when the client
    offers only legacy ciphers (RC4/DES/3DES/EXPORT/NULL class) is
    a finding,
  * certificate issues - expired / not-yet-valid, self-signed
    (issuer == subject), and hostname mismatch (the verified
    handshake failing on the name).
No exploit payloads of any kind: there is deliberately NO Heartbleed
probe - heartbeat risk is assessed only from handshake metadata the
server volunteers, and this plugin reports nothing about heartbeat
it cannot see in that metadata (it does not claim a check it did
not perform).
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

PROTOCOLS: List[Tuple[str, Optional[int], str]] = [
    # (label, ssl.TLSVersion value or None, severity-if-supported)
    ("SSLv3", None, "high"),       # offered via minimum/maximum pin
    ("TLSv1.0", ssl.TLSVersion.TLSv1, "medium"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "medium"),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ""),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ""),
]
WEAK_CIPHERS = "RC4:DES-CBC3-SHA:DES-CBC-SHA:EXP:NULL:eNULL:aNULL:MD5"


def assess_tls(matrix: Dict[str, bool], weak_ok: bool,
               cert: Dict) -> List[Tuple[str, str, str]]:
    """Pure assessment: (key, value, severity) findings from a
    completed probe matrix. Unit-testable without sockets."""
    out: List[Tuple[str, str, str]] = []
    for label, _v, sev in PROTOCOLS:
        if sev and matrix.get(label):
            out.append(("tls_deprecated_protocol",
                        f"Deprecated protocol supported: {label} "
                        "handshake completed", sev))
    if weak_ok:
        out.append(("tls_weak_cipher",
                    "Server accepted a legacy-only cipher offer "
                    "(RC4/DES/3DES/EXPORT/NULL class)", "high"))
    if cert:
        if cert.get("self_signed"):
            out.append(("tls_self_signed_cert",
                        "Certificate is self-signed (issuer == subject)",
                        "medium"))
        if cert.get("expired"):
            out.append(("tls_expired_cert",
                        f"Certificate expired (notAfter "
                        f"{cert.get('not_after')})", "high"))
        if cert.get("not_yet_valid"):
            out.append(("tls_cert_not_yet_valid",
                        "Certificate is not yet valid", "medium"))
        if cert.get("hostname_mismatch"):
            out.append(("tls_hostname_mismatch",
                        "Certificate name does not match the hostname",
                        "medium"))
    return out


def _cert_facts(cert: Dict) -> Dict:
    facts: Dict = {"self_signed": False, "expired": False,
                   "not_yet_valid": False, "not_after": None}
    try:
        subj = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
        iss = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
        facts["self_signed"] = bool(subj) and subj == iss
        na = cert.get("notAfter")
        facts["not_after"] = na
        if na:
            dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
            dt = dt.replace(tzinfo=timezone.utc)
            facts["expired"] = dt < datetime.now(timezone.utc)
        nb = cert.get("notBefore")
        if nb:
            dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z")
            dt = dt.replace(tzinfo=timezone.utc)
            facts["not_yet_valid"] = dt > datetime.now(timezone.utc)
    except Exception:
        pass
    return facts


async def _handshake(host: str, port: int, ctx_ssl: ssl.SSLContext,
                     timeout: float = 6.0):
    """One TLS handshake; returns (ssl_object_dict, cert) or None."""
    def _do():
        with socket.create_connection((host, port), timeout=timeout) \
                as raw:
            with ctx_ssl.wrap_socket(raw, server_hostname=host) as s:
                return {"version": s.version(), "cipher": s.cipher(),
                        "cert": s.getpeercert()}
    try:
        return await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, _do),
            timeout=timeout + 3)
    except Exception:
        return None


class A2svScanPlugin(Plugin):
    id = "a2sv_scan"
    label = "A2SV TLS Vuln Scan"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = ("A2SV-style TLS scan: deprecated protocol matrix "
                   "(SSLv3/TLS1.0/1.1), weak-cipher handshake, cert "
                   "expiry/self-signed/hostname checks. Handshakes "
                   "only - no exploit payloads, no Heartbleed probe.")
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        port = 443
        if target.type == "url":
            from urllib.parse import urlparse
            p = urlparse(target.normalized)
            if p.port:
                port = p.port
            if p.scheme == "http" and not p.port:
                return self._skipped("plain-http target has no TLS "
                                     "endpoint to assess")
        matrix: Dict[str, bool] = {}
        cert: Dict = {}
        main_cert: Dict = {}
        # Probe modern protocols first: if neither TLS1.2 nor TLS1.3
        # completes, the host has no assessable TLS endpoint - bail
        # instead of burning a handshake timeout per legacy protocol.
        ordered = sorted(
            PROTOCOLS, key=lambda p: 0 if p[0] in
            ("TLSv1.3", "TLSv1.2") else 1)
        probed_modern = False
        for label, ver, _sev in ordered:
            if probed_modern and not any(matrix.values()):
                break
            if label in ("TLSv1.3",):
                probed_modern = True
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            try:
                if label == "SSLv3":
                    c.minimum_version = ssl.TLSVersion.SSLv3
                    c.maximum_version = ssl.TLSVersion.SSLv3
                elif ver is not None:
                    c.minimum_version = ver
                    c.maximum_version = ver
                c.set_ciphers("ALL:@SECLEVEL=0")
            except Exception:
                matrix[label] = False
                continue
            res = await _handshake(domain, port, c)
            matrix[label] = bool(res)
            if res and label in ("TLSv1.2", "TLSv1.3") and not main_cert:
                main_cert = res.get("cert") or {}
        if not any(matrix.values()):
            return self._degraded(
                f"no TLS handshake completed on {domain}:{port}")
        if main_cert:
            cert = _cert_facts(main_cert)
        # hostname verification (verified handshake)
        vc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        vc.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            vc.load_default_certs()
        except Exception:
            pass
        vres = await _handshake(domain, port, vc)
        if vres is None and (matrix.get("TLSv1.2") or
                             matrix.get("TLSv1.3")):
            cert["hostname_mismatch"] = True
        # weak-cipher handshake
        wc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        wc.check_hostname = False
        wc.verify_mode = ssl.CERT_NONE
        weak_ok = False
        try:
            wc.set_ciphers(WEAK_CIPHERS + ":@SECLEVEL=0")
            weak_ok = bool(await _handshake(domain, port, wc))
        except Exception:
            weak_ok = False
        findings: List[Finding] = []
        for key, value, sev in assess_tls(matrix, weak_ok, cert):
            findings.append(self._f(
                "infra", key, value, source="a2sv tls handshake",
                source_url=f"https://{domain}:{port}", confidence=90,
                passive=False,
                evidence={"severity": sev, "matrix": matrix,
                          "remediation": (
                              "Disable SSLv3/TLS1.0/TLS1.1 and legacy "
                              "ciphers at the terminator; keep TLS1.2+ "
                              "with AEAD suites and a valid, matching, "
                              "CA-signed certificate.")}))
        supported = [k for k, v in matrix.items() if v]
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=(f"a2sv matrix for {domain}:{port}: supported="
                    f"{supported}, weak_cipher_accepted={weak_ok}, "
                    f"{len(findings)} findings; heartbeat not probed "
                    "(metadata-only policy)"))
