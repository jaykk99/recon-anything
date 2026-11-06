"""tlsx-style TLS certificate inspection (native, keyless).

Performs a normal TLS handshake against the target's own host (443,
plus 8443 when it answers) and inspects the presented certificate:
SANs, issuer, expiry (expired / expiring-soon are flagged), protocol
and cipher from the handshake, and the self-signed flag. Read-only.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import time
from typing import Dict, List, Optional

from ._tier2_common import host_of, tls_probe
from .base import Cost, Ctx, Plugin, PluginResult, Target

EXPIRY_WARN_DAYS = 30
WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3", "SSLV2", "SSLV3"}


def parse_cert_date(value: str) -> Optional[dt.datetime]:
    """Parse an OpenSSL-style cert date ('Jun  1 12:00:00 2027 GMT')."""
    if not value or not isinstance(value, str):
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y UTC",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(" ".join(value.split()), fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed
        except Exception:
            continue
    return None


def classify_cert(cert: Dict, now: Optional[dt.datetime] = None) -> List[str]:
    """Pure classification: returns issue tags for a cert dict.

    Tags: expired, expiring_soon, self_signed, weak_protocol.
    Malformed input yields [] instead of raising.
    """
    issues: List[str] = []
    if not isinstance(cert, dict) or not cert:
        return issues
    now = now or dt.datetime.now(dt.timezone.utc)
    expires = parse_cert_date(str(cert.get("not_after", "")))
    if expires is not None:
        if expires <= now:
            issues.append("expired")
        elif (expires - now).days <= EXPIRY_WARN_DAYS:
            issues.append("expiring_soon")
    if cert.get("self_signed"):
        issues.append("self_signed")
    if str(cert.get("protocol", "")) in WEAK_PROTOCOLS:
        issues.append("weak_protocol")
    return issues


class TlsxPlugin(Plugin):
    id = "tlsx"
    label = "tlsx Cert Inspect"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    timeout_s = 60
    description = ("TLS certificate inspection: SANs, issuer, expiry, "
                   "protocol/cipher and self-signed flag, from a "
                   "read-only handshake on the target's own host.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = host_of(target)
        if not host:
            return self._skipped("no host for this target type")
        findings = []
        for port in (443, 8443):
            cert = await asyncio.to_thread(tls_probe, host, port)
            if not cert:
                continue
            sans = cert.get("san", []) or []
            findings.append(self._f(
                "infra", "tlsx_certificate",
                f"TLS cert on {host}:{port}: {cert.get('subject', '')[:100]} "
                f"issued by {cert.get('issuer', '')[:80]}, expires "
                f"{cert.get('not_after', '')}, {cert.get('protocol', '')} "
                f"{cert.get('cipher', '')}, SANs: {', '.join(sans[:6])}",
                source="tlsx handshake", confidence=95, passive=False,
                evidence={"severity": "low", "port": port,
                          "subject": cert.get("subject", ""),
                          "issuer": cert.get("issuer", ""),
                          "san": sans[:20],
                          "not_after": cert.get("not_after", ""),
                          "protocol": cert.get("protocol", ""),
                          "cipher": cert.get("cipher", ""),
                          "remediation": "Keep certificates valid, "
                                         "in-date and issued by a "
                                         "trusted CA."}))
            for san in sans[:20]:
                ctx.publish("cert_sans", san)
            sev = {"expired": "high", "expiring_soon": "medium",
                   "self_signed": "medium", "weak_protocol": "medium"}
            for issue in classify_cert(cert):
                findings.append(self._f(
                    "infra", f"tlsx_{issue}",
                    f"TLS issue on {host}:{port}: {issue} "
                    f"(expires {cert.get('not_after', '')}, "
                    f"protocol {cert.get('protocol', '')})",
                    source="tlsx handshake", confidence=95, passive=False,
                    evidence={"severity": sev.get(issue, "low"),
                              "port": port, "issue": issue,
                              "not_after": cert.get("not_after", ""),
                              "remediation": "Renew/replace the "
                                             "certificate and disable "
                                             "TLS below 1.2."}))
        if not findings:
            res = self._degraded(f"no TLS service answered on {host}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        res = self._ok(findings, f"{len(findings)} TLS findings on {host}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
