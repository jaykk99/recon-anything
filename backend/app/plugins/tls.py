"""TLS + email security plugin (Milestone 2/4).

TLS: cert chain summary, SAN list (harvests extra hostnames), issuer,
expiry. Email security: SPF, DMARC, BIMI, MTA-STS from DNS TXT records.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import List

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class TlsPlugin(Plugin):
    id = "tls"
    label = "TLS + Email Security"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Certificate details, SAN hostnames, SPF/DMARC/BIMI/MTA-STS posture."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        # --- TLS cert (direct socket; observational, no exploit) ---
        if mode == "active" or True:  # cert fetch is a normal handshake
            try:
                tls_info = await asyncio.get_event_loop().run_in_executor(
                    None, self._get_cert, domain)
                if tls_info:
                    cert = tls_info.get("cert") or {}
                    version = tls_info.get("version", "")
                    cipher = tls_info.get("cipher") or ()
                    subj = dict(x[0] for x in cert.get("subject", ()))
                    iss = dict(x[0] for x in cert.get("issuer", ()))
                    findings.append(self._f("infra", "tls_subject",
                                            subj.get("commonName", str(subj)),
                                            source="TLS handshake", confidence=95,
                                            passive=(mode == "passive")))
                    findings.append(self._f("infra", "tls_issuer",
                                            iss.get("organizationName", str(iss)),
                                            source="TLS handshake", confidence=95,
                                            passive=(mode == "passive")))
                    findings.append(self._f("infra", "tls_expires",
                                            str(cert.get("notAfter")),
                                            source="TLS handshake", confidence=95,
                                            passive=(mode == "passive")))
                    for san in cert.get("subjectAltName", []):
                        if san[0] == "DNS":
                            findings.append(self._f("dns", "tls_san", san[1],
                                                    source="TLS SAN harvest",
                                                    confidence=90,
                                                    passive=(mode == "passive")))

                    # TLS version check
                    weak_desc, weak_conf = self._check_tls_version(version)
                    if weak_desc:
                        findings.append(self._f(
                            "infra", "tls_weak_version", weak_desc,
                            source="TLS handshake", confidence=weak_conf,
                            evidence={"severity": "high" if weak_conf >= 90 else "medium"}))
                    elif version:
                        findings.append(self._f(
                            "infra", "tls_version", f"Negotiated: {version}",
                            source="TLS handshake", confidence=85,
                            passive=(mode == "passive")))

                    # Cipher suite check
                    if cipher:
                        cipher_name = cipher[0] if len(cipher) > 0 else ""
                        cipher_bits = cipher[2] if len(cipher) > 2 else 0
                        findings.append(self._f(
                            "infra", "tls_cipher",
                            f"Cipher: {cipher_name} ({cipher_bits} bits)",
                            source="TLS handshake", confidence=85,
                            passive=(mode == "passive")))
                        weak_ciphers = ("RC4", "DES", "3DES", "MD5", "NULL",
                                        "EXPORT", "anon", "PSK")
                        if any(w in cipher_name.upper() for w in weak_ciphers):
                            findings.append(self._f(
                                "infra", "tls_weak_cipher",
                                f"Weak cipher in use: {cipher_name}",
                                source="TLS handshake", confidence=80,
                                evidence={"severity": "medium"}))

                    # Cert expiry warning
                    try:
                        from datetime import datetime
                        exp = cert.get("notAfter", "")
                        # Format: 'Oct 19 12:00:00 2026 GMT'
                        exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_dt - datetime.utcnow()).days
                        if days_left < 0:
                            findings.append(self._f(
                                "infra", "tls_expired",
                                "TLS certificate EXPIRED",
                                source="TLS handshake", confidence=95,
                                evidence={"severity": "high"}))
                        elif days_left < 14:
                            findings.append(self._f(
                                "infra", "tls_expiring",
                                f"TLS certificate expires in {days_left} days",
                                source="TLS handshake", confidence=85,
                                evidence={"severity": "medium"}))
                    except Exception:
                        pass

                    # Self-signed / hostname mismatch indicators
                    cn = subj.get("commonName", "")
                    if iss.get("organizationName") == subj.get("organizationName") \
                            and subj.get("organizationName"):
                        findings.append(self._f(
                            "infra", "tls_self_signed",
                            "Certificate appears self-signed",
                            source="TLS handshake", confidence=70,
                            evidence={"severity": "medium"}))
            except Exception as e:
                findings.append(self._f("infra", "tls_note",
                                        f"TLS fetch failed: {str(e)[:120]}",
                                        source="TLS handshake", confidence=40))

        # --- email security from DNS ---
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 10

        async def txt(name: str) -> List[str]:
            try:
                ans = await resolver.resolve(name, "TXT")
                return [str(r).strip('"') for r in ans]
            except Exception:
                return []

        spf, _ = await ctx.cache.cached("dns", f"{domain}:TXT:spf", lambda: txt(domain))
        spf_recs = [t for t in spf if t.startswith("v=spf1")]
        if spf_recs:
            findings.append(self._f("infra", "spf", spf_recs[0][:300],
                                    source="DNS TXT", confidence=90, passive=True))
            if "+all" in spf_recs[0] or "?all" in spf_recs[0]:
                findings.append(self._f("leak", "spf_weak",
                                        "SPF allows any sender (+all/?all)",
                                        source="DNS TXT", confidence=85, passive=True))
        else:
            findings.append(self._f("infra", "spf", "no SPF record",
                                    source="DNS TXT", confidence=85, passive=True))

        dmarc, _ = await ctx.cache.cached("dns", f"{domain}:TXT:dmarc",
                                          lambda: txt(f"_dmarc.{domain}"))
        dmarc_recs = [t for t in dmarc if t.startswith("v=DMARC1")]
        if dmarc_recs:
            findings.append(self._f("infra", "dmarc", dmarc_recs[0][:300],
                                    source="DNS TXT", confidence=90, passive=True))
            if "p=none" in dmarc_recs[0]:
                findings.append(self._f("leak", "dmarc_weak",
                                        "DMARC policy is p=none (monitoring only)",
                                        source="DNS TXT", confidence=80, passive=True))
        else:
            findings.append(self._f("infra", "dmarc", "no DMARC record",
                                    source="DNS TXT", confidence=85, passive=True))

        bimi, _ = await ctx.cache.cached("dns", f"{domain}:TXT:bimi",
                                         lambda: txt(f"default._bimi.{domain}"))
        if any(t.startswith("v=BIMI1") for t in bimi):
            findings.append(self._f("infra", "bimi", "BIMI record present",
                                    source="DNS TXT", confidence=85, passive=True))

        # DKIM: check common selectors
        dkim_found = False
        for selector in ("default", "google", "k1", "s1", "s2", "selector1",
                         "selector2", "everlytickey1", "cm", "mail"):
            dkim_txt, _ = await ctx.cache.cached(
                "dns", f"{selector}._domainkey.{domain}",
                lambda s=selector: txt(f"{s}._domainkey.{domain}"))
            if any("v=DKIM1" in t or "k=rsa" in t for t in dkim_txt):
                findings.append(self._f(
                    "infra", "dkim",
                    f"DKIM selector '{selector}' published",
                    source="DNS TXT", confidence=85, passive=True))
                dkim_found = True
                break
        if not dkim_found:
            findings.append(self._f(
                "infra", "dkim",
                "No common DKIM selector found - email signing may be missing",
                source="DNS TXT", confidence=65, passive=True))

        # MX record analysis for email spoofing risk
        mx_recs = []
        try:
            mx_ans = await resolver.resolve(domain, "MX")
            mx_recs = [str(r.exchange).rstrip(".") for r in mx_ans]
        except Exception:
            pass
        if mx_recs:
            findings.append(self._f(
                "infra", "mx_records",
                f"MX: {', '.join(mx_recs[:5])}",
                source="DNS MX", confidence=90, passive=True))
        else:
            findings.append(self._f(
                "infra", "mx_records",
                "No MX records - domain cannot receive email",
                source="DNS MX", confidence=85, passive=True))

        # MTA-STS via HTTPS policy file
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                            timeout=12)
            if r.status_code == 200 and "version: STSv1" in r.text:
                findings.append(self._f("infra", "mta_sts", "MTA-STS policy published",
                                        source="mta-sts TXT/HTTPS", confidence=85,
                                        passive=True))
        except Exception:
            pass

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"TLS + email security for {domain}")
        res.duration_ms = dur
        return res

    @staticmethod
    def _get_cert(domain: str):
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return {
                    "cert": ssock.getpeercert(),
                    "version": ssock.version(),
                    "cipher": ssock.cipher(),
                }

    @staticmethod
    def _check_tls_version(version: str) -> tuple:
        """Return (is_weak, description)."""
        weak = {
            "TLSv1": ("TLS 1.0 enabled - deprecated, POODLE/BEAST risk", 75),
            "TLSv1.1": ("TLS 1.1 enabled - deprecated", 70),
            "SSLv3": ("SSLv3 enabled - critically broken (POODLE)", 95),
            "SSLv2": ("SSLv2 enabled - critically broken", 95),
        }
        return weak.get(version, (None, 0))
