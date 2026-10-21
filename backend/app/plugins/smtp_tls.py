"""Mail server TLS (STARTTLS) audit plugin.

For each MX host: grabs the SMTP banner, checks STARTTLS is advertised,
and verifies the TLS handshake actually succeeds (many servers
advertise STARTTLS but fail the handshake - a downgrade trap). Also
flags cleartext-auth advertisement before TLS.

Detection only: banner reads + TLS handshake on the mail port. Nothing
is sent beyond EHLO/STARTTLS negotiation; no mail, no auth attempts.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from typing import List, Optional

import dns.asyncresolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

BANNER_RE = re.compile(r"^(220)[^\r\n]*", re.M)


def _smtp_audit(host: str, timeout: float = 10.0) -> dict:
    """Blocking SMTP audit. Returns dict of observations."""
    out = {"host": host, "banner": "", "starttls": False,
           "tls_ok": False, "tls_version": "", "auth_plain": False,
           "error": ""}
    try:
        s = socket.create_connection((host, 25), timeout=timeout)
        s.settimeout(timeout)
    except Exception as e:
        out["error"] = f"connect failed: {e.__class__.__name__}"
        return out
    try:
        banner = s.recv(1024).decode("utf-8", "ignore")
        m = BANNER_RE.search(banner)
        out["banner"] = (m.group(0)[:120] if m else banner[:120]).strip()
        s.sendall(b"EHLO recon-probe\r\n")
        ehlo = b""
        try:
            while True:
                chunk = s.recv(4096)
                ehlo += chunk
                if not chunk or b"250 " in ehlo.split(b"\r\n")[-2:]:
                    break
                if len(ehlo) > 8192:
                    break
        except Exception:
            pass
        ehlo_s = ehlo.decode("utf-8", "ignore")
        out["starttls"] = "STARTTLS" in ehlo_s.upper()
        out["auth_plain"] = bool(re.search(r"AUTH.*PLAIN", ehlo_s, re.I))
        if out["starttls"]:
            try:
                s.sendall(b"STARTTLS\r\n")
                resp = s.recv(1024).decode("utf-8", "ignore")
                if resp.startswith("220"):
                    ctx_ = ssl.create_default_context()
                    tls = ctx_.wrap_socket(s, server_hostname=host)
                    out["tls_ok"] = True
                    out["tls_version"] = tls.version() or ""
                    tls.close()
                    return out
            except Exception as e:
                out["error"] = f"STARTTLS handshake failed: {e.__class__.__name__}"
                return out
        s.close()
    except Exception as e:
        out["error"] = f"audit failed: {e.__class__.__name__}"
    return out


class SmtpTlsPlugin(Plugin):
    id = "smtp_tls"
    label = "Mail Server TLS"
    accepts = ["domain", "email"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Audit MX hosts: STARTTLS advertisement, handshake "
                   "success, cleartext auth exposure.")
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        res = dns.asyncresolver.Resolver(configure=False)
        res.nameservers = ["8.8.8.8", "1.1.1.1"]
        res.timeout = 6
        res.lifetime = 10
        try:
            ans = await res.resolve(domain, "MX")
            mx_hosts = sorted({str(rr.exchange).rstrip(".")
                               for rr in ans})[:5]
        except Exception:
            return self._skipped("no MX records")
        if not mx_hosts:
            return self._skipped("no MX records")

        results = await asyncio.gather(
            *(asyncio.to_thread(_smtp_audit, h) for h in mx_hosts))
        findings: List = []
        for r in results:
            host = r["host"]
            if r["error"] and not r["banner"]:
                continue  # host down; dns/email_infra already note MX
            if not r["starttls"]:
                findings.append(self._f(
                    "network", "smtp_no_starttls",
                    f"MX {host} does not advertise STARTTLS - mail is "
                    "plaintext",
                    source="mail TLS audit", confidence=90, passive=True,
                    evidence={"severity": "medium", "host": host,
                              "banner": r["banner"],
                              "remediation": ("Enable STARTTLS on the MTA; "
                                              "plaintext SMTP leaks message "
                                              "contents in transit.")}))
            elif not r["tls_ok"]:
                findings.append(self._f(
                    "network", "smtp_starttls_broken",
                    f"MX {host} advertises STARTTLS but the handshake "
                    f"fails ({r['error']}) - downgrade trap",
                    source="mail TLS audit", confidence=85, passive=True,
                    evidence={"severity": "medium", "host": host,
                              "remediation": ("Fix the TLS config on the MTA "
                                              "(cert chain, protocols); a "
                                              "broken STARTTLS is worse than "
                                              "none because senders assume "
                                              "encryption.")}))
            elif r["tls_version"] in ("TLSv1", "TLSv1.1"):
                findings.append(self._f(
                    "network", "smtp_weak_tls",
                    f"MX {host} negotiates {r['tls_version']} - deprecated",
                    source="mail TLS audit", confidence=85, passive=True,
                    evidence={"severity": "medium", "host": host,
                              "version": r["tls_version"],
                              "remediation": ("Disable TLS 1.0/1.1 on the "
                                              "MTA; require TLS 1.2+.")}))
            if r["auth_plain"] and not r["tls_ok"]:
                findings.append(self._f(
                    "network", "smtp_cleartext_auth",
                    f"MX {host} advertises plaintext AUTH without working "
                    "TLS - credentials would cross the wire in cleartext",
                    source="mail TLS audit", confidence=85, passive=True,
                    evidence={"severity": "high", "host": host,
                              "remediation": ("Disable AUTH before STARTTLS "
                                              "completes (or fix TLS so AUTH "
                                              "is encrypted).")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"audited {len(mx_hosts)} MX hosts, {len(findings)} "
                   "findings")
