"""Bank infrastructure detectors (fin_* pack, infrastructure family).

Eight detection-only checks: a certificate trio for banking hosts
(expired, name mismatch, weak key/signature/protocol - read from the
presented certificate during a normal TLS handshake), staging/UAT
banking environments, certificate-transparency names that betray
internal systems, public status pages naming internal core systems,
spoofable alert-sender subdomains, and third-party scripts loaded on
login/payment pages (skimming risk). No logins, no credential use,
no transactions.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .bankpack_util import (FinPlugin, doh, fetch_paths, fetch_text,
                            parse_json_text)
from .base import Ctx, PluginResult, Target

# ---------------------------------------------------------------------------
# 33-35. Certificate trio (expired / mismatch / weak)
# ---------------------------------------------------------------------------


def _host_port(target: Target) -> Tuple[Optional[str], int]:
    n = target.normalized or ""
    if target.type == "url":
        u = urlparse(n if "://" in n else f"https://{n}")
        if u.hostname:
            return u.hostname, u.port or 443
    host = re.sub(r"^(https?://)?(www\.)?", "", n).split("/")[0] \
        .split(":")[0].strip().lower()
    return (host or None), 443


def grab_cert(host: str, port: int, timeout: float = 3.0):
    """TLS handshake; returns (x509 cert, negotiated version).

    Reads only what the server presents to any client. Raises on any
    failure - callers degrade to ok(0).
    """
    from cryptography import x509
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sctx.check_hostname = False
    sctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with sctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            version = tls.version()
    return x509.load_der_x509_certificate(der), version


def cert_summary(cert, tls_version: Optional[str]) -> Dict:
    """Plain-dict certificate facts the trio checks (pure/testable)."""
    from cryptography.x509.oid import ExtensionOID, NameOID
    cn = None
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        cn = attrs[0].value
    names: List[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        from cryptography import x509 as _x509
        names += [str(v) for v in
                  san.get_values_for_type(_x509.DNSName)]
        names += [str(v) for v in
                  san.get_values_for_type(_x509.IPAddress)]
    except Exception:
        pass
    key_bits = None
    key_kind = None
    try:
        pub = cert.public_key()
        key_kind = type(pub).__name__
        key_bits = getattr(pub, "key_size", None)
        if key_bits is None and hasattr(pub, "curve"):
            key_bits = pub.curve.key_size
    except Exception:
        pass
    sig_hash = None
    try:
        sig_hash = cert.signature_hash_algorithm.name
    except Exception:
        pass
    return {
        "cn": cn, "names": names,
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "sig_hash": sig_hash, "key_bits": key_bits, "key_kind": key_kind,
        "tls_version": tls_version,
    }


def host_covered(summary: Dict, host: str) -> bool:
    """Does the cert cover this host (exact, SAN, or one-label wildcard)?"""
    host = (host or "").lower()
    candidates = [c.lower() for c in summary.get("names") or []]
    if summary.get("cn"):
        candidates.append(str(summary["cn"]).lower())
    for name in candidates:
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix) and host.count(".") == \
                    name.count("."):
                return True
    return False


def cert_expiry_issue(summary: Dict, now: dt.datetime) -> Optional[str]:
    if summary["not_after"] and summary["not_after"] < now:
        return f"expired on {summary['not_after'].date().isoformat()}"
    if summary["not_before"] and summary["not_before"] > now:
        return f"not valid before {summary['not_before'].date().isoformat()}"
    return None


def cert_weak_issues(summary: Dict) -> List[str]:
    out = []
    if (summary.get("sig_hash") or "").lower() in ("md5", "sha1"):
        out.append(f"weak signature hash {summary['sig_hash']}")
    bits = summary.get("key_bits")
    if bits and bits < 2048:
        out.append(f"weak public key ({bits} bits, "
                   f"{summary.get('key_kind') or 'key'})")
    if summary.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3",
                                      "SSLv2"):
        out.append(f"legacy protocol negotiated "
                   f"({summary['tls_version']})")
    return out


class _CertPlugin(FinPlugin):
    """Shared grab for the trio; each subclass reports its own slice."""
    issue_kind = ""

    async def _summary(self, target: Target, ctx: Ctx):
        host, port = _host_port(target)
        if not host:
            return None, None, None
        try:
            cert, version = await asyncio.to_thread(
                grab_cert, host, port)
        except Exception:
            return host, port, None
        return host, port, cert_summary(cert, version)


class FinCertExpiredPlugin(_CertPlugin):
    id = "fin_cert_expired"
    label = "Banking Certificate Expired"
    description = ("TLS certificate on the banking host is expired or "
                   "not yet valid, read from the certificate the server "
                   "presents during a normal handshake.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        host, port, summary = await self._summary(target, ctx)
        if summary is None:
            return self._ok([], f"no certificate read for {host}")
        issue = cert_expiry_issue(summary, dt.datetime.now(dt.timezone.utc))
        if not issue:
            return self._ok([], f"certificate for {host} in date "
                                f"(until {summary['not_after'].date()})")
        return self._ok([self.fin_finding(
            "fin_cert_expired",
            f"Certificate for {host}:{port} {issue}",
            f"https://{host}:{port}/", "high",
            "Renew the certificate and automate renewal; an expired "
            "cert on a banking host trains customers to click through "
            "warnings.",
            not_after=str(summary["not_after"]))],
            f"expired certificate on {host}")


class FinCertMismatchPlugin(_CertPlugin):
    id = "fin_cert_mismatch"
    label = "Banking Certificate Name Mismatch"
    description = ("TLS certificate presented for the banking host "
                   "does not cover that hostname (CN/SAN mismatch).")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        host, port, summary = await self._summary(target, ctx)
        if summary is None:
            return self._ok([], f"no certificate read for {host}")
        if host_covered(summary, host):
            return self._ok([], f"certificate covers {host}")
        names = summary.get("names") or [summary.get("cn") or "?"]
        return self._ok([self.fin_finding(
            "fin_cert_mismatch",
            f"Certificate for {host}:{port} covers {', '.join(names)} "
            f"- not {host}",
            f"https://{host}:{port}/", "high",
            "Issue a certificate whose SANs cover the banking "
            "hostname; mismatches break trust and indicate a "
            "mis-pointed or legacy service.",
            covers=names)], f"name mismatch on {host}")


class FinCertWeakPlugin(_CertPlugin):
    id = "fin_cert_weak"
    label = "Banking Certificate Weak"
    description = ("Weak TLS material on the banking host: short keys, "
                   "MD5/SHA1 signatures, or a legacy protocol version "
                   "negotiated.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        host, port, summary = await self._summary(target, ctx)
        if summary is None:
            return self._ok([], f"no certificate read for {host}")
        issues = cert_weak_issues(summary)
        if not issues:
            return self._ok([], f"certificate strength ok for {host}")
        return self._ok([self.fin_finding(
            "fin_cert_weak",
            f"Weak TLS on {host}:{port}: {'; '.join(issues)}",
            f"https://{host}:{port}/", "medium",
            "Reissue with a 2048+ bit key and SHA-256 signature; "
            "disable TLS below 1.2 on banking hosts.",
            issues=issues)], f"weak TLS material on {host}")


# ---------------------------------------------------------------------------
# 36. fin_staging_env - staging / UAT online-banking environments
# ---------------------------------------------------------------------------

STAGING_PREFIXES = (
    "uat", "dev", "test", "staging", "stage", "preprod", "sandbox",
    "qa", "online-uat", "ebank-dev",
)
_BANKING_PAGE_RE = re.compile(
    r"(online\s+banking|internet\s+banking|sign\s?on|log\s?in|"
    r"username|password)", re.IGNORECASE)


def is_banking_login_page(text: str) -> bool:
    return bool(text) and bool(_BANKING_PAGE_RE.search(text))


class FinStagingEnvPlugin(FinPlugin):
    id = "fin_staging_env"
    label = "Staging Banking Environment Exposed"
    description = ("Non-production online-banking environments "
                   "(uat/dev/test/staging subdomains) that resolve and "
                   "serve a banking login surface to the internet.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not domain:
            return self._skipped("no host for this target type")
        findings = []
        for prefix in STAGING_PREFIXES:
            sub = f"{prefix}.{domain}"
            answers = await doh(ctx, sub, "A")
            if not answers:
                continue
            got = await fetch_text(ctx, f"https://{sub}/")
            if got and is_banking_login_page(got[1]):
                findings.append(self.fin_finding(
                    "fin_staging_banking_env",
                    f"Non-production banking environment live at "
                    f"{sub} (resolves to {answers[0]}, serves a "
                    f"banking login page)",
                    f"https://{sub}/", "high",
                    "Take non-production banking environments off the "
                    "public internet or behind VPN + SSO; they usually "
                    "run weaker auth against production-like data.",
                    subdomain=sub, resolves_to=answers[0]))
        if not findings:
            return self._ok([], f"no live staging banking envs on {domain}")
        return self._ok(findings,
                        f"{len(findings)} staging env(s) on {domain}")


# ---------------------------------------------------------------------------
# 37. fin_ct_internal_names - CT logs betraying internal banking hostnames
# ---------------------------------------------------------------------------

_INTERNAL_LABELS = {
    "internal", "intranet", "corp", "dev", "uat", "staging", "test",
    "qa", "vpn", "admin", "core", "switch",
}


def _name_looks_internal(name: str) -> bool:
    """True when a NON-TLD label of the hostname is an internal marker
    (a bare .test TLD or a 'latest' label must not count)."""
    labels = name.lower().split(".")
    for label in labels[:-1]:  # last label is the TLD - never a marker
        parts = label.split("-")
        if any(p in _INTERNAL_LABELS for p in parts):
            return True
    return False


def find_internal_cert_names(entries) -> List[str]:
    """Internal-looking hostnames from crt.sh entry dicts."""
    out = set()
    if not isinstance(entries, list):
        return []
    for e in entries:
        if not isinstance(e, dict):
            continue
        for field in ("name_value", "common_name"):
            raw = e.get(field) or ""
            for name in str(raw).splitlines():
                name = name.strip().lstrip("*.")
                if name and _name_looks_internal(name):
                    out.add(name)
    return sorted(out)[:10]


class FinCtInternalNamesPlugin(FinPlugin):
    id = "fin_ct_internal_names"
    label = "CT Log Internal Hostname Leak"
    description = ("Certificates logged in public CT logs whose names "
                   "betray internal banking systems (internal, core, "
                   "switch, uat, vpn hostnames).")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not domain:
            return self._skipped("no host for this target type")
        got = await fetch_text(
            ctx, f"https://crt.sh/?q=%25.{domain}&output=json")
        names = find_internal_cert_names(
            parse_json_text(got[1]) if got else None)
        if not names:
            return self._ok([], f"no internal cert names for {domain}")
        return self._ok([self.fin_finding(
            "fin_ct_internal_name",
            f"CT logs reveal internal-looking hostnames for {domain}: "
            f"{', '.join(names)}",
            f"https://crt.sh/?q=%25.{domain}", "medium",
            "Use wildcard certificates or a private CA for internal "
            "systems so their names never reach public CT logs.",
            names=names)], f"{len(names)} internal cert name(s)")


# ---------------------------------------------------------------------------
# 38. fin_status_internals - status pages naming internal core systems
# ---------------------------------------------------------------------------

STATUS_PATHS = (
    "/status", "/system-status", "/incidents", "/statuspage",
    "/service-status",
)
_CORE_MARKER_RE = re.compile(
    r"(core\s+banking|payment\s+switch|card\s+management|payment\s+hub|"
    r"interchange\s+status)", re.IGNORECASE)
_INTERNAL_SYSTEM_RE = re.compile(r"\b[A-Z]{2,5}-(?:PROD|CORE|SW|PAY)-\d+\b")
_TICKET_RE = re.compile(r"\bINC\d{5,}\b")


def analyze_status_page(text: str) -> List[Dict]:
    """Internal core-system names / ticket IDs on a status page."""
    out: List[Dict] = []
    if not text or not _CORE_MARKER_RE.search(text):
        return out
    for name in sorted(set(_INTERNAL_SYSTEM_RE.findall(text)))[:5]:
        out.append({"issue": "internal_system_name", "value": name})
    for tid in sorted(set(_TICKET_RE.findall(text)))[:3]:
        out.append({"issue": "internal_ticket_id", "value": tid})
    return out


class FinStatusInternalsPlugin(FinPlugin):
    id = "fin_status_internals"
    label = "Status Page Internal Systems"
    description = ("Public status/incident pages that name internal "
                   "core-banking or payment systems and internal "
                   "incident ticket IDs.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        pages = await fetch_paths(ctx, base, STATUS_PATHS)
        sub_answers = await doh(ctx, f"status.{domain}", "A")
        if sub_answers:
            got = await fetch_text(ctx, f"https://status.{domain}/")
            if got:
                pages.append(got)
        for url, text, _h in pages:
            for issue in analyze_status_page(text):
                findings.append(self.fin_finding(
                    "fin_status_page_internals",
                    f"Status page {url} names internal "
                    f"{issue['issue'].replace('_', ' ')}: {issue['value']}",
                    url, "medium",
                    "Publish status with customer-facing service "
                    "names; internal instance names and ticket IDs "
                    "map the estate for attackers.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"status pages clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} status internal(s) on {domain}")


# ---------------------------------------------------------------------------
# 39. fin_alerts_mail_posture - spoofable alert-sender subdomains
# ---------------------------------------------------------------------------

ALERT_SUBDOMAINS = (
    "alerts", "notify", "notifications", "securemail", "estatements",
)


def spf_present(txt_answers: List[str]) -> bool:
    return any(a.lower().startswith("v=spf1") for a in txt_answers or [])


class FinAlertsMailPosturePlugin(FinPlugin):
    id = "fin_alerts_mail_posture"
    label = "Alert Subdomain Spoofable (No SPF)"
    description = ("Banking alert/notification subdomains (alerts., "
                   "notify., securemail., estatements.) that resolve "
                   "but publish no SPF record - anyone can spoof the "
                   "bank's alert sender.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not domain:
            return self._skipped("no host for this target type")
        findings = []
        for sub_name in ALERT_SUBDOMAINS:
            sub = f"{sub_name}.{domain}"
            a = await doh(ctx, sub, "A")
            mx = await doh(ctx, sub, "MX")
            if not a and not mx:
                continue
            txt = await doh(ctx, sub, "TXT")
            if not spf_present(txt):
                findings.append(self.fin_finding(
                    "fin_alert_subdomain_no_spf",
                    f"Alert subdomain {sub} resolves "
                    f"({'A' if a else 'MX'} present) but publishes no "
                    f"SPF record - its sender address is spoofable",
                    None, "medium",
                    "Publish SPF (and DMARC) for every subdomain that "
                    "sends or appears to send bank mail, including "
                    "parked ones (v=spf1 -all).",
                    subdomain=sub))
        if not findings:
            return self._ok([], f"alert subdomains protected on {domain}")
        return self._ok(findings,
                        f"{len(findings)} spoofable subdomain(s) on {domain}")


# ---------------------------------------------------------------------------
# 40. fin_login_thirdparty_scripts - third-party scripts on login/pay pages
# ---------------------------------------------------------------------------

LOGIN_PATHS = ("/login", "/signon", "/sign-in", "/online-banking",
               "/checkout", "/pay")
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']",
                            re.IGNORECASE)
_TRUSTED_SCRIPT_HOSTS = (
    "www.googletagmanager.com", "www.google-analytics.com",
    "www.gstatic.com", "js.stripe.com", "www.paypal.com",
    "checkoutshopper-live.adyen.com", "www.adyen.com",
    "assets.checkout.com", "cdnjs.cloudflare.com",
    "static.cloudflareinsights.com",
)


def find_untrusted_scripts(html: str, page_url: str) -> List[str]:
    """Third-party script hosts on a page that are not the page's own
    host and not a well-known processor/tag host."""
    page_host = urlparse(page_url).netloc
    out = set()
    for m in _SCRIPT_SRC_RE.finditer(html or ""):
        src = m.group(1)
        host = urlparse(src).netloc
        if not host or host == page_host:
            continue
        if host in _TRUSTED_SCRIPT_HOSTS:
            continue
        out.add(host)
    return sorted(out)


class FinLoginScriptsPlugin(FinPlugin):
    id = "fin_login_thirdparty_scripts"
    label = "Third-Party Scripts on Login/Payment Pages"
    description = ("Login and payment pages loading JavaScript from "
                   "unexpected third-party hosts - the Magecart "
                   "skimming pattern. Scripts are inventoried, never "
                   "executed.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, LOGIN_PATHS):
            hosts = find_untrusted_scripts(text, url)
            if hosts:
                findings.append(self.fin_finding(
                    "fin_login_thirdparty_script",
                    f"Sensitive page {url} loads scripts from "
                    f"untrusted third parties: {', '.join(hosts)}",
                    url, "medium",
                    "Load only first-party or processor scripts on "
                    "login/payment pages, with SRI hashes and a "
                    "strict CSP; audit every third-party tag.",
                    script_hosts=hosts))
        if not findings:
            return self._ok([], f"login page scripts clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} page(s) with third-party "
                        f"scripts on {domain}")
