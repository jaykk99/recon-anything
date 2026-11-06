"""Metasploit auxiliary-scanner style service/version CVE matcher.

DETECTION ONLY (Tier-6 rule). In the spirit of MSF auxiliary version
scanners (auxiliary/scanner/*/_version): connect to common non-HTTP
services, read the banner the service volunteers (plus one benign
protocol greeting where the service needs one: SMTP EHLO, FTP SYST),
extract the product + version, and match it against a small curated
table of well-known version-bounded CVEs. No exploit modules, no
checks beyond banner reads, no credentials, nothing is sent that a
normal client would not send during connect.

Distinct remainder vs existing plugins (checked against master 847):
- banners.py records TCP banners as informational findings and
  matches its VULN_HINTS against HTTP response headers only; it never
  version-matches a raw service banner against CVEs.
- cves.py matches versions found in HTTP headers / meta generators /
  JS filenames (the web surface), not socket banners.
- port_audit.py sweeps ~1000 ports and flags dangerous ports by
  number; its only CVE text is port-keyed advice, not a version match.
This plugin is the version->CVE join for infrastructure services.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Patch or upgrade the service to a supported version, "
               "and do not expose infrastructure services directly to "
               "the internet - put them behind a VPN or firewall "
               "allowlist.")

# (port, service label, greeting to send after connect or None)
SERVICES: List[Tuple[int, str, Optional[bytes]]] = [
    (21, "FTP", b"SYST\r\n"),
    (22, "SSH", None),
    (25, "SMTP", b"EHLO recon.local\r\n"),
    (110, "POP3", None),
    (143, "IMAP", None),
    (3306, "MySQL", None),
    (5900, "VNC", None),
]

# Version extractors: service -> (regex with one group = version,
# product label used in the CVE table)
EXTRACTORS: Dict[str, Tuple[re.Pattern, str]] = {
    "FTP": (re.compile(r"(?:vsFTPd|vsftpd)\s+(\d+\.\d+\.\d+)", re.I),
            "vsFTPd"),
    "SSH": (re.compile(r"OpenSSH[_-](\d+\.\d+(?:\.\d+)?)", re.I),
            "OpenSSH"),
    "SMTP": (re.compile(r"Exim\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Exim"),
    "MySQL": (re.compile(r"(\d+\.\d+\.\d+)-MariaDB", re.I), "MariaDB"),
}

# Generic FTP product versions (ProFTPD announces "ProFTPD 1.3.5").
PROFTPD_RX = re.compile(r"ProFTPD\s+(\d+\.\d+\.\d+)", re.I)

# Curated version-bounded CVE table:
# (product, op, ref_version, cve, severity, note, exploitability)
CVE_TABLE: List[Tuple[str, str, str, str, str, str, str]] = [
    ("vsFTPd", "==", "2.3.4", "CVE-2011-2523", "high",
     "vsFTPd 2.3.4 shipped with a malicious backdoor in the official "
     "archive.", "weaponized"),
    ("ProFTPD", "==", "1.3.5", "CVE-2015-3306", "high",
     "ProFTPD 1.3.5 mod_copy allows unauthenticated file copy "
     "(SITE CPFR/CPTO).", "weaponized"),
    ("OpenSSH", "<", "7.4", "CVE-2016-0777", "medium",
     "OpenSSH clients before 7.4 leak private key material via the "
     "roaming feature (server banner shows the daemon version line).",
     "public_poc"),
    ("OpenSSH", "<", "5.4", "CVE-2010-4478", "medium",
     "Ancient OpenSSH (pre-5.4) has multiple known vulnerabilities "
     "and is long past end of support.", "public_poc"),
    ("Exim", "==", "4.91", "CVE-2019-10149", "high",
     "Exim 4.91 return-of-the-wizard RCE in string expansion.",
     "weaponized"),
    ("Exim", "<", "4.87", "CVE-2016-1531", "high",
     "Exim before 4.87: local/remote code execution issues in the "
     "perl_startup path and set-uid handling.", "public_poc"),
    ("MariaDB", "<", "10.3", "CVE-2019-2614", "medium",
     "MariaDB before 10.3 is end-of-life and carries unpatched "
     "server vulnerabilities.", "theoretical"),
]


def _ver_tuple(s: str) -> Tuple[int, ...]:
    out = []
    for chunk in re.split(r"[.\-+_]", s or ""):
        m = re.match(r"(\d+)", chunk)
        if not m:
            break
        out.append(int(m.group(1)))
    return tuple(out) or (0,)


def _matches(op: str, ver: Tuple[int, ...], ref: str) -> bool:
    r = _ver_tuple(ref)
    n = max(len(ver), len(r))
    v = ver + (0,) * (n - len(ver))
    rr = r + (0,) * (n - len(r))
    if op == "==":
        return v == rr
    if op == "<":
        return v < rr
    if op == "<=":
        return v < rr or v == rr
    return False


def parse_banner(service: str, banner: str) -> Optional[Tuple[str, str]]:
    """Extract (product, version) from a service banner, or None."""
    if not banner:
        return None
    if service == "FTP":
        m = PROFTPD_RX.search(banner)
        if m:
            return "ProFTPD", m.group(1)
    spec = EXTRACTORS.get(service)
    if spec:
        rx, product = spec
        m = rx.search(banner)
        if m:
            return product, m.group(1)
    if service == "MySQL":
        m = re.match(r".{0,8}?(\d+\.\d+\.\d+)", banner, re.S)
        if m and "MariaDB" not in banner:
            return "MySQL", m.group(1)
    return None


def match_cves(product: str, version: str) -> List[Dict[str, str]]:
    """All curated CVE rows matching product+version."""
    ver = _ver_tuple(version)
    out = []
    for prod, op, ref, cve, sev, note, expl in CVE_TABLE:
        if prod == product and _matches(op, ver, ref):
            out.append({"cve": cve, "severity": sev, "note": note,
                        "exploitability": expl})
    return out


async def _grab_banner(host: str, port: int,
                       greeting: Optional[bytes]) -> str:
    """Read a service banner (one benign greeting at most).

    Module-level so fixture tests can substitute canned banners
    without real sockets.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=4)
    except Exception:
        return ""
    try:
        data = await asyncio.wait_for(reader.read(512), timeout=3)
        text = data.decode("utf-8", "replace")
        if greeting and text:
            try:
                writer.write(greeting)
                await writer.drain()
                more = await asyncio.wait_for(reader.read(512),
                                              timeout=2)
                text += more.decode("utf-8", "replace")
            except Exception:
                pass
        return text.strip()
    except Exception:
        return ""
    finally:
        try:
            writer.close()
        except Exception:
            pass


class MsfAuxiliaryPlugin(Plugin):
    id = "msf_auxiliary"
    label = "MSF Auxiliary Version Scan (detection)"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("Auxiliary-style service enumeration: banner/version "
                   "reads on common services matched against a curated "
                   "known-vulnerable version table. Detection only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = domain_from_target(target.type, target.normalized)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped(
                "needs active mode (opens service connections)")
        findings: List[Finding] = []
        for port, service, greeting in SERVICES:
            banner = await _grab_banner(host, port, greeting)
            if not banner:
                continue
            parsed = parse_banner(service, banner)
            if not parsed:
                continue
            product, version = parsed
            for hit in match_cves(product, version):
                findings.append(self._f(
                    "infra", "msf_aux_version_cve",
                    f"{product} {version} on {host}:{port} ({service}) "
                    f"matches {hit['cve']}: {hit['note']}",
                    source="msf-auxiliary version scan",
                    source_url=f"tcp://{host}:{port}",
                    confidence=85,
                    evidence={"severity": hit["severity"],
                              "exploitability": hit["exploitability"],
                              "remediation": REMEDIATION,
                              "banner": banner[:160], "cve": hit["cve"],
                              "product": product, "version": version,
                              "port": port, "service": service},
                    passive=False, bounty_value="medium"))
        res = self._ok(findings,
                       f"banner/version scan of {len(SERVICES)} services")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
