"""Edge appliance / infrastructure service detector.

Fingerprints VPN gateways, load balancers and mail servers from
banners, headers, portal pages and TLS certs, extracts versions where
possible, and cross-references the repo's CVE database (reuse of the
matcher in cves.py, with a local fallback copy).

Passive/port-probe detection only: no auth attempts, no exploit
payloads, no state changes. TCP/UDP port probes run in active mode
only; header/body/cert fingerprinting runs in both modes.
"""
from __future__ import annotations

import asyncio
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# --- CVE matcher reuse: import cves.py's database + version helpers.
# If that import ever fails, local fallbacks keep the plugin working.
try:
    from .cves import VERSION_CVES as _VERSION_CVES
    from .cves import _parse_version as _parse_version
    from .cves import _check as _check
except Exception:  # pragma: no cover
    _VERSION_CVES: List[Dict] = []

    def _parse_version(s: str) -> Tuple[int, ...]:
        parts = []
        for chunk in re.split(r"[.\-+_]", s or ""):
            m = re.match(r"(\d+)", chunk)
            if m:
                parts.append(int(m.group(1)))
            else:
                break
        return tuple(parts) or (0,)

    def _ver_lt(v: Tuple[int, ...], ref: Tuple[int, ...]) -> bool:
        n = max(len(v), len(ref))
        return (v + (0,) * (n - len(v))) < (ref + (0,) * (n - len(ref)))

    def _ver_eq(v: Tuple[int, ...], ref: Tuple[int, ...]) -> bool:
        n = max(len(v), len(ref))
        return (v + (0,) * (n - len(v))) == (ref + (0,) * (n - len(ref)))

    def _check(op: str, ver: Tuple[int, ...], ref: str) -> bool:
        r = _parse_version(ref)
        if op == "<":
            return _ver_lt(ver, r)
        if op == "<=":
            return _ver_lt(ver, r) or _ver_eq(ver, r)
        if op == "==":
            return _ver_eq(ver, r)
        if op == ">=":
            return not _ver_lt(ver, r)
        return False

# Appliance CVE entries: real, public CVEs. version_re has one capture
# group; vuln is a list of (op, version) - ANY match means vulnerable.
# Branch-specific fix versions are noted in the title; entries flagged
# version_optional fire as "verify manually" advisories.
EDGE_CVE_DB: List[Dict] = [
    {
        "software": "Fortinet FortiGate/FortiOS",
        "version_re": r"fortios[^\d]*(\d+\.\d+\.\d+)|fortigate[^\d]*v?(\d+\.\d+\.\d+)",
        "vuln": [("<", "7.4.3")],
        "cve": "CVE-2024-21762",
        "severity": "high",
        "exploitability": "weaponized",
        "title": ("FortiOS out-of-bounds write RCE via FGFM "
                  "(fixed 7.6.0/7.4.3/7.2.7/7.0.14/6.4.15 - verify branch)"),
        "remediation": ("Upgrade FortiOS to a fixed branch release and audit "
                        "for compromise - this CVE was exploited in the wild."),
    },
    {
        "software": "Palo Alto GlobalProtect",
        "version_re": r"globalprotect[^\d]*(\d+\.\d+\.\d+)",
        "vuln": [("<", "10.2.9"), ("<", "11.0.4"), ("<", "11.1.2")],
        "cve": "CVE-2024-3400",
        "severity": "high",
        "exploitability": "weaponized",
        "title": ("GlobalProtect command injection RCE (fixed "
                  "10.2.9-h1/11.0.4-h1/11.1.2-h3 - verify hotfix level)"),
        "remediation": ("Apply the hotfix release for your branch "
                        "immediately; this was exploited at scale."),
    },
    {
        "software": "Ivanti Connect Secure / Pulse Secure",
        "version_re": r"(?:ivanti|pulse secure)[^\d]*(\d+\.\d+R\d+)",
        "vuln": [("<", "9.1.0")],
        "cve": "CVE-2024-21887",
        "severity": "high",
        "exploitability": "weaponized",
        "title": ("Ivanti Connect Secure command injection RCE via crafted "
                  "requests (patched in 9.1R14.4/9.1R17.2/9.1R18/22.x - "
                  "verify exact build)"),
        "remediation": ("Upgrade to a patched Ivanti build and run the "
                        "vendor integrity checker - mass-exploited in 2024."),
    },
    {
        "software": "Citrix NetScaler / ADC",
        "version_re": r"citrix[^\d]*(?:adc|netscaler)[^\d]*(\d+\.\d+)",
        "vuln": [("<", "13.1")],
        "cve": "CVE-2023-4966",
        "severity": "high",
        "exploitability": "weaponized",
        "title": ("Citrix Bleed session hijack (fixed 13.1-53.17/13.0-92.19/"
                  "12.1-65.35/10.5-... - verify build)"),
        "remediation": ("Upgrade to a fixed build AND kill all active and "
                        "persistent sessions - stolen tokens survive patching."),
    },
    {
        "software": "F5 BIG-IP",
        "version_re": r"big-ip[^\d]*(\d+\.\d+\.\d+)",
        "vuln": [("<", "17.1.0")],
        "cve": "CVE-2023-46747",
        "severity": "high",
        "exploitability": "weaponized",
        "title": ("BIG-IP configuration utility auth bypass RCE "
                  "(fixed 17.1.0.3/16.1.4/15.1.10 - verify point release)"),
        "remediation": ("Upgrade to a fixed point release and restrict "
                        "management interface to trusted IPs."),
    },
    {
        "software": "Microsoft Exchange / OWA",
        "version_re": r"x-owa-version[:\s]+(\d+\.\d+\.\d+\.\d+)",
        "vuln": [("<", "15.2.0.0")],
        "cve": "CVE-2021-26855",
        "severity": "high",
        "exploitability": "weaponized",
        "title": ("ProxyLogon SSRF leading to RCE (fixed in Apr/May 2021 "
                  "security updates - verify patch level)"),
        "remediation": ("Apply Exchange security updates and hunt for "
                        "post-exploitation artifacts."),
        "version_optional": False,
    },
]

EOL_NOTES = {
    "pulse secure": ("Pulse Secure is end-of-life (rebranded Ivanti Connect "
                     "Secure; 9.1x line EOL). Migrate to a supported Ivanti "
                     "build - unpatched VPN gateways are a top ransomware "
                     "entry point."),
    "exchange 2013": "Exchange 2013 is end-of-life (Apr 2023). Migrate now.",
    "exchange 2016": "Exchange 2016 is end-of-life (Oct 2023). Migrate now.",
}

REMEDIATION_APPLIANCE = ("Patch the appliance to a vendor-supported release, "
                         "restrict its management interface to trusted IPs, "
                         "enable MFA on VPN portals, and monitor auth logs.")

# Canonical appliance names + per-appliance version extractors over the
# banner blob (headers, cookies, page markers, SMTP banners).
APPLIANCE_IDENTIFIERS = [
    ("Fortinet", "medium",
     [r"fortigate", r"fortios", r"fortinet"],
     [r"fortigate[^\d]*v?(\d+\.\d+\.\d+)", r"fortios[^\d]*(\d+\.\d+\.\d+)"]),
    ("Palo Alto GlobalProtect", "medium",
     [r"globalprotect", r"palo alto"],
     [r"globalprotect[^\d]*(\d+\.\d+\.\d+)"]),
    ("Ivanti Connect Secure", "medium",
     [r"pulse secure", r"ivanti connect", r"/dana-na/"],
     [r"(?:pulse secure|ivanti)[^\d]*(\d+\.\d+R\d+)"]),
    ("Cisco AnyConnect/ASA", "medium",
     [r"cisco anyconnect", r"cisco secure client", r"/\+webvpn\+/", r"\bcisco\b"],
     []),
    ("Citrix ADC", "medium",
     [r"citrix", r"netscaler", r"nsc_"],
     [r"citrix[^\d]*(?:adc|netscaler)[^\d]*(\d+\.\d+)"]),
    ("F5 BIG-IP", "medium",
     [r"bigipserver", r"\bbigip\b", r"f5 networks"],
     [r"big-ip[^\d]*(\d+\.\d+\.\d+)"]),
    ("Microsoft Exchange", "medium",
     [r"/owa/", r"/ecp/", r"outlook web app", r"microsoft esmtp",
      r"x-owa-version"],
     [r"x-owa-version[:\s]+(\d+\.\d+\.\d+\.\d+)"]),
    ("HAProxy", "low",
     [r"haproxy"],
     [r"haproxy[^\d/]*(\d+\.\d+(?:\.\d+)?)"]),
    ("AWS ALB/ELB", "low",
     [r"awselb"],
     [r"awselb/(\d+\.\d+)"]),
    ("OpenVPN", "medium",
     [r"openvpn"],
     [r"openvpn[^\d]*(\d+\.\d+(?:\.\d+)?)"]),
    ("WireGuard", "medium",
     [r"wireguard"],
     []),
]


def _identify_appliances(blob: str) -> List[Tuple[str, str, Optional[str]]]:
    """(canonical name, severity, version|None) from a banner blob."""
    out: List[Tuple[str, str, Optional[str]]] = []
    low = blob.lower()
    for name, sev, needles, ver_res in APPLIANCE_IDENTIFIERS:
        if not any(re.search(n, low) for n in needles):
            continue
        ver = None
        for vr in ver_res:
            m = re.search(vr, low)
            if m:
                ver = m.group(1)
                break
        out.append((name, sev, ver))
    return out


def _match_db(banner_text: str, db: List[Dict]) -> List[Dict]:
    """Run version-bounded CVE entries against a banner/header blob."""
    out = []
    hay = banner_text.lower()
    for entry in db:
        try:
            m = re.search(entry["version_re"], hay, re.I)
        except Exception:
            continue
        if not m:
            continue
        ver_str = None
        for i in range(1, (m.lastindex or 0) + 1):
            if m.group(i):
                ver_str = m.group(i)
                break
        vulnerable = False
        if entry.get("version_optional"):
            vulnerable = True
        elif ver_str:
            ver = _parse_version(ver_str)
            for op, ref in entry.get("vuln", []):
                if _check(op, ver, ref):
                    vulnerable = True
                    break
        if vulnerable:
            e = dict(entry)
            e["detected_version"] = ver_str
            out.append(e)
    return out


def _cert_orgs(host: str) -> List[str]:
    """Passive TLS cert issuer/subject orgs (no auth, cert only)."""
    import ssl
    orgs: List[str] = []
    try:
        sctx = ssl.create_default_context()
        sctx.check_hostname = False
        sctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=5) as sock:
            with sctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
        for section in ("issuer", "subject"):
            for rdn in cert.get(section, ()):  # type: ignore[union-attr]
                for key, val in rdn:
                    if key in ("organizationName", "commonName"):
                        orgs.append(str(val))
    except Exception:
        pass
    return orgs


async def _tcp_banner(host: str, port: int, timeout: float = 4.0) -> Optional[str]:
    """Grab a TCP banner; None if closed/filtered. No payload beyond a
    polite SMTP EHLO where the protocol demands a greeting."""
    def _do() -> Optional[str]:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
            except Exception:
                data = b""
            if port in (25, 587) and not data:
                try:
                    s.sendall(b"EHLO recon\r\n")
                    data = s.recv(1024)
                except Exception:
                    pass
            s.close()
            return data.decode("utf-8", "replace") if data else ""
        except Exception:
            return None
    try:
        return await asyncio.to_thread(_do)
    except Exception:
        return None


async def _wireguard_probe(host: str, timeout: float = 3.0) -> bool:
    """Send a WireGuard handshake initiation; any reply = WireGuard on
    UDP 51820. 148-byte random initiation, the standard fingerprint."""
    def _do() -> bool:
        try:
            import secrets as _secrets
            pkt = b"\x01\x00\x00\x00" + _secrets.token_bytes(144)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto(pkt, (host, 51820))
                s.recvfrom(256)
                return True
            except socket.timeout:
                return False
            finally:
                s.close()
        except Exception:
            return False
    try:
        return await asyncio.to_thread(_do)
    except Exception:
        return False


class EdgeAppliancesPlugin(Plugin):
    id = "edge_appliances"
    label = "Edge Appliance Fingerprinter"
    accepts = ["domain", "url", "ip"]
    passive = True
    aggressive = False
    cost = Cost.FREE
    group = "infra"
    description = ("Detect VPN gateways, load balancers and mail servers "
                   "from banners/headers/portal pages/certs, extract "
                   "versions, and match known CVEs. Passive + port probes; "
                   "no auth attempts.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or (target.normalized if target.type == "ip" else None)
        if not host:
            return self._skipped("no host for this target type")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        is_ip = target.type == "ip"

        banners: List[str] = []
        base = None
        if not is_ip:
            base = await web_base(ctx, target, domain or host)

        # 1. Header/body fingerprinting from the base fetch (both modes)
        server_h = powered = ""
        page_url = ""
        if base:
            try:
                page = await ctx.fetch_page(base, timeout=25)
                if page:
                    headers = {k.lower(): v for k, v in
                               page["headers"].items()}
                    server_h = headers.get("server", "")
                    powered = headers.get("x-powered-by", "")
                    page_url = page["url"]
                    banners.append(f"server: {server_h}")
                    banners.append(f"x-powered-by: {powered}")
                    for ck in ("set-cookie",):
                        if ck in headers:
                            banners.append(f"{ck}: {headers[ck][:200]}")
                    body = page["text"][:200000]
                    body_low = body.lower()
                    # Portal page markers
                    markers = {
                        "GlobalProtect": ["globalprotect", "palo alto networks"],
                        "Fortinet": ["fortigate", "fortinet"],
                        "Pulse Secure/Ivanti": ["/dana-na/", "pulse secure",
                                                "ivanti connect"],
                        "Cisco AnyConnect": ["/+webvpn+/", "cisco anyconnect",
                                             "cisco secure client"],
                        "Citrix ADC": ["/vpn/index.html", "citrix", "netscaler",
                                       "nsc_"],
                        "F5 BIG-IP": ["bigipserver", "f5 networks", "/my.policy"],
                        "Exchange/OWA": ["/owa/", "/ecp/", "x-owa-version",
                                         "outlook web app"],
                        "HAProxy": ["haproxy"],
                        "AWS ALB/ELB": ["awselb"],
                        "OpenVPN AS": ["openvpn", "/admin/"],
                    }
                    for name, needles in markers.items():
                        if any(n in body_low for n in needles):
                            banners.append(f"page-marker: {name}")
                    if headers.get("x-owa-version"):
                        banners.append(f"x-owa-version: {headers['x-owa-version']}")
            except Exception:
                pass

        # 1b. Identify appliances from the banner blob (headers, cookies,
        # page markers). One finding per appliance with version if found.
        seen_appliances = set()
        blob0 = "\n".join(banners)
        for name, sev, ver in _identify_appliances(blob0):
            if name in seen_appliances:
                continue
            seen_appliances.add(name)
            findings.append(self._f(
                "infra", "edge_appliance",
                f"{name} detected"
                f"{' version ' + ver if ver else ''} "
                f"(banner/header fingerprint). "
                f"{'Check known CVEs below; ' if ver else ''}"
                f"Restrict management interfaces to trusted IPs.",
                source="banner fingerprint",
                source_url=page_url or None,
                confidence=80 if ver else 70, passive=passive,
                evidence={"severity": sev, "appliance": name,
                          "version": ver or "unknown",
                          "remediation": REMEDIATION_APPLIANCE}))

        # 2. Known portal paths (cheap probes, shared cache)
        portal_paths = [
            ("/ssl-vpn/login.esp", "Fortinet", "Fortinet", "fortinet"),
            ("/dana-na/auth/url_default/welcome.cgi", "Pulse Secure/Ivanti",
             "Ivanti Connect Secure", "pulse"),
            ("/+webvpn+/index.html", "Cisco AnyConnect",
             "Cisco AnyConnect/ASA", "cisco"),
            ("/global-protect/login.esp", "Palo Alto GlobalProtect",
             "Palo Alto GlobalProtect", "globalprotect"),
            ("/vpn/index.html", "Citrix ADC", "Citrix ADC", "citrix"),
            ("/my.policy", "F5 BIG-IP", "F5 BIG-IP", "f5"),
            ("/owa/", "Exchange/OWA", "Microsoft Exchange", "owa"),
            ("/ecp/", "Exchange/ECP", "Microsoft Exchange", "ecp"),
        ]
        sem = asyncio.Semaphore(6)

        async def portal_probe(path: str, name: str, tag: str):
            async with sem:
                if not base:
                    return None
                try:
                    data = await ctx.probe(base.rstrip("/") + path, timeout=8)
                    if data.get("status", 0) in (200, 401, 403):
                        txt = (data.get("text") or "")[:3000].lower()
                        if tag in txt or data["status"] == 200:
                            return name, path, data["status"]
                    return None
                except Exception:
                    return None

        if not is_ip:
            for res in await asyncio.gather(
                    *(portal_probe(p, n, t) for p, n, _, t in portal_paths)):
                if res:
                    name, path, status = res
                    canon = next((c for _, n, c, _ in portal_paths if n == name),
                                 name)
                    banners.append(f"portal-path: {name} {path} -> {status}")
                    if canon in seen_appliances:
                        continue
                    seen_appliances.add(canon)
                    findings.append(self._f(
                        "infra", "edge_appliance",
                        f"{name} portal reachable at {path} "
                        f"(HTTP {status}). Management/VPN portals exposed "
                        f"to the internet are high-value targets - restrict "
                        f"to trusted IPs and enforce MFA.",
                        source="portal probe",
                        source_url=(base or "").rstrip("/") + path,
                        confidence=85, passive=passive,
                        evidence={"severity": "medium",
                                  "appliance": canon, "path": path,
                                  "http_status": status,
                                  "remediation": REMEDIATION_APPLIANCE}))

        # 3. TLS cert org hints (passive, both modes)
        if not is_ip:
            try:
                orgs = await asyncio.to_thread(_cert_orgs, host)
                for org in orgs:
                    banners.append(f"cert-org: {org}")
                    low = org.lower()
                    for vendor, name in (("fortinet", "Fortinet"),
                                         ("palo alto", "Palo Alto GlobalProtect"),
                                         ("citrix", "Citrix ADC"),
                                         ("ivanti", "Ivanti Connect Secure")):
                        if vendor in low and name not in seen_appliances:
                            seen_appliances.add(name)
                            findings.append(self._f(
                                "infra", "edge_appliance",
                                f"{name} appliance hinted by TLS cert "
                                f"({'/'.join(orgs[:2])}).",
                                source="TLS cert", source_url=f"https://{host}/",
                                confidence=60, passive=passive,
                                evidence={"severity": "low",
                                          "appliance": name,
                                          "remediation": REMEDIATION_APPLIANCE}))
                            break
            except Exception:
                pass

        # 4. Port probes (active mode only): SMTP banners, OpenVPN TCP,
        # WireGuard UDP 51820
        if not passive:
            async def smtp_probe(port: int):
                async with sem:
                    banner = await _tcp_banner(host, port)
                    return port, banner

            for port, banner in await asyncio.gather(
                    *(smtp_probe(p) for p in (25, 587))):
                if banner is None:
                    continue
                low = banner.lower()
                svc = "SMTP"
                ver = None
                for pat, name in ((r"postfix", "Postfix"),
                                  (r"exim[^\d]*(\d+\.\d+)", "Exim"),
                                  (r"sendmail[^\d]*(\d+\.\d+\.\d+)", "Sendmail"),
                                  (r"microsoft esmtp", "Exchange SMTP"),
                                  (r"zimbra", "Zimbra")):
                    m = re.search(pat, low)
                    if m:
                        svc = name
                        try:
                            ver = m.group(1)
                        except IndexError:
                            ver = None
                        break
                banners.append(f"smtp-{port}: {banner[:160]}")
                if svc == "Exchange SMTP" and "Microsoft Exchange" in seen_appliances:
                    continue
                seen_appliances.add("SMTP")
                findings.append(self._f(
                    "infra", "edge_appliance",
                    f"Mail server on port {port}: {svc}"
                    f"{' v' + ver if ver else ''} "
                    f"(banner: {banner[:100].strip()}).",
                    source=f"SMTP banner port {port}",
                    confidence=80, passive=False,
                    evidence={"severity": "low", "appliance": svc,
                              "version": ver or "unknown", "port": port,
                              "remediation": REMEDIATION_APPLIANCE}))

            ovpn = await _tcp_banner(host, 1194)
            if ovpn is not None:
                banners.append("openvpn: TCP 1194 open")
                findings.append(self._f(
                    "infra", "edge_appliance",
                    "OpenVPN port (TCP 1194) accepts connections. "
                    "Confirm it is an authorized VPN gateway; restrict "
                    "management and keep OpenVPN patched.",
                    source="TCP port probe", confidence=70, passive=False,
                    evidence={"severity": "medium", "appliance": "OpenVPN",
                              "port": 1194,
                              "remediation": REMEDIATION_APPLIANCE}))
            if await _wireguard_probe(host):
                banners.append("wireguard: UDP 51820 responded")
                findings.append(self._f(
                    "infra", "edge_appliance",
                    "WireGuard responded on UDP 51820. Confirm it is an "
                    "authorized VPN gateway.",
                    source="UDP port probe", confidence=80, passive=False,
                    evidence={"severity": "medium", "appliance": "WireGuard",
                              "port": 51820,
                              "remediation": REMEDIATION_APPLIANCE}))
        else:
            findings.append(self._f(
                "infra", "edge_appliance_note",
                "Port probes skipped (passive mode): SMTP banners "
                "(25/587), OpenVPN TCP 1194 and WireGuard UDP 51820 are "
                "only probed in active mode.",
                source="edge appliance fingerprinter", confidence=40,
                passive=True))

        # 5. CVE cross-reference: appliance DB + cves.py's version DB
        blob = "\n".join(banners)
        seen_cves = set()
        for entry in _match_db(blob, EDGE_CVE_DB):
            key = (entry["cve"], entry["software"])
            if key in seen_cves:
                continue
            seen_cves.add(key)
            findings.append(self._f(
                "infra", "appliance_cve",
                f"{entry['severity'].upper()}: {entry['software']} - "
                f"{entry['title']} [{entry['cve']}] "
                f"(detected version {entry.get('detected_version') or 'unknown'})",
                source="appliance CVE matcher",
                source_url=page_url or None,
                confidence=85 if entry.get("detected_version") else 60,
                passive=passive,
                exploitability=entry["exploitability"],
                evidence={"severity": entry["severity"], "cve": entry["cve"],
                          "software": entry["software"],
                          "detected_version": entry.get("detected_version") or "unknown",
                          "remediation": entry["remediation"]}))
        for entry in _match_db(blob, _VERSION_CVES):
            key = (entry["cve"], entry["software"])
            if key in seen_cves:
                continue
            seen_cves.add(key)
            findings.append(self._f(
                "infra", "appliance_cve",
                f"{entry['severity'].upper()}: {entry['software']} - "
                f"{entry['title']} [{entry['cve']}] "
                f"(detected version {entry.get('detected_version') or 'unknown'})",
                source="CVE matcher (cves.py db)",
                source_url=page_url or None,
                confidence=80 if entry.get("detected_version") else 60,
                passive=passive,
                exploitability=entry.get("exploitability", "unknown"),
                evidence={"severity": entry["severity"], "cve": entry["cve"],
                          "software": entry["software"],
                          "detected_version": entry.get("detected_version") or "unknown",
                          "remediation": entry["remediation"]}))

        # 6. EOL flags
        for needle, note in EOL_NOTES.items():
            if needle in blob.lower():
                findings.append(self._f(
                    "infra", "appliance_eol",
                    f"EOL software detected: {note}",
                    source="EOL check", confidence=70, passive=passive,
                    evidence={"severity": "high", "remediation": note}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} appliance findings "
                                 f"({'active' if not passive else 'passive'})")
        res.duration_ms = dur
        return res
