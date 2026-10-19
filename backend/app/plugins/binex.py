"""Deep binary static analysis (APK/IPA).

Expands on mobile.py with deeper static analysis of Android APKs
(obtained from public mirrors) - no decompilation, no emulator:

- Permission audit: flags dangerous permissions (camera, location,
  SMS, contacts, etc.) with risk ratings
- Exported components: activities/services/receivers/providers with
  exported=true (attack surface)
- Hardcoded secrets: API keys, tokens, URLs, IPs from strings
- Native libraries: .so inventory, arch, suspicious names
- Deep links & URL schemes
- Signer certificate info (SHA-256 fingerprint, subject)
- DEX file inventory (class count estimate)

iOS: App Store metadata only (IPA download needs auth).

All static. Nothing is executed.
"""
from __future__ import annotations

import hashlib
import io
import re
import time
import zipfile
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

from ..ratelimit import fetch
from .base import Cost, Ctx, Plugin, PluginResult, Target
from .jsminer import SECRET_PATTERNS

# Android dangerous permissions and why they matter.
DANGEROUS_PERMS = {
    "CAMERA": "can capture photos/video",
    "RECORD_AUDIO": "can record microphone",
    "ACCESS_FINE_LOCATION": "precise GPS location",
    "ACCESS_COARSE_LOCATION": "approximate location",
    "READ_CONTACTS": "read address book",
    "READ_SMS": "read text messages",
    "SEND_SMS": "send text messages (premium SMS risk)",
    "READ_CALL_LOG": "read call history",
    "READ_PHONE_STATE": "read IMEI/phone number",
    "READ_EXTERNAL_STORAGE": "read shared storage",
    "WRITE_EXTERNAL_STORAGE": "write shared storage",
    "GET_ACCOUNTS": "list device accounts",
    "USE_BIOMETRIC": "biometric auth",
    "NFC": "near-field communication",
    "BLUETOOTH_CONNECT": "connect to BT devices",
    "REQUEST_INSTALL_PACKAGES": "install other APKs (dropper risk)",
    "SYSTEM_ALERT_WINDOW": "draw over other apps (overlay attacks)",
    "BIND_ACCESSIBILITY_SERVICE": "accessibility (very powerful)",
    "READ_CALENDAR": "read calendar events",
}

SECRET_LABELS = {
    "aws": "AWS key", "gcp": "GCP key", "stripe": "Stripe key",
    "github": "GitHub token", "slack": "Slack token",
    "firebase": "Firebase key", "google_api": "Google API key",
    "private_key": "private key material",
}

REMEDIATION = ("Review this binary finding for sensitive exposure. "
               "Remove hardcoded secrets, minimize permissions, and "
               "set exported=false on components that don't need it.")


def _strings(data: bytes, min_len: int = 6) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    out = []
    cur = []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


class BinexPlugin(Plugin):
    id = "binex"
    label = "Deep Binary Analysis"
    accepts = ["play_store", "app_store", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "mobile"
    description = ("Deep APK static analysis: permissions, exported "
                   "components, secrets, native libs, signer.")
    requires_keys = []
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List = []
        if target.type == "play_store":
            pkg = target.normalized
            m = re.search(r"[?&]id=([a-zA-Z0-9_.]+)", pkg)
            if m:
                pkg = m.group(1)
            await self._analyze_pkg(ctx, pkg, findings)
        elif target.type == "apk_url":
            await self._analyze_url(ctx, target.normalized, findings)
        elif target.type == "app_store":
            findings.append(self._f(
                "mobile", "binex_ios_note",
                "IPA download requires Apple auth - metadata only. "
                "Use the mobile plugin for App Store metadata.",
                source="binex", confidence=90,
                evidence={"severity": "low", "remediation": REMEDIATION}))
        else:
            return self._skipped(
                "binex needs a Play Store target or direct APK URL")
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"binary analysis: {len(findings)} findings")
        res.duration_ms = dur
        return res

    async def _analyze_pkg(self, ctx: Ctx, pkg: str, findings: List):
        mirrors = [
            f"https://d.apkpure.com/b/APK/{pkg}?version=latest",
        ]
        for url in mirrors:
            if time.monotonic() - getattr(self, "_t0", time.monotonic()) > 25:
                break
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
            except Exception:
                continue
            ctype = r.headers.get("content-type", "")
            if (r.status_code == 200 and len(r.content) > 500_000
                    and ("octet-stream" in ctype or "apk" in ctype
                         or r.content[:2] == b"PK")):
                findings.append(self._f(
                    "mobile", "binex_apk_size",
                    f"APK obtained: {len(r.content) // 1024} KB",
                    source="APK mirror", confidence=85,
                    evidence={"severity": "low", "bytes": len(r.content),
                              "remediation": REMEDIATION}))
                self._deep_analyze(r.content, findings)
                return
        findings.append(self._f(
            "mobile", "binex_no_apk",
            "APK not available from public mirrors (skipped)",
            source="binex", confidence=60,
            evidence={"severity": "low", "remediation": REMEDIATION}))

    async def _analyze_url(self, ctx: Ctx, url: str, findings: List):
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
        except Exception as e:
            findings.append(self._f(
                "mobile", "binex_dl_error", str(e)[:120],
                source="binex", confidence=50,
                evidence={"severity": "low", "remediation": REMEDIATION}))
            return
        if r.status_code == 200 and r.content[:2] == b"PK":
            self._deep_analyze(r.content, findings)
        else:
            findings.append(self._f(
                "mobile", "binex_dl_error",
                f"URL did not return an APK (HTTP {r.status_code})",
                source="binex", confidence=60,
                evidence={"severity": "low", "remediation": REMEDIATION}))

    # -- deep static analysis -----------------------------------------
    def _deep_analyze(self, data: bytes, findings: List):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return
        names = zf.namelist()

        # Signer certificate fingerprint.
        self._cert_info(zf, names, findings)
        # Manifest: permissions + exported components.
        self._manifest(zf, findings)
        # DEX inventory.
        self._dex_info(zf, names, findings)
        # Native libraries.
        self._native_libs(names, findings)
        # Strings: URLs, IPs, secrets.
        self._strings_analysis(zf, names, findings)

    def _cert_info(self, zf: zipfile.ZipFile, names: List[str],
                   findings: List):
        for n in names:
            if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA")):
                try:
                    blob = zf.read(n)
                    fp = hashlib.sha256(blob).hexdigest()[:16]
                    findings.append(self._f(
                        "mobile", "binex_signer",
                        f"APK signed (cert SHA-256:{fp}...)",
                        source=n, confidence=80,
                        evidence={"severity": "low",
                                  "cert_sha256_prefix": fp,
                                  "remediation": REMEDIATION}))
                except Exception:
                    pass
                break

    def _manifest(self, zf: zipfile.ZipFile, findings: List):
        try:
            raw = zf.read("AndroidManifest.xml")
        except KeyError:
            return
        text = raw.decode("utf-8", errors="ignore")

        # Permissions with danger ratings.
        perms = set(re.findall(r"android\.permission\.([A-Z_0-9]+)", text))
        # Also catch <uses-permission android:name="..."> forms.
        for pm in set(re.findall(
                r'<uses-permission[^>]*android:name="([^"]+)"', text)):
            short = pm.split(".")[-1]
            perms.add(short)
        dangerous = sorted(p for p in perms if p in DANGEROUS_PERMS)
        if dangerous:
            findings.append(self._f(
                "mobile", "binex_dangerous_perms",
                f"{len(dangerous)} dangerous permissions: "
                f"{', '.join(dangerous[:8])}",
                source="AndroidManifest.xml", confidence=90,
                evidence={"severity": "medium",
                          "permissions": dangerous,
                          "why": {p: DANGEROUS_PERMS[p]
                                  for p in dangerous[:8]},
                          "remediation": REMEDIATION}))

        # Exported components (binary XML: strings still visible).
        exported = []
        for comp in ("activity", "service", "receiver", "provider"):
            for m in re.finditer(
                    rf"<{comp}[^>]*android:name=\"([^\"]+)\"[^>]*>",
                    text):
                tag = m.group(0)
                name = m.group(1)
                if "exported=\"true\"" in tag:
                    exported.append(f"{comp}:{name.split('.')[-1]}")
        if exported:
            findings.append(self._f(
                "mobile", "binex_exported",
                f"{len(exported)} exported components: "
                f"{', '.join(exported[:6])}",
                source="AndroidManifest.xml", confidence=85,
                evidence={"severity": "medium",
                          "components": exported[:20],
                          "remediation": REMEDIATION}))

        # Deep link schemes/hosts.
        schemes = set(re.findall(r"android:scheme=\"([^\"]+)\"", text))
        hosts = set(re.findall(r"android:host=\"([^\"]+)\"", text))
        if schemes:
            findings.append(self._f(
                "mobile", "binex_deeplinks",
                f"Deep link schemes: {', '.join(sorted(schemes)[:6])}",
                source="AndroidManifest.xml", confidence=85,
                evidence={"severity": "low",
                          "schemes": sorted(schemes)[:10],
                          "hosts": sorted(hosts)[:10],
                          "remediation": REMEDIATION}))

        # Package name + version.
        pkg = re.search(r"package=\"([^\"]+)\"", text)
        ver = re.search(r"android:versionName=\"([^\"]+)\"", text)
        if pkg:
            findings.append(self._f(
                "mobile", "binex_pkg",
                f"Package {pkg.group(1)}"
                + (f" v{ver.group(1)}" if ver else ""),
                source="AndroidManifest.xml", confidence=95,
                evidence={"severity": "low",
                          "package": pkg.group(1),
                          "remediation": REMEDIATION}))

    def _dex_info(self, zf: zipfile.ZipFile, names: List[str],
                  findings: List):
        dexes = [n for n in names if n.endswith(".dex")]
        if dexes:
            findings.append(self._f(
                "mobile", "binex_dex",
                f"{len(dexes)} DEX files: {', '.join(dexes[:4])}",
                source="APK", confidence=90,
                evidence={"severity": "low", "dex_files": dexes,
                          "remediation": REMEDIATION}))

    def _native_libs(self, names: List[str], findings: List):
        sos = [n for n in names if n.endswith(".so")]
        if not sos:
            return
        archs = set()
        for s in sos:
            m = re.search(r"lib/([^/]+)/", s)
            if m:
                archs.add(m.group(1))
        suspicious = [s.split("/")[-1] for s in sos
                      if any(k in s.lower() for k in
                             ("crypto", "ssl", "frida", "substrate"))]
        findings.append(self._f(
            "mobile", "binex_native",
            f"{len(sos)} native libraries "
            f"({', '.join(sorted(archs)[:4])})",
            source="APK lib/", confidence=85,
            evidence={"severity": "low", "count": len(sos),
                      "architectures": sorted(archs),
                      "sample": [s.split("/")[-1] for s in sos[:10]],
                      "suspicious": suspicious[:5],
                      "remediation": REMEDIATION}))

    def _strings_analysis(self, zf: zipfile.ZipFile, names: List[str],
                          findings: List):
        blob_parts = []
        for n in names:
            if n.endswith(".dex"):
                try:
                    blob_parts.append(
                        zf.read(n)[:1500000].decode("utf-8",
                                                   errors="ignore"))
                except Exception:
                    pass
            if len(blob_parts) >= 3:
                break
        text = "\n".join(blob_parts)
        if not text:
            return

        # Hardcoded URLs (skip common SDK noise).
        urls = set()
        for m in re.finditer(
                r"https?://[a-zA-Z0-9.-]+\.[a-z]{2,24}(?:/[^\s\"'<>]*)?",
                text):
            u = m.group(0)
            if any(x in u for x in ("schemas.android", "w3.org",
                                    "googleapis.com", "gstatic.com")):
                continue
            urls.add(u[:200])
            if len(urls) >= 25:
                break
        if urls:
            findings.append(self._f(
                "api", "binex_hardcoded_urls",
                f"{len(urls)} hardcoded URLs in DEX: "
                f"{', '.join(sorted(urls)[:3])}",
                source="DEX strings", confidence=75,
                evidence={"severity": "low", "urls": sorted(urls)[:25],
                          "remediation": REMEDIATION}))

        # Hardcoded IPs.
        ips = set(re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)) - {"0.0.0.0",
                                                     "127.0.0.1"}
        ips = {ip for ip in ips
               if all(0 <= int(p) <= 255 for p in ip.split("."))}
        if ips:
            findings.append(self._f(
                "infra", "binex_hardcoded_ips",
                f"Hardcoded IPs in DEX: {', '.join(sorted(ips)[:5])}",
                source="DEX strings", confidence=80,
                evidence={"severity": "medium", "ips": sorted(ips)[:15],
                          "remediation": REMEDIATION}))

        # Secrets via shared patterns (values redacted in titles).
        seen: Set[str] = set()
        secret_hits = []
        for label, pat in SECRET_PATTERNS.items():
            try:
                rx = re.compile(pat)
            except re.error:
                continue
            for m in rx.finditer(text):
                val = m.group(0)
                key = f"{label}:{val[:12]}"
                if key in seen:
                    continue
                seen.add(key)
                secret_hits.append((label, val[:8] + "..."))
                if len(secret_hits) >= 10:
                    break
            if len(secret_hits) >= 10:
                break
        if secret_hits:
            kinds = sorted(set(l for l, _ in secret_hits))
            findings.append(self._f(
                "leak", "binex_secrets",
                f"{len(secret_hits)} hardcoded secrets in DEX "
                f"({', '.join(kinds[:4])})",
                source="DEX strings", confidence=85,
                evidence={"severity": "high",
                          "kinds": kinds,
                          "samples_redacted": [s for _, s in
                                               secret_hits[:10]],
                          "exploitability": "theoretical",
                          "remediation": REMEDIATION},
                bounty_value="high"))
