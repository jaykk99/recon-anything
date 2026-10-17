"""Mobile app analysis plugin (Milestone 5).

Accepts Play Store URL / package id / App Store URL.
- Android: Play Store page metadata + best-effort APK pull from a public
  mirror, unzip, strings extraction, secret regex scan, permission and
  deep-link harvesting.
- iOS: App Store lookup API (free, no key) for metadata; IPA download
  needs auth so it is skipped with a clear status.

All parsing is static. No device, no emulator needed.
"""
from __future__ import annotations

import io
import re
import tempfile
import time
import zipfile
from typing import List
from urllib.parse import quote

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .jsminer import SECRET_PATTERNS


class MobilePlugin(Plugin):
    id = "mobile"
    label = "Mobile App Analysis"
    accepts = ["play_store", "app_store"]
    passive = True
    cost = Cost.FREEMIUM
    group = "mobile"
    description = "APK/IPA metadata, static strings, secret scan, deep links."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        if target.type == "play_store":
            await self._android(target, ctx, findings)
        elif target.type == "app_store":
            await self._ios(target, ctx, findings)
        else:
            return self._skipped("needs a Play Store or App Store target")
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"mobile analysis for {target.normalized}")
        res.duration_ms = dur
        return res

    # -- Android -------------------------------------------------------
    async def _android(self, target: Target, ctx: Ctx, findings: List[Finding]):
        pkg = target.normalized
        m = re.search(r"[?&]id=([a-zA-Z0-9_.]+)", pkg)
        if m:
            pkg = m.group(1)
        page_url = f"https://play.google.com/store/apps/details?id={quote(pkg)}&hl=en&gl=US"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", page_url, timeout=25)
        except Exception as e:
            findings.append(self._f("mobile", "play_page_error", str(e)[:150],
                                    source="Play Store", confidence=40))
            return
        if r.status_code != 200:
            findings.append(self._f("mobile", "play_page_error",
                                    f"HTTP {r.status_code}",
                                    source="Play Store", confidence=40))
            return
        html = r.text
        title = re.search(r"<title>(.*?)</title>", html, re.S)
        if title:
            findings.append(self._f("mobile", "app_title",
                                    re.sub(r"\s+", " ", title.group(1)).strip()[:200],
                                    source="Play Store page", source_url=page_url,
                                    confidence=90, passive=True))
        dev = re.search(r'"developerName":"([^"]+)"', html)
        if dev:
            findings.append(self._f("mobile", "developer", dev.group(1)[:200],
                                    source="Play Store page", confidence=90, passive=True))
        # deep links / URLs embedded in the page JSON
        for um in set(re.findall(r"https?://[a-zA-Z0-9.-]+\.[a-z]{2,24}(?:/[^\s\"'<>]*)?", html)):
            if "play.google.com" in um or "googleapis.com" in um:
                continue
            findings.append(self._f("api", "mobile_url", um[:300],
                                    source="Play Store page", confidence=60, passive=True))
            if len([f for f in findings if f.key == "mobile_url"]) > 30:
                break

        # best-effort APK pull from a public mirror
        apk_ok = await self._try_apk(ctx, pkg, findings)
        if not apk_ok:
            findings.append(self._f("mobile", "apk_note",
                                    "APK download not available from public mirrors "
                                    "(skipped, not an error)",
                                    source="APK mirror", confidence=50, passive=True))

    async def _try_apk(self, ctx: Ctx, pkg: str, findings: List[Finding]) -> bool:
        mirrors = [
            f"https://d.apkpure.com/b/APK/{pkg}?version=latest",
        ]
        for url in mirrors:
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=60)
            except Exception:
                continue
            ctype = r.headers.get("content-type", "")
            if r.status_code == 200 and len(r.content) > 1_000_000 and \
                    ("octet-stream" in ctype or "apk" in ctype or r.content[:2] == b"PK"):
                self._analyze_apk(r.content, findings)
                findings.append(self._f("mobile", "apk_source",
                                        f"APK obtained ({len(r.content)//1024} KB)",
                                        source="APK mirror", confidence=80, passive=True))
                return True
        return False

    def _analyze_apk(self, data: bytes, findings: List[Finding]):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return
        names = zf.namelist()
        # manifest (binary XML, strings only)
        try:
            manifest = zf.read("AndroidManifest.xml")
            text = manifest.decode("utf-8", errors="ignore")
            for pm in set(re.findall(r"android\.permission\.([A-Z_]+)", text)):
                findings.append(self._f("mobile", "permission", pm,
                                        source="AndroidManifest.xml", confidence=85,
                                        passive=True))
            for sm in set(re.findall(r"android:scheme=\"([^\"]+)\"", text)):
                findings.append(self._f("mobile", "deep_link_scheme", sm,
                                        source="AndroidManifest.xml", confidence=85,
                                        passive=True))
        except KeyError:
            pass
        # strings across dex + resources (bounded)
        blob_parts = []
        for n in names:
            if n.endswith(".dex") or n.endswith(".xml") or n.endswith(".json"):
                try:
                    blob_parts.append(zf.read(n)[:2000000].decode("utf-8", errors="ignore"))
                except Exception:
                    continue
            if len("".join(blob_parts)) > 6000000:
                break
        blob = "\n".join(blob_parts)
        seen = set()
        for kind, pat, conf in SECRET_PATTERNS:
            for m in re.finditer(pat, blob):
                v = m.group(0)[:200]
                if (kind, v) in seen:
                    continue
                seen.add((kind, v))
                findings.append(self._f("leak", f"apk_{kind}", v,
                                        source="APK strings", confidence=conf,
                                        passive=True))
                if len(seen) > 60:
                    return
        for um in set(re.findall(r"https?://[a-zA-Z0-9.-]+\.[a-z]{2,24}(?:/[^\s\"'<>]*)?", blob)):
            if len([f for f in findings if f.key == "apk_url"]) > 40:
                break
            findings.append(self._f("api", "apk_url", um[:300],
                                    source="APK strings", confidence=65, passive=True))

    # -- iOS -----------------------------------------------------------
    async def _ios(self, target: Target, ctx: Ctx, findings: List[Finding]):
        raw = target.normalized
        m = re.search(r"/id(\d+)", raw)
        app_id = m.group(1) if m else (raw if raw.isdigit() else None)
        if not app_id:
            findings.append(self._f("mobile", "ios_note",
                                    "need an App Store URL or numeric app id",
                                    source="input", confidence=40))
            return
        url = f"https://itunes.apple.com/lookup?id={app_id}&country=us"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20)
            data = r.json()
        except Exception as e:
            findings.append(self._f("mobile", "ios_error", str(e)[:150],
                                    source="App Store lookup", confidence=40))
            return
        results = data.get("results", [])
        if not results:
            findings.append(self._f("mobile", "ios_error", "app not found",
                                    source="App Store lookup", confidence=60))
            return
        app = results[0]
        for key, label in (("trackName", "app_title"), ("sellerName", "developer"),
                           ("bundleId", "bundle_id"), ("version", "version"),
                           ("primaryGenreName", "genre")):
            if app.get(key):
                findings.append(self._f("mobile", label, str(app[key])[:200],
                                        source="App Store lookup",
                                        source_url=app.get("trackViewUrl"),
                                        confidence=90, passive=True))
        findings.append(self._f("mobile", "ipa_note",
                                "IPA download requires Apple ID auth (skipped)",
                                source="App Store", confidence=50, passive=True))
