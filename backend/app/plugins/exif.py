"""Image metadata (EXIF) extractor (OSINT: media forensics category).

Finds images on the target homepage, downloads a few, and extracts
EXIF metadata: GPS coordinates, camera/device, software, timestamps.
GPS data is a real OPSEC finding. Read-only GETs of public images.
"""
from __future__ import annotations

import asyncio
import re
import struct
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .injutil import same_domain
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

IMG_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif")


def parse_exif_jpeg(data: bytes) -> Dict[str, str]:
    """Minimal EXIF parser: returns GPS + device/software tags found."""
    out: Dict[str, str] = {}
    try:
        if data[:2] != b"\xff\xd8":
            return out
        pos = 2
        while pos + 4 < len(data):
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            if marker == 0xD9:
                break
            seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if marker == 0xE1:  # APP1: EXIF
                seg = data[pos + 4:pos + 2 + seg_len]
                _parse_tiff(seg, out)
                if out:
                    break
            pos += 2 + seg_len
            if pos > 200000:
                break
    except Exception:
        pass
    return out


def _parse_tiff(seg: bytes, out: Dict[str, str]) -> None:
    try:
        if seg[:6] != b"Exif\x00\x00":
            return
        tiff = seg[6:]
        endian = "<" if tiff[:2] == b"II" else ">"
        if tiff[:2] not in (b"II", b"MM"):
            return
        gps_off = _ifd_entry(tiff, endian, 0x8825)
        if gps_off:
            lat = _gps_coord(tiff, endian, gps_off, 0x0002, 0x0001)
            lon = _gps_coord(tiff, endian, gps_off, 0x0004, 0x0003)
            if lat and lon:
                out["gps"] = f"{lat}, {lon}"
        soft = _tag_ascii(tiff, endian, 0x0131)
        if soft:
            out["software"] = soft[:80]
        model = _tag_ascii(tiff, endian, 0x0110)
        if model:
            out["camera"] = model[:80]
        dt = _tag_ascii(tiff, endian, 0x9003)
        if dt:
            out["taken"] = dt[:40]
    except Exception:
        pass


def _ifd_entry(tiff: bytes, endian: str, tag: int) -> Optional[int]:
    try:
        off = struct.unpack(endian + "I", tiff[4:8])[0]
        n = struct.unpack(endian + "H", tiff[off:off + 2])[0]
        for i in range(min(n, 40)):
            e = off + 2 + i * 12
            t = struct.unpack(endian + "H", tiff[e:e + 2])[0]
            if t == tag:
                return struct.unpack(endian + "I", tiff[e + 8:e + 12])[0]
    except Exception:
        pass
    return None


def _tag_ascii(tiff: bytes, endian: str, tag: int) -> Optional[str]:
    try:
        off = struct.unpack(endian + "I", tiff[4:8])[0]
        n = struct.unpack(endian + "H", tiff[off:off + 2])[0]
        for i in range(min(n, 40)):
            e = off + 2 + i * 12
            t = struct.unpack(endian + "H", tiff[e:e + 2])[0]
            if t == tag:
                cnt = struct.unpack(endian + "I", tiff[e + 4:e + 8])[0]
                voff = struct.unpack(endian + "I", tiff[e + 8:e + 12])[0]
                raw = tiff[voff:voff + min(cnt, 120)]
                return raw.split(b"\x00")[0].decode("utf-8", "replace").strip()
    except Exception:
        pass
    return None


def _gps_coord(tiff: bytes, endian: str, gps_ifd: int,
               coord_tag: int, ref_tag: int) -> Optional[str]:
    try:
        n = struct.unpack(endian + "H", tiff[gps_ifd:gps_ifd + 2])[0]
        vals = None
        ref = ""
        for i in range(min(n, 20)):
            e = gps_ifd + 2 + i * 12
            t = struct.unpack(endian + "H", tiff[e:e + 2])[0]
            if t == coord_tag:
                voff = struct.unpack(endian + "I", tiff[e + 8:e + 12])[0]
                vals = []
                for j in range(3):
                    num = struct.unpack(endian + "I", tiff[voff + j * 8:voff + j * 8 + 4])[0]
                    den = struct.unpack(endian + "I", tiff[voff + j * 8 + 4:voff + j * 8 + 8])[0]
                    vals.append(num / den if den else 0)
            elif t == ref_tag:
                voff = struct.unpack(endian + "I", tiff[e + 8:e + 12])[0]
                ref = tiff[voff:voff + 2].split(b"\x00")[0].decode("ascii", "replace")
        if vals:
            dec = vals[0] + vals[1] / 60 + vals[2] / 3600
            if ref in ("S", "W"):
                dec = -dec
            return f"{dec:.6f}{ref}"
    except Exception:
        pass
    return None


class ExifPlugin(Plugin):
    id = "exif"
    label = "Image EXIF Extractor"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Extract EXIF GPS/device metadata from site images."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        imgs = []
        for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = m.group(1)
            if src.startswith("data:"):
                continue
            low = src.lower().split("?")[0]
            if low.endswith(IMG_EXTS):
                full = urljoin(page_url, src)
                if same_domain(full, domain):
                    imgs.append(full)
            if len(imgs) >= 8:
                break

        # Fetch images concurrently (was sequential: 8 images x 15s timeouts
        # could stall this plugin for 2 minutes on a slow host). Same
        # images, same parsing, same findings - just in parallel.
        async def fetch_meta(img_url):
            try:
                ir = await fetch(ctx.http, ctx.limiter, "GET", img_url,
                                 timeout=15)
                if ir.status_code != 200 or len(ir.content) < 100:
                    return None
                meta = parse_exif_jpeg(ir.content[:300000])
                return (img_url, meta) if meta else None
            except Exception:
                return None

        img_sem = asyncio.Semaphore(4)

        async def fetch_meta_capped(img_url):
            async with img_sem:
                return await fetch_meta(img_url)

        img_results = await asyncio.gather(
            *(fetch_meta_capped(u) for u in imgs))

        for item in img_results:
            if not item:
                continue
            img_url, meta = item
            for k, v in meta.items():
                sev = "critical" if k == "gps" else "medium"
                label = {"gps": "GPS coordinates in image EXIF",
                         "camera": "camera/device in EXIF",
                         "software": "software in EXIF",
                         "taken": "capture time in EXIF"}.get(k, k)
                findings.append(self._f(
                    "leak", "exif_metadata",
                    f"{sev.upper()}: {label}: {v} ({img_url.split('/')[-1][:60]})",
                    source="EXIF scan", source_url=img_url,
                    confidence=90, passive=passive,
                    evidence={"severity": sev, "field": k, "value": v,
                              "remediation": "Strip EXIF metadata from images before publishing. "
                                             "GPS coordinates reveal physical locations."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(imgs)} images, {len(findings)} EXIF findings")
        res.duration_ms = dur
        return res
