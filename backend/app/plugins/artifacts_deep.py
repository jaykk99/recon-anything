"""Deep-artifacts pack (da_*): the web-visible layer of the "below the
OS" stack - memory/crash dumps, debug symbols, compiled-code archives,
WASM modules, firmware images, device config exports, OTA manifests
and build-artifact directory listings.

Deduped against the 575-plugin registry that existed when this pack
was built (ids AND paths/patterns read, not assumed):

- .js.map + sourcesContent secret mining -> owned by sourcemap.py
  (complete: secrets, internal URLs, routes, debug flags). NOT repeated.
- /actuator/heapdump reachability -> owned by infodisclosure.py.
  da_heap_dump covers the OTHER dump surfaces (loose .hprof files,
  V8 heap snapshots, thread dumps) with format-signature proof.
- Path-presence for web.config, backup archives (.zip/.tar.gz),
  SQL/SQLite dumps, .env -> owned by artifacts.py + backup.py.
  da_archive_configs does something different: it reads a hosted
  JAR/WAR's ZIP CENTRAL DIRECTORY (names only) and one bounded small
  config entry inside it.
- Loose /google-services.json -> pf pack (privfind.py). An .apk ON THE
  TARGET that CONTAINS google-services.json is a different surface;
  deep APK/IPA static analysis from mirrors -> owned by binex.py.
  da_mobile_package reports target-hosted packages + config entry
  NAMES only.
- Generic open-directory detection -> owned by opendir.py (it does
  not probe /bin/, /src/, /__pycache__/, /WEB-INF/ and never reads
  listed filenames). da_build_listing covers exactly those dirs and
  fires on the artifact FILENAMES listed.
- IoT device fingerprinting / firmware version banners -> iot.py.
  da_firmware_image / da_device_config_export / da_ota_manifest cover
  downloadable firmware FILES, config EXPORTS and update MANIFESTS,
  none of which iot.py fetches.
- Go pprof -> infodisclosure.py. Java/.NET/PHP dump files: nothing
  probed them, and nothing anywhere verified a binary format
  signature (MDMP, HPROF, ELF core, PDB MSF, wasm, uImage...).

Hard rules for this pack:
- Read-only ranged reads. Signatures come from a HEAD + a Range
  window of the first bytes (cap 16 KB); archive contents come from
  the ZIP central directory at the END of the file (tail range read)
  plus, for JAR/WAR only, ONE config entry whose compressed size is
  <= 16 KB. Whole dumps/archives are never downloaded.
- Evidence is type + size + names + masked secrets (secretutils
  redact + SHA-256 fingerprint). Full secret values never reach a
  Finding.
- Authorized targets only; nothing found is ever used.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import struct
import time
import zlib
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import collect_texts
from .secretutils import is_placeholder, redact
from .sourcemap import INTERNAL_URL_RE
from .wayback import fetch_cdx

HEAD_CAP = 8192            # signature window for dumps/symbols/firmware
WASM_CAP = 16384           # wasm sections live near the head
TEXT_CAP = 32768           # listings / manifests
ZIP_TAIL = 65557           # EOCD (22) + max zip comment (65535)
ZIP_CD_CAP = 262144        # central-directory window cap
CONFIG_ENTRY_CAP = 16384   # max compressed size of one config entry read
MAX_ENTRIES = 500

_REMEDIATION = (
    "Remove the artifact from the public web surface (it belongs in "
    "build storage, not the web root), treat anything it contains - "
    "credentials, session data, source, symbols - as compromised, "
    "rotate exposed secrets, and audit access logs for downloads.")


def _fingerprint(value: str) -> str:
    return hashlib.sha256(
        (value or "").encode("utf-8", "ignore")).hexdigest()


def _host_of(target: Target) -> Optional[str]:
    if target.type == "url":
        return urlparse(target.normalized).hostname
    return domain_from_target(target.type, target.normalized)


async def _origin(ctx: Ctx, target: Target) -> Optional[str]:
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
        return target.normalized.rstrip("/")
    domain = domain_from_target(target.type, target.normalized)
    if not domain:
        return None
    return (await web_base(ctx, target, domain)).rstrip("/")


async def _req(ctx: Ctx, method: str, url: str, timeout: int = 8,
               **kw) -> Any:
    try:
        return await fetch(ctx.http, ctx.limiter, method, url,
                           timeout=timeout, max_retries=0, **kw)
    except Exception:
        return None


def _clen(r) -> Optional[int]:
    try:
        v = r.headers.get("content-length")
        return int(v) if v else None
    except Exception:
        return None


def _total_from_range(r) -> Optional[int]:
    try:
        cr = r.headers.get("content-range", "") or ""
    except Exception:
        return None
    m = re.search(r"/(\d+)\s*$", cr)
    return int(m.group(1)) if m else None


async def _head(ctx: Ctx, url: str) -> Tuple[int, Optional[int], str]:
    """(status_as_get, total_size, content_type) for a URL.

    HEAD first; servers that refuse HEAD (405/501) get a 1-byte Range
    GET instead. Status 206 is normalized to 200 (the file exists).
    """
    r = await _req(ctx, "HEAD", url)
    if r is not None and r.status_code in (405, 501):
        r = None
    if r is None:
        r = await _req(ctx, "GET", url, headers={"Range": "bytes=0-0"},
                       follow_redirects=True)
        if r is None:
            return 0, None, ""
        size = _total_from_range(r) or _clen(r)
        st = 200 if r.status_code == 206 else r.status_code
        return st, size, (r.headers.get("content-type") or "")
    return r.status_code, _clen(r), (r.headers.get("content-type") or "")


async def _window(ctx: Ctx, url: str, start: int,
                  length: int) -> Tuple[bytes, Optional[int], bool]:
    """Ranged read: (bytes, total_size, range_honored).

    Asks for exactly `length` bytes at `start` via a Range header and
    never returns more than `length` bytes to the caller.
    """
    r = await _req(ctx, "GET", url,
                   headers={"Range": f"bytes={start}-{start + length - 1}"},
                   follow_redirects=True)
    if r is None or r.status_code not in (200, 206):
        return b"", None, False
    if r.status_code == 206:
        return r.content[:length], _total_from_range(r) or _clen(r), True
    return r.content[:length], _clen(r) or len(r.content), False


async def _tail(ctx: Ctx, url: str,
                size: Optional[int]) -> Tuple[bytes, int]:
    """(tail_bytes, tail_absolute_start) - the last ZIP_TAIL bytes."""
    if size:
        start = max(0, size - ZIP_TAIL)
        data, _, _ = await _window(ctx, url, start, ZIP_TAIL)
        return data, start
    r = await _req(ctx, "GET", url,
                   headers={"Range": f"bytes=-{ZIP_TAIL}"},
                   follow_redirects=True)
    if r is None or r.status_code not in (200, 206):
        return b"", 0
    total = _total_from_range(r) or _clen(r)
    data = r.content[-ZIP_TAIL:]
    start = max(0, (total or len(data)) - len(data))
    return data, start


# ---------------------------------------------------------------------------
# ZIP central directory (names + offsets only; no bulk extraction)
# ---------------------------------------------------------------------------

def _eocd(tail: bytes) -> Optional[Tuple[int, int, int]]:
    """(entry_count, cd_size, cd_offset) from an EOCD record, or None."""
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0 or idx + 22 > len(tail):
        return None
    try:
        (_sig, _d1, _d2, _n1, n_total, cd_size, cd_offset,
         _cl) = struct.unpack_from("<IHHHHIIH", tail, idx)
    except Exception:
        return None
    return n_total, cd_size, cd_offset


def _parse_cd(buf: bytes) -> List[Tuple[str, int, int, int]]:
    """Parse central-directory headers -> (name, method, comp_size,
    local_header_offset), capped at MAX_ENTRIES."""
    out: List[Tuple[str, int, int, int]] = []
    pos = 0
    while pos + 46 <= len(buf) and len(out) < MAX_ENTRIES:
        if buf[pos:pos + 4] != b"PK\x01\x02":
            break
        try:
            (_sig, _vm, _vn, _fl, method, _tm, _dt, _crc, comp,
             _unc) = struct.unpack_from("<IHHHHHHIII", buf, pos)
            nlen, elen, clen = struct.unpack_from("<HHH", buf, pos + 28)
            lho = struct.unpack_from("<I", buf, pos + 42)[0]
        except Exception:
            break
        name = buf[pos + 46:pos + 46 + nlen].decode("utf-8", "ignore")
        out.append((name, method, comp, lho))
        pos += 46 + nlen + elen + clen
    return out


async def _zip_entries(ctx: Ctx, url: str,
                       size: Optional[int]) -> Optional[List[Tuple[str, int, int, int]]]:
    """Central-directory entries for a remote zip, or None if the tail
    does not hold a readable EOCD."""
    tail, tail_start = await _tail(ctx, url, size)
    if not tail:
        return None
    found = _eocd(tail)
    if not found:
        return None
    _count, cd_size, cd_offset = found
    if tail_start <= cd_offset and cd_offset + cd_size <= tail_start + len(tail):
        cdbuf = tail[cd_offset - tail_start: cd_offset - tail_start + cd_size]
    else:
        cdbuf, _, _ = await _window(ctx, url, cd_offset,
                                    min(cd_size, ZIP_CD_CAP))
    if not cdbuf:
        return None
    return _parse_cd(cdbuf)


async def _zip_entry_text(ctx: Ctx, url: str,
                          entry: Tuple[str, int, int, int]) -> Optional[str]:
    """Read ONE small entry (bounded by CONFIG_ENTRY_CAP compressed).

    Used only for config files inside JAR/WAR archives: a properties
    file is a few hundred bytes, not bulk extraction."""
    _name, method, comp, lho = entry
    if comp <= 0 or comp > CONFIG_ENTRY_CAP or method not in (0, 8):
        return None
    head, _, _ = await _window(ctx, url, lho, 1024)
    if len(head) < 30 or head[:4] != b"PK\x03\x04":
        return None
    try:
        nlen, elen = struct.unpack_from("<HH", head, 26)
    except Exception:
        return None
    data_start = 30 + nlen + elen
    if data_start + comp > len(head):
        head, _, _ = await _window(ctx, url, lho,
                                   data_start + comp + 64)
    raw = head[data_start:data_start + comp]
    if len(raw) < comp:
        return None
    try:
        if method == 8:
            raw = zlib.decompress(raw, -15)
    except Exception:
        return None
    return raw.decode("utf-8", "ignore")


_CONFIG_SECRET_RES = [
    ("datasource_password",
     re.compile(r"(?im)(?:spring\.)?datasource\.password\s*[:=]\s*"
                r"[\"']?(\S{4,})")),
    ("jdbc_password_param",
     re.compile(r"jdbc:[^\s\"']{0,200}?(?:password|pwd)=([^\s&\"']{4,})",
                re.I)),
    ("password_assignment",
     re.compile(r"(?im)^\s*[A-Za-z0-9_.\-]*(?:password|passwd|pwd)\s*[:=]"
                r"\s*[\"']?([^\s\"']{4,})")),
    ("secret_assignment",
     re.compile(r"(?im)^\s*[A-Za-z0-9_.\-]*(?:secret|api[-_.]?key|"
                r"access[-_.]?key|auth[-_.]?token)\s*[:=]\s*[\"']?"
                r"([A-Za-z0-9_\-./+=]{8,})")),
]


def _scan_config_secrets(text: str) -> List[Tuple[str, str]]:
    """(pattern_name, raw_value) hits; placeholders and ${ENV} refs are
    not leaks and are skipped."""
    hits: List[Tuple[str, str]] = []
    if not text:
        return hits
    for name, rx in _CONFIG_SECRET_RES:
        for m in rx.finditer(text):
            val = (m.group(1) or "").strip().strip("\"'")
            if not val or val.startswith("${") or is_placeholder(val):
                continue
            hits.append((name, val))
            break
    return hits


# ---------------------------------------------------------------------------
# WASM head parsing (imports / exports from the first window)
# ---------------------------------------------------------------------------

def _leb(buf: bytes, pos: int) -> Tuple[Optional[int], int]:
    result = 0
    shift = 0
    while pos < len(buf) and shift <= 63:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    return None, pos


def _wstr(buf: bytes, pos: int) -> Tuple[Optional[str], int]:
    n, pos = _leb(buf, pos)
    if n is None or pos + n > len(buf):
        return None, pos
    return buf[pos:pos + n].decode("utf-8", "ignore"), pos + n


def _skip_limits(buf: bytes, pos: int) -> int:
    if pos >= len(buf):
        return pos
    flag = buf[pos]
    pos += 1
    _, pos = _leb(buf, pos)
    if flag & 0x01:
        _, pos = _leb(buf, pos)
    return pos


def _parse_wasm(window: bytes) -> Optional[Dict[str, Any]]:
    """Parse magic/version + import/export names from a head window."""
    if len(window) < 8 or window[:4] != b"\x00asm":
        return None
    info: Dict[str, Any] = {
        "version": struct.unpack_from("<I", window, 4)[0],
        "imports": [], "exports": [], "truncated": False}
    pos = 8
    try:
        while pos < len(window):
            sec = window[pos]
            pos += 1
            size, pos = _leb(window, pos)
            if size is None:
                break
            end = pos + size
            if end > len(window):
                info["truncated"] = True
            if sec == 2:  # imports
                count, p = _leb(window, pos)
                for _ in range(min(count or 0, 40)):
                    mod, p = _wstr(window, p)
                    nm, p = _wstr(window, p)
                    if mod is None or nm is None or p >= len(window):
                        break
                    kind = window[p]
                    p += 1
                    if kind == 0:
                        _, p = _leb(window, p)
                    elif kind in (1, 2):
                        if kind == 1:
                            p += 1  # element type
                        p = _skip_limits(window, p)
                    elif kind == 3:
                        p += 2  # value type + mutability
                    else:
                        break
                    info["imports"].append(f"{mod}.{nm}")
                    if p >= end:
                        break
            elif sec == 7:  # exports
                count, p = _leb(window, pos)
                for _ in range(min(count or 0, 40)):
                    nm, p = _wstr(window, p)
                    if nm is None or p >= len(window):
                        break
                    p += 1  # kind
                    _, p = _leb(window, p)  # index
                    info["exports"].append(nm)
                    if p >= end:
                        break
            if end <= pos:
                break
            pos = end
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Directory-listing helpers
# ---------------------------------------------------------------------------

_LISTING_MARKERS = ("index of /", "directory listing for",
                    "<title>index of", "parent directory")


def _listing_names(text: str) -> List[str]:
    names: List[str] = []
    for m in re.finditer(r'href="([^"#?]+)"', text or ""):
        href = unquote(m.group(1))
        name = href.rstrip("/").rsplit("/", 1)[-1]
        if name and name not in (".", "..") and name not in names:
            names.append(name)
    return names


def _is_listing(text: str) -> bool:
    low = (text or "")[:6000].lower()
    return any(m in low for m in _LISTING_MARKERS)


_LINK_RX = re.compile(
    r"""(?:href|src)\s*=\s*["']([^"']+)["']|(https?://[^\s"'<>]+)""", re.I)


# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------

class _DeepArtifact(Plugin):
    id = None  # abstract
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 90

    PATHS: List[str] = []
    LINK_EXTS: Tuple[str, ...] = ()
    KEY = ""

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        return []

    async def _linked(self, ctx: Ctx, target: Target) -> List[str]:
        """Artifact URLs linked from the homepage / same-host JS."""
        if not self.LINK_EXTS:
            return []
        host = _host_of(target)
        if not host:
            return []
        try:
            texts = await collect_texts(ctx, target)
        except Exception:
            return []
        out: List[str] = []
        for _where, text, page_url in texts:
            for m in _LINK_RX.finditer(text or ""):
                raw = m.group(1) or m.group(2) or ""
                if not raw:
                    continue
                full = urljoin(page_url, raw)
                p = urlparse(full)
                if p.hostname != host:
                    continue
                if p.path.lower().endswith(self.LINK_EXTS) \
                        and full not in out:
                    out.append(full.split("#")[0].split("?")[0])
                if len(out) >= 12:
                    return out
        return out

    async def _archived(self, ctx: Ctx, target: Target) -> Dict[str, str]:
        """{path: earliest_timestamp} from the shared Wayback CDX."""
        host = _host_of(target)
        if not host:
            return {}
        try:
            rows = await fetch_cdx(ctx, host)
        except Exception:
            return {}
        archived: Dict[str, str] = {}
        if isinstance(rows, list) and len(rows) > 1:
            header, data = rows[0], rows[1:]
            ts_i = header.index("timestamp") if "timestamp" in header else 0
            url_i = header.index("original") if "original" in header else 1
            for r in data:
                if len(r) <= max(ts_i, url_i):
                    continue
                p = urlparse(r[url_i]).path or "/"
                if p not in archived or r[ts_i] < archived[p]:
                    archived[p] = r[ts_i]
        return archived

    async def _passive(self, ctx: Ctx, target: Target,
                       origin: str) -> List[Finding]:
        archived = await self._archived(ctx, target)
        findings: List[Finding] = []
        for path in self.PATHS:
            ts = archived.get(path)
            if not ts:
                continue
            findings.append(self._f(
                "leak", f"{self.KEY}_archived",
                f"{path} was archived ({ts}) - {self.label} artifact "
                f"was publicly reachable",
                source="Wayback CDX", source_url=origin + path,
                confidence=70, passive=True,
                evidence={"severity": "medium", "detector": self.id,
                          "archived_at": ts,
                          "remediation": _REMEDIATION}))
        return findings

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        origin = await _origin(ctx, target)
        if not origin:
            return self._skipped("no web origin for this target type")
        findings: List[Finding] = []
        if self.module_mode(ctx) == "passive":
            findings = await self._passive(ctx, target, origin)
            res = self._ok(findings,
                           f"{len(findings)} archived artifact(s) (passive)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls: List[str] = [origin + p for p in self.PATHS]
        for u in await self._linked(ctx, target):
            if u not in urls:
                urls.append(u)
        sem = asyncio.Semaphore(6)

        async def one(u: str) -> List[Finding]:
            async with sem:
                try:
                    return await self.check(ctx, u)
                except Exception:
                    return []

        parts = await asyncio.gather(*[one(u) for u in urls])
        for part in parts:
            findings.extend(part)
            self._checkpoint(findings)
        res = self._ok(
            findings,
            f"{len(urls)} candidate artifact URL(s), "
            f"{len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


def _ev(plugin_id: str, **kw) -> Dict[str, Any]:
    ev = {"detector": plugin_id, "remediation": _REMEDIATION}
    ev.update(kw)
    return ev


# ---------------------------------------------------------------------------
# 1. Memory & crash dumps
# ---------------------------------------------------------------------------

class DaHeapDump(_DeepArtifact):
    """Heap dumps and thread dumps: Java .hprof files (loose paths and
    the Spring Boot 1.x style /heapdump endpoint), V8/Node heap
    snapshots, and JVM thread dumps. infodisclosure.py owns the
    Actuator reachability probes including /actuator/heapdump; this
    detector owns the loose-file surfaces and PROVES the format from
    the first bytes instead of trusting the path."""
    id = "da_heap_dump"
    label = "Heap Dump Exposure (da)"
    group = "web"
    description = ("Java heap dumps (.hprof), Node/V8 heap snapshots "
                   "and JVM thread dumps verified by format signature "
                   "from a capped ranged read.")
    KEY = "heap_dump_exposed"
    PATHS = ["/heapdump", "/heap.hprof", "/java.hprof", "/dump.hprof",
             "/heapdump.hprof", "/heap.heapsnapshot",
             "/node.heapsnapshot", "/snapshot.heapsnapshot",
             "/actuator/threaddump", "/threaddump"]
    LINK_EXTS = (".hprof", ".heapsnapshot")

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, size, _ct = await _head(ctx, url)
        if status != 200:
            return out
        path = urlparse(url).path.lower()
        if "threaddump" in path:
            data, _t, _h = await _window(ctx, url, 0, TEXT_CAP // 2)
            text = data.decode("utf-8", "ignore")
            threads: Optional[int] = None
            try:
                j = json.loads(text)
                if isinstance(j, dict) and isinstance(j.get("threads"),
                                                      list):
                    threads = len(j["threads"])
            except Exception:
                pass
            if threads is None and "Full thread dump" not in text:
                return out
            ev = _ev(self.id, format="JVM thread dump", size_bytes=size,
                     bytes_read=len(data))
            if threads is not None:
                ev["thread_count"] = threads
            out.append(self._f(
                "leak", "thread_dump_exposed",
                f"JVM thread dump exposed at {url} - live thread "
                f"stacks, locks and app internals are downloadable",
                source=self.id, source_url=url, confidence=88,
                evidence=ev))
            return out
        data, total, honored = await _window(ctx, url, 0, 4096)
        fmt = None
        if data.startswith(b"JAVA PROFILE"):
            fmt = ("Java heap dump (HPROF "
                   + data.split(b"\x00")[0].decode("ascii", "ignore")
                   .replace("JAVA PROFILE", "").strip() + ")")
        elif path.endswith(".heapsnapshot") and \
                data.lstrip().startswith(b'{"snapshot"'):
            fmt = "V8/Node heap snapshot (JSON)"
        if not fmt:
            return out
        total = total or size
        out.append(self._f(
            "leak", self.KEY,
            f"{fmt} exposed at {url} - a heap dump contains every "
            f"object in memory: credentials, session tokens, keys and "
            f"user data",
            source=self.id, source_url=url, confidence=95,
            evidence=_ev(self.id, format=fmt, size_bytes=total,
                         size_human=(f"{total / 1048576:.1f} MB"
                                     if total else "unknown"),
                         bytes_read=len(data), range_honored=honored)))
        return out


class DaCrashDump(_DeepArtifact):
    """Windows minidumps and Unix core dumps at loose paths, verified
    by the MDMP magic or an ELF header whose e_type is ET_CORE."""
    id = "da_crash_dump"
    label = "Crash/Core Dump Exposure (da)"
    group = "web"
    description = ("Windows minidump (.dmp) and ELF core dump files "
                   "verified by file signature from a capped ranged "
                   "read.")
    KEY = "crash_dump_exposed"
    PATHS = ["/memory.dmp", "/crash.dmp", "/minidump.dmp", "/app.dmp",
             "/crashdump.dmp", "/dump.dmp", "/core", "/core.dump",
             "/coredump"]
    LINK_EXTS = (".dmp", ".mdmp")

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, size, ctype = await _head(ctx, url)
        if status != 200:
            return out
        data, total, honored = await _window(ctx, url, 0, 4096)
        fmt = None
        if data.startswith(b"MDMP"):
            fmt = "Windows minidump (MDMP)"
        elif data.startswith(b"\x7fELF") and len(data) >= 18:
            endian = "little" if data[5] == 1 else "big"
            if int.from_bytes(data[16:18], endian) == 4:  # ET_CORE
                fmt = "ELF core dump (ET_CORE)"
        total = total or size
        if fmt:
            out.append(self._f(
                "leak", self.KEY,
                f"{fmt} exposed at {url} - crash dumps carry process "
                f"memory: secrets, tokens and user data at crash time",
                source=self.id, source_url=url, confidence=95,
                evidence=_ev(self.id, format=fmt, size_bytes=total,
                             bytes_read=len(data),
                             range_honored=honored)))
        elif size and size >= 4096 and data[:1] not in (b"<", b"") \
                and "html" not in (ctype or ""):
            out.append(self._f(
                "leak", self.KEY,
                f"Possible crash dump at {url} ({size} bytes of binary "
                f"at a dump path; format signature not recognized)",
                source=self.id, source_url=url, confidence=50,
                evidence=_ev(self.id, format="unverified binary",
                             size_bytes=size, bytes_read=len(data))))
        return out


# ---------------------------------------------------------------------------
# 2. Debug symbols
# ---------------------------------------------------------------------------

class DaDebugSymbols(_DeepArtifact):
    """Windows PDB symbol files (MSF signature) and macOS/iOS dSYM
    bundles (probed through their Contents/Info.plist)."""
    id = "da_debug_symbols"
    label = "Debug Symbols Exposure (da)"
    group = "web"
    description = ("PDB debug symbol files verified by the MSF "
                   "signature and dSYM bundles exposed via their "
                   "Info.plist.")
    KEY = "debug_symbols_exposed"
    PATHS = ["/app.pdb", "/program.pdb", "/Web.pdb", "/bin/app.pdb",
             "/app.dSYM/Contents/Info.plist"]
    LINK_EXTS = (".pdb",)

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, size, _ct = await _head(ctx, url)
        if status != 200:
            return out
        if url.lower().endswith(".plist"):
            data, _t, _h = await _window(ctx, url, 0, 4096)
            text = data.decode("utf-8", "ignore")
            if "<plist" in text or "CFBundle" in text:
                bundle = url.split(".dSYM/")[0].rsplit("/", 1)[-1] \
                    + ".dSYM"
                out.append(self._f(
                    "leak", self.KEY,
                    f"dSYM debug-symbol bundle exposed at {url} "
                    f"({bundle}) - symbols map the shipped binary's "
                    f"functions, types and source paths",
                    source=self.id, source_url=url, confidence=85,
                    evidence=_ev(self.id, format="dSYM bundle",
                                 bundle=bundle, bytes_read=len(data))))
            return out
        data, total, honored = await _window(ctx, url, 0, 4096)
        if data.startswith(b"Microsoft C/C++ MSF 7.00") or \
                data.startswith(b"Microsoft C/C++ program database"):
            out.append(self._f(
                "leak", self.KEY,
                f"PDB debug symbols exposed at {url} - full function "
                f"names, source file paths and type layout for the "
                f"shipped binary",
                source=self.id, source_url=url, confidence=95,
                evidence=_ev(self.id, format="PDB (MSF)",
                             size_bytes=total or size,
                             bytes_read=len(data),
                             range_honored=honored)))
        return out


# ---------------------------------------------------------------------------
# 3. Compiled archives: JAR/WAR (config names + one bounded config read)
#    and target-hosted mobile packages (config entry names only)
# ---------------------------------------------------------------------------

_CONFIG_NAME_RE = re.compile(
    r"(?:^|/)(?:application|bootstrap|application-[\w]+)\."
    r"(?:properties|ya?ml)$|WEB-INF/web\.xml$|"
    r"META-INF/persistence\.xml$|\.properties$", re.I)
_CONFIG_VALUE_RE = re.compile(
    r"(?:^|/)(?:application|bootstrap|application-[\w]+)\."
    r"(?:properties|ya?ml)$", re.I)
_KEYSTORE_RE = re.compile(r"\.(?:jks|keystore|p12|pfx)$", re.I)


class _ArchiveBase(_DeepArtifact):
    READ_VALUES = False
    INTERESTING_RE = _CONFIG_NAME_RE

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, size, _ct = await _head(ctx, url)
        entries = None
        if status == 200 or status == 0:
            entries = await _zip_entries(ctx, url, size)
        if entries is None:
            if status == 200:
                head, _t, _h = await _window(ctx, url, 0, 64)
                if head.startswith(b"PK\x03\x04"):
                    out.append(self._f(
                        "leak", self.KEY,
                        f"Compiled archive exposed at {url} (ZIP "
                        f"signature verified; central directory not "
                        f"readable within the read cap)",
                        source=self.id, source_url=url, confidence=70,
                        evidence=_ev(self.id, format="ZIP archive",
                                     size_bytes=size,
                                     bytes_read=len(head))))
            return out
        names = [e[0] for e in entries]
        out.append(self._f(
            "leak", self.KEY,
            f"Compiled archive downloadable at {url} "
            f"({len(names)} entries"
            + (f", {size} bytes" if size else "") + ") - the shipped "
            f"application itself, its config layout and embedded "
            f"resources are public",
            source=self.id, source_url=url, confidence=90,
            evidence=_ev(self.id, format="ZIP archive",
                         size_bytes=size, entry_count=len(names))))
        interesting = [n for n in names if self.INTERESTING_RE.search(n)]
        if interesting:
            out.append(self._f(
                "leak", f"{self.KEY}_config_entries",
                f"Archive at {url} embeds configuration: "
                + ", ".join(interesting[:12]),
                source=self.id, source_url=url, confidence=90,
                evidence=_ev(self.id,
                             config_entries=interesting[:25],
                             entry_count=len(names))))
        keystores = [n for n in names if _KEYSTORE_RE.search(n)]
        if keystores:
            out.append(self._f(
                "leak", f"{self.KEY}_keystore_entry",
                f"Archive at {url} embeds a keystore file: "
                + ", ".join(keystores[:6])
                + " (name only - contents never read)",
                source=self.id, source_url=url, confidence=92,
                evidence=_ev(self.id, keystore_entries=keystores[:10])))
        if self.READ_VALUES:
            for entry in entries:
                if not _CONFIG_VALUE_RE.search(entry[0]):
                    continue
                text = await _zip_entry_text(ctx, url, entry)
                hits = _scan_config_secrets(text or "")
                for pattern, raw in hits[:3]:
                    out.append(self._f(
                        "leak", f"{self.KEY}_config_secret",
                        f"Hardcoded secret in {entry[0]} inside the "
                        f"archive at {url}: {pattern} = "
                        f"{raw} "
                        f"(sha256 {_fingerprint(raw)[:16]}...) - "
                        f"read from one bounded config entry",
                        source=self.id, source_url=url, confidence=94,
                        evidence=_ev(
                            self.id, config_entry=entry[0],
                            pattern=pattern, masked_value=redact(raw),
                            full_value=raw,
                            sha256=_fingerprint(raw))))
                if hits:
                    break
        return out


class DaArchiveConfigs(_ArchiveBase):
    """Hosted JAR/WAR/EAR: ZIP central-directory listing (ranged tail
    read) flags embedded config filenames and keystores; ONE small
    config entry (application.properties/yml, <= 16 KB compressed) is
    read for hardcoded secrets, masked + fingerprinted. The archive
    itself is never downloaded."""
    id = "da_archive_configs"
    label = "App Archive Config Exposure (da)"
    group = "web"
    description = ("JAR/WAR archives: embedded config filenames via "
                   "ZIP central directory, keystore names, and masked "
                   "secrets from one bounded config entry.")
    KEY = "archive_configs"
    READ_VALUES = True
    PATHS = ["/app.jar", "/app.war", "/server.jar", "/server.war",
             "/api.jar", "/application.jar", "/main.jar",
             "/webapp.war", "/app.ear"]
    LINK_EXTS = (".jar", ".war", ".ear")


_MOBILE_INTERESTING_RE = re.compile(
    r"google-services\.json$|GoogleService-Info\.plist$|"
    r"agconnect-services\.json$|(^|/)assets/[^/]+\.json$|"
    r"(^|/)[^/]+\.plist$", re.I)


class DaMobilePackage(_ArchiveBase):
    """APK/IPA/AAB hosted on the TARGET itself (binex.py analyzes
    packages from public mirrors; the pf pack flags the LOOSE
    google-services.json file). This detector reports the hosted
    package plus the config entry NAMES inside it - no entry contents
    are read."""
    id = "da_mobile_package"
    label = "Hosted Mobile Package (da)"
    group = "mobile"
    description = ("APK/IPA/AAB hosted on the target: presence plus "
                   "config entry names from the ZIP central "
                   "directory (google-services.json and friends).")
    KEY = "mobile_package"
    READ_VALUES = False
    INTERESTING_RE = _MOBILE_INTERESTING_RE
    PATHS = ["/app.apk", "/app-release.apk", "/android.apk",
             "/app.ipa", "/app.aab"]
    LINK_EXTS = (".apk", ".ipa", ".aab")


_URL_RX = re.compile(r"https?://[^\s\"'<>\\]{4,200}")


class DaWasmSurface(_DeepArtifact):
    """WebAssembly modules: the magic + version are verified and the
    import/export surface is parsed from the head window (sections sit
    at the front of the module). Embedded URLs in the window are
    reported; internal ones are the interesting leak."""
    id = "da_wasm_surface"
    label = "WASM Module Surface (da)"
    group = "web"
    description = ("WebAssembly modules verified by the \\0asm magic; "
                   "import/export names and embedded URLs parsed from "
                   "a capped head window.")
    KEY = "wasm_surface"
    PATHS = ["/main.wasm", "/app.wasm", "/index.wasm",
             "/program.wasm", "/module.wasm"]
    LINK_EXTS = (".wasm",)

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, size, _ct = await _head(ctx, url)
        if status != 200:
            return out
        data, total, honored = await _window(ctx, url, 0, WASM_CAP)
        info = _parse_wasm(data)
        if not info:
            return out
        text = data.decode("latin-1", "ignore")
        urls = []
        for m in _URL_RX.finditer(text):
            u = m.group(0).rstrip(".,);]")
            if u not in urls:
                urls.append(u)
            if len(urls) >= 8:
                break
        internal = [u for u in urls
                    if INTERNAL_URL_RE.search(u)]
        ev = _ev(self.id, format="WebAssembly",
                 wasm_version=info["version"],
                 size_bytes=total or size, bytes_read=len(data),
                 range_honored=honored,
                 window_truncated=bool(info["truncated"]),
                 imports=info["imports"][:20],
                 exports=info["exports"][:20])
        if urls:
            ev["embedded_urls"] = urls[:5]
        out.append(self._f(
            "leak", self.KEY,
            f"WebAssembly module exposed at {url}: "
            f"{len(info['imports'])} import(s), "
            f"{len(info['exports'])} export(s) visible - the "
            f"module's API surface (and any embedded endpoints) is "
            f"public",
            source=self.id, source_url=url, confidence=85,
            evidence=ev))
        if internal:
            out.append(self._f(
                "leak", "wasm_internal_url",
                f"WASM module at {url} embeds internal URL(s): "
                + ", ".join(internal[:4]),
                source=self.id, source_url=url, confidence=88,
                evidence=_ev(self.id, internal_urls=internal[:6],
                             bytes_read=len(data))))
        return out


# ---------------------------------------------------------------------------
# 4. Firmware & device artifacts
# ---------------------------------------------------------------------------

_FW_SIGS = [
    (b"\x27\x05\x19\x56", "uImage (U-Boot legacy image)"),
    (b"HDR0", "TRX firmware image"),
    (b"hsqs", "SquashFS filesystem image"),
    (b"UBI#", "UBI flash image"),
    (b"\xd0\x0d\xfe\xed", "Flattened Device Tree / FIT image"),
]


class DaFirmwareImage(_DeepArtifact):
    """Downloadable firmware images at conventional paths, verified by
    image signature (uImage / TRX / SquashFS / UBI / FDT) from a small
    head window."""
    id = "da_firmware_image"
    label = "Firmware Image Exposure (da)"
    group = "infra"
    description = ("Firmware images (.bin/.img/.fw/.trx) verified by "
                   "format signature - uImage, TRX, SquashFS, UBI, "
                   "device-tree.")
    KEY = "firmware_image"
    PATHS = ["/firmware.bin", "/firmware.img", "/firmware.fw",
             "/fw.bin", "/fw.img", "/update.bin", "/upgrade.bin",
             "/sysupgrade.bin", "/openwrt.bin", "/firmware.trx",
             "/firmware.chk"]
    LINK_EXTS = (".trx", ".chk")

    async def _linked(self, ctx: Ctx, target: Target) -> List[str]:
        # Generic .bin/.img links are everywhere (downloads, media);
        # only firmware-named ones are this detector's surface.
        raw = await super()._linked(ctx, target)
        out = list(raw)
        if not self.LINK_EXTS:
            return out
        host = _host_of(target)
        try:
            texts = await collect_texts(ctx, target)
        except Exception:
            texts = []
        for _w, text, page_url in texts:
            for m in _LINK_RX.finditer(text or ""):
                full = urljoin(page_url, m.group(1) or m.group(2) or "")
                p = urlparse(full)
                base = (p.path or "").lower()
                if p.hostname != host:
                    continue
                if base.endswith((".bin", ".img", ".fw")) and any(
                        k in base for k in ("firmware", "update",
                                            "upgrade", "sysupgrade")):
                    clean = full.split("#")[0].split("?")[0]
                    if clean not in out:
                        out.append(clean)
                if len(out) >= 12:
                    return out
        return out

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, size, ctype = await _head(ctx, url)
        if status != 200:
            return out
        data, total, honored = await _window(ctx, url, 0, 4096)
        fmt = None
        for magic, name in _FW_SIGS:
            if data.startswith(magic):
                fmt = name
                break
        total = total or size
        if fmt:
            out.append(self._f(
                "infra", self.KEY,
                f"Firmware image exposed at {url}: {fmt} - a "
                f"downloadable firmware image can be unpacked "
                f"offline for hardcoded credentials, keys and "
                f"vulnerabilities",
                source=self.id, source_url=url, confidence=95,
                evidence=_ev(self.id, format=fmt, size_bytes=total,
                             bytes_read=len(data),
                             range_honored=honored)))
        elif size and size >= 32768 and data[:1] not in (b"<", b"") \
                and "text" not in (ctype or "") \
                and "json" not in (ctype or ""):
            out.append(self._f(
                "infra", self.KEY,
                f"Possible firmware image at {url} ({size} bytes of "
                f"binary at a firmware path; signature not "
                f"recognized)",
                source=self.id, source_url=url, confidence=55,
                evidence=_ev(self.id, format="unverified binary",
                             size_bytes=size, bytes_read=len(data))))
        return out


_CRED_FIELD_RE = re.compile(
    r"[A-Za-z0-9_.\-]{0,24}(?:password|passwd|pwd|psk|wpa|ssid|secret)"
    r"[A-Za-z0-9_.\-]{0,12}", re.I)


class DaDeviceConfig(_DeepArtifact):
    """Router/IoT/device configuration exports (config.bin,
    backup.cfg, ...). The export being downloadable at all is the
    finding; credential FIELD NAMES visible in the first bytes raise
    it (values are never copied into evidence)."""
    id = "da_device_config_export"
    label = "Device Config Export (da)"
    group = "infra"
    description = ("Device/router configuration exports at "
                   "conventional paths; first-bytes classification and "
                   "credential field names as evidence.")
    KEY = "device_config_export"
    PATHS = ["/config.bin", "/backup.cfg", "/config.cfg",
             "/settings.cfg", "/router.cfg", "/device.cfg",
             "/config.dat", "/backup.bin", "/settings.bin",
             "/conf.bin"]

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, size, ctype = await _head(ctx, url)
        if status != 200 or not size:
            return out
        data, _t, honored = await _window(ctx, url, 0, HEAD_CAP)
        head_low = data[:512].lower()
        if b"<html" in head_low or b"<!doctype html" in head_low:
            return out  # SPA/HTML fallback, not an export
        if data.lstrip()[:1] in (b"{", b"["):
            kind = "JSON"
        elif data.lstrip().startswith(b"<?xml") or \
                data.lstrip().startswith(b"<config"):
            kind = "XML"
        elif sum(1 for b in data[:256] if b in (9, 10, 13)
                 or 32 <= b < 127) > 200:
            kind = "text"
        else:
            kind = "binary"
        text = data.decode("latin-1", "ignore")
        fields: List[str] = []
        for m in _CRED_FIELD_RE.finditer(text):
            f = m.group(0)
            if f not in fields:
                fields.append(f)
            if len(fields) >= 8:
                break
        ev = _ev(self.id, format=f"device config export ({kind})",
                 size_bytes=size, bytes_read=len(data),
                 range_honored=honored)
        if fields:
            ev["credential_fields_in_first_bytes"] = fields
        out.append(self._f(
            "infra", self.KEY,
            f"Device configuration export downloadable at {url} "
            f"({kind}, {size} bytes)"
            + (" - credential fields visible in the first bytes: "
               + ", ".join(fields) if fields else "")
            + " - config exports typically carry admin credentials, "
              "Wi-Fi keys and network layout",
            source=self.id, source_url=url,
            confidence=92 if fields else 80,
            evidence=ev))
        return out


_VERSION_KEY_RE = re.compile(r"version|build|release|revision", re.I)
_URL_VALUE_RX = re.compile(r"https?://[^\s\"'<>\\]{4,300}")


def _manifest_walk(obj: Any, depth: int = 0):
    """Yield (key, string_value) pairs from a parsed JSON manifest."""
    if depth > 4:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                yield str(k), v
            else:
                yield from _manifest_walk(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:20]:
            yield from _manifest_walk(v, depth + 1)


class DaOtaManifest(_DeepArtifact):
    """OTA / firmware update manifests (JSON): version fields and the
    download URLs they hand out - internal URLs reveal staging/update
    infrastructure that was never meant to be public."""
    id = "da_ota_manifest"
    label = "OTA/Update Manifest (da)"
    group = "infra"
    description = ("Firmware/OTA update manifests leaking version "
                   "info and download URLs (internal URLs flagged).")
    KEY = "ota_manifest"
    PATHS = ["/firmware.json", "/update.json", "/ota.json",
             "/version.json", "/updates.json", "/release.json",
             "/firmware/manifest.json", "/ota/update.json"]

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, _size, _ct = await _head(ctx, url)
        if status != 200:
            return out
        data, _t, _h = await _window(ctx, url, 0, TEXT_CAP // 2)
        text = data.decode("utf-8", "ignore").strip()
        parsed = None
        try:
            parsed = json.loads(text)
        except Exception:
            cut = text.rfind("}")
            if cut > 0:
                try:
                    parsed = json.loads(text[:cut + 1])
                except Exception:
                    parsed = None
        if not isinstance(parsed, (dict, list)):
            return out
        pairs = list(_manifest_walk(parsed))
        keys = [k for k, _v in pairs]
        signal = any(_VERSION_KEY_RE.search(k) or
                     k.lower() in ("url", "download", "firmware",
                                   "ota", "update", "file", "image")
                     for k in keys)
        if not signal:
            return out
        version = next((v for k, v in pairs
                        if _VERSION_KEY_RE.search(k) and len(v) <= 60),
                       None)
        urls: List[str] = []
        for _k, v in pairs:
            for m in _URL_VALUE_RX.finditer(v):
                u = m.group(0).rstrip(".,);]")
                if u not in urls:
                    urls.append(u)
        internal = [u for u in urls if INTERNAL_URL_RE.search(u)]
        ev = _ev(self.id, format="OTA/update manifest (JSON)",
                 bytes_read=len(data))
        if version:
            ev["reported_version"] = version
        if urls:
            ev["download_urls"] = urls[:5]
        out.append(self._f(
            "infra", self.KEY,
            f"Update manifest exposed at {url}"
            + (f" (version {version})" if version else "")
            + " - reveals firmware versions and where devices fetch "
              "updates from",
            source=self.id, source_url=url, confidence=85,
            evidence=ev))
        if internal:
            out.append(self._f(
                "infra", "ota_manifest_internal_url",
                f"Update manifest at {url} points devices at internal "
                f"URL(s): " + ", ".join(internal[:4]),
                source=self.id, source_url=url, confidence=90,
                evidence=_ev(self.id, internal_urls=internal[:6])))
        return out


# ---------------------------------------------------------------------------
# 5. Build-artifact listings (bytecode caches, source trees, symbol dirs)
# ---------------------------------------------------------------------------

_ARTIFACT_EXTS = (".pyc", ".class", ".ts", ".tsx", ".jsx", ".pdb",
                  ".hprof", ".dmp", ".jar", ".war", ".wasm", ".apk",
                  ".py", ".dll", ".exe")


class DaBuildListing(_DeepArtifact):
    """Directory listings of build-artifact folders (/bin/, /src/,
    /__pycache__/, /WEB-INF/, /firmware/, /artifacts/): opendir.py
    reports generic listings elsewhere; this detector fires on the
    artifact FILENAMES a listing hands out - bytecode, symbols,
    sources and packages."""
    id = "da_build_listing"
    label = "Build Artifact Listing (da)"
    group = "web"
    description = ("Open listings of build folders exposing compiled "
                   "artifacts by filename: .pyc/.class/.pdb/.hprof/"
                   ".jar/.wasm and source files.")
    KEY = "build_listing"
    PATHS = ["/bin/", "/src/", "/__pycache__/", "/WEB-INF/",
             "/firmware/", "/artifacts/"]

    async def check(self, ctx: Ctx, url: str) -> List[Finding]:
        out: List[Finding] = []
        status, _size, _ct = await _head(ctx, url)
        if status != 200:
            return out
        data, _t, _h = await _window(ctx, url, 0, TEXT_CAP)
        text = data.decode("utf-8", "ignore")
        if not _is_listing(text):
            return out
        names = _listing_names(text)
        interesting = [n for n in names
                       if n.lower().endswith(_ARTIFACT_EXTS)]
        if not interesting:
            return out
        out.append(self._f(
            "leak", self.KEY,
            f"Build-artifact listing at {url} hands out compiled/"
            f"source files: " + ", ".join(interesting[:12])
            + f" ({len(names)} entries listed)",
            source=self.id, source_url=url, confidence=90,
            evidence=_ev(self.id, format="directory listing",
                         artifact_files=interesting[:20],
                         listed_entries=len(names),
                         bytes_read=len(data))))
        return out

    async def _passive(self, ctx: Ctx, target: Target,
                       origin: str) -> List[Finding]:
        archived = await self._archived(ctx, target)
        findings: List[Finding] = []
        for d in self.PATHS:
            hits = [p for p in archived
                    if p.startswith(d)
                    and p.lower().endswith(_ARTIFACT_EXTS)]
            if not hits:
                continue
            findings.append(self._f(
                "leak", f"{self.KEY}_archived",
                f"Archived listing contents under {d}: "
                + ", ".join(hits[:8])
                + " - build artifacts were publicly reachable",
                source="Wayback CDX", source_url=origin + d,
                confidence=65, passive=True,
                evidence=_ev(self.id, archived_paths=hits[:12])))
        return findings


DA_IDS = [
    "da_heap_dump", "da_crash_dump", "da_debug_symbols",
    "da_archive_configs", "da_wasm_surface", "da_mobile_package",
    "da_firmware_image", "da_device_config_export", "da_ota_manifest",
    "da_build_listing",
]
