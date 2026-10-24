"""Canary payload builders for the deep-artifacts pack (da_*).

Every payload is synthetic. The one fake secret is assembled from
fragments at build time so the assembled value never appears in
source (GitHub Push Protection); tests assert it never appears in
findings either - only its masked form + SHA-256 fingerprint.
"""
from __future__ import annotations

import io
import json
import struct
import zipfile

# Fragment-assembled fake secret (canary only).
FAKE_A = "CanaryFake"
FAKE_B = "Pass-9871"
FAKE_SECRET = FAKE_A + FAKE_B


def fake_hprof(total: int = 300_000) -> bytes:
    head = b"JAVA PROFILE 1.0.2\x00" + struct.pack(">I", 4)
    return head + b"\x00" * max(0, total - len(head))


def fake_heapsnapshot() -> bytes:
    return json.dumps({
        "snapshot": {"meta": {"node_fields": ["type", "name"]},
                     "node_count": 3, "edge_count": 2},
        "nodes": [], "edges": [], "locations": []}).encode()


def fake_threaddump() -> bytes:
    return json.dumps({"threads": [
        {"threadName": "main", "threadState": "RUNNABLE",
         "stackTrace": []},
        {"threadName": "http-worker-1", "threadState": "WAITING",
         "stackTrace": []},
        {"threadName": "scheduler", "threadState": "TIMED_WAITING",
         "stackTrace": []}]}).encode()


def fake_mdmp(total: int = 120_000) -> bytes:
    head = b"MDMP" + struct.pack("<II", 42899, 0)
    return head + b"\x00" * max(0, total - len(head))


def fake_core() -> bytes:
    e = bytearray(64)
    e[0:4] = b"\x7fELF"
    e[4] = 2          # 64-bit
    e[5] = 1          # little-endian
    e[6] = 1          # version
    struct.pack_into("<H", e, 16, 4)  # e_type = ET_CORE
    return bytes(e) + b"\x00" * 4096


def fake_pdb(total: int = 90_000) -> bytes:
    head = b"Microsoft C/C++ MSF 7.00\x00\x00\x00"
    return head + b"\x00" * max(0, total - len(head))


def fake_dsym_plist() -> bytes:
    return (b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<plist version="1.0"><dict>'
            b'<key>CFBundleIdentifier</key>'
            b'<string>com.example.app.dsym</string>'
            b'</dict></plist>')


def _leb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _wstr(s: str) -> bytes:
    b = s.encode()
    return _leb(len(b)) + b


def _section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + _leb(len(payload)) + payload


def fake_wasm() -> bytes:
    types = _section(1, _leb(1) + b"\x60\x00\x00")
    imports = _section(2, _leb(1) + _wstr("env")
                       + _wstr("fetch_internal") + b"\x00\x00")
    funcs = _section(3, _leb(1) + b"\x00")
    exports = _section(7, _leb(1) + _wstr("main") + b"\x00\x01")
    blob = (b"endpoint=https://api.example.com/v1 "
            b"meta=http://192.168.10.9/internal/meta ")
    custom = _section(0, _wstr("meta") + blob)
    return b"\x00asm" + struct.pack("<I", 1) + types + imports \
        + funcs + exports + custom


def _zip_bytes(entries) -> bytes:
    """entries: list of (name, bytes, compress_type)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data, ctype in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = ctype
            z.writestr(info, data)
    return buf.getvalue()


def fake_jar(with_secret: bool = True) -> bytes:
    props = ("spring.application.name=canary\n"
             "spring.datasource.url=jdbc:postgresql://db:5432/app\n")
    if with_secret:
        props += "spring.datasource.password=" + FAKE_SECRET + "\n"
    props += "server.port=8080\n"
    return _zip_bytes([
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n",
         zipfile.ZIP_STORED),
        ("BOOT-INF/classes/application.properties", props.encode(),
         zipfile.ZIP_DEFLATED),
        ("BOOT-INF/classes/com/acme/App.class",
         b"\xca\xfe\xba\xbe" + b"\x00" * 128, zipfile.ZIP_STORED),
        ("BOOT-INF/lib/keystore.jks", b"\xfe\xed\xfe\xed" + b"\x00" * 64,
         zipfile.ZIP_STORED),
    ])


def fake_apk() -> bytes:
    return _zip_bytes([
        ("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64,
         zipfile.ZIP_STORED),
        ("google-services.json",
         b'{"project_info": {"project_id": "canary"}}',
         zipfile.ZIP_STORED),
        ("classes.dex", b"dex\n035\x00" + b"\x00" * 128,
         zipfile.ZIP_STORED),
        ("assets/config.json", b"{}", zipfile.ZIP_STORED),
    ])


def fake_firmware(total: int = 200_000) -> bytes:
    head = b"\x27\x05\x19\x56" + struct.pack(">7I", 0, 0, 0, 0, 0, 0, 0)
    return head + b"\xff" * max(0, total - len(head))


def fake_config_bin() -> bytes:
    body = bytearray(b"\x7fCFG\x00\x02\x00\x00")
    body += b"wifi_ssid\x00HomeNet\x00"
    body += b"\x00\x01\x02"
    body += b"admin_password\x00placeholder-value\x00"
    body += b"\x00" * 64
    body += b"wpa_psk\x00another-value\x00"
    body += b"\x00" * 512
    return bytes(body)


def fake_ota_manifest() -> bytes:
    return json.dumps({
        "firmware": {
            "version": "4.2.1",
            "url": "http://192.168.10.5/fw/update.bin",
            "sha256": "0" * 64},
        "channel": "stable"}).encode()


def fake_listing() -> bytes:
    return (b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">'
            b'<html><head><title>Index of /bin</title></head><body>'
            b'<h1>Index of /bin</h1><ul>'
            b'<li><a href="/">Parent Directory</a></li>'
            b'<li><a href="App.dll">App.dll</a></li>'
            b'<li><a href="App.pdb">App.pdb</a></li>'
            b'<li><a href="worker.class">worker.class</a></li>'
            b'<li><a href="notes.txt">notes.txt</a></li>'
            b'</ul></body></html>')


def fake_homepage() -> bytes:
    return (b'<html><head><title>Canary</title></head><body>'
            b'<h1>canary site</h1>'
            b'<a href="/files/app.hprof">heap</a>'
            b'<script src="/static/app.js"></script>'
            b'</body></html>')
