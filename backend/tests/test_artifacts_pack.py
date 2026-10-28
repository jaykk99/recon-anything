"""Deep-artifacts pack (da_*) detector tests.

Canary-first: a Range-honoring mock site serves planted artifacts
(fake hprof/MDMP/PDB/WASM/JAR/APK/firmware/config/manifest/listing).
Every detector must fire with the right evidence, reads must stay
capped (the server tracks bytes served per path), the planted secret
must never appear in full, and a clean site must stay silent.
"""
from __future__ import annotations

import hashlib
import json
import re

import httpx
import pytest

from app.cache import Cache
from app.plugins.artifacts_deep import DA_IDS
from app.plugins.base import Ctx, Target
from app.plugins.registry import discover
from app.ratelimit import RateLimiter

import artifacts_samples as S


# ---------------------------------------------------------------------------
# Range-honoring canary server (MockTransport)
# ---------------------------------------------------------------------------

class Canary:
    """Serves ROUTES, honors Range, records bytes served per path."""

    def __init__(self, routes):
        self.routes = routes  # path -> (bytes, content_type)
        self.served = {}      # path -> total body bytes sent
        self.ranges = {}      # path -> list of Range headers seen

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "web.archive.org" in url:
            rows = [["urlkey", "timestamp", "original"],
                    ["test,canary)/heap.hprof", "20240101000000",
                     "https://canary.test/heap.hprof"]]
            return httpx.Response(200, json=rows)
        path = request.url.path
        if path not in self.routes:
            return httpx.Response(404, text="not found")
        body, ctype = self.routes[path]
        total = len(body)
        if request.method == "HEAD":
            return httpx.Response(
                200, headers={"Content-Length": str(total),
                              "Content-Type": ctype})
        rng = request.headers.get("range", "")
        self.ranges.setdefault(path, []).append(rng)
        if rng.startswith("bytes="):
            spec = rng[6:]
            if spec.startswith("-"):
                n = int(spec[1:])
                part = body[-n:] if n < total else body
                start = total - len(part)
            else:
                a, _, b = spec.partition("-")
                start = int(a)
                end = int(b) if b else total - 1
                part = body[start:end + 1]
            self.served[path] = self.served.get(path, 0) + len(part)
            return httpx.Response(
                206, content=part,
                headers={"Content-Range":
                         f"bytes {start}-{start + len(part) - 1}/{total}",
                         "Content-Length": str(len(part)),
                         "Content-Type": ctype})
        self.served[path] = self.served.get(path, 0) + total
        return httpx.Response(200, content=body,
                              headers={"Content-Length": str(total),
                                       "Content-Type": ctype})


def _ctx(canary: Canary, modes=None) -> Ctx:
    transport = httpx.MockTransport(canary.handler)
    return Ctx(
        run_id="t", mode="active",
        http=httpx.AsyncClient(transport=transport,
                               follow_redirects=True, trust_env=False),
        cache=Cache(), keys={}, limiter=RateLimiter(),
        evidence_dir="/tmp", source_type="website",
        module_overrides=modes or {})


TARGET = Target(raw="https://canary.test/", type="url",
                normalized="https://canary.test/")


def _full_routes():
    return {
        "/": (S.fake_homepage(), "text/html"),
        "/static/app.js": (b"console.log(1)", "text/javascript"),
        "/heap.hprof": (S.fake_hprof(), "application/octet-stream"),
        "/files/app.hprof": (S.fake_hprof(), "application/octet-stream"),
        "/heap.heapsnapshot": (S.fake_heapsnapshot(),
                               "application/octet-stream"),
        "/actuator/threaddump": (S.fake_threaddump(),
                                 "application/json"),
        "/memory.dmp": (S.fake_mdmp(), "application/octet-stream"),
        "/core": (S.fake_core(), "application/octet-stream"),
        "/app.pdb": (S.fake_pdb(), "application/octet-stream"),
        "/app.dSYM/Contents/Info.plist": (S.fake_dsym_plist(),
                                          "text/xml"),
        "/program.wasm": (S.fake_wasm(), "application/wasm"),
        "/app.jar": (S.fake_jar(), "application/java-archive"),
        "/app.apk": (S.fake_apk(), "application/vnd.android.package"),
        "/firmware.bin": (S.fake_firmware(),
                          "application/octet-stream"),
        "/config.bin": (S.fake_config_bin(),
                        "application/octet-stream"),
        "/firmware.json": (S.fake_ota_manifest(), "application/json"),
        "/bin/": (S.fake_listing(), "text/html"),
    }


def _run(plugin_id, canary, modes=None):
    import asyncio
    reg = discover()
    return asyncio.run(reg[plugin_id]().run(TARGET, _ctx(canary, modes)))


def _keys(res):
    return [f.key for f in res.findings]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_all_da_detectors_registered():
    reg = discover()
    for pid in DA_IDS:
        assert pid in reg, pid
    assert len(DA_IDS) == 10


# ---------------------------------------------------------------------------
# Detectors fire on the canary
# ---------------------------------------------------------------------------

def test_heap_dump_fires_with_signature_and_cap():
    canary = Canary(_full_routes())
    res = _run("da_heap_dump", canary)
    assert res.status == "ok"
    keys = _keys(res)
    assert keys.count("heap_dump_exposed") >= 2  # .hprof + snapshot
    assert "thread_dump_exposed" in keys
    hprof = next(f for f in res.findings
                 if f.key == "heap_dump_exposed"
                 and "HPROF" in f.value)
    assert hprof.evidence["size_bytes"] == 300_000
    assert hprof.evidence["bytes_read"] <= 4096
    td = next(f for f in res.findings if f.key == "thread_dump_exposed")
    assert td.evidence["thread_count"] == 3
    # Linked artifact from the homepage was probed too.
    assert "/files/app.hprof" in canary.served
    # The 300 KB dump was never downloaded: capped ranged reads only.
    assert canary.served["/heap.hprof"] <= 4096
    assert canary.served["/files/app.hprof"] <= 4096


def test_crash_dump_fires_mdmp_and_elf_core():
    canary = Canary(_full_routes())
    res = _run("da_crash_dump", canary)
    assert res.status == "ok"
    vals = [f.value for f in res.findings if f.key == "crash_dump_exposed"]
    assert any("MDMP" in v for v in vals)
    assert any("ELF core" in v for v in vals)
    assert canary.served["/memory.dmp"] <= 4096


def test_debug_symbols_fire_pdb_and_dsym():
    canary = Canary(_full_routes())
    res = _run("da_debug_symbols", canary)
    assert res.status == "ok"
    assert _keys(res).count("debug_symbols_exposed") == 2
    vals = " ".join(f.value for f in res.findings)
    assert "PDB" in vals and "dSYM" in vals


def test_archive_configs_names_keystore_and_masked_secret():
    canary = Canary(_full_routes())
    res = _run("da_archive_configs", canary)
    assert res.status == "ok"
    keys = _keys(res)
    assert "archive_configs" in keys
    assert "archive_configs_config_entries" in keys
    assert "archive_configs_keystore_entry" in keys
    assert "archive_configs_config_secret" in keys
    entries = next(f for f in res.findings
                   if f.key == "archive_configs_config_entries")
    assert any("application.properties" in n
               for n in entries.evidence["config_entries"])
    secret_f = next(f for f in res.findings
                    if f.key == "archive_configs_config_secret")
    blob = json.dumps(secret_f.value) + json.dumps(secret_f.evidence)
    assert S.FAKE_SECRET not in blob
    digest = hashlib.sha256(S.FAKE_SECRET.encode()).hexdigest()
    assert digest in blob  # fingerprint, not the value
    masked = secret_f.evidence["masked_value"]
    assert masked != S.FAKE_SECRET and S.FAKE_SECRET not in masked
    assert "..." in masked or "*" in masked  # visibly redacted


def test_wasm_surface_imports_exports_and_internal_url():
    canary = Canary(_full_routes())
    res = _run("da_wasm_surface", canary)
    assert res.status == "ok"
    assert "wasm_surface" in _keys(res)
    assert "wasm_internal_url" in _keys(res)
    f = next(f for f in res.findings if f.key == "wasm_surface")
    assert "env.fetch_internal" in f.evidence["imports"]
    assert "main" in f.evidence["exports"]


def test_mobile_package_config_entry_names():
    canary = Canary(_full_routes())
    res = _run("da_mobile_package", canary)
    assert res.status == "ok"
    assert "mobile_package" in _keys(res)
    ent = next(f for f in res.findings
               if f.key == "mobile_package_config_entries")
    assert any("google-services.json" in n
               for n in ent.evidence["config_entries"])


def test_firmware_image_signature_and_cap():
    canary = Canary(_full_routes())
    res = _run("da_firmware_image", canary)
    assert res.status == "ok"
    f = next(f for f in res.findings if f.key == "firmware_image")
    assert "uImage" in f.value
    assert f.evidence["size_bytes"] == 200_000
    assert canary.served["/firmware.bin"] <= 4096


def test_device_config_export_credential_fields():
    canary = Canary(_full_routes())
    res = _run("da_device_config_export", canary)
    assert res.status == "ok"
    f = next(f for f in res.findings
             if f.key == "device_config_export")
    fields = f.evidence["credential_fields_in_first_bytes"]
    assert any("password" in x for x in fields)
    # Field NAMES only - the planted values must not be evidence.
    blob = json.dumps(f.evidence)
    assert "placeholder-value" not in blob
    assert "another-value" not in blob


def test_ota_manifest_version_and_internal_url():
    canary = Canary(_full_routes())
    res = _run("da_ota_manifest", canary)
    assert res.status == "ok"
    assert "ota_manifest" in _keys(res)
    assert "ota_manifest_internal_url" in _keys(res)
    f = next(f for f in res.findings if f.key == "ota_manifest")
    assert f.evidence["reported_version"] == "4.2.1"


def test_build_listing_artifact_filenames():
    canary = Canary(_full_routes())
    res = _run("da_build_listing", canary)
    assert res.status == "ok"
    f = next(f for f in res.findings if f.key == "build_listing")
    names = f.evidence["artifact_files"]
    assert "App.pdb" in names and "worker.class" in names
    assert "notes.txt" not in names


def test_no_full_secret_anywhere_in_any_finding():
    canary = Canary(_full_routes())
    blob = ""
    for pid in DA_IDS:
        res = _run(pid, canary)
        assert res.status == "ok", pid
        for f in res.findings:
            blob += f.value + json.dumps(f.evidence) + "\n"
    assert S.FAKE_SECRET not in blob


def test_passive_mode_uses_wayback():
    canary = Canary(_full_routes())
    res = _run("da_heap_dump", canary,
               modes={"da_heap_dump": "passive"})
    assert res.status == "ok"
    assert "heap_dump_exposed_archived" in _keys(res)


# ---------------------------------------------------------------------------
# Clean site silence
# ---------------------------------------------------------------------------

def test_clean_site_silence():
    routes = {
        "/": (b"<html><head><title>ok</title></head><body>hello"
              b"</body></html>", "text/html"),
        "/static/app.js": (b"console.log(1)", "text/javascript"),
    }
    for pid in DA_IDS:
        canary = Canary(routes)
        res = _run(pid, canary)
        assert res.status == "ok", pid
        assert res.findings == [], (pid, [f.key for f in res.findings])
