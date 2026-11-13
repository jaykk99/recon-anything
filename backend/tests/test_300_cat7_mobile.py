"""Cat-7 Mobile plugins (300-expansion, 2026-11-05): 29 plugins.

Per plugin: fires on a VULN fixture, silent on a CLEAN fixture, no
crash on malformed input. Fixtures are tiny synthetic artifacts built
in-test (APK/IPA-like zips, DEX string blobs, Mach-O header bytes,
plist XML, prefs XML, real sqlite3 files). Credential/storage items
additionally assert the raw secret never appears in any finding.

Live smoke: every wrapper runs end-to-end over a realistic synthetic
APK + IPA written to disk (see test_wrapper_smoke_all_plugins).
"""
import asyncio
import io
import json
import os
import plistlib
import sqlite3
import struct
import sys
import zipfile

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins._cat7_common import build_from_files, \
    build_from_zip_bytes  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = ["ipa_entitlement_plister", "objc_runtime_spy",
       "swift_name_demangler", "shared_preferences_dump",
       "ios_keychain_item_scraper", "ios_mach_o_encryption_checker",
       "nsuserdefaults_leak_scanner", "flutter_bloc_state_tracer",
       "react_native_bundle_extractor", "sqlite_mobile_db_decryptor",
       "ios_geoloc_spoof_detector", "fcm_push_token_leak",
       "jadx_headless_bridge", "frida_runtime_script_injector",
       "dex_bytecode_pattern_matcher", "android_root_detection_bypass",
       "ssl_pinning_remover_frida", "biometric_auth_bypass_hook",
       "obfuscation_dexguard_eval", "android_intent_fuzzer",
       "deeplink_uri_exploitation_finder", "native_library_so_bridge",
       "safetynet_attestation_simulator", "apk_signature_v3_verifier",
       "android_backup_flag_check", "android_webview_allow_file_access",
       "bad_provider_authority_checker", "app_tampering_hash_verify",
       "mobile_device_id_harvester"]

REG = discover()
SECRET = "rawsecretvalue1234567890"


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(404)), trust_env=False)
    return Ctx(run_id="cat7-test", mode="passive", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run(plugin_id, path):
    plugin = REG[plugin_id]()
    coro = plugin.run(Target(raw=str(path), type="file",
                             normalized=str(path)), _ctx())
    try:
        return asyncio.run(coro)
    except RuntimeError:  # a loop is already running in this thread
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _zip_bytes(files) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _all_text(findings) -> str:
    return json.dumps([{"v": f.value, "e": f.evidence}
                       for f in findings], default=str)


# ------------------------------------------------------------------
# Fixture builders
# ------------------------------------------------------------------

MANIFEST_VULN = """<manifest package="com.example.vuln" android:versionName="1.0">
  <application android:debuggable="true" android:allowBackup="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="*" android:pathPrefix="/open"/>
      </intent-filter>
    </activity>
    <receiver android:name=".BootReceiver" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <provider android:name=".DataProvider" android:authorities="com.example.vuln.data"
              android:exported="true" android:grantUriPermissions="true"/>
  </application>
</manifest>"""

MANIFEST_CLEAN_INTENT = """<manifest package="com.example.clean">
  <application android:debuggable="false" android:allowBackup="false">
    <activity android:name=".Main" android:exported="true"
              android:permission="com.example.clean.PERM">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="https" android:host="example.com"/>
      </intent-filter>
    </activity>
    <provider android:name=".P" android:authorities="com.example.clean.p"
              android:exported="false"/>
  </application>
</manifest>"""

MANIFEST_CLEAN_DEEPLINK = """<manifest package="com.example.clean">
  <application>
    <activity android:name=".Main" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.com"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""


def make_macho(cryptid: int) -> bytes:
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24,
                      0, 0)
    lc = struct.pack("<IIIIII", 0x2C, 24, 4096, 8192, cryptid, 0)
    return hdr + lc


def make_elf(hardened: bool) -> bytes:
    data = bytearray(256)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little endian
    struct.pack_into("<H", data, 16, 3 if hardened else 2)  # ET_DYN/EXEC
    struct.pack_into("<Q", data, 32, 64)                    # phoff
    struct.pack_into("<H", data, 54, 56)                    # phentsize
    struct.pack_into("<H", data, 56, 2 if hardened else 1)  # phnum
    # PHDR 1: GNU_STACK (executable only when not hardened)
    struct.pack_into("<I", data, 64, 0x6474E551)
    struct.pack_into("<I", data, 68, 0x6 if hardened else 0x7)
    if hardened:
        struct.pack_into("<I", data, 120, 0x6474E552)       # GNU_RELRO
        struct.pack_into("<I", data, 124, 0x4)
    tail = b"Java_com_example_Native_foo\x00JNI_OnLoad\x00" \
        if not hardened else b"internal\x00helper\x00"
    data[180:180 + len(tail)] = tail
    return bytes(data)


def make_signing_block(schemes) -> bytes:
    pairs = b""
    for sid in schemes:
        val = b"\x01\x02\x03\x04"
        pairs += struct.pack("<QI", 4 + len(val), sid) + val
    size = len(pairs) + 16
    return (b"PK\x03\x04fakedata" + struct.pack("<Q", size) + pairs +
            struct.pack("<Q", size) + b"APK Sig Block 42" +
            b"PK\x05\x06" + b"\x00" * 18)


def make_provision(entitlements) -> bytes:
    plist = plistlib.dumps({"Entitlements": entitlements})
    return b"\x30\x82\x10\x00signedjunk" + plist + b"\x00\x00"


def make_sqlite_file(path, rows):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE genp (acct TEXT, svce TEXT, agrp TEXT,"
                " pdmn TEXT, data BLOB)")
    con.executemany("INSERT INTO genp VALUES (?,?,?,?,?)", rows)
    con.commit()
    con.close()


def make_plain_db_bytes(tmp_path) -> bytes:
    p = tmp_path / "plain.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE t (secret TEXT)")
    con.execute("INSERT INTO t VALUES ('x')")
    con.commit()
    con.close()
    return p.read_bytes()


def keys_of(findings):
    return {f["key"] for f in findings}


# ------------------------------------------------------------------
# 187 IPA entitlements
# ------------------------------------------------------------------
from app.plugins.ipa_entitlement_plister import analyze_entitlements, \
    analyze_ipa  # noqa: E402


def test_ipa_entitlements_vuln():
    prov = {"Entitlements": {"get-task-allow": True,
                             "aps-environment": "development",
                             "application-identifier": "TEAMID.*"}}
    out = analyze_entitlements(prov)
    assert {"ipa_get_task_allow", "ipa_aps_development",
            "ipa_wildcard_app_id"} <= keys_of(out)


def test_ipa_entitlements_clean_and_zip():
    prov = {"Entitlements": {"get-task-allow": False,
                             "aps-environment": "production",
                             "application-identifier": "TEAMID.com.x"}}
    assert analyze_entitlements(prov) == []
    art = build_from_zip_bytes(_zip_bytes(
        {"Payload/X.app/embedded.mobileprovision":
         make_provision({"get-task-allow": True})}))
    assert keys_of(analyze_ipa(art)) == {"ipa_get_task_allow"}


# ------------------------------------------------------------------
# 188 ObjC runtime spy (static)
# ------------------------------------------------------------------
from app.plugins.objc_runtime_spy import analyze_objc_strings  # noqa: E402


def test_objc_vuln():
    out = analyze_objc_strings(
        ["method_exchangeImplementations", "canEvaluatePolicy",
         "LoginViewController", "plain text with spaces"])
    assert {"objc_swizzling_surface", "objc_sensitive_selectors",
            "objc_class_inventory"} <= keys_of(out)


def test_objc_clean():
    assert analyze_objc_strings(["hello world", "some string here"]) == []


# ------------------------------------------------------------------
# 189 Swift demangler
# ------------------------------------------------------------------
from app.plugins.swift_name_demangler import analyze_swift, \
    demangle_swift  # noqa: E402


def test_swift_demangle_subset():
    r = demangle_swift("$s5MyApp7Session4userSSvp")
    assert r is not None and "MyApp" in r and "Session" in r \
        and "user" in r


def test_swift_vuln_clean():
    out = analyze_swift(["$s5MyApp7Session4userSSvp",
                         "$s5MyApp5Login5startyyF"])
    assert keys_of(out) == {"swift_demangled_inventory"}
    assert "MyApp" in out[0]["value"]
    assert analyze_swift(["plain string", "nothing here"]) == []


# ------------------------------------------------------------------
# 191 Shared preferences
# ------------------------------------------------------------------
from app.plugins.shared_preferences_dump import analyze_prefs_xml  # noqa: E402


def test_shared_prefs_vuln_masked():
    xml = ('<map><string name="session_token">' + SECRET + "</string>"
           '<string name="theme">dark</string></map>')
    out = analyze_prefs_xml(xml)
    assert keys_of(out) == {"shared_prefs_plaintext_secret"}
    assert SECRET not in json.dumps(out, default=str)


def test_shared_prefs_clean():
    xml = '<map><string name="theme">dark</string>' \
          '<int name="level" value="3"/></map>'
    assert analyze_prefs_xml(xml) == []


# ------------------------------------------------------------------
# 192 iOS keychain
# ------------------------------------------------------------------
from app.plugins.ios_keychain_item_scraper import \
    analyze_keychain_rows  # noqa: E402


def test_keychain_vuln_masked():
    rows = [{"table": "genp", "acct": "user@example.com",
             "svce": "com.app", "pdmn": "dk",
             "data": SECRET.encode()}]
    out = analyze_keychain_rows(rows)
    assert keys_of(out) == {"keychain_weak_accessibility"}
    assert SECRET not in json.dumps(out, default=str)


def test_keychain_clean():
    rows = [{"table": "genp", "acct": "a", "svce": "s", "pdmn": "ak",
             "data": b"x"}, {"table": "inet", "acct": "b", "svce": "s",
                             "pdmn": "cku", "data": b"y"}]
    assert analyze_keychain_rows(rows) == []


def test_keychain_wrapper_sqlite(tmp_path):
    db = tmp_path / "keychain-db.sqlite"
    make_sqlite_file(db, [("user@example.com", "com.app", "g",
                           "ck", SECRET.encode())])
    res = _run("ios_keychain_item_scraper", db)
    assert len(res.findings) == 1
    assert SECRET not in _all_text(res.findings)


# ------------------------------------------------------------------
# 197 Mach-O encryption
# ------------------------------------------------------------------
from app.plugins.ios_mach_o_encryption_checker import analyze_macho, \
    parse_macho_encryption  # noqa: E402


def test_macho_vuln_clean():
    assert parse_macho_encryption(make_macho(0))["cryptid"] == 0
    assert keys_of(analyze_macho(make_macho(0))) == \
        {"macho_decrypted_binary"}
    assert analyze_macho(make_macho(1)) == []
    assert analyze_macho(b"\x00\x01garbage") == []


# ------------------------------------------------------------------
# 201 NSUserDefaults
# ------------------------------------------------------------------
from app.plugins.nsuserdefaults_leak_scanner import \
    analyze_plist_bytes  # noqa: E402


def test_nsuserdefaults_vuln_masked():
    blob = plistlib.dumps({"auth_token": SECRET, "theme": "dark"})
    out = analyze_plist_bytes(blob)
    assert keys_of(out) == {"nsuserdefaults_plaintext_secret"}
    assert SECRET not in json.dumps(out, default=str)


def test_nsuserdefaults_clean():
    assert analyze_plist_bytes(plistlib.dumps({"theme": "dark"})) == []
    assert analyze_plist_bytes(b"not a plist") == []


# ------------------------------------------------------------------
# 202 Flutter
# ------------------------------------------------------------------
from app.plugins.flutter_bloc_state_tracer import analyze_flutter  # noqa: E402


def test_flutter_vuln_masked():
    so = (b"\x00https://api.example.com/v1\x00LoginBloc\x00"
          b"SessionCubit\x00/home\x00/login\x00")
    art = build_from_files({
        "lib/arm64-v8a/libapp.so": so,
        "flutter_assets/config.json":
            json.dumps({"api_key": SECRET, "feature_x": True}).encode()})
    out = analyze_flutter(art)
    ks = keys_of(out)
    assert "flutter_surface_inventory" in ks
    assert "flutter_embedded_secret" in ks
    assert SECRET not in json.dumps(out, default=str)


def test_flutter_clean():
    art = build_from_files({"classes.dex": b"Lcom/example/Foo;"})
    assert analyze_flutter(art) == []


# ------------------------------------------------------------------
# 203 React Native bundle
# ------------------------------------------------------------------
from app.plugins.react_native_bundle_extractor import analyze_bundle  # noqa: E402


def test_rn_bundle_vuln_masked():
    bundle = ('var cfg = {apiKey: "' + SECRET + '"}; '
              'fetch("https://api.example.com/v1")').encode()
    out = analyze_bundle("assets/index.android.bundle", bundle)
    assert "rn_bundle_secret" in keys_of(out)
    assert SECRET not in json.dumps(out, default=str)


def test_rn_bundle_clean():
    out = analyze_bundle("main.jsbundle",
                         b"console.log('hello world');")
    assert out == []


# ------------------------------------------------------------------
# 204 SQLite posture
# ------------------------------------------------------------------
from app.plugins.sqlite_mobile_db_decryptor import \
    analyze_sqlite_db  # noqa: E402


def test_sqlite_plaintext_vuln(tmp_path):
    data = make_plain_db_bytes(tmp_path)
    out = analyze_sqlite_db(data, "app.db")
    assert keys_of(out) == {"mobile_db_plaintext"}


def test_sqlite_encrypted_clean():
    blob = bytes(range(256)) * 8  # non-SQLite header: encrypted/foreign
    assert analyze_sqlite_db(blob, "enc.db") == []
    assert analyze_sqlite_db(b"", "x.db") == []


# ------------------------------------------------------------------
# 206 Geoloc
# ------------------------------------------------------------------
from app.plugins.ios_geoloc_spoof_detector import analyze_geoloc  # noqa: E402


def test_geoloc_vuln_clean():
    assert keys_of(analyze_geoloc(
        "CLLocationManager requestLocationUpdates")) == \
        {"geoloc_no_integrity_check"}
    assert analyze_geoloc(
        "FusedLocationProviderClient getLastLocation "
        "isFromMockProvider") == []
    assert analyze_geoloc("no location at all") == []


# ------------------------------------------------------------------
# 209 FCM token leak
# ------------------------------------------------------------------
def test_fcm_vuln_masked():
    from app.plugins.fcm_push_token_leak import analyze_fcm_texts
    token = "dXyZ123456:APA91b" + "A1_-" * 25
    out = analyze_fcm_texts({"logcat.txt": f"FCM token: {token} ok"})
    assert keys_of(out) == {"fcm_token_leak"}
    assert token not in json.dumps(out, default=str)


def test_fcm_clean():
    from app.plugins.fcm_push_token_leak import analyze_fcm_texts
    assert analyze_fcm_texts({"a.log": "app started normally"}) == []


# ------------------------------------------------------------------
# 181 JADX bridge
# ------------------------------------------------------------------
from app.plugins.jadx_headless_bridge import analyze_code_review  # noqa: E402


def test_jadx_vuln_clean():
    code = 'Cipher.getInstance("DES/ECB/PKCS5Padding"); ' \
           'getSharedPreferences("x", MODE_WORLD_READABLE)'
    out = analyze_code_review(code, False)
    assert {"jadx_weak_crypto_des", "jadx_world_readable_storage"} \
        <= keys_of(out)
    clean = 'Cipher.getInstance("AES/GCM/NoPadding")'
    assert analyze_code_review(clean, False) == []


# ------------------------------------------------------------------
# 183 Frida surface (static)
# ------------------------------------------------------------------
from app.plugins.frida_runtime_script_injector import \
    analyze_frida_surface  # noqa: E402


def test_frida_vuln_clean():
    art = build_from_files({
        "AndroidManifest.xml": MANIFEST_VULN.encode(),
        "lib/arm64-v8a/libfrida-gadget.so": b"\x7fELF",
        "assets/frida-gadget.config": b"{}"})
    ks = keys_of(analyze_frida_surface(art))
    assert {"frida_hook_framework_present", "frida_gadget_config",
            "frida_debuggable_build"} <= ks
    clean = build_from_files({
        "AndroidManifest.xml": MANIFEST_CLEAN_INTENT.encode(),
        "lib/arm64-v8a/libapp.so": b"\x7fELF"})
    assert analyze_frida_surface(clean) == []


# ------------------------------------------------------------------
# 184 DEX tracker matcher
# ------------------------------------------------------------------
from app.plugins.dex_bytecode_pattern_matcher import \
    analyze_dex_trackers  # noqa: E402


def test_dex_trackers_vuln_clean():
    dex = ("Lcom/google/android/gms/analytics/Tracker;"
           "Lcom/appsflyer/AppsFlyerLib;Lcom/example/Foo;")
    out = analyze_dex_trackers(dex)
    assert keys_of(out) == {"dex_tracker_inventory"}
    assert "AppsFlyer" in out[0]["value"]
    assert analyze_dex_trackers("Lcom/example/Foo;") == []


# ------------------------------------------------------------------
# 185 Root posture (detection only)
# ------------------------------------------------------------------
from app.plugins.android_root_detection_bypass import \
    analyze_root_posture, root_posture  # noqa: E402


def test_root_posture_vuln_clean():
    assert root_posture("plain app strings") == "absent"
    assert keys_of(analyze_root_posture("plain app strings")) == \
        {"root_detection_absent"}
    weak = analyze_root_posture('check "/system/xbin/su" Superuser.apk')
    assert keys_of(weak) == {"root_detection_weak"}
    strong = "com.scottyab.rootbeer.RootBeer PlayIntegrity"
    assert analyze_root_posture(strong) == []


# ------------------------------------------------------------------
# 186 SSL pinning posture (detection only)
# ------------------------------------------------------------------
from app.plugins.ssl_pinning_remover_frida import analyze_pinning  # noqa: E402


def test_pinning_vuln_clean():
    vuln = build_from_files({
        "res/xml/network_security_config.xml":
            b'<network-security-config><base-config '
            b'cleartextTrafficPermitted="true"/></network-security-config>',
        "classes.dex": b"Lcom/example/Net;"})
    ks = keys_of(analyze_pinning(vuln))
    assert "pinning_cleartext_permitted" in ks
    assert "pinning_absent" in ks
    clean = build_from_files({
        "res/xml/network_security_config.xml":
            b'<network-security-config><domain-config>'
            b'<pin-set><pin digest="SHA-256">AAAA</pin></pin-set>'
            b'</domain-config></network-security-config>',
        "classes.dex": b"CertificatePinner build"})
    assert analyze_pinning(clean) == []


# ------------------------------------------------------------------
# 190 Biometric posture (detection only)
# ------------------------------------------------------------------
from app.plugins.biometric_auth_bypass_hook import \
    analyze_biometric  # noqa: E402


def test_biometric_vuln_clean():
    vuln = "BiometricPrompt authenticate onAuthenticationSucceeded"
    assert "biometric_no_crypto_binding" in \
        keys_of(analyze_biometric(vuln))
    clean = ("BiometricPrompt onAuthenticationSucceeded CryptoObject "
             "Cipher init BIOMETRIC_STRONG")
    assert analyze_biometric(clean) == []
    assert analyze_biometric("no auth code here") == []


# ------------------------------------------------------------------
# 193 Obfuscation eval
# ------------------------------------------------------------------
from app.plugins.obfuscation_dexguard_eval import analyze_obfuscation  # noqa: E402


def test_obfuscation_vuln_clean():
    vuln = build_from_files({"classes.dex": (
        "Lcom/example/LoginActivity;Lcom/example/PasswordManager;"
        "Lcom/example/AuthTokenStore;Lcom/example/HomeActivity;"
    ).encode()})
    assert "obfuscation_readable_sensitive_names" in \
        keys_of(analyze_obfuscation(vuln))
    clean = build_from_files({"classes.dex": (
        "La/b;Lc/d;Le/f;Lg/h;Li/j;Lk/l;Lm/n;Lo/p;Lq/r;Ls/t;"
    ).encode()})
    assert analyze_obfuscation(clean) == []


# ------------------------------------------------------------------
# 194 Intent fuzzer (static)
# ------------------------------------------------------------------
from app.plugins.android_intent_fuzzer import analyze_intents  # noqa: E402


def test_intents_vuln_clean():
    ks = keys_of(analyze_intents(MANIFEST_VULN))
    assert "intent_exported_system_receiver" in ks
    assert "intent_deeplink_exported_overlap" in ks
    assert analyze_intents(MANIFEST_CLEAN_INTENT) == []


# ------------------------------------------------------------------
# 195 Deeplink finder
# ------------------------------------------------------------------
from app.plugins.deeplink_uri_exploitation_finder import \
    analyze_deeplinks  # noqa: E402


def test_deeplinks_vuln_clean():
    ks = keys_of(analyze_deeplinks(MANIFEST_VULN))
    assert "deeplink_custom_scheme_hijackable" in ks
    assert "deeplink_wildcard_host" in ks
    assert analyze_deeplinks(MANIFEST_CLEAN_DEEPLINK) == []


# ------------------------------------------------------------------
# 196 Native .so bridge
# ------------------------------------------------------------------
from app.plugins.native_library_so_bridge import analyze_so  # noqa: E402


def test_so_vuln_clean():
    out = analyze_so("lib/arm64-v8a/libfoo.so", make_elf(False))
    assert {"so_weak_hardening", "so_jni_exports"} <= keys_of(out)
    assert analyze_so("lib/arm64-v8a/libfoo.so", make_elf(True)) == []
    assert analyze_so("libfoo.so", b"not an elf") == []


# ------------------------------------------------------------------
# 198 SafetyNet posture
# ------------------------------------------------------------------
from app.plugins.safetynet_attestation_simulator import \
    analyze_attestation  # noqa: E402


def test_attestation_vuln_clean():
    vuln = "SafetyNetClient attest basicIntegrity ctsProfileMatch"
    assert keys_of(analyze_attestation(vuln)) == \
        {"attestation_client_only_trust"}
    assert keys_of(analyze_attestation("ordinary app code only")) \
        == {"attestation_absent"}
    clean = "PlayIntegrity IntegrityManager nonce serverVerify"
    assert analyze_attestation(clean) == []


# ------------------------------------------------------------------
# 199 APK signature v3
# ------------------------------------------------------------------
from app.plugins.apk_signature_v3_verifier import analyze_signature, \
    parse_signing_block  # noqa: E402

V2, V3 = 0x7109871A, 0xF05368C0


def test_signature_vuln_clean():
    blob = make_signing_block([V2])
    parsed = parse_signing_block(blob)
    assert parsed and parsed["schemes"] == ["v2"]
    art = build_from_zip_bytes(blob)
    assert keys_of(analyze_signature(art)) == {"apk_no_v3_signing"}
    clean = build_from_zip_bytes(make_signing_block([V2, V3]))
    assert analyze_signature(clean) == []
    v1only = build_from_zip_bytes(_zip_bytes(
        {"META-INF/CERT.RSA": b"cert", "classes.dex": b"dex"}))
    assert keys_of(analyze_signature(v1only)) == \
        {"apk_v1_only_signing"}


# ------------------------------------------------------------------
# 200 Backup flags
# ------------------------------------------------------------------
from app.plugins.android_backup_flag_check import \
    analyze_backup_flags  # noqa: E402


def test_backup_flags_vuln_clean():
    ks = keys_of(analyze_backup_flags(MANIFEST_VULN, []))
    assert ks == {"android_debuggable_true",
                  "android_allow_backup_no_rules"}
    assert analyze_backup_flags(MANIFEST_CLEAN_INTENT, []) == []


# ------------------------------------------------------------------
# 205 WebView file access
# ------------------------------------------------------------------
from app.plugins.android_webview_allow_file_access import \
    analyze_webview  # noqa: E402


def test_webview_vuln_clean():
    vuln = ("WebView setAllowUniversalAccessFromFileURLs "
            "setAllowFileAccess addJavascriptInterface "
            "setJavaScriptEnabled")
    ks = keys_of(analyze_webview(vuln))
    assert {"webview_universal_file_access", "webview_allow_file_access",
            "webview_js_interface"} <= ks
    clean = "WebView loadUrl setJavaScriptEnabled onPageFinished"
    assert analyze_webview(clean) == []


# ------------------------------------------------------------------
# 207 Provider authority
# ------------------------------------------------------------------
from app.plugins.bad_provider_authority_checker import \
    analyze_providers  # noqa: E402


def test_providers_vuln_clean():
    ks = keys_of(analyze_providers(MANIFEST_VULN, {}))
    assert {"provider_grant_uri_permissions",
            "provider_exported_no_permission_split"} <= ks
    fp = analyze_providers("", {"res/xml/file_paths.xml":
                                "<paths><root-path path=\".\"/></paths>"})
    assert keys_of(fp) == {"fileprovider_root_path_scope"}
    assert analyze_providers(MANIFEST_CLEAN_INTENT, {}) == []


# ------------------------------------------------------------------
# 208 Tamper self-check
# ------------------------------------------------------------------
from app.plugins.app_tampering_hash_verify import \
    analyze_tamper_checks  # noqa: E402


def test_tamper_vuln_clean():
    assert keys_of(analyze_tamper_checks("ordinary app code")) == \
        {"tamper_self_check_absent"}
    assert keys_of(analyze_tamper_checks(
        "getPackageInfo GET_SIGNATURES compare")) == \
        {"tamper_self_check_partial"}
    assert analyze_tamper_checks("PlayIntegrity IntegrityManager") == []


# ------------------------------------------------------------------
# 210 Device-ID collection (detection)
# ------------------------------------------------------------------
from app.plugins.mobile_device_id_harvester import \
    analyze_device_ids  # noqa: E402


def test_device_ids_vuln_clean():
    out = analyze_device_ids("getDeviceId getImei AdvertisingIdClient",
                             "")
    assert keys_of(out) == {"device_id_collection_inventory"}
    assert out[0]["evidence"]["telephony_ungated"] is True
    assert analyze_device_ids("getLastLocation onCreate", "") == []


# ------------------------------------------------------------------
# Cross-cutting: registry, malformed inputs, wrapper smoke
# ------------------------------------------------------------------

def test_registry_count_1191():
    assert len(REG) == 1414, f"registry size {len(REG)}, expected 1414"
    for pid in IDS:
        assert pid in REG, pid
        assert REG[pid].group == "mobile"


@pytest.mark.parametrize("pid", IDS)
def test_no_crash_on_malformed(pid):
    plugin = REG[pid]()
    assert isinstance(plugin.analyze({}), list)
    garbage = build_from_files({"x.bin": b"\xff\xfe\x00garbage",
                                "AndroidManifest.xml": b"<broken"})
    assert isinstance(plugin.analyze(garbage), list)
    res = _run(pid, "/nonexistent/path/does-not-exist.apk")
    assert res.status.value == "ok" and res.findings == []


def test_wrapper_smoke_all_plugins(tmp_path):
    """Live smoke: every wrapper end-to-end on realistic synthetic
    APK + IPA files on disk. No devices, no third-party apps."""
    apk = tmp_path / "smoke.apk"
    apk.write_bytes(_zip_bytes({
        "AndroidManifest.xml": MANIFEST_VULN.encode(),
        "classes.dex": (
            "Lcom/google/android/gms/analytics/Tracker;"
            "Cipher.getInstance(\"DES/ECB/PKCS5Padding\") "
            "MODE_WORLD_READABLE BiometricPrompt "
            "onAuthenticationSucceeded WebView "
            "setAllowUniversalAccessFromFileURLs getDeviceId "
            "CLLocationManager SafetyNet basicIntegrity "
            "ctsProfileMatch").encode(),
        "lib/arm64-v8a/libfoo.so": make_elf(False),
        "lib/arm64-v8a/libfrida-gadget.so": b"\x7fELF",
        "assets/index.android.bundle":
            ('var k = {apiKey: "' + SECRET + '"};').encode(),
        "META-INF/CERT.RSA": b"cert",
    }))
    ipa = tmp_path / "smoke.ipa"
    ipa.write_bytes(_zip_bytes({
        "Payload/Smoke.app/Smoke": make_macho(0),
        "Payload/Smoke.app/embedded.mobileprovision":
            make_provision({"get-task-allow": True,
                            "aps-environment": "development"}),
    }))
    counts = {}
    for pid in IDS:
        target_file = ipa if pid.startswith(("ipa_", "objc_",
                                              "ios_mach")) else apk
        res = _run(pid, target_file)
        assert res.status.value == "ok", pid
        counts[pid] = len(res.findings)
        blob = _all_text(res.findings)
        assert SECRET not in blob, pid
    # Spot-check the wrappers that must fire on these fixtures.
    for pid in ("ipa_entitlement_plister", "ios_mach_o_encryption_checker",
                "android_backup_flag_check", "android_intent_fuzzer",
                "deeplink_uri_exploitation_finder",
                "bad_provider_authority_checker",
                "dex_bytecode_pattern_matcher", "jadx_headless_bridge",
                "frida_runtime_script_injector",
                "react_native_bundle_extractor",
                "android_webview_allow_file_access",
                "mobile_device_id_harvester",
                "ios_geoloc_spoof_detector",
                "safetynet_attestation_simulator",
                "biometric_auth_bypass_hook",
                "native_library_so_bridge",
                "apk_signature_v3_verifier"):
        assert counts[pid] >= 1, f"{pid} silent on smoke fixture"
