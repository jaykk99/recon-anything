"""Cat-6 (300-expansion) Electron & JavaScript plugin tests.

For every new plugin: fires on a VULN fixture, silent on a CLEAN fixture,
and never crashes on malformed input. Pure analysis functions are driven
directly; a stub-ctx run() test covers the artifact-bus path, and the
masked-evidence plugins assert raw secrets never appear in output.
"""
import asyncio
import importlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.plugins import base  # noqa: E402
from app.plugins.registry import discover  # noqa: E402


def _fn(mod_name, func_name):
    mod = importlib.import_module(f"app.plugins.{mod_name}")
    return getattr(mod, func_name)


CASES = {}


def case(pid):
    def deco(fn):
        CASES[pid] = fn
        return fn
    return deco


# ---------------------------------------------------------------- fixtures
ELECTRON_VULN = """
const {BrowserWindow} = require('electron');
const win = new BrowserWindow({webPreferences: {
  nodeIntegration: true, contextIsolation: false,
  enableRemoteModule: true, sandbox: false}});
win.loadFile('index.html');
"""
ELECTRON_CLEAN = """
const {BrowserWindow} = require('electron');
const win = new BrowserWindow({webPreferences: {
  nodeIntegration: false, contextIsolation: true, sandbox: true}});
win.loadURL('https://example.com/');
"""

# 151 ------------------------------------------------------------------
def test_asar_vuln():
    analyze = _fn("asar_unpacker_stream", "analyze_asar")
    header = json.dumps({"files": {"main.js": {"size": 10, "offset": "0"},
                                   ".env": {"size": 5, "offset": "10"}}})
    blob = header + "\nconst password = \"fixture-secret-123\";\n"
    hits = analyze(blob)
    keys = {h["key"] for h in hits}
    assert "asar_risky_file" in keys and "asar_embedded_secret" in keys
    assert "fixture-secret-123" not in json.dumps(hits)


def test_asar_clean():
    analyze = _fn("asar_unpacker_stream", "analyze_asar")
    header = json.dumps({"files": {"main.js": {"size": 3, "offset": "0"}}})
    assert analyze(header + "\nconsole.log('hi');\n") == []


# 152 ------------------------------------------------------------------
def test_v8_bytecode_vuln():
    analyze = _fn("v8_bytecode_decompiler", "analyze_v8_bytecode")
    blob = (b"\xde\xad\xbe\xef cached-data https://192.168.1.50/internal "
            b"api_key = 'abcdef123456' process.mainModule ")
    hits = analyze(blob)
    keys = {h["key"] for h in hits}
    assert "jsc_internal_url" in keys and "jsc_embedded_secret" in keys


def test_v8_bytecode_clean():
    analyze = _fn("v8_bytecode_decompiler", "analyze_v8_bytecode")
    assert analyze(b"hello world, plain readable strings only") == []


# 153 ------------------------------------------------------------------
def test_node_integration_vuln():
    analyze = _fn("electron_node_integration_check", "analyze_node_integration")
    keys = {h["key"] for h in analyze(ELECTRON_VULN)}
    assert "electron_node_integration_no_isolation" in keys
    assert "electron_remote_module" in keys


def test_node_integration_clean():
    analyze = _fn("electron_node_integration_check", "analyze_node_integration")
    assert analyze(ELECTRON_CLEAN) == []


# 154 ------------------------------------------------------------------
def test_context_isolation_vuln():
    analyze = _fn("context_isolation_audit", "analyze_context_isolation")
    src = ELECTRON_VULN + """
contextBridge.exposeInMainWorld('electron', {ipcRenderer: ipcRenderer, fs: require('fs')});
"""
    keys = {h["key"] for h in analyze(src)}
    assert "context_isolation_disabled" in keys
    assert "context_bridge_privileged_exposure" in keys


def test_context_isolation_clean():
    analyze = _fn("context_isolation_audit", "analyze_context_isolation")
    src = ELECTRON_CLEAN + """
contextBridge.exposeInMainWorld('api', {getVersion: () => ipcRenderer.invoke('get-version')});
"""
    assert analyze(src) == []


# 155 ------------------------------------------------------------------
def test_preload_vuln():
    analyze = _fn("preload_script_interceptor", "analyze_preload")
    src = """
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('electron', ipcRenderer);
ipcRenderer.invoke('shell:open-file', path);
ipcRenderer.sendSync('config:get', 'x');
"""
    keys = {h["key"] for h in analyze(src)}
    assert "preload_raw_ipcrenderer" in keys and "preload_risky_channel" in keys


def test_preload_clean():
    analyze = _fn("preload_script_interceptor", "analyze_preload")
    src = """
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('api', {
  getVersion: () => ipcRenderer.invoke('app:get-version'),
});
"""
    assert analyze(src) == []


# 156 ------------------------------------------------------------------
def test_cdp_vuln():
    analyze = _fn("chrome_devtools_protocol_wire", "analyze_cdp")
    src = '{"scripts": {"start": "electron . --remote-debugging-port=9222"}}'
    keys = {h["key"] for h in analyze(src)}
    assert "cdp_remote_debugging_port" in keys


def test_cdp_clean():
    analyze = _fn("chrome_devtools_protocol_wire", "analyze_cdp")
    assert analyze('{"scripts": {"start": "electron ."}}') == []


# 157 ------------------------------------------------------------------
def test_obfuscator_vuln():
    analyze = _fn("js_obfuscator_deobfuscator", "analyze_obfuscation")
    src = ("var _0x4f2a = ['hello','world']; var _0x1b3c = _0x4f2a[0];"
           "function _0x9d8e(){ return _0x4f2a[1]; }"
           "var _0x77aa = 1; var _0x55bb = 2; var _0x33cc = 3;")
    assert {h["key"] for h in analyze(src)} == {"js_obfuscated_bundle"}


def test_obfuscator_clean():
    analyze = _fn("js_obfuscator_deobfuscator", "analyze_obfuscation")
    src = "function greet(name) { const msg = 'hello ' + name; return msg; }"
    assert analyze(src) == []


# 160 ------------------------------------------------------------------
def test_ipc_vuln():
    analyze = _fn("electron_ipc_fuzzer", "analyze_ipc_handlers")
    src = """
const {ipcMain, shell} = require('electron');
ipcMain.handle('run-cmd', (event, cmd) => {
  return shell.openExternal(cmd);
});
"""
    keys = {h["key"] for h in analyze(src)}
    assert "ipc_handler_unvalidated_dangerous" in keys


def test_ipc_clean():
    analyze = _fn("electron_ipc_fuzzer", "analyze_ipc_handlers")
    src = """
const {ipcMain} = require('electron');
ipcMain.handle('get-setting', (event, key) => {
  if (!event.sender || typeof key !== 'string') { throw new Error('bad'); }
  return store.get(key);
});
"""
    assert analyze(src) == []


# 162 ------------------------------------------------------------------
def test_napi_vuln():
    analyze = _fn("native_addon_napi_scanner", "analyze_napi")
    src = ("napi_module_register napi_get_buffer_info napi_create_buffer "
           "strcpy strcat sprintf unsafe_copy_routine padding padding")
    assert "napi_unsafe_string_fn" in {h["key"] for h in analyze(src)}


def test_napi_clean():
    analyze = _fn("native_addon_napi_scanner", "analyze_napi")
    src = ("napi_ok napi_status checked on every call; memcpy_s bounded; "
           "napi_get_value_string with length validation everywhere here")
    assert analyze(src) == []


# 167 ------------------------------------------------------------------
def test_globals_vuln():
    analyze = _fn("global_scope_pollution_checker", "analyze_globals")
    src = ("window.apiEndpoint = 'https://example.com';\n"
           "leakedCounter = 0;\n"
           "for (item of items) { leakedCounter += item; }\n")
    keys = {h["key"] for h in analyze(src)}
    assert "global_window_write" in keys and "implicit_global" in keys


def test_globals_clean():
    analyze = _fn("global_scope_pollution_checker", "analyze_globals")
    src = ("'use strict';\nconst config = {debug: false};\nlet counter = 0;\n"
           "for (const item of items) { counter += item; }\n"
           "function add(a, b) { return a + b; }\n"
           "module.exports = {add, config};\n")
    assert analyze(src) == []


# 168 ------------------------------------------------------------------
def test_eval_vuln():
    analyze = _fn("js_eval_execution_tracker", "analyze_eval_sinks")
    src = "const x = eval(userInput); setTimeout(\"doThing()\", 100);"
    keys = {h["key"] for h in analyze(src)}
    assert "eval_tainted" in keys and "string_timer" in keys


def test_eval_clean():
    analyze = _fn("js_eval_execution_tracker", "analyze_eval_sinks")
    assert analyze("const x = JSON.parse(input); setTimeout(doThing, 100);") == []


# 170 ------------------------------------------------------------------
def test_dead_code_vuln():
    analyze = _fn("dead_code_elimination_differ", "analyze_dead_code")
    src = "if (false) { startAdminPanel(); grantAllAccess(); }\nrunApp();"
    assert "dead_code_block" in {h["key"] for h in analyze(src)}


def test_dead_code_clean():
    analyze = _fn("dead_code_elimination_differ", "analyze_dead_code")
    assert analyze("function runApp() { return start(); } runApp();") == []


def test_dead_code_diff():
    analyze = _fn("dead_code_elimination_differ", "analyze_dead_code")
    shipped = "function openAdminDebugPanel() {} function start() {}"
    reference = "function start() {}"
    keys = {h["key"] for h in analyze(shipped, reference)}
    assert "hidden_feature_in_build" in keys


# 171 ------------------------------------------------------------------
def test_protocol_vuln():
    analyze = _fn("electron_protocol_register_audit", "analyze_protocol_handlers")
    src = """
protocol.registerFileProtocol('app', (request, cb) => {
  const filePath = path.join(__dirname, request.url);
  shell.openExternal(request.url);
  cb({path: filePath});
});
"""
    assert "protocol_handler_unsanitized" in {h["key"] for h in analyze(src)}


def test_protocol_clean():
    analyze = _fn("electron_protocol_register_audit", "analyze_protocol_handlers")
    src = """
protocol.handle('app', (request) => {
  const url = new URL(request.url);
  const filePath = path.normalize(path.join(APP_DIR, url.pathname));
  if (!filePath.startsWith(APP_DIR)) { throw new Error('blocked'); }
  return net.fetch('file://' + filePath);
});
"""
    assert analyze(src) == []


# 172 ------------------------------------------------------------------
def test_chromium_flags_vuln():
    analyze = _fn("chromium_command_line_flagger", "analyze_chromium_flags")
    src = ("app.commandLine.appendSwitch('disable-web-security');\n"
           "// flags: --ignore-certificate-errors --remote-debugging-port=9222")
    keys = {h["key"] for h in analyze(src)}
    assert "chromium_disable_web_security" in keys
    assert "chromium_ignore_cert_errors" in keys


def test_chromium_flags_clean():
    analyze = _fn("chromium_command_line_flagger", "analyze_chromium_flags")
    assert analyze("app.commandLine.appendSwitch('enable-logging');") == []


# 173 ------------------------------------------------------------------
def test_worker_vuln():
    analyze = _fn("web_worker_message_spy", "analyze_worker_messages")
    src = """
const w = new Worker('w.js');
self.onmessage = (e) => {
  const result = eval(e.data.code);
  self.postMessage(result);
};
"""
    assert "worker_message_to_sink" in {h["key"] for h in analyze(src)}


def test_worker_clean():
    analyze = _fn("web_worker_message_spy", "analyze_worker_messages")
    src = """
self.addEventListener('message', (e) => {
  if (e.origin !== 'https://app.example.com') { return; }
  const data = e.data;
  if (typeof data !== 'object' || !data.type) { return; }
  self.postMessage({ok: true});
});
"""
    assert analyze(src) == []


# 174 ------------------------------------------------------------------
def test_crypto_subtle_vuln():
    analyze = _fn("crypto_subtle_hook", "analyze_crypto_subtle")
    src = "const raw = await crypto.subtle.exportKey('raw', key);"
    assert "subtle_raw_key_export" in {h["key"] for h in analyze(src)}
    src2 = "crypto.subtle = hookedSubtle; crypto.subtle.encrypt = wrap;"
    assert "subtle_hooked" in {h["key"] for h in analyze(src2)}


def test_crypto_subtle_clean():
    analyze = _fn("crypto_subtle_hook", "analyze_crypto_subtle")
    src = ("const digest = await crypto.subtle.digest('SHA-256', data);"
           "const key = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt']);")
    assert analyze(src) == []


# 159 (variant) ----------------------------------------------------------
def test_proto_hunter_vuln():
    analyze = _fn("prototype_pollution_hunter", "analyze_proto_pollution_static")
    src = """
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) { merge(target[key], source[key]); }
    else { target[key] = source[key]; }
  }
}
merge({}, JSON.parse(userInput));
"""
    assert "proto_unsafe_merge" in {h["key"] for h in analyze(src)}
    assert analyze("obj['__proto__'] = polluted;") != []


def test_proto_hunter_clean():
    analyze = _fn("prototype_pollution_hunter", "analyze_proto_pollution_static")
    src = """
function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor') { continue; }
    if (typeof source[key] === 'object') { merge(target[key], source[key]); }
    else { target[key] = source[key]; }
  }
}
merge({}, JSON.parse(input));
"""
    assert analyze(src) == []


# 161 (variant) ----------------------------------------------------------
def test_browserify_vuln():
    analyze = _fn("browserify_dependency_splitter", "analyze_browserify")
    src = ("require=(function(){})()({1:[function(require,module,exports){\n"
           "module.exports = 'hello';\n},{}],"
           "2:[function(require,module,exports){\n"
           "const password = \"hunter2secret\";\n},{}]});")
    hits = analyze(src)
    assert "browserify_module_secret" in {h["key"] for h in hits}
    assert "hunter2secret" not in json.dumps(hits)


def test_browserify_clean():
    analyze = _fn("browserify_dependency_splitter", "analyze_browserify")
    assert analyze("function main() { return 42; } main();") == []


# 163 (variant, masked) --------------------------------------------------
RAW_TOKEN = "supersecretvalue123"


def test_storage_vuln_masked():
    analyze = _fn("localstorage_credential_harvester", "analyze_storage_dump")
    dump = json.dumps({"theme": "dark", "access_token": RAW_TOKEN, "locale": "en"})
    hits = analyze(dump)
    assert "storage_credential_key" in {h["key"] for h in hits}
    assert RAW_TOKEN not in json.dumps(hits)


def test_storage_clean():
    analyze = _fn("localstorage_credential_harvester", "analyze_storage_dump")
    assert analyze(json.dumps({"theme": "dark", "locale": "en-US"})) == []


# 165 (variant) ----------------------------------------------------------
def test_electron_csp_vuln():
    analyze = _fn("electron_csp_evaluator", "analyze_electron_csp")
    assert "electron_csp_missing" in {h["key"] for h in analyze(ELECTRON_VULN)}
    html = ('<meta http-equiv="Content-Security-Policy" '
            'content="default-src *; script-src \'unsafe-inline\' *">')
    keys = {h["key"] for h in analyze(html)}
    assert "electron_csp_wildcard" in keys


def test_electron_csp_clean():
    analyze = _fn("electron_csp_evaluator", "analyze_electron_csp")
    html = ('<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'self\'; script-src \'self\'">')
    assert analyze(html) == []


# 166 (variant) ----------------------------------------------------------
def test_vm2_vuln():
    analyze = _fn("vm2_sandbox_escape_test", "analyze_vm2")
    src = """
const {NodeVM} = require('vm2');
const vm = new NodeVM({});
vm.run("this.constructor.constructor('return process')().exit()");
"""
    keys = {h["key"] for h in analyze(src)}
    assert "vm2_escape_shape" in keys and "vm2_unhardened" in keys


def test_vm2_clean():
    analyze = _fn("vm2_sandbox_escape_test", "analyze_vm2")
    src = """
const {VM} = require('vm2');
const vm = new VM({eval: false, wasm: false});
vm.freeze({});
const out = vm.run('1 + 1');
"""
    assert analyze(src) == []
    assert analyze("const x = 1; // no sandbox library here") == []


# 175 (variant) ----------------------------------------------------------
def _wasm(membody: bytes) -> bytes:
    return b"\x00asm" + b"\x01\x00\x00\x00" + bytes([5, len(membody)]) + membody


def test_wasm_vuln():
    analyze = _fn("wasm_memory_growth_tracker", "analyze_wasm_memory")
    hits = analyze(_wasm(bytes([1, 0, 1])))  # 1 memory, flags=0, initial=1, no max
    assert "wasm_memory_unbounded" in {h["key"] for h in hits}
    js = "while (true) { memory.grow(1); }"
    assert "wasm_grow_in_loop" in {h["key"] for h in analyze(js)}


def test_wasm_clean():
    analyze = _fn("wasm_memory_growth_tracker", "analyze_wasm_memory")
    assert analyze(_wasm(bytes([1, 1, 1, 10]))) == []  # max=10 pages


# 176 (variant, masked) --------------------------------------------------
RAW_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart"


def test_heap_vuln_masked():
    analyze = _fn("v8_heap_snapshot_parser", "analyze_heap_snapshot")
    snap = json.dumps({"snapshot": {"meta": {}}, "strings": ["hello", RAW_JWT]})
    hits = analyze(snap)
    assert "heap_retained_secret" in {h["key"] for h in hits}
    assert RAW_JWT not in json.dumps(hits)


def test_heap_clean():
    analyze = _fn("v8_heap_snapshot_parser", "analyze_heap_snapshot")
    snap = json.dumps({"snapshot": {"meta": {}}, "strings": ["hello", "Settings"]})
    assert analyze(snap) == []


# 179 (variant, masked) --------------------------------------------------
RAW_GHP = "ghp_" + "A" * 36


def test_crash_vuln_masked():
    analyze = _fn("electron_crash_dump_extractor", "analyze_crash_dump")
    blob = (b"MDMP" + b"\x00" * 32 + b"electron.exe\x00KERNEL32.dll\x00"
            + RAW_GHP.encode() + b"\x00EXCEPTION_ACCESS_VIOLATION\x00")
    hits = analyze(blob)
    keys = {h["key"] for h in hits}
    assert "crash_dump_parsed" in keys and "crash_dump_secret_remnant" in keys
    assert RAW_GHP not in json.dumps(hits)


def test_crash_clean():
    analyze = _fn("electron_crash_dump_extractor", "analyze_crash_dump")
    assert analyze(b"just a plain log line, nothing else here") == []


# 180 (variant) ----------------------------------------------------------
def test_sourceurl_vuln():
    analyze = _fn("source_url_annotation_miner", "analyze_sourceurl")
    src = "console.log(1);\n//# sourceURL=/Users/alice/projects/secret-app/main.js"
    hits = analyze(src)
    assert "sourceurl_path_leak" in {h["key"] for h in hits}


def test_sourceurl_clean():
    analyze = _fn("source_url_annotation_miner", "analyze_sourceurl")
    assert analyze("console.log(1);\n//# sourceURL=app.js") == []


# ------------------------------------------------- malformed + registry
ALL_FUNCS = [
    ("asar_unpacker_stream", "analyze_asar"),
    ("v8_bytecode_decompiler", "analyze_v8_bytecode"),
    ("electron_node_integration_check", "analyze_node_integration"),
    ("context_isolation_audit", "analyze_context_isolation"),
    ("preload_script_interceptor", "analyze_preload"),
    ("chrome_devtools_protocol_wire", "analyze_cdp"),
    ("js_obfuscator_deobfuscator", "analyze_obfuscation"),
    ("electron_ipc_fuzzer", "analyze_ipc_handlers"),
    ("native_addon_napi_scanner", "analyze_napi"),
    ("global_scope_pollution_checker", "analyze_globals"),
    ("js_eval_execution_tracker", "analyze_eval_sinks"),
    ("dead_code_elimination_differ", "analyze_dead_code"),
    ("electron_protocol_register_audit", "analyze_protocol_handlers"),
    ("chromium_command_line_flagger", "analyze_chromium_flags"),
    ("web_worker_message_spy", "analyze_worker_messages"),
    ("crypto_subtle_hook", "analyze_crypto_subtle"),
    ("prototype_pollution_hunter", "analyze_proto_pollution_static"),
    ("browserify_dependency_splitter", "analyze_browserify"),
    ("localstorage_credential_harvester", "analyze_storage_dump"),
    ("electron_csp_evaluator", "analyze_electron_csp"),
    ("vm2_sandbox_escape_test", "analyze_vm2"),
    ("wasm_memory_growth_tracker", "analyze_wasm_memory"),
    ("v8_heap_snapshot_parser", "analyze_heap_snapshot"),
    ("electron_crash_dump_extractor", "analyze_crash_dump"),
    ("source_url_annotation_miner", "analyze_sourceurl"),
]

NEW_IDS = [m for m, _f in ALL_FUNCS]


@pytest.mark.parametrize("mod_name,func_name", ALL_FUNCS)
def test_malformed_input_never_crashes(mod_name, func_name):
    fn = _fn(mod_name, func_name)
    for bad in (None, "", b"", b"\x00\xff\xfe garbage {{{", "{not json",
                "x" * 10, 12345):
        out = fn(bad)
        assert isinstance(out, list)


def test_all_25_registered():
    reg = discover()
    missing = [pid for pid in NEW_IDS if pid not in reg]
    assert not missing, f"missing from registry: {missing}"
    assert len(NEW_IDS) == 25


# ------------------------------------------------------- stub-ctx run()
class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None


class CtxStub:
    def __init__(self, artifacts=None):
        self.run_id = "test"
        self.mode = "passive"
        self.http = None
        self.cache = _FakeCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = {}
        if artifacts:
            self.shared["artifacts"] = list(artifacts)

    def publish(self, kind, item):
        bucket = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in bucket:
                bucket.append(item)
        else:
            bucket.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        return None

    async def probe(self, url, timeout=8):
        return {"status": 0, "headers": {}, "text": "", "url": url}


def _run_plugin(pid, artifacts):
    cls = discover()[pid]
    target = base.Target(raw="artifact-bundle", type="url",
                         normalized="artifact-bundle")
    ctx = CtxStub(artifacts=artifacts)
    return asyncio.run(cls().run(target, ctx))


def test_run_path_electron_vuln_and_clean():
    res = _run_plugin("electron_node_integration_check", [ELECTRON_VULN])
    assert res.status.value == "ok" and len(res.findings) >= 1
    res2 = _run_plugin("electron_node_integration_check", [ELECTRON_CLEAN])
    assert res2.status.value == "ok" and len(res2.findings) == 0


def test_run_path_storage_masked():
    dump = json.dumps({"access_token": RAW_TOKEN})
    res = _run_plugin("localstorage_credential_harvester", [dump])
    assert len(res.findings) >= 1
    blob = json.dumps([{"value": f.value, "evidence": f.evidence}
                       for f in res.findings])
    assert RAW_TOKEN not in blob


def test_run_path_dead_target_no_crash():
    for pid in NEW_IDS:
        res = _run_plugin(pid, [])
        assert res.status.value == "ok", pid
