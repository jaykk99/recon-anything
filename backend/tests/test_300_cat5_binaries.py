"""Cat-5 (300-expansion) Native Binaries & Decompiler Bridges.

Per plugin: fires on a VULN fixture, silent on a CLEAN fixture, no
crash on malformed input. Fixtures are tiny synthetic PE/ELF/Mach-O
byte strings built here; plugins are driven both at their pure
analyze() layer and end-to-end through run() with the artifact in
ctx.shared["binary_artifacts"] (operator-supplied artifact lane).
"""
import asyncio
import os
import struct
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = [
    "ghidra_headless_orchestrator", "hopper_asm_aligner", "ida_pro_bridge",
    "binwalk_entropy_scanner", "radare2_control_flow",
    "angr_symbolic_executor", "gdb_runtime_tracer",
    "capstone_disasm_engine", "unicorn_emulator_core",
    "dwarf_debug_symbol_reader", "pe_header_anomaly_check",
    "elf_plt_hook_finder", "macho_entitlement_analyzer",
    "rop_chain_compiler", "aslr_bypass_evaluator", "dep_nx_status_check",
    "stack_canary_verifier", "string_xref_mapper",
    "stripped_binary_resolver", "vtable_structure_builder",
    "anti_debug_bypass_tool", "binary_diffing_bindiff",
    "import_table_reconstructor", "memory_dump_analyzer",
    "sigmaker_pattern_finder", "obfuscation_entropy_calc",
    "code_cave_locator", "plt_got_hijack_detector",
    "thread_context_spy", "hardware_breakpoint_hook",
]

BASE_VA = 0x400000

# ---------------------------------------------------------------------------
# Synthetic ELF64 builder
# ---------------------------------------------------------------------------

def build_elf(code=b"\x31\xc0\xc3", rodata=b"", dynstr_names=(),
              symbols=(), etype=3, gnu_stack_flags=6, relro=False,
              bind_now=False, extra_sections=(), got_plt_entries=None,
              plt_stub=None, dynamic_flags=None):
    """Minimal ELF64-LE. Sections: .text .rodata .dynstr [.dynamic]
    [.symtab/.strtab] [extra...] [.got.plt] [.plt] .shstrtab."""
    secs = []  # (name, type, flags, data)
    secs.append((".text", 1, 0x6, bytes(code)))
    if rodata:
        secs.append((".rodata", 1, 0x2, bytes(rodata)))
    if dynstr_names:
        blob = b"\x00" + b"\x00".join(
            n.encode() for n in dynstr_names) + b"\x00"
        secs.append((".dynstr", 3, 0x2, blob))
    if bind_now or dynamic_flags is not None:
        entries = b""
        if bind_now:
            entries += struct.pack("<qQ", 24, 0)  # DT_BIND_NOW
        if dynamic_flags is not None:
            entries += struct.pack("<qQ", 30, dynamic_flags)  # DT_FLAGS
        entries += struct.pack("<qQ", 0, 0)
        secs.append((".dynamic", 6, 0x3, entries))
    if symbols:
        strtab = b"\x00" + b"\x00".join(
            s.encode() for s in symbols) + b"\x00"
        secs.append((".symtab", 2, 0x0, b"\x00" * 24 * (len(symbols) + 1)))
        secs.append((".strtab", 3, 0x0, strtab))
    for nm, ty, fl, data in extra_sections:
        secs.append((nm, ty, fl, bytes(data)))
    if got_plt_entries is not None:
        blob = b"".join(struct.pack("<Q", v) for v in got_plt_entries)
        secs.append((".got.plt", 1, 0x3, blob))
    if plt_stub is not None:
        secs.append((".plt", 1, 0x6, bytes(plt_stub)))
    # shstrtab
    names = [""] + [s[0] for s in secs] + [".shstrtab"]
    shstr = b""
    name_off = {}
    for n in names:
        name_off[n] = len(shstr)
        shstr += n.encode() + b"\x00"
    secs.append((".shstrtab", 3, 0x0, shstr))
    shstrndx = len(secs)  # index in final list (after null section)

    phdrs = [(1, 5, 0)]  # PT_LOAD R+X (filesz fixed up later)
    if gnu_stack_flags is not None:
        phdrs.append((0x6474E551, gnu_stack_flags, 0))  # PT_GNU_STACK
    if relro:
        phdrs.append((0x6474E552, 4, 0))  # PT_GNU_RELRO
    phoff = 64
    data_off = phoff + 56 * len(phdrs)
    offsets = []
    cur = data_off
    for _nm, _ty, _fl, data in secs:
        offsets.append(cur)
        cur += len(data)
    shoff = cur
    total = shoff + 64 * (len(secs) + 1)
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # 64-bit
    ehdr[5] = 1  # LE
    ehdr[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16, etype, 62, 1,
                     BASE_VA + offsets[0], phoff, shoff, 0, 64, 56,
                     len(phdrs), 64, len(secs) + 1, shstrndx)
    out = bytearray(ehdr)
    for ptype, pflags, _x in phdrs:
        if ptype == 1:
            out += struct.pack("<IIQQQQQQ", ptype, pflags, 0, BASE_VA,
                               BASE_VA, total, total, 0x1000)
        else:
            out += struct.pack("<IIQQQQQQ", ptype, pflags, 0, BASE_VA,
                               BASE_VA, 0, 0, 0x10)
    sec_addrs = []
    for (nm, ty, fl, data), off in zip(secs, offsets):
        sec_addrs.append(BASE_VA + off)
        out += data
    out += b"\x00" * 64  # null section
    for (nm, ty, fl, data), off in zip(secs, offsets):
        out += struct.pack("<IIQQQQIIQQ", name_off[nm], ty, fl,
                           BASE_VA + off, off, len(data), 0, 0, 1, 0)
    return bytes(out)


def patch_ref(blob: bytes, string: bytes) -> bytes:
    """Patch the mov rax,imm64 placeholder in .text to point at string."""
    data = bytearray(blob)
    soff = data.find(string)
    assert soff > 0, "string not in fixture"
    ph = data.find(b"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00")
    assert ph > 0, "placeholder not in fixture"
    struct.pack_into("<Q", data, ph + 2, BASE_VA + soff)
    return bytes(data)


# ---------------------------------------------------------------------------
# Synthetic PE32+ builder
# ---------------------------------------------------------------------------

def build_pe(code=b"\x31\xc0\xc3", imports=None, timestamp=1700000000,
             checksum=0x1234, dllchars=0x8160, entry_writable=False,
             extra_strings=b"", text_vsize=None, text_raw_size=0x200,
             text_tail=b""):
    """Minimal PE32+. dllchars default: DYNAMIC_BASE|NX|NO_SEH|GUARD-ish
    clean posture (0x8160 = HIGH_ENTROPY|DYNAMIC_BASE|NX_COMPAT|TERMINAL)."""
    imports = imports or {}
    # ---- .idata content -------------------------------------------------
    idata = bytearray()
    if imports:
        dlls = list(imports.items())
        desc_size = 20 * (len(dlls) + 1)
        idata += b"\x00" * desc_size
        descs = []
        for dll, funcs in dlls:
            ilt_off = len(idata)
            idata += b"\x00" * (8 * (len(funcs) + 1))
            name_rvas = []
            for fn in funcs:
                hn_off = len(idata)
                idata += struct.pack("<H", 0) + fn.encode() + b"\x00"
                if len(idata) % 2:
                    idata += b"\x00"
                name_rvas.append(0x2000 + hn_off)
            dll_off = len(idata)
            idata += dll.encode() + b"\x00"
            ilt = b"".join(struct.pack("<Q", r) for r in name_rvas)
            ilt += b"\x00" * 8
            idata[ilt_off:ilt_off + len(ilt)] = ilt
            descs.append((0x2000 + ilt_off, 0x2000 + dll_off,
                          0x2000 + ilt_off))
        for i, (oft, nm, ft) in enumerate(descs):
            struct.pack_into("<IIIII", idata, i * 20, oft, 0, 0, nm, ft)
    idata = bytes(idata)
    # ---- headers ---------------------------------------------------------
    dos = bytearray(b"\x90" * 0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    text_data = bytearray(bytes(code) + bytes(extra_strings))
    if text_tail:
        need = text_raw_size - (text_vsize or len(text_data))
        text_data = bytearray(bytes(code))
        text_data += b"\x00" * max(0, (text_vsize or 0) - len(text_data))
        text_data += bytes(text_tail)
        text_data += b"\x00" * max(0, text_raw_size - len(text_data))
    text_blob = bytes(text_data[:text_raw_size]).ljust(text_raw_size, b"\x00")
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)  # entry RVA (.text)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<I", opt, 56, 0x1000)  # section alignment
    struct.pack_into("<I", opt, 60, 0x200)   # file alignment
    struct.pack_into("<I", opt, 64, checksum)
    struct.pack_into("<H", opt, 70, dllchars)
    struct.pack_into("<I", opt, 108, 16)     # number of dirs
    if imports:
        struct.pack_into("<II", opt, 112 + 8, 0x2000, len(idata))
    coff = struct.pack("<HHIIIHH", 0x8664, 2, timestamp, 0, 0, 240, 0x0022)
    text_chars = 0x60000020 | (0x80000000 if entry_writable else 0)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text", text_vsize or len(code),
                       0x1000, text_raw_size, 0x200, 0, 0, 0, 0, text_chars)
    sec2 = struct.pack("<8sIIIIIIHHI", b".idata", len(idata), 0x2000,
                       (len(idata) + 0x1FF) & ~0x1FF or 0x200, 0x400,
                       0, 0, 0, 0, 0x40000040)
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec1 + sec2
    headers = headers.ljust(0x200, b"\x00")
    return headers + text_blob + idata.ljust(0x200, b"\x00")


# ---------------------------------------------------------------------------
# Synthetic Mach-O 64 builder
# ---------------------------------------------------------------------------

def build_macho(entitlements=b"", initprot=5):
    cmds = b""
    seg = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__TEXT", 0x100000000,
                      0x1000, 0, 0x1000, 7, initprot, 0, 0)
    cmds += seg
    cs_off = 32 + len(cmds) + 16
    if entitlements:
        cmds += struct.pack("<IIII", 0x1D, 16, cs_off, len(entitlements))
    ncmds = 2 if entitlements else 1
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, ncmds,
                      len(cmds), 0, 0)
    blob = hdr + cmds + (entitlements or b"")
    # magic must be the on-disk little-endian bytes cf fa ed fe
    blob = b"\xcf\xfa\xed\xfe" + blob[4:]
    return blob


BENIGN_ENT = (b'<?xml version="1.0"?><plist><dict>'
              b'<key>com.apple.security.app-sandbox</key><true/>'
              b'</dict></plist>')
DANGER_ENT = (b'<?xml version="1.0"?><plist><dict>'
              b'<key>get-task-allow</key><true/>'
              b'<key>com.apple.security.cs.allow-unsigned-executable-memory'
              b'</key><true/></dict></plist>')

CLEAN_ELF = build_elf(dynstr_names=["malloc", "free"],
                      symbols=["main", "helper"])
CLEAN_PE = build_pe(imports={"kernel32.dll": [
    "CreateFileA", "ReadFile", "WriteFile", "CloseHandle"]})
CLEAN_MACHO = build_macho(entitlements=BENIGN_ENT)


# ---------------------------------------------------------------------------
# Wrapper plumbing
# ---------------------------------------------------------------------------

def _ctx(artifacts=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(404, request=r)),
        follow_redirects=True, trust_env=False)
    ctx = Ctx(run_id="cat5-test", mode="active", http=client,
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    if artifacts is not None:
        ctx.shared["binary_artifacts"] = list(artifacts)
    return ctx


def run_plugin(pid, artifacts=None, target=None):
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx(artifacts)
    tgt = target or Target(raw="supplied-binary", type="binary",
                           normalized="supplied-binary")
    async def _go():
        try:
            return await asyncio.wait_for(cls().run(tgt, ctx), timeout=30)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def keys_of(res):
    return {f.key for f in res.findings}


def A(mod, data, name="fixture"):
    import importlib
    m = importlib.import_module(f"app.plugins.{mod}")
    return m.analyze(data, name)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_all_cat5_plugins_registered():
    from app.plugins.registry import discover
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing"
    assert len(reg) == 1341


@pytest.mark.parametrize("pid", IDS)
def test_no_crash_on_malformed(pid):
    bad = Target(raw="", type="email", normalized="not a url @@")
    res = run_plugin(pid, artifacts=[b"\x00\xffgarbage" * 10], target=bad)
    assert res is not None and isinstance(res.findings, list)
    res2 = run_plugin(pid, artifacts=None, target=bad)
    assert res2 is not None and res2.findings == []


# ---------------------------------------------------------------------------
# 121 ghidra / 123 ida (dangerous call graph)
# ---------------------------------------------------------------------------

VULN_DANGER_ELF = build_elf(
    code=b"\xe8\x00\x00\x00\x00\xc3",
    dynstr_names=["strcpy", "system", "printf"])
CLEAN_DANGER_ELF = build_elf(code=b"\x31\xc0\xc3",
                             dynstr_names=["malloc", "free"])


def test_ghidra_fires_and_silent():
    assert A("ghidra_headless_orchestrator", VULN_DANGER_ELF)
    assert A("ghidra_headless_orchestrator", CLEAN_DANGER_ELF) == []
    assert "ghidra_dangerous_callgraph" in keys_of(
        run_plugin("ghidra_headless_orchestrator", [VULN_DANGER_ELF]))
    assert run_plugin("ghidra_headless_orchestrator",
                      [CLEAN_DANGER_ELF]).findings == []


def test_ida_fires_and_silent():
    assert A("ida_pro_bridge", VULN_DANGER_ELF)
    assert A("ida_pro_bridge", CLEAN_DANGER_ELF) == []
    assert "ida_dangerous_pseudocode_call" in keys_of(
        run_plugin("ida_pro_bridge", [VULN_DANGER_ELF]))
    assert run_plugin("ida_pro_bridge", [CLEAN_DANGER_ELF]).findings == []


# ---------------------------------------------------------------------------
# 122 hopper / 138 string-xref
# ---------------------------------------------------------------------------

def _xref_elf():
    code = b"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xc3"
    blob = build_elf(code=code, rodata=b"/bin/sh\x00harmless\x00")
    return patch_ref(blob, b"/bin/sh")


def test_hopper_fires_and_silent():
    vuln = _xref_elf()
    clean = build_elf(code=b"\x31\xc0\xc3", rodata=b"/bin/sh\x00")
    assert A("hopper_asm_aligner", vuln)
    assert A("hopper_asm_aligner", clean) == []
    assert run_plugin("hopper_asm_aligner", [vuln]).findings
    assert run_plugin("hopper_asm_aligner", [clean]).findings == []


def test_string_xref_fires_and_silent():
    vuln = _xref_elf()
    clean = build_elf(code=b"\x31\xc0\xc3", rodata=b"hello world\x00")
    assert A("string_xref_mapper", vuln)
    assert A("string_xref_mapper", clean) == []
    assert run_plugin("string_xref_mapper", [vuln]).findings
    assert run_plugin("string_xref_mapper", [clean]).findings == []


# ---------------------------------------------------------------------------
# 124 binwalk / 146 obfuscation entropy
# ---------------------------------------------------------------------------

def test_binwalk_fires_and_silent():
    vuln = b"A" * 64 + bytes(range(256)) * 8 + b"\x1f\x8b\x08payload"
    clean = b"hello world, plain text blob. " * 40
    hits = A("binwalk_entropy_scanner", vuln)
    assert {h["key"] for h in hits} >= {"binwalk_high_entropy_region"}
    assert A("binwalk_entropy_scanner", clean) == []
    assert run_plugin("binwalk_entropy_scanner", [vuln]).findings
    assert run_plugin("binwalk_entropy_scanner", [clean]).findings == []


def test_obfuscation_fires_and_silent():
    vuln = build_elf(extra_sections=[("UPX0", 1, 0x6, bytes(range(256)) * 4)])
    assert A("obfuscation_entropy_calc", vuln)
    assert A("obfuscation_entropy_calc", CLEAN_ELF) == []
    assert run_plugin("obfuscation_entropy_calc", [vuln]).findings
    assert run_plugin("obfuscation_entropy_calc", [CLEAN_ELF]).findings == []


# ---------------------------------------------------------------------------
# 125 radare2 CFG / 126 angr / 128 capstone / 129 unicorn
# ---------------------------------------------------------------------------

def test_radare2_fires_and_silent():
    vuln = build_elf(code=b"\xeb\x02\x31\xc0\xc3")  # jmp over a block
    clean = build_elf(code=b"\x31\xc0\xc3")
    assert A("radare2_control_flow", vuln)
    assert A("radare2_control_flow", clean) == []
    assert run_plugin("radare2_control_flow", [vuln]).findings
    assert run_plugin("radare2_control_flow", [clean]).findings == []


def test_angr_fires_and_silent():
    vuln = build_elf(code=b"\x74\x02\x0f\x05\xc3\x0f\x05\xc3")
    clean = build_elf(code=b"\x31\xc0\xc3")
    hits = A("angr_symbolic_executor", vuln)
    assert hits and hits[0]["key"] == "angr_crash_pathway"
    assert A("angr_symbolic_executor", clean) == []
    assert run_plugin("angr_symbolic_executor", [vuln]).findings
    assert run_plugin("angr_symbolic_executor", [clean]).findings == []


def test_capstone_fires_and_silent():
    vuln = build_elf(code=b"\x31\xc0\x0f\x05\xc3")
    clean = build_elf(code=b"\x31\xc0\xc3")
    assert A("capstone_disasm_engine", vuln)
    assert A("capstone_disasm_engine", clean) == []
    assert run_plugin("capstone_disasm_engine", [vuln]).findings
    assert run_plugin("capstone_disasm_engine", [clean]).findings == []


def test_unicorn_fires_and_silent():
    from app.plugins.unicorn_emulator_core import emulate
    assert emulate(b"\xb8\x2a\x00\x00\x00\x0f\x05")["sink"][0] == "syscall"
    assert emulate(b"\xb8\x2a\x00\x00\x00\xc3")["sink"] is None
    vuln = build_elf(code=b"\xb8\x2a\x00\x00\x00\x0f\x05\xc3")
    clean = build_elf(code=b"\xb8\x2a\x00\x00\x00\xc3")
    assert A("unicorn_emulator_core", vuln)
    assert A("unicorn_emulator_core", clean) == []
    assert run_plugin("unicorn_emulator_core", [vuln]).findings
    assert run_plugin("unicorn_emulator_core", [clean]).findings == []


# ---------------------------------------------------------------------------
# 127 gdb tracer (static) / 141 anti-debug / 149 thread context / 150 hw bp
# ---------------------------------------------------------------------------

def test_gdb_tracer_fires_and_silent():
    vuln = build_elf(code=b"\x94\xc3",
                     rodata=b"ptrace\x00PTRACE_ATTACH\x00")
    clean = build_elf(code=b"\x31\xc0\xc3", rodata=b"hello\x00")
    keys = {h["key"] for h in A("gdb_runtime_tracer", vuln)}
    assert "gdb_tracer_api_presence" in keys
    assert "gdb_stack_pivot_pattern" in keys
    assert A("gdb_runtime_tracer", clean) == []
    assert run_plugin("gdb_runtime_tracer", [vuln]).findings
    assert run_plugin("gdb_runtime_tracer", [clean]).findings == []


def test_antidebug_fires_and_silent():
    vuln = build_elf(rodata=b"IsDebuggerPresent\x00"
                            b"CheckRemoteDebuggerPresent\x00")
    clean = build_elf(rodata=b"ordinary string\x00")
    assert A("anti_debug_bypass_tool", vuln)
    assert A("anti_debug_bypass_tool", clean) == []
    assert run_plugin("anti_debug_bypass_tool", [vuln]).findings
    assert run_plugin("anti_debug_bypass_tool", [clean]).findings == []


def test_thread_context_fires_and_silent():
    vuln = build_elf(rodata=b"SetThreadContext\x00SuspendThread\x00")
    clean = build_elf(rodata=b"ordinary\x00")
    keys = {h["key"] for h in A("thread_context_spy", vuln)}
    assert "thread_context_hijack_pattern" in keys
    assert A("thread_context_spy", clean) == []
    assert run_plugin("thread_context_spy", [vuln]).findings
    assert run_plugin("thread_context_spy", [clean]).findings == []


def test_hw_breakpoint_fires_and_silent():
    vuln = build_elf(rodata=b"hardware breakpoint handler installed\x00")
    clean = build_elf(rodata=b"ordinary\x00")
    assert A("hardware_breakpoint_hook", vuln)
    assert A("hardware_breakpoint_hook", clean) == []
    assert run_plugin("hardware_breakpoint_hook", [vuln]).findings
    assert run_plugin("hardware_breakpoint_hook", [clean]).findings == []


# ---------------------------------------------------------------------------
# 130 dwarf / 139 stripped / 140 vtable
# ---------------------------------------------------------------------------

def test_dwarf_fires_and_silent():
    vuln = build_elf(extra_sections=[
        (".debug_info", 1, 0x0, b"\x00DW_AT_name\x00DW_TAG_subprogram\x00"),
        (".debug_line", 1, 0x0, b"\x00" * 16)])
    assert A("dwarf_debug_symbol_reader", vuln)
    assert A("dwarf_debug_symbol_reader", CLEAN_ELF) == []
    assert run_plugin("dwarf_debug_symbol_reader", [vuln]).findings
    assert run_plugin("dwarf_debug_symbol_reader",
                      [CLEAN_ELF]).findings == []


def test_stripped_fires_and_silent():
    crc = struct.pack("<I", 0xEDB88320)
    vuln = build_elf(rodata=b"data" + crc)  # no .symtab -> stripped
    clean = build_elf(rodata=b"data" + crc, symbols=["main"])  # has symtab
    hits = A("stripped_binary_resolver", vuln)
    assert hits and "CRC32" in hits[0]["value"]
    assert A("stripped_binary_resolver", clean) == []
    assert run_plugin("stripped_binary_resolver", [vuln]).findings
    assert run_plugin("stripped_binary_resolver", [clean]).findings == []


def test_vtable_fires_and_silent():
    table = b"VTAB" + b"\x00" * 68
    blob = bytearray(build_elf(
        code=b"\x31\xc0\xc3\x90\x90\x90\x90\x90",
        rodata=b"_ZTV7MyClass\x00",
        extra_sections=[(".data.rel.ro", 1, 0x3, table)]))
    # locate .text VA from the known code bytes, write 3 aligned pointers
    text_off = bytes(blob).find(b"\x31\xc0\xc3\x90\x90\x90\x90\x90")
    tab_off = bytes(blob).find(b"VTAB")
    slot = (tab_off + 4 + 7) & ~7
    for i in range(3):
        struct.pack_into("<Q", blob, slot + i * 8, BASE_VA + text_off + i)
    vuln = bytes(blob)
    assert A("vtable_structure_builder", vuln)
    assert A("vtable_structure_builder", CLEAN_ELF) == []
    assert run_plugin("vtable_structure_builder", [vuln]).findings
    assert run_plugin("vtable_structure_builder",
                      [CLEAN_ELF]).findings == []


# ---------------------------------------------------------------------------
# 131 PE anomaly / 143 import table
# ---------------------------------------------------------------------------

def test_pe_anomaly_fires_and_silent():
    vuln = build_pe(timestamp=0, checksum=0, entry_writable=True)
    hits = A("pe_header_anomaly_check", vuln)
    keys = {h["key"] for h in hits}
    assert "pe_timestamp_anomaly" in keys
    assert "pe_entry_in_writable_section" in keys
    assert A("pe_header_anomaly_check", CLEAN_PE) == []
    assert run_plugin("pe_header_anomaly_check", [vuln]).findings
    assert run_plugin("pe_header_anomaly_check", [CLEAN_PE]).findings == []


def test_import_table_fires_and_silent():
    vuln = build_pe(imports={"kernel32.dll": ["LoadLibraryA"]},
                    extra_strings=b"GetProcAddress\x00")
    hits = A("import_table_reconstructor", vuln)
    assert hits and hits[0]["key"] == "iat_manual_resolution_packing"
    assert A("import_table_reconstructor", CLEAN_PE) == []
    assert run_plugin("import_table_reconstructor", [vuln]).findings
    assert run_plugin("import_table_reconstructor",
                      [CLEAN_PE]).findings == []


# ---------------------------------------------------------------------------
# 132 ELF PLT / 148 GOT hijack
# ---------------------------------------------------------------------------

def test_elf_plt_fires_and_silent():
    vuln = build_elf(got_plt_entries=[0, 0, 0, 0])  # GOT, no RELRO
    clean = build_elf(relro=True, bind_now=True,
                      got_plt_entries=[0, 0, 0, 0])
    hits = A("elf_plt_hook_finder", vuln)
    assert hits and hits[0]["key"] == "elf_writable_got"
    assert A("elf_plt_hook_finder", clean) == []
    assert run_plugin("elf_plt_hook_finder", [vuln]).findings
    assert run_plugin("elf_plt_hook_finder", [clean]).findings == []


def test_got_hijack_fires_and_silent():
    # .text is the first section; its VA = BASE + offset. Build once with
    # zero GOT to learn the text address from the section header layout:
    # text data starts right after headers, so search for its bytes.
    probe = build_elf(code=b"\x31\xc0\xc3\x90\x90\x90\x90\x90",
                      got_plt_entries=[0, 0, 0, 0])
    text_off = probe.find(b"\x31\xc0\xc3\x90\x90\x90\x90\x90")
    vuln = build_elf(code=b"\x31\xc0\xc3\x90\x90\x90\x90\x90",
                     got_plt_entries=[0, 0, 0, BASE_VA + text_off + 1],
                     plt_stub=b"\xff\x25\x00\x00\x00\x00" + b"\x90" * 10)
    clean = build_elf(code=b"\x31\xc0\xc3\x90\x90\x90\x90\x90",
                      got_plt_entries=[0, 0, 0, 0],
                      plt_stub=b"\xff\x25\x00\x00\x00\x00" + b"\x90" * 10)
    hits = A("plt_got_hijack_detector", vuln)
    assert hits and hits[0]["key"] == "got_entry_points_to_text"
    assert A("plt_got_hijack_detector", clean) == []
    assert run_plugin("plt_got_hijack_detector", [vuln]).findings
    assert run_plugin("plt_got_hijack_detector", [clean]).findings == []


# ---------------------------------------------------------------------------
# 133 Mach-O entitlements
# ---------------------------------------------------------------------------

def test_macho_fires_and_silent():
    vuln = build_macho(entitlements=DANGER_ENT)
    hits = A("macho_entitlement_analyzer", vuln)
    assert hits and hits[0]["key"] == "macho_dangerous_entitlement"
    assert A("macho_entitlement_analyzer", CLEAN_MACHO) == []
    assert run_plugin("macho_entitlement_analyzer", [vuln]).findings
    assert run_plugin("macho_entitlement_analyzer",
                      [CLEAN_MACHO]).findings == []


# ---------------------------------------------------------------------------
# 134 ROP inventory / 135 ASLR / 136 NX / 137 canary
# ---------------------------------------------------------------------------

def test_rop_fires_and_silent():
    vuln = build_elf(code=b"\x31\xc0\xc3" * 8, etype=2, gnu_stack_flags=7,
                     dynstr_names=["strcpy"])
    clean = build_elf(code=b"\x55\x48\x89\xe5\x31\xc0\xc3")
    hits = A("rop_chain_compiler", vuln)
    assert hits and hits[0]["key"] == "rop_gadget_inventory"
    assert "no chain" in hits[0]["value"]
    assert A("rop_chain_compiler", clean) == []
    assert run_plugin("rop_chain_compiler", [vuln]).findings
    assert run_plugin("rop_chain_compiler", [clean]).findings == []


def test_aslr_fires_and_silent():
    vuln = build_elf(etype=2)  # ET_EXEC non-PIE
    clean = build_elf(etype=3)
    hits = A("aslr_bypass_evaluator", vuln)
    assert hits and hits[0]["key"] == "aslr_non_pie_binary"
    assert A("aslr_bypass_evaluator", clean) == []
    assert run_plugin("aslr_bypass_evaluator", [vuln]).findings
    assert run_plugin("aslr_bypass_evaluator", [clean]).findings == []


def test_dep_nx_fires_and_silent():
    vuln = build_elf(gnu_stack_flags=7)  # RWE stack
    hits = A("dep_nx_status_check", vuln)
    assert hits and hits[0]["key"] == "nx_executable_stack"
    assert A("dep_nx_status_check", CLEAN_ELF) == []
    assert run_plugin("dep_nx_status_check", [vuln]).findings
    assert run_plugin("dep_nx_status_check", [CLEAN_ELF]).findings == []


def test_canary_fires_and_silent():
    vuln = build_elf(dynstr_names=["strcpy", "memcpy", "printf"])
    clean = build_elf(dynstr_names=["strcpy", "__stack_chk_fail"])
    hits = A("stack_canary_verifier", vuln)
    assert hits and hits[0]["key"] == "canary_missing_with_buffer_funcs"
    assert A("stack_canary_verifier", clean) == []
    assert run_plugin("stack_canary_verifier", [vuln]).findings
    assert run_plugin("stack_canary_verifier", [clean]).findings == []


# ---------------------------------------------------------------------------
# 142 bindiff / 144 memory dump / 145 sigmaker / 147 code cave
# ---------------------------------------------------------------------------

def test_bindiff_fires_and_silent():
    import importlib
    m = importlib.import_module("app.plugins.binary_diffing_bindiff")
    old = build_elf(code=b"\x55\x48\x89\xe5\x31\xc0\xc3\x90\x90\x31\xdb\xc3")
    new = build_elf(code=b"\x55\x48\x89\xe5\x31\xc0\xc3\x90\x90\x31\xff\xc3")
    assert m.analyze_pair(old, new)
    assert m.analyze_pair(old, old) == []
    assert run_plugin("binary_diffing_bindiff", [old, new]).findings
    assert run_plugin("binary_diffing_bindiff", [old]).findings == []


def test_memory_dump_fires_and_silent_and_masked():
    vuln = (b"remnant\x00http://example.com/internal\x00"
            b"password=SuperSecret123\x00"
            b"AKIAIOSFODNN7EXAMPLE\x00cmd.exe /c whoami\x00")
    hits = A("memory_dump_analyzer", vuln)
    keys = {h["key"] for h in hits}
    assert "dump_secret_remnant_masked" in keys
    assert "dump_plaintext_urls" in keys
    blob = str(hits)
    assert "SuperSecret123" not in blob
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    clean = b"ordinary memory contents, nothing special\x00" * 4
    assert A("memory_dump_analyzer", clean) == []
    res = run_plugin("memory_dump_analyzer", [vuln])
    assert res.findings
    assert all("SuperSecret123" not in f.value for f in res.findings)
    assert run_plugin("memory_dump_analyzer", [clean]).findings == []


def test_sigmaker_fires_and_silent():
    from app.plugins.sigmaker_pattern_finder import make_signature
    sig = make_signature(b"\xe8\x01\x02\x03\x04\xc3", 0, 16)
    assert sig.startswith("E8 ?? ?? ?? ??")
    vuln = build_elf(code=b"\xe8\x00\x00\x00\x00" + b"\x90" * 16 + b"\xc3")
    clean = build_elf(code=b"\x90" * 20 + b"\xc3")
    assert A("sigmaker_pattern_finder", vuln)
    assert A("sigmaker_pattern_finder", clean) == []
    assert run_plugin("sigmaker_pattern_finder", [vuln]).findings
    assert run_plugin("sigmaker_pattern_finder", [clean]).findings == []


def test_code_cave_fires_and_silent():
    vuln = build_pe(text_vsize=16, text_raw_size=0x200,
                    text_tail=b"\x41" * 60)
    hits = A("code_cave_locator", vuln)
    assert hits and any(h["evidence"].get("anomalous") for h in hits)
    clean = b"\x01" * 600  # raw blob: no caves, no structure
    assert A("code_cave_locator", clean) == []
    assert run_plugin("code_cave_locator", [vuln]).findings
    assert run_plugin("code_cave_locator", [clean]).findings == []


# ---------------------------------------------------------------------------
# Live smoke: every plugin completes on a real local binary
# ---------------------------------------------------------------------------

def test_live_smoke_real_binary_completes():
    path = "/bin/ls"
    if not os.path.isfile(path):
        pytest.skip("/bin/ls not present")
    tgt = Target(raw=path, type="file", normalized=path)
    for pid in IDS:
        res = run_plugin(pid, artifacts=None, target=tgt)
        assert res is not None, pid
        assert isinstance(res.findings, list), pid
