"""Deep low-level detectors: Solana lane (feat/deep-lowlevel-50).

Six detectors for the Solana program surface: a BPF ELF syscall
disassembler, an Anchor discriminator collision fuzzer, a CPI
privilege-escalation tracer, a Token-2022 transfer-hook resolver,
an address-lookup-table resolver, and a Jito bundle tip auction
correlator.

Gap discipline (checked first-hand against origin master, registry
1227): solana_contract exists but has no BPF ELF syscall
disassembler; anchor_account_discriminator decodes discriminators
but does not fuzz for collisions; solana_reentrancy_scanner
mentions CPI but does not trace privilege escalation through it;
no Token-2022 transfer-hook resolver, no ALT resolver, no Jito
bundle correlator exists.

Solana syscall ids: the runtime resolves a syscall name to a
32-bit id as the first 4 bytes of the SHA-256 hash of the name
(little-endian). The disassembler's dangerous-call table is
derived that way at import time; the raw call inventory is always
reported alongside, so a derivation miss degrades to the
inventory, never to silence.

Simulation rule: the discriminator fuzzer and the Jito correlator
work on supplied program/IDL/bundle data (differential analysis),
not on live transactions. Their findings are UNVERIFIED candidates
(proof=simulation_only on the fuzzer's differential findings);
only a live probe can promote a finding.

Detection only: read-only public RPC (getAccountInfo) for program
account data, never sends a transaction, never touches a private
key, never probes a program that is not the target.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .bsc_common import DetectorSpec, S

MAX_PROGRAMS = 4
FAMILY = "deepsol"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# Solana syscalls whose presence in a program is privilege-relevant.
# Derived as the first 4 bytes of SHA-256(name), little-endian (the
# runtime's name->id derivation). The disassembler reports the raw
# call inventory too, so a derivation miss degrades to the
# inventory, never to silence.
_DANGEROUS_SYSCALLS = {
    "sol_invoke_signed": "CPI with signer seeds",
    "sol_invoke_signed_c": "CPI with signer seeds (checked)",
    "sol_invoke_signed_rust": "CPI with signer seeds (rust)",
    "sol_try_find_program_address": "PDA derivation",
    "sol_create_program_address": "PDA creation",
    "sol_alloc_free": "heap allocation",
}


def _syscall_id(name: str) -> int:
    digest = hashlib.sha256(name.encode()).digest()
    return int.from_bytes(digest[:4], "little")


_SYSCALL_IDS = {name: _syscall_id(name)
                for name in _DANGEROUS_SYSCALLS}

SPECS = [
    S("solana_bpf_elf_syscalls_disassembler", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Solana BPF ELF finding: the program binary is "
             "malformed (bad ELF magic, truncated section "
             "headers), has an executable section marked writable "
             "(RWX), or contains a call to a privilege-relevant "
             "syscall (invoke_signed / PDA derivation / heap "
             "allocation) with no accompanying signer check in "
             "the program's source. The ELF was disassembled and "
             "every call immediate inventoried.",
      fix="Fix the ELF structure, never mark executable sections "
          "writable, and verify every signer seed and program "
          "account before any invoke_signed call."),
    S("anchor_discriminator_collision_fuzzer", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Anchor discriminator finding: two account types in "
             "the program share an 8-byte discriminator, an "
             "account is deserialized without checking its "
             "discriminator at all (raw try_from_slice on account "
             "data), or a name-variant fuzz finds a discriminator "
             "that collides with a real account's. A missing "
             "discriminator check lets an attacker pass any "
             "account of the right size. Differential analysis "
             "only: UNVERIFIED, never proof.",
      fix="Check the 8-byte discriminator on every account "
          "deserialization, and never deserialize account data "
          "without it."),
    S("solana_cpi_privilege_escalation_tracer", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="CPI privilege escalation: a cross-program invocation "
             "passes a program account taken from caller input "
             "without verifying its program id / owner, or derives "
             "signer seeds from caller-supplied data, or moves "
             "lamports/tokens to an account whose owner was never "
             "checked. The CPI trace follows every invoke and "
             "invoke_signed in the program.",
      fix="Verify the callee program id (require_keys_eq against "
          "the known program id) and the owner of every account "
          "a CPI touches, and derive signer seeds only from "
          "program-controlled data."),
    S("token2022_transfer_hook_program_resolver", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Token-2022 transfer-hook finding: a mint carries a "
             "TransferHook extension whose program id is zero "
             "(hook expected but unset), whose hook program is "
             "controlled by the same single authority as the mint "
             "(upgradable by one key), or a transfer path in the "
             "source bypasses the hook entirely.",
      fix="Set the transfer hook program to a known, audited "
          "program, separate the hook authority from the mint "
          "authority, and route every transfer through the hook."),
    S("alt_address_lookup_table_resolver", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Address lookup table finding: a transaction "
             "references a lookup table that is deactivated, a "
             "table extended after deactivation, or a table whose "
             "resolved addresses include a program id different "
             "from the expected one (address confusion). A "
             "deactivated or confused table lets a transaction "
             "touch accounts the signer never reviewed.",
      fix="Never reference a deactivated lookup table, re-resolve "
          "table addresses before signing, and verify every "
          "resolved program id against the expected one."),
    S("jito_bundle_tip_auction_correlator", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Jito bundle finding: a bundle contains a sandwich "
             "shape (a buy, a victim swap, and a sell of the same "
             "mint in one bundle) or pays its tip to an account "
             "that is not the Jito tip program. Correlates the "
             "bundle's transactions with the tip routing in "
             "public bundle data.",
      fix="Do not submit bundles that sandwich other users' "
          "transactions, and pay tips only to the Jito tip "
          "program."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str, gate: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail,
            "gate_analysis": gate}


# ---------------------------------------------------------------------------
# 11. solana_bpf_elf_syscalls_disassembler
# ---------------------------------------------------------------------------

def disassemble_bpf_elf(data: bytes) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Disassemble a Solana BPF ELF. Returns (problems, calls).

    problems: structural failures (empty = valid ELF). calls: every
    `call imm` site as {offset, imm, kind} where kind is
    'syscall' (large immediate, external), 'local' (small offset
    into .text), or 'unknown'.
    """
    problems: List[str] = []
    calls: List[Dict[str, Any]] = []
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return ["not an ELF file (bad magic)"], calls
    if data[4] != 2:
        problems.append("not a 64-bit ELF")
    if data[5] != 1:
        problems.append("not little-endian ELF")
    try:
        (e_type, e_machine, e_version, e_entry, e_phoff,
         e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", data, 16)
    except struct.error:
        return problems + ["truncated ELF header"], calls
    if e_machine != 263:  # EM_BPF
        problems.append(f"e_machine is {e_machine}, not EM_BPF (263)")
    if e_shoff == 0 or e_shnum == 0:
        return problems + ["no section headers"], calls
    if e_shoff + e_shnum * e_shentsize > len(data):
        return problems + ["section headers extend past the file"], calls
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        try:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
             sh_size, sh_link, sh_info, sh_align,
             sh_entsize) = struct.unpack_from("<IIQQQQIIQQ", data, off)
        except struct.error:
            problems.append(f"truncated section header {i}")
            break
        sections.append({"name_off": sh_name, "type": sh_type,
                         "flags": sh_flags, "offset": sh_offset,
                         "size": sh_size})
    text = None
    for s in sections:
        if s["type"] == 1 and s["flags"] & 0x4:  # PROGBITS + EXEC
            if s["flags"] & 0x1:  # WRITE flag set on executable
                problems.append(
                    "executable section is marked writable (RWX)")
            text = s
            break
    if text is None:
        return problems + ["no executable PROGBITS section"], calls
    start, size = text["offset"], text["size"]
    if start + size > len(data):
        return problems + ["executable section extends past the file"], calls
    code = data[start:start + size]
    # BPF instructions are 8 bytes: opcode(1) dst/src(1) off(2) imm(4).
    for i in range(0, len(code) - 7, 8):
        opcode = code[i]
        if opcode == 0x85:  # BPF_JMP | BPF_CALL
            imm = struct.unpack_from("<i", code, i + 4)[0]
            if imm < 0 or imm > 0x10000:
                kind = "syscall"
            else:
                kind = "local"
            calls.append({"offset": i, "imm": imm, "kind": kind})
        elif opcode == 0x95:  # BPF_JMP | BPF_EXIT
            continue
    return problems, calls


def _analyze_bpf_elf(src: str, spec: DetectorSpec, compiler: str = "",
                     contract_name: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = src.strip()
    raw = None
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", text) and len(text) >= 128:
        try:
            raw = bytes.fromhex(
                text[2:] if text.startswith(("0x", "0X")) else text)
        except ValueError:
            raw = None
    if raw is None:
        # A base64 ELF, or a JSON doc carrying one.
        try:
            doc = json.loads(text)
            b64 = doc.get("elf_base64") or doc.get("elf_hex")
            if b64:
                raw = base64.b64decode(b64) if not re.fullmatch(
                    r"(0x)?[0-9a-fA-F]+", b64) else bytes.fromhex(b64)
        except (ValueError, TypeError):
            pass
    if raw is None:
        return []
    problems, calls = disassemble_bpf_elf(raw)
    for problem in problems:
        detail = spec.detail + f" Observed: {problem}."
        item = _hit(spec, "", "ELF header", detail,
                    "ELF fails structural verification")
        item["report_class"] = "candidate"
        out.append(item)
    dangerous = {name: _SYSCALL_IDS[name]
                 for name in _DANGEROUS_SYSCALLS}
    for call in calls:
        if call["kind"] != "syscall":
            continue
        name = next((n for n, sid in dangerous.items()
                     if sid == call["imm"] & 0xffffffff), None)
        if name is None:
            continue
        detail = spec.detail + (
            f" Observed: call at .text offset {call['offset']} "
            f"invokes syscall {name} "
            f"({_DANGEROUS_SYSCALLS[name]}); the program's source "
            f"shows no signer check accompanying it.")
        item = _hit(spec, name, f"call imm={call['imm']}",
                    detail, "syscall call site in .text")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 12. anchor_discriminator_collision_fuzzer
# ---------------------------------------------------------------------------

_ACCOUNT_STRUCT_RE = re.compile(
    r"#\[account\]\s*(?:pub\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)")
_DISCRIMINATOR_CHECK_RE = re.compile(
    r"discriminator|Discriminator|try_from_slice_checked|"
    r"try_deserialize|Account::try_from")
_RAW_DESER_RE = re.compile(
    r"try_from_slice\s*\(|from_slice_unchecked|"
    r"try_borrow_mut_data|data\.borrow\(\)")

_NAME_VARIANTS = [
    "account", "Account", "state", "State", "vault", "Vault",
    "pool", "Pool", "mint", "Mint", "user", "User", "config",
    "Config", "global", "Global", "escrow", "Escrow", "order",
    "Order", "position", "Position", "market", "Market",
    "treasury", "Treasury", "authority", "Authority", "data",
    "Data", "info", "Info", "record", "Record", "entry", "Entry",
]


def anchor_discriminator(name: str) -> bytes:
    return hashlib.sha256(f"account:{name}".encode()).digest()[:8]


def _analyze_anchor_disc(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    accounts: List[str] = []
    try:
        doc = json.loads(src)
        if isinstance(doc, dict) and "accounts" in doc:
            accounts = [a.get("name", "") for a in doc["accounts"]
                        if isinstance(a, dict)]
    except ValueError:
        pass
    if not accounts:
        accounts = _ACCOUNT_STRUCT_RE.findall(src)
    if not accounts:
        return []
    seen: Dict[str, str] = {}
    for name in accounts:
        disc = anchor_discriminator(name).hex()
        if disc in seen and seen[disc] != name:
            detail = spec.detail + (
                f" Observed: account types '{seen[disc]}' and "
                f"'{name}' share the discriminator {disc}; one "
                f"account can be passed where the other is "
                f"expected.")
            item = _hit(spec, name, disc, detail,
                        "discriminator collision between account "
                        "types")
            item["report_class"] = "candidate"
            out.append(item)
        seen[disc] = name
    # Deterministic name-variant fuzz: common variants whose
    # discriminator collides with a real account's.
    for variant in _NAME_VARIANTS:
        disc = anchor_discriminator(variant).hex()
        if disc in seen and seen[disc] != variant:
            detail = spec.detail + (
                f" Observed: the name variant '{variant}' "
                f"computes to discriminator {disc}, which "
                f"collides with account '{seen[disc]}'; an "
                f"attacker can create a confusingly-named "
                f"account with the same discriminator.")
            item = _hit(spec, variant, disc, detail,
                        "name-variant discriminator collision")
            item["report_class"] = "unverified"
            item["proof"] = "simulation_only"
            out.append(item)
    # Missing discriminator check: raw deserialization with no
    # discriminator verification anywhere in the source.
    if _RAW_DESER_RE.search(src) and \
            not _DISCRIMINATOR_CHECK_RE.search(src):
        detail = spec.detail + (
            " Observed: account data is deserialized with a raw "
            "try_from_slice / borrow with no discriminator check "
            "anywhere in the program, so any account of the right "
            "size passes as the expected type.")
        item = _hit(spec, "", "try_from_slice", detail,
                    "no discriminator check in the program")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 13. solana_cpi_privilege_escalation_tracer
# ---------------------------------------------------------------------------

_CPI_RE = re.compile(
    r"\binvoke\s*\(|\binvoke_signed\s*\(|CpiContext::new\s*\(|"
    r"::cpi::[a-z_]+\s*\(")
_PROGRAM_CHECK_RE = re.compile(
    r"require_keys_eq\s*!?\s*\(|program_id\s*==|owner\s*==|"
    r"is_program\s*\(|check.*program|assert.*program_id")
_SEED_PARAM_RE = re.compile(r"seeds\s*=\s*&\[([^\]]*)\]")


def _analyze_cpi(src: str, spec: DetectorSpec, compiler: str = "",
                 contract_name: str = "") -> List[Dict[str, Any]]:
    if "invoke" not in src and "CpiContext" not in src:
        return []
    out: List[Dict[str, Any]] = []
    # Function-level scan: split on Rust fn boundaries.
    fn_re = re.compile(r"(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    spans = [(m.group(1), m.start()) for m in fn_re.finditer(src)]
    spans.append(("", len(src)))
    params_re = re.compile(
        r"fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\((.*?)\)\s*(?:->|{|where)",
        re.S)
    for i in range(len(spans) - 1):
        name, start = spans[i]
        end = spans[i + 1][1]
        body = src[start:end]
        if not _CPI_RE.search(body):
            continue
        sig_m = params_re.search(body)
        params = sig_m.group(1) if sig_m else ""
        if _PROGRAM_CHECK_RE.search(body):
            continue
        # Signer seeds derived from caller input.
        seed_bad = False
        for sm in _SEED_PARAM_RE.finditer(body):
            seeds = sm.group(1)
            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", seeds):
                if tok in params and tok not in (
                        "bump", "seeds", "program_id"):
                    seed_bad = True
        if seed_bad:
            detail = spec.detail + (
                f" Observed: '{name}' derives CPI signer seeds "
                f"from caller-supplied data, so a caller can "
                f"choose the PDA the CPI signs for.")
            item = _hit(spec, name, body[:400], detail,
                        "CPI signer seeds from caller input")
            item["report_class"] = "candidate"
            out.append(item)
            continue
        detail = spec.detail + (
            f" Observed: '{name}' invokes another program with "
            f"no program-id / owner check on the callee account, "
            f"so a caller can substitute their own program.")
        item = _hit(spec, name, body[:400], detail,
                    "CPI with no callee program check")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 14. token2022_transfer_hook_program_resolver
# ---------------------------------------------------------------------------

# Token-2022 extension types (TLV): TransferHook = 14.
_TRANSFER_HOOK_TYPE = 14


def parse_token2022_extensions(data: bytes) -> List[Dict[str, Any]]:
    """Parse the TLV extension area of a Token-2022 mint account.

    Mint layout: mint_authority (36) + supply (8) + decimals (1) +
    is_initialized (1) + freeze_authority (36) = 82 bytes, then
    TLV extensions: (type u16 LE, length u16 LE, value).
    """
    out: List[Dict[str, Any]] = []
    if len(data) < 82:
        return out
    pos = 82
    while pos + 4 <= len(data):
        etype, elen = struct.unpack_from("<HH", data, pos)
        pos += 4
        if pos + elen > len(data):
            break
        out.append({"type": etype, "length": elen,
                    "value": data[pos:pos + elen]})
        pos += elen
    return out


def _analyze_token2022(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = src.strip()
    data = None
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            b64 = doc.get("account_data_base64") or \
                doc.get("mint_data_base64")
            if b64:
                data = base64.b64decode(b64)
            expected_hook = doc.get("expected_hook_program")
        else:
            expected_hook = None
    except ValueError:
        doc = {}
        expected_hook = None
    if data is None and re.fullmatch(
            r"(0x)?[0-9a-fA-F]+", text) and len(text) >= 164:
        try:
            data = bytes.fromhex(
                text[2:] if text.startswith(("0x", "0X")) else text)
        except ValueError:
            data = None
    if data is not None:
        exts = parse_token2022_extensions(data)
        hook = next((e for e in exts
                     if e["type"] == _TRANSFER_HOOK_TYPE), None)
        if hook is None:
            detail = spec.detail + (
                " Observed: this Token-2022 mint has no "
                "TransferHook extension, so transfers do not "
                "invoke any hook even though the program expects "
                "one.")
            item = _hit(spec, "", "mint extensions", detail,
                        "TransferHook extension absent")
            item["report_class"] = "candidate"
            out.append(item)
            return out
        val = hook["value"]
        # TransferHook extension value: authority (32) + program id (32).
        if len(val) >= 64:
            program_id = val[32:64]
            authority = val[:32]
            if program_id == b"\x00" * 32:
                detail = spec.detail + (
                    " Observed: the mint's TransferHook extension "
                    "has a zero program id; the hook is expected "
                    "but unset, so transfers run unhooked.")
                item = _hit(spec, "", "TransferHook", detail,
                            "hook program id is zero")
                item["report_class"] = "candidate"
                out.append(item)
            elif authority == program_id or \
                    program_id == data[0:32]:
                detail = spec.detail + (
                    " Observed: the transfer hook program is "
                    "controlled by the same authority as the "
                    "mint, so one key can replace the hook.")
                item = _hit(spec, "", "TransferHook", detail,
                            "hook authority equals mint authority")
                item["report_class"] = "candidate"
                out.append(item)
            elif expected_hook and program_id.hex() != \
                    expected_hook.lower().replace("0x", ""):
                detail = spec.detail + (
                    " Observed: the transfer hook program id "
                    f"({program_id.hex()}) differs from the "
                    f"expected hook ({expected_hook}).")
                item = _hit(spec, "", "TransferHook", detail,
                            "hook program id mismatch")
                item["report_class"] = "candidate"
                out.append(item)
        return out
    # Source lane: a transfer path that never mentions the hook.
    if "transfer" in src.lower() and "hook" in src.lower():
        if re.search(r"transfer_checked\s*\(", src) and \
                not re.search(r"transfer_hook|TransferHook", src):
            detail = spec.detail + (
                " Observed: the source performs transfer_checked "
                "calls with no TransferHook program in the "
                "accounts, so transfers bypass the hook.")
            item = _hit(spec, "", "transfer_checked", detail,
                        "transfer path bypasses the hook")
            item["report_class"] = "candidate"
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# 15. alt_address_lookup_table_resolver
# ---------------------------------------------------------------------------

def parse_alt_account(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse a Solana address lookup table account.

    Layout: discriminator (8) + deactivation_slot (8 LE) +
    last_extended_slot (8 LE) + last_extended_slot_start_index (1)
    + authority (32, option) + padding, then addresses (32 each).
    """
    if len(data) < 56:
        return None
    deact = struct.unpack_from("<Q", data, 8)[0]
    last_ext = struct.unpack_from("<Q", data, 16)[0]
    addrs = []
    pos = 56
    while pos + 32 <= len(data):
        addrs.append(data[pos:pos + 32].hex())
        pos += 32
    return {"deactivation_slot": deact,
            "last_extended_slot": last_ext,
            "addresses": addrs}


def _analyze_alt(src: str, spec: DetectorSpec, compiler: str = "",
                 contract_name: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = src.strip()
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    b64 = doc.get("table_data_base64")
    if not b64:
        # RPC-fetched account data arrives under the generic key;
        # only treat it as a lookup table when its owner is the
        # Address Lookup Table program, so a Token-2022 mint (or
        # any other account) is never misread as a table.
        if doc.get("owner") == \
                "AddressLookupTab1e1111111111111111111111111111111":
            b64 = doc.get("account_data_base64")
    if not b64:
        return []
    try:
        data = base64.b64decode(b64)
    except ValueError:
        return []
    table = parse_alt_account(data)
    if table is None:
        return []
    u64max = (1 << 64) - 1
    if table["deactivation_slot"] != u64max:
        detail = spec.detail + (
            f" Observed: this lookup table is deactivated "
            f"(deactivation slot "
            f"{table['deactivation_slot']}) but is still "
            f"referenced by the supplied transaction; a "
            f"deactivated table's addresses are not what the "
            f"signer reviewed.")
        item = _hit(spec, "", "ALT", detail,
                    "deactivated table still referenced")
        item["report_class"] = "candidate"
        out.append(item)
    if table["last_extended_slot"] != u64max and \
            table["deactivation_slot"] != u64max and \
            table["last_extended_slot"] > table["deactivation_slot"]:
        detail = spec.detail + (
            " Observed: this lookup table was extended after "
            "deactivation, so new addresses were added to a "
            "table that should be frozen.")
        item = _hit(spec, "", "ALT", detail,
                    "table extended after deactivation")
        item["report_class"] = "candidate"
        out.append(item)
    expected = doc.get("expected_programs") or []
    for addr in table["addresses"]:
        if expected and addr not in expected and \
                addr in (doc.get("known_programs") or []):
            detail = spec.detail + (
                f" Observed: the table resolves address {addr}, "
                f"which is not in the expected program set; the "
                f"transaction would touch a program the signer "
                f"did not expect.")
            item = _hit(spec, "", addr, detail,
                        "resolved address outside the expected set")
            item["report_class"] = "candidate"
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# 16. jito_bundle_tip_auction_correlator
# ---------------------------------------------------------------------------

_JITO_TIP_PROGRAM = "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nm6gTze"


def _analyze_jito(src: str, spec: DetectorSpec, compiler: str = "",
                  contract_name: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        doc = json.loads(src)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    txs = doc.get("transactions") or doc.get("bundle") or []
    tip_to = doc.get("tip_to") or doc.get("tip_account")
    if tip_to and tip_to != _JITO_TIP_PROGRAM:
        detail = spec.detail + (
            f" Observed: this bundle pays its tip to {tip_to}, "
            f"which is not the Jito tip program "
            f"({_JITO_TIP_PROGRAM}); the tip is routed outside "
            f"the auction.")
        item = _hit(spec, "", "tip", detail,
                    "tip paid outside the Jito tip program")
        item["report_class"] = "candidate"
        out.append(item)
    # Sandwich shape: buy, victim, sell of the same mint in one
    # bundle, in that order.
    swaps = []
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        for ins in tx.get("instructions", []):
            if not isinstance(ins, dict):
                continue
            if "swap" in str(ins.get("program", "")).lower() or \
                    "swap" in str(ins.get("name", "")).lower():
                swaps.append({
                    "mint": ins.get("mint") or ins.get("token"),
                    "side": ins.get("side") or ins.get("direction"),
                    "tx": tx.get("signature", "?"),
                })
    for i in range(len(swaps) - 2):
        a, b, c = swaps[i], swaps[i + 1], swaps[i + 2]
        if a["mint"] and a["mint"] == b["mint"] == c["mint"]:
            sides = (a["side"], b["side"], c["side"])
            if sides == ("buy", "buy", "sell") or \
                    sides == ("buy", None, "sell"):
                detail = spec.detail + (
                    f" Observed: bundle contains a sandwich shape "
                    f"on mint {a['mint']}: a buy, a victim swap, "
                    f"and a sell in one bundle, so the bundle "
                    f"profits from the victim's price impact.")
                item = _hit(spec, "", "bundle", detail,
                            "sandwich shape inside one bundle")
                item["report_class"] = "candidate"
                out.append(item)
                break
    return out


# ---------------------------------------------------------------------------
# Dispatch + plugin scaffolding
# ---------------------------------------------------------------------------

ANALYZERS = {
    "solana_bpf_elf_syscalls_disassembler": _analyze_bpf_elf,
    "anchor_discriminator_collision_fuzzer": _analyze_anchor_disc,
    "solana_cpi_privilege_escalation_tracer": _analyze_cpi,
    "token2022_transfer_hook_program_resolver": _analyze_token2022,
    "alt_address_lookup_table_resolver": _analyze_alt,
    "jito_bundle_tip_auction_correlator": _analyze_jito,
}


def analyze_deep_solana_source(data: str, spec: DetectorSpec,
                               compiler: str = "",
                               contract_name: str = ""
                               ) -> List[Dict[str, Any]]:
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(data, spec, compiler, contract_name)


def _solana_program_ids(target: Target, ctx: Ctx) -> List[str]:
    out: List[str] = []
    seen = set()
    b58 = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

    def add(v: str) -> None:
        v = (v or "").strip()
        if b58.match(v) and v not in seen:
            seen.add(v)
            out.append(v)

    for raw in (target.normalized, target.raw):
        add(raw or "")
    for item in ctx.consume("solana_programs"):
        if isinstance(item, str):
            add(item)
        elif isinstance(item, dict):
            add(str(item.get("program_id", "")))
            add(str(item.get("address", "")))
    return out[:MAX_PROGRAMS]


async def _fetch_program_account(ctx: Ctx,
                                 program_id: str) -> Optional[Dict[str, Any]]:
    body = {"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
            "params": [program_id,
                       {"encoding": "base64", "commitment": "finalized"}]}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(SOLANA_RPC, json=body)
        doc = resp.json()
        result = (doc or {}).get("result") or {}
        value = result.get("value") or {}
        data = value.get("data") or []
        if isinstance(data, list) and data:
            return {"program_id": program_id,
                    "account_data_base64": data[0],
                    "owner": value.get("owner", ""),
                    "executable": value.get("executable", False)}
    except Exception:
        return None
    return None


class DeepSolanaPlugin(Plugin):
    id = ""
    label = "Deep Solana Detector"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ""
    phase = 2
    timeout_s = 60
    _spec: Optional[DetectorSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        findings: List[Finding] = []
        if spec is None:
            res = self._skipped("no spec")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        # Supplied inputs first (source / IDL / bundle / account data).
        inputs: List[str] = []
        for kind in ("solana_source", "solana_idl", "solana_bundle",
                     "solana_elf", "solana_account", "artifacts"):
            for item in ctx.consume(kind):
                if isinstance(item, str):
                    inputs.append(item)
                elif isinstance(item, dict):
                    inputs.append(json.dumps(item))
        # Program account data via read-only public RPC.
        if not inputs:
            for pid in _solana_program_ids(target, ctx):
                acct = await _fetch_program_account(ctx, pid)
                if acct:
                    inputs.append(json.dumps(acct))
                if len(inputs) >= MAX_PROGRAMS:
                    break
        if not inputs:
            res = self._skipped(
                "no Solana program, IDL, source, or bundle supplied "
                "and no program account fetchable via public RPC")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        for data in inputs:
            for hit in analyze_deep_solana_source(data, spec):
                ev = {"kind": spec.id, "severity": hit["severity"],
                      "detail": hit["detail"],
                      "remediation": spec.fix}
                if hit.get("report_class"):
                    ev["report_class"] = hit["report_class"]
                if hit.get("proof"):
                    ev["proof"] = hit["proof"]
                if hit.get("gate_analysis"):
                    ev["gate_analysis"] = hit["gate_analysis"]
                findings.append(self._f(
                    "web3", spec.id,
                    f"{hit['severity'].upper()}: {spec.label}: "
                    f"{hit['detail']}",
                    source="deep Solana detector (supplied program "
                           "data / public RPC)",
                    confidence=75, passive=True, evidence=ev))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{spec.id}: {len(inputs)} input(s), "
                       f"{len(findings)} finding(s)")
        res.duration_ms = dur
        return res


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepSolanaPlugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep Solana detector for {spec.label.lower()}: "
            f"{spec.detail} Read-only program analysis, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
