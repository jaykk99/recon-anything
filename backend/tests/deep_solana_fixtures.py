"""Fixtures for the deep Solana detectors (feat/deep-lowlevel-50).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate";
CLEAN[id] (the protected shape) MUST stay silent under ALL
six Solana detectors.

Inputs are dicts consumed by analyze_deep_solana_inputs:
  solana_source (Rust), solana_elf (base64 ELF),
  solana_idl (JSON), solana_account (base64 account data),
  solana_bundle (JSON), artifacts (list of dicts).
"""
import base64
import hashlib
import json
import struct

# ---------------------------------------------------------------------------
# 11. solana_bpf_elf_syscalls_disassembler
# ---------------------------------------------------------------------------

SOL_INVOKE_SIGNED_ID = int.from_bytes(
    hashlib.sha256(b"sol_invoke_signed").digest()[:4], "little")


def _elf(instructions: bytes) -> bytes:
    text_off = 0x40 + 64  # ELF header + 1 section header
    code = instructions
    e_shoff = text_off + len(code)
    elf = bytearray()
    elf += struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        2, 263, 1, 0, 0, e_shoff, 0, 0x40, 0, 0, 64, 1, 0)
    elf += b"\x00" * 64  # one section header (unused)
    elf += code
    # Section header for .text at index 1: PROGBITS, ALLOC|EXEC.
    sh = struct.pack("<IIQQQQIIQQ", 1, 1, 0x6, 0, text_off, len(code),
                     0, 0, 0, 0)
    elf += sh
    return bytes(elf)


def _insn(opcode: int, dst: int = 0, src: int = 0, off: int = 0,
          imm: int = 0) -> bytes:
    return struct.pack("<BBhI", opcode, (dst & 0xF) | ((src & 0xF) << 4),
                       off, imm & 0xFFFFFFFF)


_BPF_CLEAN = base64.b64encode(_elf(_insn(0x95))).decode()
_BPF_VULN = base64.b64encode(_elf(
    _insn(0x85, imm=SOL_INVOKE_SIGNED_ID - 2**32
          if SOL_INVOKE_SIGNED_ID >= 2**31 else SOL_INVOKE_SIGNED_ID)
    + _insn(0x95))).decode()

# ---------------------------------------------------------------------------
# 12. anchor_discriminator_collision_fuzzer
# ---------------------------------------------------------------------------

_ANCHOR_VULN = """
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.balance -= amount;
    Ok(())
}

pub fn load_vault(account: &AccountInfo) -> Result<Vault> {
    let data = account.try_borrow_mut_data()?;
    let vault = Vault::try_from_slice(&data)?;
    Ok(vault)
}
"""

_ANCHOR_CLEAN = """
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    require!(vault.owner == ctx.accounts.signer.key(), "not owner");
    require_keys_eq!(vault.owner, ctx.accounts.signer.key());
    let expected: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    require!(ctx.accounts.vault.discriminator() == expected, "bad discriminator");
    vault.balance -= amount;
    Ok(())
}
"""

# ---------------------------------------------------------------------------
# 13. solana_cpi_privilege_escalation_tracer
# ---------------------------------------------------------------------------

_CPI_VULN = """
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let ix = anchor_lang::solana_program::system_instruction::transfer(
        &ctx.accounts.from.key(), &ctx.accounts.to.key(), amount);
    invoke(&ix, &[ctx.accounts.from.clone(), ctx.accounts.to.clone()])?;
    Ok(())
}
"""

_CPI_CLEAN = """
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.program.key(), anchor_lang::solana_program::system_program::ID);
    let ix = anchor_lang::solana_program::system_instruction::transfer(
        &ctx.accounts.from.key(), &ctx.accounts.to.key(), amount);
    invoke(&ix, &[ctx.accounts.from.clone(), ctx.accounts.to.clone()])?;
    Ok(())
}
"""

# ---------------------------------------------------------------------------
# 14. token2022_transfer_hook_program_resolver
# ---------------------------------------------------------------------------

def _token2022_mint(hook_program: bytes, hook_authority: bytes) -> str:
    header = bytearray(82)
    header[0:4] = struct.pack("<I", 0)      # mint authority option
    header[4:36] = b"\x00" * 32
    header[36:44] = struct.pack("<Q", 1_000_000)
    header[44] = 6                          # decimals
    header[45] = 1                          # is_initialized
    header[46:50] = struct.pack("<I", 1)    # freeze authority option
    header[50:82] = b"\x00" * 32
    tlv = struct.pack("<HH", 14, 64)        # TransferHook, 64 bytes
    tlv += hook_authority + hook_program
    return base64.b64encode(bytes(header) + tlv).decode()


_TOKEN2022_VULN = _token2022_mint(b"\x00" * 32, b"\x01" * 32)
_TOKEN2022_CLEAN = _token2022_mint(b"\x02" * 32, b"\x01" * 32)

# ---------------------------------------------------------------------------
# 15. alt_address_lookup_table_resolver
# ---------------------------------------------------------------------------

def _alt_table(deactivation_slot: int, addresses: list) -> str:
    out = bytearray()
    out += b"\x01" * 8          # discriminator
    out += struct.pack("<Q", deactivation_slot)
    out += struct.pack("<Q", 200)   # last extended slot
    out += b"\x00"                 # last extended slot index
    out += b"\x03" * 31            # authority (parser reads addresses at 56)
    for a in addresses:
        out += bytes([a]) * 32
    return base64.b64encode(bytes(out)).decode()


_ALT_VULN = _alt_table(100, [0xAA])
_ALT_CLEAN = _alt_table(2**64 - 1, [0xAA])

# ---------------------------------------------------------------------------
# 16. jito_bundle_tip_auction_correlator
# ---------------------------------------------------------------------------

JITO_TIP_PROGRAM = "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nm6gTze"

_JITO_VULN = json.dumps({
    "bundle_id": "bundle-vuln",
    "transactions": [
        {"slot": 300, "signer": "attacker",
         "instructions": [{"program": "swap", "side": "buy",
                           "amount": 100, "token": "TOKENX"}]},
        {"slot": 300, "signer": "victim",
         "instructions": [{"program": "swap", "side": "buy",
                           "amount": 1000, "token": "TOKENX"}]},
        {"slot": 300, "signer": "attacker",
         "instructions": [{"program": "swap", "side": "sell",
                           "amount": 100, "token": "TOKENX"}]},
    ],
    "tip_to": "attacker",
    "tip_lamports": 5000000,
})

_JITO_CLEAN = json.dumps({
    "bundle_id": "bundle-clean",
    "transactions": [
        {"slot": 300, "signer": "user",
         "instructions": [{"program": "pump", "type": "buy",
                           "amount": 100, "token": "TOKENX"}]},
    ],
    "tip_to": JITO_TIP_PROGRAM,
    "tip_lamports": 10000,
})

VULN = {
    "solana_bpf_elf_syscalls_disassembler": {"solana_elf": _BPF_VULN},
    "anchor_discriminator_collision_fuzzer": {"solana_source": _ANCHOR_VULN},
    "solana_cpi_privilege_escalation_tracer": {"solana_source": _CPI_VULN},
    "token2022_transfer_hook_program_resolver": {"solana_account": _TOKEN2022_VULN},
    "alt_address_lookup_table_resolver": {"solana_account": _ALT_VULN},
    "jito_bundle_tip_auction_correlator": {"solana_bundle": _JITO_VULN},
}

CLEAN = {
    "solana_bpf_elf_syscalls_disassembler": {"solana_elf": _BPF_CLEAN},
    "anchor_discriminator_collision_fuzzer": {"solana_source": _ANCHOR_CLEAN},
    "solana_cpi_privilege_escalation_tracer": {"solana_source": _CPI_CLEAN},
    "token2022_transfer_hook_program_resolver": {"solana_account": _TOKEN2022_CLEAN},
    "alt_address_lookup_table_resolver": {"solana_account": _ALT_CLEAN},
    "jito_bundle_tip_auction_correlator": {"solana_bundle": _JITO_CLEAN},
}
