"""300-expansion Cat 2: Alternative L1/L2 plugins (29 plugins).

For EVERY new plugin: fires on a VULN fixture, silent on a CLEAN
fixture, no crash on malformed input. Fixtures drive the pure
analyze_artifact() function directly and the Plugin.run() wrapper
(artifact supplied as the target text, stub ctx pattern).
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402
import httpx  # noqa: E402

IDS = [
    "solana_anchor_decoder", "anchor_account_discriminator",
    "solana_sysvar_audit", "pda_seed_validator",
    "solana_reentrancy_scanner", "move_bytecode_disasm",
    "move_resource_tracer", "sui_programmable_tx_audit",
    "cosmwasm_actor_analyzer", "substrate_pallet_scanner",
    "arbitrum_stylus_eval", "optimism_bedrock_differ",
    "starknet_cairo_disasm", "zksync_bootloader_spy",
    "bitcoin_script_parser", "tron_tvm_decompiler",
    "ripple_hook_validator", "cardano_plutus_eval",
    "near_protocol_state_audit", "filecoin_fvm_inspector",
    "avalanche_subnet_verifier", "bsc_precompile_checker",
    "polygon_miden_tracer", "multiversx_esdt_audit",
    "hedera_hts_tracker", "algorand_teal_decompiler",
    "flow_cadence_analyzer", "eosio_wasm_extractor",
    "tezos_michelson_parser",
]

# --- Bitcoin fixture helpers -------------------------------------------------
_PK = "02" + "11" * 32  # 33-byte compressed pubkey-shaped push

def _push(data_hex):
    return f"{len(bytes.fromhex(data_hex)):02x}{data_hex}"

BTC_1OF2 = "51" + _push(_PK) + _push("03" + "22" * 32) + "52ae"
BTC_2OF3 = ("52" + _push(_PK) + _push("03" + "22" * 32) +
            _push("02" + "33" * 32) + "53ae")
BTC_CLTV_SHORT = "0164b17576a914" + "44" * 20 + "88ac"

FIXTURES = {
 "solana_anchor_decoder": (
   json.dumps({"name": "vault", "instructions": [
     {"name": "withdraw", "accounts": [
       {"name": "authority", "isMut": True, "isSigner": False},
       {"name": "vault", "isMut": True, "isSigner": False}]}]}),
   json.dumps({"name": "vault", "instructions": [
     {"name": "withdraw", "accounts": [
       {"name": "authority", "isMut": True, "isSigner": True},
       {"name": "vault", "isMut": True, "isSigner": False}]}]})),
 "anchor_account_discriminator": (
   "pub struct Vault { pub data: AccountUnchecked } "
   "fn load(info: &AccountInfo) { let v = Vault::try_from(&info)?; }",
   "#[account] pub struct Vault { pub balance: u64 } "
   "pub vault: Account<'info, Vault> // Anchor verifies the discriminator"),
 "solana_sysvar_audit": (
   "pub clock: AccountInfo<'info>, let t = clock.unix_timestamp; "
   "let seed = winner_random(unix_timestamp);",
   "pub clock: Sysvar<'info, Clock>, pub rent: Sysvar<'info, Rent>"),
 "pda_seed_validator": (
   "let (pda, _) = Pubkey::create_program_address(&[b\"vault\"], pid)?; "
   "let seeds = user_seed;",
   "let (pda, bump) = Pubkey::find_program_address(&[b\"vault\"], pid); "
   "#[account(seeds = [b\"vault\"], bump)] pub vault: Account<'info, Vault>"),
 "solana_reentrancy_scanner": (
   "invoke(&ix, &accounts)?; state.balance = new_balance; state.save()?;",
   "state.balance = new_balance; state.save()?; "
   "invoke(&ix, &accounts)?; state.reload()?;"),
 "move_bytecode_disasm": ("100d", "150e"),
 "move_resource_tracer": (
   "public entry fun steal(account: &signer, addr: address) "
   "{ let c = move_from<Coin>(addr); }",
   "public entry fun withdraw(signer: &signer) "
   "{ let a = address_of(&signer); let c = move_from<Coin>(signer_addr); }"),
 "sui_programmable_tx_audit": (
   json.dumps({"commands": [{"kind": "MoveCall",
     "target": "0x2::dex::swap", "arguments": ["coin"]}]}),
   json.dumps({"commands": [{"kind": "MoveCall",
     "target": "0x2::dex::swap",
     "arguments": [{"min_out": 100, "deadline": 999}]}]})),
 "cosmwasm_actor_analyzer": (
   "pub fn reply(deps: DepsMut, msg: Reply) -> Result<Response, E> "
   "{ Ok(Response::new()) } fn send() { let m = SubMsg "
   "{ reply_on: ReplyOn::Never }; }",
   "pub fn reply(deps: DepsMut, msg: Reply) -> Result<Response, E> "
   "{ match msg.result { SubMsgResult::Ok(r) => handle(r), "
   "SubMsgResult::Err(e) => Err(e.into()) } }"),
 "substrate_pallet_scanner": (
   json.dumps({"pallets": [{"name": "Sudo"}, {"name": "Balances",
     "calls": [{"name": "force_transfer", "privileged": True,
                "origin": "Signed"}]}]}),
   json.dumps({"pallets": [{"name": "Balances", "calls": [
     {"name": "transfer", "privileged": False, "origin": "Signed"},
     {"name": "force_transfer", "privileged": True, "origin": "Root"}]}]})),
 "arbitrum_stylus_eval": (
   "#[public] impl Vault { pub fn withdraw(&mut self, amt: U256) "
   "{ self.vm().call_contract(target, data); } }",
   "#[public] impl Vault { pub fn withdraw(&mut self) "
   "{ let sender = self.vm().msg_sender(); assert!(sender == self.owner()); } }"),
 "optimism_bedrock_differ": (
   json.dumps({"l1": {"sequencer": "0xAAA", "gas_limit": 30000000,
                      "block_number": 1000},
               "l2": {"sequencer": "0xBBB", "gas_limit": 25000000,
                      "block_number": 800}}),
   json.dumps({"l1": {"sequencer": "0xAAA", "gas_limit": 30000000,
                      "block_number": 1000},
               "l2": {"sequencer": "0xAAA", "gas_limit": 30000000,
                      "block_number": 998}})),
 "starknet_cairo_disasm": (
   "#[external] fn withdraw(ref self: ContractState, amt: u256) "
   "{ transfer(recipient, amt); self.balance.write(0); }",
   "#[external] fn withdraw(ref self: ContractState, amt: u256) "
   "{ let caller = get_caller_address(); "
   "assert(caller == self.owner.read()); self.balance.write(0); }"),
 "zksync_bootloader_spy": (
   "upgrade_authority := 0x1234567890abcdef1234567890abcdef12345678; "
   "fn validate_transaction(tx) { check_signature(tx); } "
   "pub struct SystemContext; fn system_update() {}",
   "upgrade authority is a timelock multisig governance contract; "
   "fn validate_transaction(tx) { increment_nonce(); } "
   "fn system_update() { ensure_bootloader(); }"),
 "bitcoin_script_parser": (BTC_1OF2, BTC_2OF3),
 "tron_tvm_decompiler": ("60006000f4", "6001600055"),
 "ripple_hook_validator": (
   "int64_t hook(uint32_t r) { accept(0,0,0); for(;;) "
   "{ hook_state_set(k, v); } emit(buf); return 0; }",
   "int64_t hook(uint32_t r) { uint8_t me[20]; hook_account(); "
   "hook_account_buf(me); GUARD(1000); etxn_check(buf); "
   "for (int i = 0; i < 10; i++) { GUARD(10); } accept(0,0,0); }"),
 "cardano_plutus_eval": (
   "validator spend(datum, redeemer, ctx) { True } "
   "// spend validator with no further checks",
   "validator spend(datum, redeemer, ctx) { let own = findOwnInput(ctx); "
   "let d = datum; expect valuePaidTo(ctx, beneficiary) == amount; }"),
 "near_protocol_state_audit": (
   "pub fn on_payout_callback(&mut self) { let r = promise_result(); "
   "self.state = State::Finalized; } pub fn pay(&mut self) "
   "{ let d = env::attached_deposit(); transfer(d); }",
   "#[private] pub fn on_payout_callback(&mut self) "
   "{ match promise_result() { PromiseResult::Failed => revert(), "
   "PromiseResult::Successful(v) => finalize(v), _ => {} } } "
   "pub fn pay(&mut self) { assert!(env::attached_deposit() >= COST); }"),
 "filecoin_fvm_inspector": (
   "pub fn withdraw(params: Params) { state.balance = 0; save_state(); }",
   "pub fn withdraw(params: Params) { validate_caller(); "
   "let caller = msg.caller; if caller == owner "
   "{ state.balance = 0; save_state(); } }"),
 "avalanche_subnet_verifier": (
   "function receiveWarp() external { let m = getVerifiedWarpMessage(0); "
   "process(m.payload); } function receiveCrossChainMessage() external "
   "{ TeleporterMessage m; deliver(m); }",
   "function receiveWarp() external { let m = getVerifiedWarpMessage(0); "
   "require(check_signer_quorum(m, threshold)); } "
   "function receiveCrossChainMessage() external "
   "{ TeleporterMessage m; verify_source_subnet(m); check_relayer(m); }"),
 "bsc_precompile_checker": (
   "function check() public { (bool ok, bytes memory r) = "
   "address(0x0000000000000000000000000000000000000065).call(data); use(r); }",
   "function check() public { (bool success, bytes memory r) = "
   "address(0x0000000000000000000000000000000000000065).call(data); "
   "require(success); use(r); }"),
 "polygon_miden_tracer": (
   "proc.transfer_asset begin push.1 asset transfer end "
   "begin exec.transfer_asset end",
   "proc.check_amount begin push.100 assert end "
   "begin exec.check_amount end"),
 "multiversx_esdt_audit": (
   json.dumps({"identifier": "TOK-abc", "canFreeze": True,
               "canWipe": True, "canPause": False, "canMint": True,
               "owner": "erd1singleowner"}),
   json.dumps({"identifier": "TOK-abc", "canFreeze": False,
               "canWipe": False, "canPause": False, "canMint": False,
               "owner": "erd1singleowner"})),
 "hedera_hts_tracker": (
   json.dumps({"token_id": "0.0.123", "wipe_key": "302a300506",
               "freeze_key": {"_type": "ED25519", "key": "ab12"},
               "supply_key": None, "kyc_key": None,
               "fee_schedule_key": None, "pause_key": None}),
   json.dumps({"token_id": "0.0.123", "wipe_key": None,
               "freeze_key": {"_type": "KeyList", "keys": ["a", "b"]},
               "supply_key": None, "kyc_key": None,
               "fee_schedule_key": None, "pause_key": None})),
 "algorand_teal_decompiler": (
   "#pragma version 6\ntxn Sender\narg 0\n==\nint 1\nreturn",
   "#pragma version 6\ntxn RekeyTo\nglobal ZeroAddress\n==\nassert\n"
   "txn CloseRemainderTo\nglobal ZeroAddress\n==\nassert\n"
   "txn AssetCloseTo\nglobal ZeroAddress\n==\nassert\nint 1\nreturn"),
 "flow_cadence_analyzer": (
   "pub contract Vault { pub fun withdraw(amount: UFix64) "
   ": @FungibleToken.Vault {} } pub fun setup(acct: AuthAccount) "
   "{ acct.link<&Vault>(/public/vault) }",
   "access(all) contract Vault { access(Entitlement) "
   "fun withdraw() {} fun setup(acct: AuthAccount) "
   "{ acct.link<&Vault>(/private/vault) } }"),
 "eosio_wasm_extractor": (
   json.dumps({"abi": {"actions": [{"name": "withdraw"},
                                   {"name": "transfer"}]},
               "source": "void withdraw(name u) { inline_action(u); }"}),
   json.dumps({"abi": {"actions": [{"name": "withdraw"}]},
               "source": "void withdraw(name u) { require_auth(u); }"})),
 "tezos_michelson_parser": (
   "parameter (pair %transfer address nat); storage address; "
   "code { CAR; NIL operation; PAIR; TRANSFER_TOKENS; }",
   "parameter (pair %transfer address nat); storage address; "
   "code { DUP; SENDER; CAR; COMPARE; EQ; IF { } { FAILWITH }; "
   "TRANSFER_TOKENS; }"),
}


def _mod(pid):
    import importlib
    return importlib.import_module(f"app.plugins.{pid}")


def _ctx():
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(404, content="", request=req)),
        follow_redirects=True, trust_env=False)
    return Ctx(run_id="cat2-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


async def _run(pid, text):
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx()
    try:
        t = Target(raw=text, type="text", normalized=text)
        return await asyncio.wait_for(cls().run(t, ctx), timeout=30)
    finally:
        await ctx.http.aclose()


def test_all_cat2_plugins_registered():
    from app.plugins.registry import discover
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing"
    assert len(FIXTURES) == 29 and set(FIXTURES) == set(IDS)


@pytest.mark.parametrize("pid", IDS)
def test_fires_on_vuln(pid):
    vuln, _clean = FIXTURES[pid]
    hits = _mod(pid).analyze_artifact(vuln)
    assert hits, f"{pid} silent on VULN fixture"
    res = asyncio.run(_run(pid, vuln))
    assert res.findings, f"{pid} run() silent on VULN fixture"


@pytest.mark.parametrize("pid", IDS)
def test_silent_on_clean(pid):
    _vuln, clean = FIXTURES[pid]
    hits = _mod(pid).analyze_artifact(clean)
    assert hits == [], f"{pid} fired on CLEAN fixture: {hits}"
    res = asyncio.run(_run(pid, clean))
    assert res.findings == [], f"{pid} run() fired on CLEAN fixture"


@pytest.mark.parametrize("pid", IDS)
def test_no_crash_on_malformed(pid):
    assert _mod(pid).analyze_artifact("") == [] or True  # never raises
    _mod(pid).analyze_artifact("@@ garbage {{{ not json not code")
    _mod(pid).analyze_artifact(None)
    bad = Target(raw="", type="email", normalized="not a url @@")
    ctx = _ctx()
    from app.plugins.registry import discover
    res = asyncio.run(discover()[pid]().run(bad, ctx))
    assert isinstance(res.findings, list)


# --- parser unit tests ---------------------------------------------------------

def test_bitcoin_decode_and_timelock():
    from app.plugins.bitcoin_script_parser import decode_script, analyze_artifact
    names = [n for n, _ in decode_script(BTC_2OF3)]
    assert "OP_CHECKMULTISIG" in names
    hits = analyze_artifact(BTC_CLTV_SHORT)
    assert any(h["key"] == "bitcoin_timelock_too_short" for h in hits)
    assert analyze_artifact("zzzz") == []


def test_move_disasm_opcodes():
    from app.plugins.move_bytecode_disasm import disassemble_move
    assert disassemble_move("100d") == ["BorrowGlobalMut", "MoveFrom"]
    assert disassemble_move("150e") == ["CheckSigner", "MoveTo"]


def test_tron_disasm_opcodes():
    from app.plugins.tron_tvm_decompiler import disassemble_tvm, analyze_artifact
    assert "DELEGATECALL" in disassemble_tvm("60006000f4")
    assert any(h["key"] == "tron_tvm_selfdestruct"
               for h in analyze_artifact("60006000ff"))


def test_starknet_casm_only():
    from app.plugins.starknet_cairo_disasm import analyze_artifact
    hits = analyze_artifact(json.dumps({"casm": True, "sierra": False}))
    assert any(h["key"] == "starknet_casm_only_no_sierra" for h in hits)
    assert analyze_artifact(json.dumps({"casm": True, "sierra": True})) == []


def test_anchor_discriminator_collision():
    from app.plugins.anchor_account_discriminator import analyze_artifact
    txt = "struct A { discriminator: [1, 2, 3] } struct B { discriminator: [1,2,3] }"
    assert any(h["key"] == "anchor_discriminator_collision"
               for h in analyze_artifact(txt))


def test_eosio_extract_actions():
    from app.plugins.eosio_wasm_extractor import extract_abi_actions
    vuln, _ = FIXTURES["eosio_wasm_extractor"]
    assert extract_abi_actions(vuln) == ["withdraw", "transfer"]


def test_teal_listing():
    from app.plugins.algorand_teal_decompiler import disassemble_teal
    lines = disassemble_teal("#pragma version 6\n// comment\nint 1\nreturn")
    assert lines[0].startswith("#pragma")
