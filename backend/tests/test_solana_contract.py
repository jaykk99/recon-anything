"""Solana + pump.fun Contract Recon (solana_contract) tests.

Layers:
1. Classifier: Solana addresses, pump.fun URL forms, and sol:/solana:
   prefixes route to solana_contract - while BTC (legacy / P2SH /
   bech32), ETH, hex hashes, domains, and Android packages classify
   exactly as before.
2. Target parsing + base58 + raw account-layout fallbacks (SPL mint
   offsets, BPF upgradeable-loader Program/ProgramData states).
3. Pure analysis: mint authorities active vs revoked, holder
   concentration thresholds, Token-2022 extensions, pump.fun coin
   states, program upgrade authority active vs revoked.
4. Plugin runs with the chain/API layer stubbed (no network):
   pump coin end-to-end, safe mint, upgradeable program, account not
   found, RPC failure.

All network is mocked at the module seam (solana_contract's own
get_account_info / get_largest_accounts / fetch_pump_coin /
fetch_dex_pairs), mirroring how test_contract_recon stubs
contract_chain. Evidence values are asserted IN FULL (Jay's
2026-10-29 order: findings never mask values).
"""
import asyncio
import base64
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.classifier import classify  # noqa: E402
from app.plugins import solana_contract as sol  # noqa: E402
from app.plugins.base import PluginStatus, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

MINT = "GsnaqmpB9Xhxvh8hf1Z9HS1y76o9FPC8RaANGuc7ZpxT"      # fake mint
CREATOR = "Ev22dsDZiEqB7itHhumFPcx3iiFiD6pgbUvD9kqy8SEV"   # creator wallet
AUTHORITY = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC mint addr
PROGRAM = sol.PUMP_PROGRAM                                   # pump program
PD_ADDR = "So11111111111111111111111111111111111111112"      # fake ProgramData
ACCT_A = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"      # token account
ACCT_B = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"       # token account


def _keys(res):
    return {f.key for f in res.findings}


def _by_key(findings, key):
    return [f for f in findings if f["key"] == key]


# ---------------------------------------------------------------------------
# 1. Classifier
# ---------------------------------------------------------------------------

def test_classify_solana_forms():
    assert classify(MINT)["type"] == "solana_contract"
    assert classify(AUTHORITY)["type"] == "solana_contract"
    assert classify(PROGRAM)["type"] == "solana_contract"
    assert classify(f"https://pump.fun/coin/{MINT}")["type"] == \
        "solana_contract"
    assert classify(f"https://pump.fun/{MINT}")["type"] == \
        "solana_contract"
    assert classify(f"solana:{MINT}")["type"] == "solana_contract"
    assert classify(f"sol:{MINT}")["type"] == "solana_contract"


def test_classify_regressions_unchanged():
    # BTC in all three shapes stays crypto_wallet.
    assert classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")["type"] == \
        "crypto_wallet"
    assert classify("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")["type"] == \
        "crypto_wallet"
    assert classify("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")["type"] \
        == "crypto_wallet"
    # ETH stays crypto_wallet.
    assert classify("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")["type"] \
        == "crypto_wallet"
    # Hex hashes stay file_hash.
    assert classify("d41d8cd98f00b204e9800998ecf8427e")["type"] == \
        "file_hash"
    assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495"
                    "991b7852b855")["type"] == "file_hash"
    # Domains / Android packages / store handling unchanged.
    assert classify("example.com")["type"] == "domain"
    assert classify("com.whatsapp")["type"] == "play_store"
    # A non-pump URL is still a plain URL.
    assert classify("https://example.com/coin/" + MINT)["type"] == "url"


def test_parse_solana_target():
    assert sol.parse_solana_target(MINT) == MINT
    assert sol.parse_solana_target(f"https://pump.fun/coin/{MINT}") == MINT
    assert sol.parse_solana_target(f"https://pump.fun/{MINT}") == MINT
    assert sol.parse_solana_target(f"solana:{MINT}") == MINT
    assert sol.parse_solana_target(f"sol:{MINT}") == MINT
    assert sol.parse_solana_target("example.com") is None
    assert sol.parse_solana_target(
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e") is None
    assert sol.parse_solana_target(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") is None
    assert sol.parse_solana_target("https://pump.fun/coin/notanaddress") \
        is None
    assert sol.parse_solana_target("") is None


def test_registry():
    reg = discover()
    assert "solana_contract" in reg
    p = reg["solana_contract"]()
    assert p.group == "web3"
    assert p.requires_keys == []  # keyless, like the other web3 plugins
    assert "solana_contract" in p.accepts


# ---------------------------------------------------------------------------
# 2. Raw layout fallbacks
# ---------------------------------------------------------------------------

def test_parse_loader_raw_program_data():
    raw = (3).to_bytes(4, "little") + (123456).to_bytes(8, "little") \
        + b"\x01" + sol.b58decode(CREATOR)
    parsed = sol.parse_loader_raw(raw)
    assert parsed["type"] == "programData"
    assert parsed["info"]["upgradeAuthority"] == CREATOR
    assert parsed["info"]["slot"] == 123456
    # Authority revoked: flag byte 0.
    raw2 = (3).to_bytes(4, "little") + (1).to_bytes(8, "little") + b"\x00"
    assert sol.parse_loader_raw(raw2)["info"]["upgradeAuthority"] is None
    # Program state carries the ProgramData address.
    raw3 = (2).to_bytes(4, "little") + sol.b58decode(PD_ADDR)
    parsed3 = sol.parse_loader_raw(raw3)
    assert parsed3["info"]["programData"] == PD_ADDR


def test_parse_mint_raw():
    raw = bytearray(82)
    raw[0:4] = (1).to_bytes(4, "little")
    raw[4:36] = sol.b58decode(AUTHORITY)
    raw[36:44] = (1_000_000).to_bytes(8, "little")
    raw[44] = 6
    raw[45] = 1
    raw[46:50] = (0).to_bytes(4, "little")
    parsed = sol.parse_mint_raw(bytes(raw))
    assert parsed["mintAuthority"] == AUTHORITY
    assert parsed["freezeAuthority"] is None
    assert parsed["supply"] == "1000000"
    assert parsed["decimals"] == 6


# ---------------------------------------------------------------------------
# 3. Pure analysis: mints
# ---------------------------------------------------------------------------

def _mint_info(mint_auth=AUTHORITY, freeze_auth=AUTHORITY,
               supply="1000000", decimals=0, extensions=None):
    info = {"mintAuthority": mint_auth, "freezeAuthority": freeze_auth,
            "supply": supply, "decimals": decimals,
            "isInitialized": True}
    if extensions is not None:
        info["extensions"] = extensions
    return info


def test_analyze_mint_authorities_active():
    findings = sol.analyze_mint(MINT, _mint_info(), sol.TOKEN_PROGRAM,
                                None)
    keys = {f["key"] for f in findings}
    assert "solana_mint_authority_active" in keys
    assert "solana_freeze_authority_active" in keys
    mint_f = _by_key(findings, "solana_mint_authority_active")[0]
    assert mint_f["severity"] == "critical"
    assert AUTHORITY in mint_f["value"]  # shown in full, never masked
    assert mint_f["evidence"]["mint_authority"] == AUTHORITY
    freeze_f = _by_key(findings, "solana_freeze_authority_active")[0]
    assert freeze_f["severity"] == "high"
    assert AUTHORITY in freeze_f["value"]


def test_analyze_mint_authorities_revoked():
    findings = sol.analyze_mint(MINT, _mint_info(None, None),
                                sol.TOKEN_PROGRAM, None)
    keys = {f["key"] for f in findings}
    assert "solana_mint_authority_revoked" in keys
    assert "solana_freeze_authority_revoked" in keys
    assert "solana_mint_authority_active" not in keys
    assert "solana_freeze_authority_active" not in keys


def _largest(*amounts):
    addrs = [ACCT_A, ACCT_B, AUTHORITY, CREATOR, MINT, PROGRAM,
             PD_ADDR, sol.TOKEN_PROGRAM, sol.TOKEN2022_PROGRAM,
             sol.SYSTEM_PROGRAM]
    return [{"address": addrs[i], "amount": str(a),
             "decimals": 0, "uiAmount": float(a)}
            for i, a in enumerate(amounts)]


def test_holder_concentration_thresholds():
    # Top-1 = 60% -> high.
    findings = sol.analyze_mint(MINT, _mint_info(), sol.TOKEN_PROGRAM,
                                _largest(600_000, 100_000, 50_000))
    conc = _by_key(findings, "solana_holder_concentration")[0]
    assert conc["severity"] == "high"
    assert conc["evidence"]["top1_share"] == 0.6
    assert ACCT_A in conc["value"]  # holders shown in full
    # Top-1 = 25% -> medium.
    findings = sol.analyze_mint(MINT, _mint_info(), sol.TOKEN_PROGRAM,
                                _largest(250_000, 100_000, 50_000))
    assert _by_key(findings, "solana_holder_concentration")[0][
        "severity"] == "medium"
    # Dispersed: ten holders at 5% each -> low.
    findings = sol.analyze_mint(MINT, _mint_info(), sol.TOKEN_PROGRAM,
                                _largest(*([50_000] * 10)))
    assert _by_key(findings, "solana_holder_concentration")[0][
        "severity"] == "low"
    # Top-10 = 95% with a small top-1 -> high via the top-10 rule.
    findings = sol.analyze_mint(MINT, _mint_info(), sol.TOKEN_PROGRAM,
                                _largest(*([95_000] * 10)))
    conc = _by_key(findings, "solana_holder_concentration")[0]
    assert conc["severity"] == "high"
    assert conc["evidence"]["top10_share"] == 0.95


def test_analyze_token2022_extensions():
    exts = [
        {"extension": "permanentDelegate",
         "state": {"delegate": CREATOR}},
        {"extension": "transferFeeConfig",
         "state": {"transferFeeBasisPoints": 250, "maximumFee": "5000",
                   "transferFeeConfigAuthority": AUTHORITY,
                   "withdrawWithheldAuthority": AUTHORITY}},
        {"extension": "nonTransferable", "state": {}},
    ]
    findings = sol.analyze_mint(MINT, _mint_info(extensions=exts),
                                sol.TOKEN2022_PROGRAM, None)
    keys = {f["key"] for f in findings}
    assert "solana_token2022_permanent_delegate" in keys
    assert "solana_token2022_transfer_fee_config" in keys
    assert "solana_token2022_non_transferable" in keys
    delegate = _by_key(findings,
                       "solana_token2022_permanent_delegate")[0]
    assert delegate["severity"] == "critical"
    assert CREATOR in delegate["value"]  # state shown in full
    fee = _by_key(findings, "solana_token2022_transfer_fee_config")[0]
    assert fee["severity"] == "medium"
    assert "250" in fee["value"]
    # No extensions -> no extension findings.
    findings = sol.analyze_mint(MINT, _mint_info(), sol.TOKEN_PROGRAM,
                                None)
    assert not any(f["key"].startswith("solana_token2022_")
                   for f in findings)


# ---------------------------------------------------------------------------
# 3b. Pure analysis: pump.fun coins
# ---------------------------------------------------------------------------

PUMP_COIN = {
    "mint": MINT, "name": "Test Coin", "symbol": "TEST",
    "creator": CREATOR, "complete": False, "is_mutable": True,
    "bonding_curve": ACCT_A, "associated_bonding_curve": ACCT_B,
    "virtual_sol_reserves": 30_000_000_000,
    "virtual_token_reserves": 800_000_000_000_000,
    "total_supply": 1_000_000_000_000_000,
    "market_cap": 31.5, "usd_market_cap": 4500.0,
    "metadata_uri": "https://ipfs.io/ipfs/testcoin",
    "created_timestamp": 1730000000000, "raydium_pool": None,
}


def test_analyze_pump_coin_on_curve_mutable_dev_holds():
    largest = [{"address": ACCT_A, "amount": "150000",
                "owner": CREATOR},
               {"address": ACCT_B, "amount": "10000",
                "owner": AUTHORITY}]
    findings = sol.analyze_pump_coin(MINT, dict(PUMP_COIN), largest,
                                     1_000_000)
    keys = {f["key"] for f in findings}
    assert "pump_coin_info" in keys
    assert "pump_bonding_curve_active" in keys
    assert "pump_metadata_mutable" in keys
    assert "pump_creator_holdings" in keys
    assert "pump_graduated" not in keys
    mutable = _by_key(findings, "pump_metadata_mutable")[0]
    assert mutable["severity"] == "high"
    assert CREATOR in mutable["value"]
    dev = _by_key(findings, "pump_creator_holdings")[0]
    assert dev["severity"] == "high"  # 15% > 10% threshold
    assert dev["evidence"]["creator_share"] == 0.15
    assert CREATOR in dev["value"]  # creator shown in full
    curve = _by_key(findings, "pump_bonding_curve_active")[0]
    assert ACCT_A in curve["value"]


def test_analyze_pump_coin_graduated_immutable():
    coin = dict(PUMP_COIN)
    coin.update({"complete": True, "is_mutable": False,
                 "raydium_pool": ACCT_B})
    findings = sol.analyze_pump_coin(MINT, coin, [], 1_000_000)
    keys = {f["key"] for f in findings}
    assert "pump_graduated" in keys
    assert "pump_metadata_immutable" in keys
    assert "pump_bonding_curve_active" not in keys
    assert "pump_creator_holdings" not in keys  # creator holds nothing


def test_analyze_pump_coin_mutability_unknown():
    coin = dict(PUMP_COIN)
    del coin["is_mutable"]
    findings = sol.analyze_pump_coin(MINT, coin, [], 1_000_000)
    mutable = _by_key(findings, "pump_metadata_mutable")[0]
    assert mutable["severity"] == "medium"
    assert CREATOR in mutable["value"]


# ---------------------------------------------------------------------------
# 3c. Pure analysis: programs
# ---------------------------------------------------------------------------

def _program_account(owner):
    return {"owner": owner, "executable": True, "lamports": 100,
            "parsed_type": "program",
            "info": {"programData": PD_ADDR}, "raw_bytes": None}


def _program_data(authority):
    return {"owner": sol.BPF_UPGRADEABLE_LOADER, "executable": False,
            "lamports": 100, "parsed_type": "programData",
            "info": {"slot": 42, "upgradeAuthority": authority},
            "raw_bytes": None}


def test_analyze_program_upgrade_authority_active():
    findings = sol.analyze_program(PROGRAM,
                                   _program_account(
                                       sol.BPF_UPGRADEABLE_LOADER),
                                   _program_data(CREATOR))
    f0 = _by_key(findings, "solana_program_upgrade_authority")[0]
    assert f0["severity"] == "critical"
    assert CREATOR in f0["value"]  # authority shown in full
    assert f0["evidence"]["upgrade_authority"] == CREATOR
    assert f0["evidence"]["program_data"] == PD_ADDR


def test_analyze_program_live_authority_key():
    # Live mainnet jsonParsed ProgramData uses "authority", not
    # "upgradeAuthority" (verified 2026-11-01 against the pump.fun
    # program's ProgramData account). Both spellings must parse.
    pd = _program_data(None)
    pd["info"] = {"slot": 42, "authority": CREATOR}
    findings = sol.analyze_program(PROGRAM,
                                   _program_account(
                                       sol.BPF_UPGRADEABLE_LOADER),
                                   pd)
    f0 = _by_key(findings, "solana_program_upgrade_authority")[0]
    assert f0["evidence"]["upgrade_authority"] == CREATOR


def test_analyze_program_upgrade_authority_revoked():
    findings = sol.analyze_program(PROGRAM,
                                   _program_account(
                                       sol.BPF_UPGRADEABLE_LOADER),
                                   _program_data(None))
    keys = {f["key"] for f in findings}
    assert "solana_program_immutable" in keys
    assert "solana_program_upgrade_authority" not in keys


def test_analyze_program_non_upgradeable():
    account = _program_account(sol.BPF_LOADER_V2)
    account["info"] = {}
    findings = sol.analyze_program(PROGRAM, account, None)
    assert "solana_program_non_upgradeable" in \
        {f["key"] for f in findings}


# ---------------------------------------------------------------------------
# 4. Plugin runs (network stubbed at the module seam)
# ---------------------------------------------------------------------------

class FakeCtx:
    def __init__(self, shared=None):
        self.keys = {}
        self.mode = "passive"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = shared or {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _mint_value(mint_auth=AUTHORITY, freeze_auth=AUTHORITY,
                supply="1000000000000", decimals=6,
                extensions=None):
    info = {"mintAuthority": mint_auth, "freezeAuthority": freeze_auth,
            "supply": supply, "decimals": decimals,
            "isInitialized": True}
    if extensions is not None:
        info["extensions"] = extensions
    return {"data": {"program": "spl-token",
                     "parsed": {"info": info, "type": "mint"},
                     "space": 82},
            "executable": False, "lamports": 1461600,
            "owner": sol.TOKEN_PROGRAM}


def _token_account_value(owner, mint=MINT):
    return {"data": {"program": "spl-token",
                     "parsed": {"info": {"mint": mint, "owner": owner,
                                         "tokenAmount":
                                             {"amount": "1"}},
                                "type": "account"},
                     "space": 165},
            "executable": False, "lamports": 2039280,
            "owner": sol.TOKEN_PROGRAM}


def _patch(monkeypatch, account_by_addr, largest=None, pump=None,
           dex=None):
    async def fake_info(ctx, address):
        value = account_by_addr.get(address, "__missing__")
        if value == "__missing__":
            return {"context": {}, "value": None}
        return {"context": {}, "value": value}

    async def fake_largest(ctx, mint):
        return largest

    async def fake_pump(ctx, mint):
        return pump

    async def fake_dex(ctx, mint):
        return dex or []
    monkeypatch.setattr(sol, "get_account_info", fake_info)
    monkeypatch.setattr(sol, "get_largest_accounts", fake_largest)
    monkeypatch.setattr(sol, "fetch_pump_coin", fake_pump)
    monkeypatch.setattr(sol, "fetch_dex_pairs", fake_dex)


def test_plugin_pump_coin_end_to_end(monkeypatch):
    accounts = {MINT: _mint_value(),
                ACCT_A: _token_account_value(CREATOR)}
    largest = [{"address": ACCT_A, "amount": "150000000000",
                "decimals": 6, "uiAmount": 150000.0},
               {"address": ACCT_B, "amount": "10000000000",
                "decimals": 6, "uiAmount": 10000.0}]
    _patch(monkeypatch, accounts, largest=largest, pump=dict(PUMP_COIN))
    p = sol.SolanaContractPlugin()
    target = Target(raw=f"https://pump.fun/coin/{MINT}",
                    type="solana_contract",
                    normalized=f"https://pump.fun/coin/{MINT}")
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK
    keys = _keys(res)
    for want in ("solana_mint_authority_active",
                 "solana_freeze_authority_active",
                 "solana_holder_concentration", "pump_coin_info",
                 "pump_bonding_curve_active", "pump_metadata_mutable",
                 "pump_creator_holdings"):
        assert want in keys, f"missed {want}: {sorted(keys)}"
    dev = [f for f in res.findings
           if f.key == "pump_creator_holdings"][0]
    assert CREATOR in dev.value  # creator wallet in full
    assert dev.evidence["severity"] == "high"  # 15% of supply
    auth = [f for f in res.findings
            if f.key == "solana_mint_authority_active"][0]
    assert AUTHORITY in auth.value


def test_plugin_safe_mint(monkeypatch):
    _patch(monkeypatch, {MINT: _mint_value(None, None)}, largest=[],
           pump=None)
    p = sol.SolanaContractPlugin()
    target = Target(raw=MINT, type="solana_contract", normalized=MINT)
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    assert "solana_mint_authority_revoked" in keys
    assert "solana_freeze_authority_revoked" in keys
    assert "solana_mint_authority_active" not in keys
    assert not any(k.startswith("pump_") for k in keys)


def test_plugin_upgradeable_program(monkeypatch):
    program_value = {
        "data": {"program": "bpf-upgradeable-loader",
                 "parsed": {"info": {"programData": PD_ADDR},
                            "type": "program"},
                 "space": 36},
        "executable": True, "lamports": 1141440,
        "owner": sol.BPF_UPGRADEABLE_LOADER}
    pd_value = {
        "data": {"program": "bpf-upgradeable-loader",
                 "parsed": {"info": {"slot": 42,
                                     "upgradeAuthority": CREATOR},
                            "type": "programData"},
                 "space": 45},
        "executable": False, "lamports": 100,
        "owner": sol.BPF_UPGRADEABLE_LOADER}
    _patch(monkeypatch, {PROGRAM: program_value, PD_ADDR: pd_value})
    p = sol.SolanaContractPlugin()
    target = Target(raw=f"solana:{PROGRAM}", type="solana_contract",
                    normalized=f"solana:{PROGRAM}")
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    assert "solana_program_upgrade_authority" in keys
    f0 = [f for f in res.findings
          if f.key == "solana_program_upgrade_authority"][0]
    assert CREATOR in f0.value
    assert f0.evidence["upgrade_authority"] == CREATOR


def test_plugin_account_not_found(monkeypatch):
    _patch(monkeypatch, {})
    p = sol.SolanaContractPlugin()
    target = Target(raw=MINT, type="solana_contract", normalized=MINT)
    res = asyncio.run(p.run(target, FakeCtx()))
    assert "solana_account_not_found" in _keys(res)


def test_plugin_rpc_failure_fails_closed(monkeypatch):
    async def no_info(ctx, address):
        return None
    monkeypatch.setattr(sol, "get_account_info", no_info)
    p = sol.SolanaContractPlugin()
    target = Target(raw=MINT, type="solana_contract", normalized=MINT)
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK  # honest finding, no crash
    assert "solana_recon_failed" in _keys(res)


def test_plugin_skips_cleanly_without_solana_target():
    p = sol.SolanaContractPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK
    assert res.findings == []


# ---------------------------------------------------------------------------
# 5. On-chain pump.fun coverage (PDA derivation, bonding curve parse,
#    creator holdings, Metaplex metadata) - the pump single-coin API
#    returned 404 for every mint tested on 2026-11-01, so these paths
#    are the primary source and are tested with the API absent.
# ---------------------------------------------------------------------------

# Real vector taken from the live pump.fun LIST endpoint
# (GET frontend-api-v3.pump.fun/coins?offset=0&limit=5&... on
# 2026-11-01, which works): this mint's record names this exact
# bonding_curve and associated_bonding_curve. The PDA derivation
# must reproduce both addresses from the mint alone.
VECTOR_MINT = "666bnUsjGEPEDPof9SDcDnQRda54CfUDbL5efekupump"
VECTOR_CURVE = "Bdm5tsjycz8C5V2ifhWzFEfiTLqwvuUwLhHZSGRpNFmq"
VECTOR_ASSOC = "FKzxXfKyBZTAVidQZHN8zQTQsVYcusSsrbVaVHEwGnLZ"


def test_pda_derivation_matches_live_pump_vector():
    assert sol.bonding_curve_address(VECTOR_MINT) == VECTOR_CURVE
    # The associated curve token account (ATA of the curve PDA,
    # Token-2022 program per the live record) derives exactly too.
    assert sol.associated_token_address(
        VECTOR_CURVE, VECTOR_MINT, sol.TOKEN2022_PROGRAM) == VECTOR_ASSOC
    addr, bump = sol.find_program_address(
        [b"bonding-curve", sol.b58decode(VECTOR_MINT)], sol.PUMP_PROGRAM)
    assert addr == VECTOR_CURVE
    assert isinstance(bump, int) and 0 <= bump <= 255
    # Deterministic, valid addresses for the other PDAs.
    meta = sol.metaplex_metadata_address(MINT)
    assert sol.is_solana_address(meta)
    assert sol.metaplex_metadata_address(MINT) == meta
    # A normal pubkey IS on-curve (that is the whole point of PDAs
    # being off-curve): the system program address is a real key.
    assert sol._ed25519_on_curve(sol.b58decode(sol.SYSTEM_PROGRAM))


def _curve_bytes(complete=False, with_creator=True, total_len=None):
    raw = bytearray()
    raw += b"\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81"  # Anchor discriminator
    for v in (800_000_000_000_000, 30_000_000_000, 200_000_000_000_000,
              5_000_000_000, 1_000_000_000_000_000):
        raw += v.to_bytes(8, "little")
    raw.append(1 if complete else 0)            # complete @ offset 48
    if with_creator:
        raw += sol.b58decode(CREATOR)           # creator @ offset 49
    if total_len is not None:
        raw = raw[:total_len]
        raw += b"\x00" * max(0, total_len - len(raw))
    return bytes(raw)


def test_parse_bonding_curve_active_and_complete():
    parsed = sol.parse_bonding_curve(_curve_bytes(complete=False))
    assert parsed["complete"] is False
    assert parsed["creator"] == CREATOR
    assert parsed["virtual_sol_reserves"] == 30_000_000_000
    assert parsed["virtual_token_reserves"] == 800_000_000_000_000
    assert parsed["real_sol_reserves"] == 5_000_000_000
    assert parsed["token_total_supply"] == 1_000_000_000_000_000
    done = sol.parse_bonding_curve(_curve_bytes(complete=True))
    assert done["complete"] is True
    assert done["creator"] == CREATOR


def test_parse_bonding_curve_truncated_lengths():
    # Exactly 49 bytes: complete flag readable, no creator yet.
    parsed = sol.parse_bonding_curve(_curve_bytes(total_len=49))
    assert parsed["complete"] is False
    assert parsed["creator"] is None
    # Partial creator bytes (60 total): still no creator claimed.
    parsed = sol.parse_bonding_curve(_curve_bytes(total_len=60))
    assert parsed["creator"] is None
    # Too short to hold the complete flag: does not parse at all.
    assert sol.parse_bonding_curve(_curve_bytes(total_len=48)) is None
    assert sol.parse_bonding_curve(_curve_bytes(total_len=20)) is None
    assert sol.parse_bonding_curve(b"") is None
    assert sol.parse_bonding_curve(None) is None


def test_analyze_bonding_curve_creator_and_curve_share():
    curve = sol.parse_bonding_curve(_curve_bytes(complete=False))
    curve["address"] = VECTOR_CURVE
    largest = [{"address": ACCT_B, "amount": "500000"},   # curve ATA
               {"address": ACCT_A, "amount": "150000",
                "owner": CREATOR}]
    findings = sol.analyze_bonding_curve(MINT, curve, largest,
                                         1_000_000,
                                         curve_token_account=ACCT_B)
    keys = {f["key"] for f in findings}
    assert "pump_bonding_curve_active" in keys
    assert "pump_creator_holdings" in keys
    active = _by_key(findings, "pump_bonding_curve_active")[0]
    assert VECTOR_CURVE in active["value"]
    assert "30000000000" in active["value"]  # virtual SOL reserves
    assert active["evidence"]["curve_token_share"] == 0.5
    assert ACCT_B in active["value"]  # curve token account in full
    dev = _by_key(findings, "pump_creator_holdings")[0]
    assert dev["severity"] == "high"  # 15% > 10%
    assert dev["evidence"]["creator"] == CREATOR
    assert dev["evidence"]["creator_share"] == 0.15
    assert CREATOR in dev["value"]


def test_analyze_bonding_curve_graduated_creator_zero():
    curve = sol.parse_bonding_curve(_curve_bytes(complete=True))
    curve["address"] = VECTOR_CURVE
    findings = sol.analyze_bonding_curve(
        MINT, curve, [{"address": ACCT_A, "amount": "10",
                       "owner": AUTHORITY}], 1_000_000)
    keys = {f["key"] for f in findings}
    assert "pump_graduated" in keys
    assert "pump_bonding_curve_active" not in keys
    # Creator is ALWAYS reported when a curve exists, even at 0%.
    dev = _by_key(findings, "pump_creator_holdings")[0]
    assert dev["severity"] == "low"
    assert dev["evidence"]["creator_share"] == 0.0
    assert CREATOR in dev["value"]
    # No largest accounts at all: creator still reported, share None.
    findings = sol.analyze_bonding_curve(MINT, curve, None, 1_000_000)
    dev = _by_key(findings, "pump_creator_holdings")[0]
    assert dev["evidence"]["creator_share"] is None
    assert CREATOR in dev["value"]


def _metadata_bytes(is_mutable=True, with_creators=True):
    out = bytearray()
    out.append(4)                                # MetadataV1 key
    out += sol.b58decode(CREATOR)                # update authority
    out += sol.b58decode(MINT)                   # mint

    def _s(s):
        b = s.encode()
        return len(b).to_bytes(4, "little") + b
    out += _s("Test Coin")
    out += _s("TEST")
    out += _s("https://ipfs.io/ipfs/testcoin")
    out += (500).to_bytes(2, "little")           # seller fee bps
    if with_creators:
        out.append(1)
        out += (1).to_bytes(4, "little")
        out += sol.b58decode(CREATOR)            # creator address
        out.append(1)                            # verified
        out.append(100)                          # share
    else:
        out.append(0)
    out.append(0)                                # primarySaleHappened
    out.append(1 if is_mutable else 0)           # isMutable
    return bytes(out)


def test_parse_metaplex_metadata_mutable():
    parsed = sol.parse_metaplex_metadata(_metadata_bytes(True))
    assert parsed["update_authority"] == CREATOR
    assert parsed["mint"] == MINT
    assert parsed["name"] == "Test Coin"
    assert parsed["symbol"] == "TEST"
    assert parsed["uri"] == "https://ipfs.io/ipfs/testcoin"
    assert parsed["seller_fee_basis_points"] == 500
    assert parsed["creators"][0]["address"] == CREATOR
    assert parsed["creators"][0]["verified"] is True
    assert parsed["creators"][0]["share"] == 100
    assert parsed["primary_sale_happened"] is False
    assert parsed["is_mutable"] is True
    findings = sol.analyze_metaplex_metadata(MINT, parsed)
    f0 = _by_key(findings, "solana_metadata_mutable")[0]
    assert f0["severity"] == "high"
    assert CREATOR in f0["value"]  # update authority in full


def test_parse_metaplex_metadata_immutable_no_creators():
    parsed = sol.parse_metaplex_metadata(
        _metadata_bytes(False, with_creators=False))
    assert parsed["is_mutable"] is False
    assert parsed["creators"] is None
    findings = sol.analyze_metaplex_metadata(MINT, parsed)
    keys = {f["key"] for f in findings}
    assert "solana_metadata_immutable" in keys
    assert "solana_metadata_mutable" not in keys
    # Truncations / garbage never parse into a false finding.
    assert sol.parse_metaplex_metadata(
        _metadata_bytes(True)[:70]) is None
    assert sol.parse_metaplex_metadata(b"\x04" + b"\x00" * 10) is None
    assert sol.parse_metaplex_metadata(None) is None


def _b64_value(raw, owner):
    return {"data": [base64.b64encode(raw).decode(), "base64"],
            "executable": False, "lamports": 2000000, "owner": owner}


def _patch_base64(monkeypatch, by_addr):
    async def fake_b64(ctx, address):
        value = by_addr.get(address, "__missing__")
        if value == "__missing__":
            return {"context": {}, "value": None}
        return {"context": {}, "value": value}
    monkeypatch.setattr(sol, "get_account_info_base64", fake_b64)


def test_plugin_pump_onchain_without_api(monkeypatch):
    # The dead-API case: fetch_pump_coin returns None, yet the
    # on-chain curve + metadata reads must produce the pump
    # findings on their own.
    curve_addr = sol.bonding_curve_address(MINT)
    meta_addr = sol.metaplex_metadata_address(MINT)
    _patch_base64(monkeypatch, {
        curve_addr: _b64_value(_curve_bytes(complete=False),
                               sol.PUMP_PROGRAM),
        meta_addr: _b64_value(_metadata_bytes(True),
                              sol.MPL_TOKEN_METADATA_PROGRAM),
    })
    accounts = {MINT: _mint_value(),
                ACCT_A: _token_account_value(CREATOR)}
    largest = [{"address": ACCT_A, "amount": "150000000000",
                "decimals": 6, "uiAmount": 150000.0}]
    _patch(monkeypatch, accounts, largest=largest, pump=None)
    p = sol.SolanaContractPlugin()
    target = Target(raw=f"https://pump.fun/coin/{MINT}",
                    type="solana_contract",
                    normalized=f"https://pump.fun/coin/{MINT}")
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    for want in ("pump_bonding_curve_active", "pump_creator_holdings",
                 "solana_metadata_mutable"):
        assert want in keys, f"missed {want}: {sorted(keys)}"
    assert "pump_coin_info" not in keys  # API was absent, not needed
    dev = [f for f in res.findings
           if f.key == "pump_creator_holdings"][0]
    assert CREATOR in dev.value
    assert dev.evidence["severity"] == "high"


def test_plugin_curve_missing_no_api_claims(monkeypatch):
    # RPC answers and there is NO curve account: not on the pump
    # curve now, and the (stale) API record must not be turned into
    # curve / graduated / metadata claims.
    _patch_base64(monkeypatch, {})
    _patch(monkeypatch, {MINT: _mint_value()}, largest=[],
           pump=dict(PUMP_COIN))
    p = sol.SolanaContractPlugin()
    target = Target(raw=MINT, type="solana_contract", normalized=MINT)
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    assert "pump_bonding_curve_not_found" in keys
    assert "pump_bonding_curve_active" not in keys
    assert "pump_graduated" not in keys  # not claimed without proof
    assert "pump_metadata_mutable" not in keys
    assert "pump_creator_holdings" not in keys


# ---------------------------------------------------------------------------
# 6. Deep token audit: REAL holder distribution (getProgramAccounts
#    aggregated by owner), creator deep-dive, full Token-2022
#    dangerous-extension audit, DexScreener sell-side, authority map.
# ---------------------------------------------------------------------------

POOL_WALLET = PD_ADDR  # stands in as the pool/curve owner wallet


def _pa_entry(pubkey, owner, amount, decimals=0):
    """One getProgramAccounts result entry (jsonParsed shape)."""
    return {"pubkey": pubkey,
            "account": {
                "data": {"program": "spl-token",
                         "parsed": {
                             "info": {"mint": MINT, "owner": owner,
                                      "tokenAmount": {
                                          "amount": str(amount),
                                          "decimals": decimals}},
                             "type": "account"},
                         "space": 165},
                "executable": False, "lamports": 2039280,
                "owner": sol.TOKEN_PROGRAM}}


def _patch_program_accounts(monkeypatch, entries):
    async def fake_pa(ctx, token_program, mint):
        return entries
    monkeypatch.setattr(sol, "get_program_accounts", fake_pa)


def _patch_balance(monkeypatch, lamports):
    async def fake_bal(ctx, address):
        return lamports
    monkeypatch.setattr(sol, "get_balance", fake_bal)


def _dist_accounts():
    # Pool account holds 50%; the creator holds 25% SPLIT ACROSS
    # TWO token accounts (150k + 100k) - aggregation by owner must
    # still catch it as one wallet; a third wallet holds 5%.
    return [
        {"address": ACCT_B, "owner": POOL_WALLET, "amount": 500_000},
        {"address": ACCT_A, "owner": CREATOR, "amount": 150_000},
        {"address": AUTHORITY, "owner": CREATOR, "amount": 100_000},
        {"address": MINT, "owner": AUTHORITY, "amount": 50_000},
        {"address": PROGRAM, "owner": AUTHORITY, "amount": 0},
    ]


def test_aggregate_holders_by_owner_and_pool():
    dist = sol.aggregate_holders(
        _dist_accounts(), 1_000_000,
        pool_labels={ACCT_B: "pump.fun bonding curve"})
    assert dist["holder_count"] == 3  # zero-balance owner excluded
    assert dist["account_count"] == 4
    assert dist["top1_share"] == 0.5          # the pool owner
    assert dist["ex_pool_top1_share"] == 0.25  # the creator
    assert dist["has_pool"] is True
    top = dist["top_accounts"][0]
    assert top["address"] == ACCT_B
    assert top["pool"] == "pump.fun bonding curve"
    # Creator split across two accounts still sums to one wallet.
    raw, share = sol.owner_share(dist, CREATOR, 1_000_000)
    assert raw == 250_000
    assert share == 0.25
    assert sol.owner_rank(dist, CREATOR) == 2
    assert sol.owner_rank(dist, AUTHORITY) == 3
    assert sol.owner_rank(dist, sol.SYSTEM_PROGRAM) is None


def test_analyze_holder_distribution_pool_scoring():
    dist = sol.aggregate_holders(
        _dist_accounts(), 1_000_000,
        pool_labels={ACCT_B: "pump.fun bonding curve"})
    findings = sol.analyze_holder_distribution(MINT, dist,
                                               1_000_000, 0)
    f0 = _by_key(findings, "solana_holder_distribution")[0]
    # Scored on ex-pool shares: ex-top1 25% -> medium (raw top1 of
    # 50% would be high - the pool must not inflate the score).
    assert f0["severity"] == "medium"
    assert f0["evidence"]["scored_on"] == "pool-excluded"
    assert f0["evidence"]["ex_pool_top1_share"] == 0.25
    assert f0["evidence"]["holder_count"] == 3
    assert "POOL" in f0["value"]
    assert CREATOR in f0["value"]  # owners shown in full
    # No pool anywhere: a single 60% whale scores high on raw.
    whale = sol.aggregate_holders(
        [{"address": ACCT_A, "owner": CREATOR, "amount": 600_000},
         {"address": ACCT_B, "owner": AUTHORITY, "amount": 10_000}],
        1_000_000)
    f1 = sol.analyze_holder_distribution(MINT, whale, 1_000_000,
                                         0)[0]
    assert f1["severity"] == "high"
    assert f1["evidence"]["scored_on"] == "raw"


def test_fetch_holder_distribution_cap(monkeypatch):
    entries = [_pa_entry(ACCT_A, CREATOR, 1) for _ in range(6000)]
    _patch_program_accounts(monkeypatch, entries)
    dist = asyncio.run(sol.fetch_holder_distribution(
        FakeCtx(), MINT, sol.TOKEN_PROGRAM, 1_000_000))
    assert dist["capped"] is True
    assert dist["total_returned"] == 6000
    assert dist["processed"] == sol.MAX_HOLDER_ACCOUNTS
    f0 = sol.analyze_holder_distribution(MINT, dist, 1_000_000,
                                         0)[0]
    assert "capped" in f0["value"]  # the cap is disclosed
    # RPC failure -> None (callers fall back / report unavailable).
    _patch_program_accounts(monkeypatch, None)
    assert asyncio.run(sol.fetch_holder_distribution(
        FakeCtx(), MINT, sol.TOKEN_PROGRAM, 1_000_000)) is None


def test_fetch_holder_distribution_raw_fallback(monkeypatch):
    raw = bytearray(165)
    raw[0:32] = sol.b58decode(MINT)
    raw[32:64] = sol.b58decode(CREATOR)
    raw[64:72] = (700_000).to_bytes(8, "little")
    entry = {"pubkey": ACCT_A,
             "account": {"data": [base64.b64encode(
                 bytes(raw)).decode(), "base64"],
                         "executable": False, "lamports": 2039280,
                         "owner": sol.TOKEN_PROGRAM}}
    _patch_program_accounts(monkeypatch, [entry])
    dist = asyncio.run(sol.fetch_holder_distribution(
        FakeCtx(), MINT, sol.TOKEN_PROGRAM, 1_000_000))
    assert dist["holder_count"] == 1
    assert dist["top1_share"] == 0.7
    parsed = sol.parse_token_account_raw(bytes(raw))
    assert parsed["owner"] == CREATOR
    assert parsed["amount"] == "700000"


def test_token2022_transfer_hook_and_frozen_default():
    exts = [
        {"extension": "transferHook",
         "state": {"authority": AUTHORITY, "programId": PROGRAM}},
        {"extension": "defaultAccountState",
         "state": {"accountState": "frozen"}},
    ]
    findings = sol.analyze_token2022_extensions(
        MINT, _mint_info(extensions=exts),
        {"address": MINT, "chain": "solana"})
    keys = {f["key"] for f in findings}
    assert "solana_token2022_transfer_hook" in keys
    assert "solana_token2022_default_account_state" in keys
    hook = _by_key(findings, "solana_token2022_transfer_hook")[0]
    assert hook["severity"] == "high"
    assert PROGRAM in hook["value"]    # hook program in full
    assert AUTHORITY in hook["value"]  # hook authority in full
    frozen = _by_key(findings,
                     "solana_token2022_default_account_state")[0]
    assert frozen["severity"] == "high"
    audit = _by_key(findings, "solana_token2022_extension_audit")[0]
    assert "transferHook" in audit["evidence"]["dangerous_present"]
    assert "defaultAccountState" in \
        audit["evidence"]["dangerous_present"]


def test_token2022_default_initialized_is_clean():
    exts = [{"extension": "defaultAccountState",
             "state": {"accountState": "initialized"}}]
    findings = sol.analyze_token2022_extensions(
        MINT, _mint_info(extensions=exts),
        {"address": MINT, "chain": "solana"})
    keys = {f["key"] for f in findings}
    assert "solana_token2022_default_account_state" not in keys
    audit = _by_key(findings, "solana_token2022_extension_audit")[0]
    assert "not frozen" in \
        audit["evidence"]["audit"]["defaultAccountState"]
    assert audit["evidence"]["dangerous_present"] == []


def test_token2022_fee_nested_shape_and_info_extensions():
    exts = [
        {"extension": "transferFeeConfig",
         "state": {"transferFeeConfigAuthority": AUTHORITY,
                   "withdrawWithheldAuthority": AUTHORITY,
                   "withheldAmount": "0",
                   "newerTransferFee": {
                       "epoch": 500, "maximumFee": "1000",
                       "transferFeeBasisPoints": 100}}},
        {"extension": "memoTransfer",
         "state": {"requireIncomingTransferMemos": True}},
        {"extension": "confidentialTransferMint",
         "state": {"authority": AUTHORITY,
                   "autoApproveNewAccounts": False}},
    ]
    findings = sol.analyze_token2022_extensions(
        MINT, _mint_info(extensions=exts),
        {"address": MINT, "chain": "solana"})
    fee = _by_key(findings, "solana_token2022_transfer_fee_config")[0]
    assert fee["severity"] == "medium"
    assert "100" in fee["value"]       # basis points in full
    assert "1.00%" in fee["value"]     # rendered as a percentage
    assert AUTHORITY in fee["value"]   # fee authorities in full
    memo = _by_key(findings, "solana_token2022_memo_transfer")[0]
    assert memo["severity"] == "low"
    conf = _by_key(findings,
                   "solana_token2022_confidential_transfer_mint")[0]
    assert conf["severity"] == "low"   # info-level, per the audit
    audit = _by_key(findings, "solana_token2022_extension_audit")[0]
    assert audit["evidence"]["audit"]["permanentDelegate"] == \
        "absent - clean"


def test_token2022_audit_all_clean_and_nontransferable_high():
    findings = sol.analyze_token2022_extensions(
        MINT, _mint_info(extensions=[]),
        {"address": MINT, "chain": "solana"})
    t22 = [f for f in findings
           if f["key"].startswith("solana_token2022_")]
    assert [f["key"] for f in t22] == \
        ["solana_token2022_extension_audit"]
    assert "absent or benign" in t22[0]["value"]
    exts = [{"extension": "nonTransferable", "state": {}}]
    findings = sol.analyze_token2022_extensions(
        MINT, _mint_info(extensions=exts),
        {"address": MINT, "chain": "solana"})
    nt = _by_key(findings, "solana_token2022_non_transferable")[0]
    assert nt["severity"] == "high"  # soulbound trap, per the audit


def test_creator_wallet_dev_out_and_drained():
    dist = sol.aggregate_holders(
        [{"address": ACCT_A, "owner": AUTHORITY, "amount": 400_000},
         {"address": ACCT_B, "owner": POOL_WALLET,
          "amount": 100_000}], 1_000_000)
    findings = sol.analyze_creator_wallet(MINT, CREATOR, dist,
                                          1_000_000, 10_000)
    f0 = _by_key(findings, "solana_creator_wallet")[0]
    assert f0["severity"] == "low"
    assert "FULLY OUT" in f0["value"]  # said plainly
    assert "near zero" in f0["value"]  # drained-wallet note
    assert f0["evidence"]["creator_share"] == 0.0
    assert f0["evidence"]["creator_sol_note"] == "near-zero/drained"
    assert CREATOR in f0["value"]


def test_creator_wallet_dev_heavy_top_holder():
    accounts = [
        {"address": ACCT_A, "owner": CREATOR, "amount": 150_000},
        {"address": AUTHORITY, "owner": CREATOR, "amount": 100_000},
        {"address": ACCT_B, "owner": AUTHORITY, "amount": 50_000},
    ]
    dist = sol.aggregate_holders(accounts, 1_000_000)
    findings = sol.analyze_creator_wallet(
        MINT, CREATOR, dist, 1_000_000, 5_000_000_000)
    f0 = _by_key(findings, "solana_creator_wallet")[0]
    assert f0["severity"] == "high"  # 25% > 10% creator threshold
    assert f0["evidence"]["creator_share"] == 0.25
    assert f0["evidence"]["creator_rank"] == 1
    assert "#1 largest holder" in f0["value"]
    assert f0["evidence"]["creator_sol_balance"] == 5.0
    assert f0["evidence"]["creator_sol_note"] is None


def test_creator_wallet_unmeasured_inputs():
    findings = sol.analyze_creator_wallet(MINT, CREATOR, None,
                                          1_000_000, None)
    f0 = _by_key(findings, "solana_creator_wallet")[0]
    assert f0["severity"] == "low"
    assert "could not be measured" in f0["value"]
    assert "could not be read" in f0["value"]
    assert f0["evidence"]["creator_share"] is None


_NOW_S = 1_762_000_000.0  # fixed clock for pair-age tests


def _pair(**over):
    pair = {"pairAddress": ACCT_A, "dexId": "pumpswap",
            "liquidity": {"usd": 5000},
            "txns": {"h24": {"buys": 40, "sells": 12},
                     "h6": {"buys": 10, "sells": 3},
                     "h1": {"buys": 2, "sells": 1}},
            "priceChange": {"h24": 5.0, "h6": 2.0, "h1": 0.5},
            "pairCreatedAt": int((_NOW_S - 30 * 24 * 3600) * 1000)}
    pair.update(over)
    return pair


def test_dex_no_sells_flag():
    pair = _pair(txns={"h24": {"buys": 40, "sells": 0},
                       "h1": {"buys": 3, "sells": 0}})
    findings = sol.analyze_dex_pairs(MINT, [pair], now_s=_NOW_S)
    f0 = _by_key(findings, "solana_no_sells_recorded")[0]
    assert f0["severity"] == "high"
    assert f0["evidence"]["window"] == "h24"
    assert f0["evidence"]["buys"] == 40
    assert "40 buys" in f0["value"]
    # Sells happening -> no flag at all.
    findings = sol.analyze_dex_pairs(MINT, [_pair()], now_s=_NOW_S)
    assert "solana_no_sells_recorded" not in \
        {f["key"] for f in findings}
    # No txn data at all -> no conclusion drawn.
    bare = _pair()
    del bare["txns"]
    assert sol.analyze_dex_pairs(MINT, [bare], now_s=_NOW_S) == []


def test_dex_pair_freshness():
    fresh = _pair(pairCreatedAt=int((_NOW_S - 2 * 3600) * 1000))
    findings = sol.analyze_dex_pairs(MINT, [fresh], now_s=_NOW_S)
    f0 = _by_key(findings, "solana_pair_freshness")[0]
    assert f0["severity"] == "medium"  # under 24h old
    assert f0["evidence"]["pair_created_iso"].endswith("UTC")
    assert "2.0 hours" in f0["value"]
    aging = _pair(pairCreatedAt=int((_NOW_S - 3 * 24 * 3600) * 1000))
    f1 = sol.analyze_dex_pairs(MINT, [aging], now_s=_NOW_S)
    assert _by_key(f1, "solana_pair_freshness")[0]["severity"] == \
        "low"
    old = _pair()  # 30 days old in the fixture
    assert "solana_pair_freshness" not in \
        {f["key"] for f in sol.analyze_dex_pairs(MINT, [old],
                                                 now_s=_NOW_S)}


def test_dex_price_dump_and_pump():
    dump = _pair(priceChange={"h24": -95.0, "h6": -50.0})
    findings = sol.analyze_dex_pairs(MINT, [dump], now_s=_NOW_S)
    f0 = _by_key(findings, "solana_price_volatility")[0]
    assert f0["severity"] == "high"
    assert "-95" in f0["value"]
    assert f0["evidence"]["price_change_h24"] == -95.0
    moon = _pair(priceChange={"h24": 1500.0})
    f1 = sol.analyze_dex_pairs(MINT, [moon], now_s=_NOW_S)
    assert _by_key(f1, "solana_price_volatility")[0]["severity"] \
        == "medium"
    calm = _pair()
    assert "solana_price_volatility" not in \
        {f["key"] for f in sol.analyze_dex_pairs(MINT, [calm],
                                                 now_s=_NOW_S)}


def test_authority_map_single_wallet_concentration():
    info = _mint_info(extensions=[
        {"extension": "tokenMetadata",
         "state": {"updateAuthority": AUTHORITY, "name": "T",
                   "symbol": "T", "uri": "https://x",
                   "additionalMetadata": []}}])
    findings = sol.analyze_authority_map(MINT, info, None)
    f0 = _by_key(findings, "solana_authority_map")[0]
    # AUTHORITY holds mint + freeze + metadata = 3 powers.
    assert f0["severity"] == "medium"
    assert "CONCENTRATION" in f0["value"]
    assert f0["evidence"]["powers_by_wallet"][AUTHORITY] == [
        "mint authority", "freeze authority",
        "metadata update authority"]
    assert f0["evidence"]["metadata_authority_source"] == \
        "Token-2022 in-mint metadata"
    assert AUTHORITY in f0["value"]


def test_authority_map_revoked_and_metaplex_source():
    findings = sol.analyze_authority_map(MINT, _mint_info(None, None),
                                         None)
    f0 = _by_key(findings, "solana_authority_map")[0]
    assert f0["severity"] == "low"
    assert f0["value"].count("revoked / none") >= 4
    assert f0["evidence"]["mint_authority"] is None
    # Delegate + hook surface, and the Metaplex update authority is
    # used when the mint has no in-mint tokenMetadata extension.
    info = _mint_info(None, None, extensions=[
        {"extension": "permanentDelegate",
         "state": {"delegate": CREATOR}},
        {"extension": "transferHook",
         "state": {"authority": AUTHORITY, "programId": PROGRAM}}])
    metadata = {"update_authority": CREATOR, "address": ACCT_B}
    f1 = sol.analyze_authority_map(MINT, info, metadata)[0]
    assert f1["evidence"]["permanent_delegate"] == CREATOR
    assert f1["evidence"]["transfer_hook_program"] == PROGRAM
    assert f1["evidence"]["metadata_update_authority"] == CREATOR
    assert f1["evidence"]["metadata_authority_source"] == \
        "Metaplex metadata account"


def test_plugin_holder_distribution_replaces_largest(monkeypatch):
    entries = [
        _pa_entry(ACCT_B, POOL_WALLET, 400_000),
        _pa_entry(ACCT_A, CREATOR, 300_000),
        _pa_entry(AUTHORITY, AUTHORITY, 100_000),
    ]
    _patch_program_accounts(monkeypatch, entries)
    pair = {"pairAddress": ACCT_B, "dexId": "pumpswap",
            "liquidity": {"usd": 9000},
            "baseToken": {"symbol": "TEST"},
            "quoteToken": {"symbol": "SOL"}, "marketCap": 10000}
    _patch(monkeypatch,
           {MINT: _mint_value(None, None, supply="1000000",
                              decimals=0)},
           largest=None, pump=None, dex=[pair])
    p = sol.SolanaContractPlugin()
    target = Target(raw=MINT, type="solana_contract", normalized=MINT)
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    assert "solana_holder_distribution" in keys
    # The distribution REPLACES the largest-accounts concentration.
    assert "solana_holder_concentration" not in keys
    assert "solana_holder_distribution_unavailable" not in keys
    assert "solana_authority_map" in keys
    dist_f = [f for f in res.findings
              if f.key == "solana_holder_distribution"][0]
    assert dist_f.evidence["holder_count"] == 3
    # ACCT_B is labeled pool via the DexScreener pair address.
    assert dist_f.evidence["scored_on"] == "pool-excluded"
    assert dist_f.evidence["ex_pool_top1_share"] == 0.3


def test_plugin_distribution_unavailable_finding(monkeypatch):
    # Neither read answers: program accounts unstubbed (RPC seam
    # fails on the fake ctx) and largest-accounts returns None.
    _patch(monkeypatch, {MINT: _mint_value(None, None)}, largest=None,
           pump=None)
    p = sol.SolanaContractPlugin()
    target = Target(raw=MINT, type="solana_contract", normalized=MINT)
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    assert "solana_holder_distribution_unavailable" in keys
    assert "solana_holder_concentration" not in keys
    assert "solana_holder_distribution" not in keys


def test_plugin_creator_deep_dive_onchain(monkeypatch):
    curve_addr = sol.bonding_curve_address(MINT)
    _patch_base64(monkeypatch, {
        curve_addr: _b64_value(_curve_bytes(complete=False),
                               sol.PUMP_PROGRAM),
    })
    entries = [_pa_entry(ACCT_A, CREATOR, 200_000),
               _pa_entry(ACCT_B, AUTHORITY, 50_000)]
    _patch_program_accounts(monkeypatch, entries)
    _patch_balance(monkeypatch, 2_000_000)  # 0.002 SOL: drained
    _patch(monkeypatch,
           {MINT: _mint_value(None, None, supply="1000000",
                              decimals=0)},
           largest=None, pump=None)
    p = sol.SolanaContractPlugin()
    target = Target(raw=f"https://pump.fun/coin/{MINT}",
                    type="solana_contract",
                    normalized=f"https://pump.fun/coin/{MINT}")
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    assert "pump_bonding_curve_active" in keys
    # Creator share came from the FULL aggregation, not the
    # largest-accounts estimate.
    dev = [f for f in res.findings
           if f.key == "pump_creator_holdings"][0]
    assert dev.evidence["creator_share"] == 0.2
    assert dev.evidence["share_source"] == "holder_aggregation"
    dive = [f for f in res.findings
            if f.key == "solana_creator_wallet"][0]
    assert dive.evidence["creator_rank"] == 1
    assert dive.evidence["creator_sol_lamports"] == 2_000_000
    assert dive.evidence["creator_sol_note"] == "near-zero/drained"
    assert CREATOR in dive.value


def test_plugin_deep_extensions_and_dex_sellside(monkeypatch):
    exts = [{"extension": "permanentDelegate",
             "state": {"delegate": CREATOR}}]
    pair = {"pairAddress": ACCT_A, "dexId": "pumpswap",
            "liquidity": {"usd": 5000},
            "baseToken": {"symbol": "TEST"},
            "quoteToken": {"symbol": "SOL"}, "marketCap": 8000,
            "txns": {"h24": {"buys": 25, "sells": 0}},
            "pairCreatedAt": int(time.time() * 1000) - 3600_000,
            "priceChange": {"h24": 3.0}}
    _patch(monkeypatch,
           {MINT: _mint_value(extensions=exts)}, largest=[],
           pump=None, dex=[pair])
    p = sol.SolanaContractPlugin()
    target = Target(raw=MINT, type="solana_contract", normalized=MINT)
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = _keys(res)
    assert "solana_token2022_permanent_delegate" in keys
    assert "solana_token2022_extension_audit" in keys
    assert "solana_authority_map" in keys
    assert "solana_no_sells_recorded" in keys
    assert "solana_pair_freshness" in keys
    amap = [f for f in res.findings
            if f.key == "solana_authority_map"][0]
    assert amap.evidence["permanent_delegate"] == CREATOR
