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
import os
import sys

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
