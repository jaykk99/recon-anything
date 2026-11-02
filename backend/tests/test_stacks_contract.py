"""Stacks (Clarity) Contract Recon (stacks_contract) tests.

Layers:
1. Classifier: Stacks contract ids (SP/SM/ST principals + name)
   route to stacks_contract - while Solana, BTC, ETH, domains and
   Android packages classify exactly as before.
2. Target parsing + Clarity value decoding (response-ok wrapping,
   uint, string-ascii, optional, principals).
3. Pure Clarity source analysis on fixture contracts: guarded
   mint with enforced cap (modeled on the real fari-token-mn),
   unguarded uncapped mint, fixed-supply no-mint token, data-var
   owner with public rotation, arbitrary-principal burn.
4. Plugin runs with the Hiro layer stubbed (no network): guarded
   end-to-end, not found, rate limited, clean skip.
5. Hiro 429 discipline: one backoff retry, then rate_limited -
   never a hammer loop.

All network is mocked at the module seam (stacks_contract's own
fetch_contract / fetch_token_state / fetch), mirroring how
test_solana_contract stubs the Solana chain layer. Evidence
values are asserted IN FULL (Jay's 2026-10-29 order).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.classifier import classify  # noqa: E402
from app.plugins import stacks_contract as stx  # noqa: E402
from app.plugins.base import PluginStatus, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

DEPLOYER = "SP213KNHB5QD308TEESY1ZMX1BP8EZDPG4JWD0MEA"
FARI = DEPLOYER + ".fari-token-mn"          # Jay's Nov 1 target
OTHER = "SP2JXKMSH007NPYAQHKJPQMAQYAD90NQGTVJVQ02B"
SOL_MINT = "GsnaqmpB9Xhxvh8hf1Z9HS1y76o9FPC8RaANGuc7ZpxT"

# Modeled on the real SP213...fari-token-mn (Bitfari): hardcoded
# single-principal tx-sender mint check, MAX_MINT cap enforced in
# the private execute-mint, top-level deploy mint of 20% of cap.
# Commented-out testnet lines must NOT leak into the analysis.
GUARDED_SRC = """
(impl-trait 'SP213KNHB5QD308TEESY1ZMX1BP8EZDPG4JWD0MEA.sip-010-trait.sip-010-trait)
(define-constant MAX_MINT u10000000000000000)
(define-constant DECIMAL_PLACES u8)
(define-fungible-token fari)
(define-read-only (get-balance (owner principal))
  (ok (ft-get-balance fari owner)))
(define-read-only (get-total-supply)
  (ok (ft-get-supply fari)))
(define-read-only (get-name)
  (ok "Fari"))
(define-read-only (get-symbol)
  (ok "FARI"))
(define-read-only (get-decimals)
  (ok DECIMAL_PLACES))
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (if (is-eq tx-sender sender)
      (begin (try! (ft-transfer? fari amount sender recipient)) (ok true))
      (err u1008)))
(define-private (execute-mint (amount uint) (account principal))
  (if (< MAX_MINT (+ (ft-get-supply fari) amount))
      (err u1004)
      (begin (try! (ft-mint? fari amount account)) (ok true))))
(define-private (validate-mint (amount uint) (account principal))
  (if (<= amount u0)
      (err u1000)
      (execute-mint amount account)))
(define-public (mint (amount uint) (account principal))
  (if
   ;; auth minter for testnet
   ;;(is-eq tx-sender 'ST3FYGS9F88Y5FW2DT2Q5C7FVX99Y9HREGCXH5T9D)
   ;; auth minter for mainnet
   (is-eq tx-sender 'SP213KNHB5QD308TEESY1ZMX1BP8EZDPG4JWD0MEA)
      (validate-mint amount account)
      (err u1002)))
;; testnet mint (commented out, must be ignored)
;;(mint u2000000000000000 'ST22CGGASNT176J764WXGD5ZKDK2ZEQ6XNRC660DX)
;; mainnet mint
(mint u2000000000000000 'SP213KNHB5QD308TEESY1ZMX1BP8EZDPG4JWD0MEA)
"""

UNGUARDED_SRC = """
(define-fungible-token bad)
(define-read-only (get-total-supply)
  (ok (ft-get-supply bad)))
(define-public (mint (amount uint) (who principal))
  (ft-mint? bad amount who))
"""

NO_MINT_SRC = """
(define-fungible-token fixed)
(define-constant TOTAL u1000)
(define-read-only (get-total-supply)
  (ok (ft-get-supply fixed)))
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (err u0))
(ft-mint? fixed u1000 'SP213KNHB5QD308TEESY1ZMX1BP8EZDPG4JWD0MEA)
"""

VAR_OWNER_SRC = """
(define-data-var owner principal tx-sender)
(define-fungible-token vtok)
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u1))
    (ok (var-set owner new-owner))))
(define-public (mint (amount uint) (who principal))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u2))
    (ft-mint? vtok amount who)))
"""

BURN_SRC = """
(define-fungible-token btok)
(define-public (burn-any (amount uint) (victim principal))
  (ft-burn? btok amount victim))
(define-public (burn-mine (amount uint))
  (ft-burn? btok amount tx-sender))
"""


def _by_key(findings, key):
    return [f for f in findings if f["key"] == key]


def _fkeys(findings):
    return {f.key for f in findings}


# ---------------------------------------------------------------------------
# 1. Classifier
# ---------------------------------------------------------------------------

def test_classify_stacks_forms():
    assert classify(FARI)["type"] == "stacks_contract"
    assert classify(DEPLOYER + ".my-token")["type"] == \
        "stacks_contract"
    assert classify("SM2JXKMSH007NPYAQHKJPQMAQYAD90NQGTVJVQ02B.pool-v1")[
        "type"] == "stacks_contract"
    assert classify("ST2JXKMSH007NPYAQHKJPQMAQYAD90NQGTVJVQ02B.test")[
        "type"] == "stacks_contract"


def test_classify_regressions_unchanged():
    assert classify(SOL_MINT)["type"] == "solana_contract"
    assert classify("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")[
        "type"] == "crypto_wallet"
    assert classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")["type"] == \
        "crypto_wallet"
    assert classify("example.com")["type"] == "domain"
    assert classify("com.whatsapp")["type"] == "play_store"
    assert classify("https://example.com/x")["type"] == "url"


def test_parse_stacks_target():
    assert stx.parse_stacks_target(FARI) == FARI
    assert stx.parse_stacks_target(f"stacks:{FARI}") == FARI
    assert stx.parse_stacks_target(
        f"https://explorer.hiro.so/address/{FARI}?chain=mainnet") \
        == FARI
    assert stx.parse_stacks_target("example.com") is None
    assert stx.parse_stacks_target(SOL_MINT) is None
    assert stx.parse_stacks_target(
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e") is None
    assert stx.parse_stacks_target("") is None
    # A bare principal with no contract name is not a contract id.
    assert stx.parse_stacks_target(DEPLOYER) is None


def test_registry():
    reg = discover()
    assert "stacks_contract" in reg
    p = reg["stacks_contract"]()
    assert p.group == "web3"
    assert p.requires_keys == []  # keyless Hiro API
    assert "stacks_contract" in p.accepts


# ---------------------------------------------------------------------------
# 2. Clarity value decoding
# ---------------------------------------------------------------------------

def test_decode_clarity_values():
    # response-ok wrapping a uint: 0x07 0x01 + 16-byte big-endian.
    payload = "0x0701" + (2000000000000000).to_bytes(16, "big").hex()
    assert stx.decode_clarity_hex(payload) == ("ok", 2000000000000000)
    # bare uint.
    payload = "0x01" + (42).to_bytes(16, "big").hex()
    assert stx.decode_clarity_hex(payload) == 42
    # signed int can go negative.
    payload = "0x00" + (-5).to_bytes(16, "big", signed=True).hex()
    assert stx.decode_clarity_hex(payload) == -5
    # response-ok wrapping a string-ascii.
    raw = "FARI".encode()
    payload = "0x070d" + len(raw).to_bytes(4, "big").hex() + raw.hex()
    assert stx.decode_clarity_hex(payload) == ("ok", "FARI")
    # optional some / none, bools, response-err.
    payload = "0x0a01" + (7).to_bytes(16, "big").hex()
    assert stx.decode_clarity_hex(payload) == 7
    assert stx.decode_clarity_hex("0x09") is None
    assert stx.decode_clarity_hex("0x03") is True
    payload = "0x0801" + (1002).to_bytes(16, "big").hex()
    assert stx.decode_clarity_hex(payload) == ("err", 1002)
    # garbage degrades to None, never raises.
    assert stx.decode_clarity_hex("0xzz") is None
    assert stx.decode_clarity_hex("") is None


# ---------------------------------------------------------------------------
# 3. Source analysis
# ---------------------------------------------------------------------------

def test_analyze_guarded_mint_with_enforced_cap():
    out = stx.analyze_clarity_source(
        FARI, GUARDED_SRC,
        live={"total_supply": 2500000000000000, "decimals": 8,
              "name": "Fari", "symbol": "FARI"})
    mint = _by_key(out, "stacks_mint_authority")
    assert len(mint) == 1
    assert mint[0]["severity"] == "high"
    # Authority principal shown IN FULL, and ONLY the real mainnet
    # one - the commented-out testnet principal must not leak in.
    assert mint[0]["evidence"]["mint_authority_principals"] == \
        [DEPLOYER]
    assert "ST3FYGS9F88Y5FW2DT2Q5C7FVX99Y9HREGCXH5T9D" not in \
        str(mint[0]["evidence"])
    assert mint[0]["evidence"]["rotatable"] is False
    cap = _by_key(out, "stacks_mint_cap")
    assert len(cap) == 1
    assert cap[0]["evidence"]["cap"] == 10000000000000000
    assert cap[0]["evidence"]["cap_enforced"] is True
    # Supply state: deploy mint 2e15 = 20% of cap; live 2.5e15 =
    # 25% of cap; 5e14 minted since deploy.
    supply = _by_key(out, "stacks_supply_state")
    assert len(supply) == 1
    ev = supply[0]["evidence"]
    assert ev["deploy_mint_amount"] == 2000000000000000
    assert ev["deploy_mint_recipient"] == DEPLOYER
    assert ev["deploy_mint_pct_of_cap"] == 20.0
    assert ev["total_supply"] == 2500000000000000
    assert ev["supply_pct_of_cap"] == 25.0
    assert ev["minted_since_deploy"] == 500000000000000
    # tx-sender pattern fires (mint + transfer both keyed on it).
    txs = _by_key(out, "stacks_tx_sender_auth")
    assert len(txs) == 1
    assert "mint" in txs[0]["evidence"]["functions"]
    # Authority map: no burn, no pause, no freeze.
    amap = _by_key(out, "stacks_authority_map")
    assert len(amap) == 1
    assert "no burn function" in amap[0]["value"]
    assert "freeze/blacklist: none" in amap[0]["value"]


def test_analyze_unguarded_uncapped_mint():
    out = stx.analyze_clarity_source(OTHER + ".bad", UNGUARDED_SRC)
    mint = _by_key(out, "stacks_mint_authority")
    assert len(mint) == 1
    assert mint[0]["severity"] == "critical"
    assert "UNGUARDED MINT" in mint[0]["value"]
    cap = _by_key(out, "stacks_mint_cap")
    assert len(cap) == 1
    assert cap[0]["severity"] == "high"
    assert cap[0]["evidence"]["cap"] is None


def test_analyze_no_mint_fixed_supply():
    out = stx.analyze_clarity_source(FARI, NO_MINT_SRC)
    assert _by_key(out, "stacks_mint_authority") == []
    assert _by_key(out, "stacks_mint_cap") == []
    amap = _by_key(out, "stacks_authority_map")
    assert len(amap) == 1
    assert "NO mint function" in amap[0]["value"]
    assert amap[0]["evidence"]["has_mint"] is False


def test_analyze_var_owner_with_rotation():
    out = stx.analyze_clarity_source(OTHER + ".vtok", VAR_OWNER_SRC)
    mint = _by_key(out, "stacks_mint_authority")
    assert len(mint) == 1
    assert mint[0]["severity"] == "high"
    assert mint[0]["evidence"]["mint_authority_var"] == "owner"
    assert mint[0]["evidence"]["rotatable"] is True
    rot = _by_key(out, "stacks_owner_rotation")
    assert len(rot) == 1
    assert rot[0]["evidence"]["setter_functions"] == ["set-owner"]


def test_analyze_arbitrary_burn():
    out = stx.analyze_clarity_source(OTHER + ".btok", BURN_SRC)
    burn = _by_key(out, "stacks_burn_authority")
    assert len(burn) == 1
    assert burn[0]["severity"] == "high"
    assert burn[0]["evidence"]["burn_function"] == "burn-any"
    amap = _by_key(out, "stacks_authority_map")
    assert "arbitrary holders" in amap[0]["value"]


def test_source_getter_fallback():
    cs = stx.ClaritySource(GUARDED_SRC)
    vals = stx.source_getter_values(cs)
    assert vals == {"name": "Fari", "symbol": "FARI", "decimals": 8}


# ---------------------------------------------------------------------------
# 4. Plugin runs (Hiro layer stubbed)
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
        bucket = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in bucket:
                bucket.append(item)
        else:
            bucket.append(item)


def _patch(monkeypatch, status="ok", data=None, live=None):
    async def fake_fetch_contract(ctx, base, contract_id):
        return status, data

    async def fake_state(ctx, base, contract_id, getter_names):
        return dict(live or {})

    monkeypatch.setattr(stx, "fetch_contract", fake_fetch_contract)
    monkeypatch.setattr(stx, "fetch_token_state", fake_state)


def test_plugin_guarded_end_to_end(monkeypatch):
    data = {"source_code": GUARDED_SRC, "clarity_version": 1,
            "block_height": 26442, "tx_id": "0xabc123",
            "abi": "{\"functions\": []}"}
    _patch(monkeypatch, data=data,
           live={"total_supply": 2500000000000000, "decimals": 8,
                 "name": "Fari", "symbol": "FARI"})
    p = stx.StacksContractPlugin()
    res = asyncio.run(p.run(Target(raw=FARI, type="stacks_contract"),
                            FakeCtx()))
    assert res.status == PluginStatus.OK
    keys = _fkeys(res.findings)
    assert "stacks_contract_identity" in keys
    assert "stacks_mint_authority" in keys
    assert "stacks_mint_cap" in keys
    assert "stacks_authority_map" in keys
    assert "stacks_supply_state" in keys
    ident = [f for f in res.findings
             if f.key == "stacks_contract_identity"][0]
    assert ident.evidence["token_name"] == "Fari"
    assert ident.evidence["sip_010"] is True
    assert ident.evidence["deployer"] == DEPLOYER


def test_plugin_contract_not_found(monkeypatch):
    _patch(monkeypatch, status="not_found", data=None)
    p = stx.StacksContractPlugin()
    res = asyncio.run(p.run(Target(raw=FARI, type="stacks_contract"),
                            FakeCtx()))
    assert res.status == PluginStatus.OK
    assert _fkeys(res.findings) == {"stacks_contract_not_found"}


def test_plugin_rate_limited(monkeypatch):
    _patch(monkeypatch, status="rate_limited", data=None)
    p = stx.StacksContractPlugin()
    res = asyncio.run(p.run(Target(raw=FARI, type="stacks_contract"),
                            FakeCtx()))
    assert _fkeys(res.findings) == {"stacks_recon_rate_limited"}


def test_plugin_unreachable(monkeypatch):
    _patch(monkeypatch, status="unreachable", data=None)
    p = stx.StacksContractPlugin()
    res = asyncio.run(p.run(Target(raw=FARI, type="stacks_contract"),
                            FakeCtx()))
    assert _fkeys(res.findings) == {"stacks_recon_failed"}


def test_plugin_skips_cleanly_without_stacks_target():
    p = stx.StacksContractPlugin()
    target = Target(raw="example.com", type="domain")
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK
    assert res.findings == []


# ---------------------------------------------------------------------------
# 5. Hiro 429 discipline
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_hiro_429_backoff_then_ok(monkeypatch):
    calls = []

    async def fake_fetch(client, limiter, method, url, **kw):
        calls.append(url)
        if len(calls) == 1:
            return _Resp(429)
        return _Resp(200, {"source_code": "(define-fungible-token x)"})

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(stx, "fetch", fake_fetch)
    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    status, data = asyncio.run(
        stx.fetch_contract(FakeCtx(), stx.HIRO_MAINNET, FARI))
    assert status == "ok"
    assert data["source_code"].startswith("(define-fungible-token")
    assert len(calls) == 2  # exactly one retry


def test_hiro_429_twice_reports_rate_limited(monkeypatch):
    calls = []

    async def fake_fetch(client, limiter, method, url, **kw):
        calls.append(url)
        return _Resp(429)

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(stx, "fetch", fake_fetch)
    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    status, data = asyncio.run(
        stx.fetch_contract(FakeCtx(), stx.HIRO_MAINNET, FARI))
    assert status == "rate_limited"
    assert data is None
    assert len(calls) == 2  # backed off once, never hammered
