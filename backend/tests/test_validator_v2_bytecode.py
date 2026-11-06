"""Validator V2 (lane L2): bytecode-only evidence path.

With no verified source, validate_candidate used to stop at
UNVERIFIED "no verified source available" for every candidate.
With candidate["bytecode_evidence"] the engine can now settle
the dead shapes and run the measured-proof flow on a coarse
bytecode recipient read - without ever overclaiming: a present
but unclassifiable selector keeps exactly ONE named missing
piece, the bytecode recipient blocker.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins import auto_validator as av  # noqa: E402

PROBE_OK = {"status": "success", "via": "test", "detail": ""}
PROBE_REVERT = {"status": "revert", "via": "test",
                "detail": "execution reverted"}
BAL = {"native_wei": 10 ** 18,
       "observed_at": "2026-11-06T00:00:00Z", "source": "test"}
SEL = "0x3ccfd60b"  # withdraw(uint256)


def _be(present, **kw):
    be = {"flagged_selector": SEL,
          "deployed_selectors": [SEL, "0xa9059cbb"],
          "selector_present": present,
          "minimal_proxy_impl": None}
    be.update(kw)
    return be


def _cand(**kw):
    c = {"address": "0x" + "1" * 40, "chain": "ethereum",
         "function": "withdraw", "kind": "unprotected_drain"}
    c.update(kw)
    return c


def test_selector_absent_is_false_positive():
    v = av.validate_candidate(_cand(
        bytecode_evidence=_be(False), probe=PROBE_REVERT))
    assert v["verdict"] == "FALSE_POSITIVE"
    assert "absent from" in v["reason"]
    assert "dead at live state" in v["reason"]
    # Probe status rides along in the evidence.
    assert v["evidence"]["probe"]["status"] == "revert"


def test_selector_present_unclassifiable_single_named_blocker():
    v = av.validate_candidate(_cand(
        bytecode_evidence=_be(True),
        bytecode_findings=[{
            "selector": SEL, "opcodes": ["PUSH1", "SLOAD"],
            "sensitive_opcodes": []}]))
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == [
        "recipient destination (bytecode-only contract, "
        "no verified source)"]


def test_selector_present_unclassifiable_reverting_probe_is_fp():
    v = av.validate_candidate(_cand(
        bytecode_evidence=_be(True), probe=PROBE_REVERT,
        bytecode_findings=[]))
    assert v["verdict"] == "FALSE_POSITIVE"


def test_selector_present_calldata_recipient_verifies():
    # Bytecode finding for the flagged selector: the walked
    # path CALLDATALOADs (target from caller arguments) and
    # CALLs with value - a coarse CALLER-SUPPLIED read. With a
    # successful stranger probe and a positive balance the
    # normal terminal flow verifies it.
    v = av.validate_candidate(_cand(
        bytecode_evidence=_be(True), probe=PROBE_OK, balances=BAL,
        bytecode_findings=[{
            "selector": SEL,
            "opcodes": ["CALLDATALOAD", "CALL", "STOP"],
            "sensitive_opcodes": ["CALL"]}]))
    assert v["recipient"] == "CALLER-SUPPLIED"
    assert v["verdict"] == "VERIFIED_REAL"


def test_selector_present_caller_recipient_no_probe_unverified():
    v = av.validate_candidate(_cand(
        bytecode_evidence=_be(True),
        bytecode_findings=[{
            "selector": SEL, "opcodes": ["CALLER", "CALL"],
            "sensitive_opcodes": ["CALL"]}]))
    assert v["recipient"] == "CALLER"
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == ["stranger probe or fork/local "
                            "simulation"]


def test_selector_present_calldata_recipient_zero_balance_is_fp():
    v = av.validate_candidate(_cand(
        bytecode_evidence=_be(True), probe=PROBE_OK,
        balances={"native_wei": 0, "token_self_wei": 0},
        bytecode_findings=[{
            "selector": SEL, "opcodes": ["CALLDATALOAD", "CALL"],
            "sensitive_opcodes": ["CALL"]}]))
    assert v["verdict"] == "FALSE_POSITIVE"


def test_no_bytecode_evidence_keeps_legacy_missing():
    v = av.validate_candidate(_cand())
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == ["verified source"]


def test_minimal_proxy_stays_unverified_with_impl_named():
    impl = "0x" + "2" * 40
    v = av.validate_candidate(_cand(bytecode_evidence={
        "flagged_selector": SEL, "deployed_selectors": [],
        "selector_present": None, "minimal_proxy_impl": impl}))
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == [
        "recipient destination (bytecode-only contract, "
        "no verified source)"]
    assert impl in v["reason"]


# ---------------------------------------------------------------------------
# gather_and_validate wiring: source fetch fails -> bytecode
# evidence is gathered from deployed code (all I/O stubbed).
# ---------------------------------------------------------------------------

def test_gather_populates_bytecode_evidence(monkeypatch):
    async def no_source(ctx, chain, addr, key):
        return None

    async def fake_code(ctx, chain, addr):
        return "0x6080604052"

    async def fake_balance(ctx, chain, addr):
        return dict(BAL)

    async def fake_self(ctx, chain, addr):
        return None

    async def fake_reserves(ctx, chain, addr):
        return None

    monkeypatch.setattr(av.cc, "fetch_verified_source", no_source)
    monkeypatch.setattr(av.cc, "rpc_get_code", fake_code)
    monkeypatch.setattr(av.bp, "analyze", lambda code: {
        "dispatcher_found": True, "minimal_proxy_impl": None,
        "selectors": [{"selector": "0xa9059cbb"}]})
    monkeypatch.setattr(av.cl, "analyze_logic_bytecode",
                        lambda code: [])
    monkeypatch.setattr(av, "_native_balance", fake_balance)
    monkeypatch.setattr(av, "_token_self_balance", fake_self)
    monkeypatch.setattr(av, "_pair_reserves", fake_reserves)

    cand = {"address": "0x" + "1" * 40, "chain": "ethereum",
            "function": "withdraw", "kind": "unprotected_drain"}
    v = asyncio.run(av.gather_and_validate(object(), None, cand))
    # withdraw(uint256) = 0x3ccfd60b is NOT among the deployed
    # selectors the stub reports -> dead at live state.
    assert cand["bytecode_evidence"]["flagged_selector"] == SEL
    assert cand["bytecode_evidence"]["selector_present"] is False
    assert v["verdict"] == "FALSE_POSITIVE"
