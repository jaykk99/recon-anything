"""Auto-validator: the proof-set shapes, as pure engine tests.

Each case mirrors a hand-adjudicated verdict from the Nov 2/3
work: the 11 trigger-only contracts (FIXED recipients), axlUSDC
(FALSE_POSITIVE at live state), FARI (TOKEN_RISK trigger class),
Part A vulnerable fixtures (VERIFIED_REAL via local simulation /
stranger probe), and clean twins (FALSE_POSITIVE when gated with
no contrary probe, or no verdict at all from the detectors).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import recipient_first_fixtures as fx  # noqa: E402
from app.plugins import auto_validator as av  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

STRANGER_PROBE_OK = {"status": "success", "via": "test",
                     "detail": ""}
STRANGER_PROBE_REVERT = {"status": "revert", "via": "test",
                         "detail": "execution reverted"}
BAL = {"native_wei": 10**18, "observed_at": "2026-11-03T00:00:00Z",
       "source": "test"}
BAL0 = {"native_wei": 0, "observed_at": "2026-11-03T00:00:00Z",
        "source": "test"}

AXL_SRC = """
contract BurnableMintableCappedERC20 {
    function destroy(address etherDestination) external {
        selfdestruct(payable(etherDestination));
    }
}
"""


def test_no_source_is_unverified_with_missing_named():
    v = av.validate_candidate({"address": "0xabc", "kind": "drain"})
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == ["verified source"]


def test_fixed_recipient_probe_success_is_trigger_only():
    # The Nov 2 shape, 11 times over: ungated, probe succeeds,
    # destination is a hardcoded project wallet.
    v = av.validate_candidate({
        "address": "0x6cdd08de79231a1957f205a3fe5cf9dbf4b0c454",
        "chain": "bsc", "function": "withdrawStuckBNB",
        "kind": "unprotected_drain",
        "source": fx.TRIGGER_ONLY["recipient_rescue_to_param"],
        "probe": STRANGER_PROBE_OK, "balances": BAL})
    assert v["verdict"] == "TRIGGER_ONLY"
    assert v["recipient"] == "FIXED"


def test_holder_self_is_trigger_only():
    v = av.validate_candidate({
        "function": "withdraw", "kind": "unprotected_drain",
        "source": fx.TRIGGER_ONLY["recipient_overdraw_withdraw"],
        "probe": STRANGER_PROBE_OK, "balances": BAL})
    assert v["verdict"] == "TRIGGER_ONLY"
    assert v["recipient"] == "HOLDER-SELF"


FLY_SRC = """
contract BEP20FlyToken {
    mapping(address => bytes32[]) lockReason;
    mapping(address => mapping(bytes32 => Lock)) locked;
    function tokensUnlockable(address _of, bytes32 r)
        internal view returns (uint256) { return 0; }
    function unlock(address _of) public
        returns (uint256 unlockableTokens) {
        uint256 lockedTokens;
        for (uint256 i = 0; i < lockReason[_of].length; i++) {
            lockedTokens = tokensUnlockable(
                _of, lockReason[_of][i]);
            if (lockedTokens > 0) {
                unlockableTokens += lockedTokens;
                locked[_of][lockReason[_of][i]].claimed = true;
            }
        }
        if (unlockableTokens > 0)
            this.transfer(_of, unlockableTokens);
    }
}
"""


def test_fly_unlock_shape_is_holder_self_trigger_only():
    # FLY (Nov 2 adjudication): unlock(holder) pays the holder
    # only their own locked balance, metered by locked[holder]
    # and consumed via the nested .claimed flag - HOLDER-SELF,
    # never a stranger-receivable candidate.
    v = av.validate_candidate({
        "address": "0x681fd3e49a6188fc526784ee70aa1c269ee2b887",
        "chain": "bsc", "function": "unlock",
        "kind": "unprotected_drain", "source": FLY_SRC})
    assert v["verdict"] == "TRIGGER_ONLY"
    assert v["recipient"] == "HOLDER-SELF"
    assert v["evidence"].get("beneficiary_metered") == "locked"


def test_axlusdc_shape_is_false_positive_on_revert():
    v = av.validate_candidate({
        "address": "0xeb466342c4d449bc9f53a865d5cb90586f405215",
        "chain": "base", "function": "destroy",
        "kind": "unprotected_drain", "source": AXL_SRC,
        "probe": STRANGER_PROBE_REVERT, "balances": BAL0})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert v["recipient"] == "CALLER-SUPPLIED"
    assert "revert" in v["reason"]


def test_caller_supplied_probe_success_zero_balance_is_fp():
    v = av.validate_candidate({
        "function": "destroy", "kind": "unprotected_drain",
        "source": AXL_SRC, "probe": STRANGER_PROBE_OK,
        "balances": BAL0})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert "0 native balance" in v["reason"]


def test_gated_function_no_probe_is_false_positive():
    v = av.validate_candidate({
        "function": "mint", "kind": "unprotected_mint",
        "source": fx.CLEAN["recipient_mint_to_caller"]})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert v["gated"] is True


def test_fari_authority_class_is_token_risk_trigger():
    v = av.validate_candidate({
        "address": "SP213K1STH8PA9W9K7EJWB8FQFTQFAF2TQH5KWD0MEA.fari",
        "chain": "stacks", "function": "mint",
        "kind": "centralized_mint_authority",
        "authority_class": True, "recipient_override": "FIXED"})
    assert v["verdict"] == "TRIGGER_ONLY"
    assert v["subclass"] == "TOKEN_RISK"


def test_vuln_fixture_verified_real_via_simulation():
    v = av.validate_candidate({
        "function": "claim", "kind": "recipient_unbacked_claim",
        "source": fx.VULN["recipient_unbacked_claim"],
        "simulation": {"ran": True, "stranger_received": 1.0,
                       "unit": "ETH",
                       "detail": "local anvil: stranger claimed "
                                 "twice, received 2 x 1 ETH"}})
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["value"] == "1.0 ETH"


def test_vuln_fixture_verified_real_via_probe():
    v = av.validate_candidate({
        "function": "withdraw",
        "kind": "recipient_overdraw_withdraw",
        "source": fx.VULN["recipient_overdraw_withdraw"],
        "probe": STRANGER_PROBE_OK, "balances": BAL})
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["recipient"] == "CALLER"


def test_simulation_zero_received_is_false_positive():
    v = av.validate_candidate({
        "function": "claim", "kind": "recipient_unbacked_claim",
        "source": fx.VULN["recipient_unbacked_claim"],
        "simulation": {"ran": True, "stranger_received": 0,
                       "unit": "ETH", "detail": "no payout"}})
    assert v["verdict"] == "FALSE_POSITIVE"


def test_candidate_without_probe_or_sim_is_unverified():
    v = av.validate_candidate({
        "function": "claim", "kind": "recipient_unbacked_claim",
        "source": fx.VULN["recipient_unbacked_claim"],
        "balances": BAL})
    assert v["verdict"] == "UNVERIFIED"
    assert "simulation" in " ".join(v["missing"])


def test_entitlement_metered_probe_success_stays_unverified():
    v = av.validate_candidate({
        "function": "withdraw",
        "kind": "recipient_overdraw_withdraw",
        "source": fx.VULN["recipient_overdraw_withdraw"],
        "probe": STRANGER_PROBE_OK, "balances": BAL,
        "entitlement_metered": True})
    assert v["verdict"] == "UNVERIFIED"


# ---------------------------------------------------------------------------
# Plugin wrapper plumbing
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


def test_validator_plugin_no_candidates_skips():
    plugin = discover()["auto_validator"]()
    res = asyncio.run(plugin.run(
        Target(raw="ethereum:0x1111111111111111111111111111111111111111",
               type="crypto_wallet"), FakeCtx()))
    assert res.findings == []


def test_validator_plugin_emits_verdicts(monkeypatch):
    async def fake_gather(ctx, key, cand):
        return {"verdict": "TRIGGER_ONLY", "reason": "fixed dest",
                "address": cand["address"], "function": "rescueBNB",
                "kind": cand.get("kind", "")}

    monkeypatch.setattr(av, "gather_and_validate", fake_gather)
    plugin = discover()["auto_validator"]()
    ctx = FakeCtx({"validator_candidates": [
        {"address": "0x6cdd08de79231a1957f205a3fe5cf9dbf4b0c454",
         "chain": "bsc", "function": "rescueBNB",
         "kind": "unprotected_drain"}]})
    res = asyncio.run(plugin.run(
        Target(raw="bsc:0x6cdd08de79231a1957f205a3fe5cf9dbf4b0c454",
               type="crypto_wallet"), ctx))
    hits = [f for f in res.findings if f.key == "validator_verdict"]
    assert len(hits) == 1
    assert hits[0].evidence["verdict"]["verdict"] == "TRIGGER_ONLY"
