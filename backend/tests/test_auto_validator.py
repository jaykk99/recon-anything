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


SIBLING_SRC = """
contract Target {
    function ping() public {}
}
contract DepositHandler {
    function destroy(address etherDestination) external {
        selfdestruct(payable(etherDestination));
    }
}
"""


def test_out_of_scope_function_reverting_probe_is_fp():
    # axlUSDC shape: destroy() lives in a bundled sibling
    # contract, not in the deployed target; the live probe
    # reverts, so the flagged path is dead at live state.
    v = av.validate_candidate({
        "address": "0xeb466342c4d449bc9f53a865d5cb90586f405215",
        "chain": "base", "function": "destroy",
        "kind": "unprotected_drain", "source": SIBLING_SRC,
        "contract_name": "Target", "function_out_of_scope": True,
        "probe": STRANGER_PROBE_REVERT, "balances": BAL0})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert "sibling" in v["reason"]


def test_out_of_scope_function_without_probe_stays_unverified():
    v = av.validate_candidate({
        "function": "destroy", "kind": "unprotected_drain",
        "source": SIBLING_SRC, "contract_name": "Target",
        "function_out_of_scope": True, "balances": BAL0})
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == ["flagged function in deployed "
                            "contract scope"]


UNRESOLVED_GATED_SRC = """
contract GatedMystery {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    function sweep() public onlyOwner {
        _settle();
    }
    function _settle() internal {
        _accounting += 1;
    }
    uint256 private _accounting;
}
"""


def test_unresolved_recipient_but_gated_and_reverting_is_fp():
    v = av.validate_candidate({
        "function": "sweep", "kind": "access_control_flaw",
        "source": UNRESOLVED_GATED_SRC,
        "probe": STRANGER_PROBE_REVERT, "balances": BAL0})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert v["recipient"] == "UNRESOLVED"
    assert "gate" in v["reason"]


def test_unresolved_recipient_without_kill_evidence_stays_unverified():
    v = av.validate_candidate({
        "function": "sweep", "kind": "access_control_flaw",
        "source": UNRESOLVED_GATED_SRC, "balances": BAL0})
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == ["recipient destination"]


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


HELPER_FLOW_SRC = """
contract HelperFlow {
    function withdraw(uint256 amount) public {
        _payout(msg.sender, amount);
    }
    function _payout(address to, uint256 amt) internal {
        payable(to).transfer(amt);
    }
}
"""


def test_value_flow_through_internal_helper_is_classified():
    # The payout lives one hop down the internal call path.
    # Classifying the entry body alone found no destination
    # (the continuous-scanner stall); the value-flow expansion
    # must resolve it to the caller.
    v = av.validate_candidate({
        "function": "withdraw", "kind": "unprotected_drain",
        "source": HELPER_FLOW_SRC, "probe": STRANGER_PROBE_OK,
        "balances": BAL})
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["recipient"] == "CALLER"
    assert v["evidence"].get("value_flow_helpers") == ["_payout"]


def test_token_mint_payout_not_killed_by_zero_native_balance():
    # A mint payout is denominated in the token, not in wei:
    # 0 native balance must not false-positive it.
    v = av.validate_candidate({
        "function": "mint", "kind": "unprotected_mint",
        "source": fx.VULN["recipient_mint_to_caller"],
        "probe": STRANGER_PROBE_OK, "balances": BAL0})
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["evidence"].get("payout_denomination") == "token"
    # The value statement must be the issuance, never a
    # self-contradictory "0 wei upper bound".
    assert "issuance" in v["value"]


ERC4626_SRC = """
contract Vault {
    TokenLike asset;
    mapping(address => uint256) public balanceOf;
    function mint(uint256 shares, address receiver) external
        returns (uint256) {
        uint256 assets = shares;
        _deposit(msg.sender, receiver, assets, shares);
        return assets;
    }
    function _deposit(address caller, address receiver,
                      uint256 assets, uint256 shares) internal {
        SafeERC20.safeTransferFrom(asset, caller,
                                   address(this), assets);
        _mint(receiver, shares);
    }
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }
}
"""


def test_erc4626_self_funded_mint_is_not_verified_real():
    # Found live in the backlog re-run (ParifiVault, Arbitrum):
    # an ERC4626 mint whose probe succeeds with a zero amount.
    # The vault pulls the underlying from the caller before
    # minting - a deposit, not a drain.
    v = av.validate_candidate({
        "function": "mint", "kind": "access_control_flaw",
        "source": ERC4626_SRC, "probe": STRANGER_PROBE_OK,
        "balances": BAL0})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert "self-funded" in v["reason"]


WETH_SRC = """
contract WrappedNative {
    mapping(address => uint256) public balanceOf;
    function deposit() public payable {
        _mint(msg.sender, msg.value);
    }
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }
}
"""


def test_weth_style_deposit_is_self_funded():
    v = av.validate_candidate({
        "function": "deposit", "kind": "access_control_flaw",
        "source": WETH_SRC, "probe": STRANGER_PROBE_OK,
        "balances": BAL})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert "self-funded" in v["reason"]


TOKEN_CLAIM_SRC = """
contract TokenClaim {
    TokenLike tok;
    function claim() public {
        tok.transfer(msg.sender, 5);
    }
}
"""


def test_token_payout_with_zero_token_balance_is_fp():
    bal = dict(BAL0)
    bal["token_self_wei"] = 0
    v = av.validate_candidate({
        "function": "claim", "kind": "recipient_unbacked_claim",
        "source": TOKEN_CLAIM_SRC, "probe": STRANGER_PROBE_OK,
        "balances": bal})
    assert v["verdict"] == "FALSE_POSITIVE"
    assert "0 of its own token" in v["reason"]


def test_balances_and_reserves_ride_along_in_evidence():
    bal = dict(BAL)
    bal["token_self_wei"] = 12345
    bal["amm_reserves"] = {"reserve0": 100, "reserve1": 200,
                           "observed_at": "2026-11-04T00:00:00Z",
                           "source": "test"}
    v = av.validate_candidate({
        "function": "withdraw",
        "kind": "recipient_overdraw_withdraw",
        "source": fx.VULN["recipient_overdraw_withdraw"],
        "probe": STRANGER_PROBE_OK, "balances": bal})
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["evidence"]["balances"]["amm_reserves"]["reserve0"] \
        == 100
    assert v["evidence"]["probe"]["status"] == "success"


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
