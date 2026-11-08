"""Validator V2 regression fixtures: the two live false
positives that motivated the measured-receipt invariant.

Both were stamped VERIFIED_REAL by validator v1 / the first
v2 cut and corrected by hand (see
recon-million-2026-11-06/results/corrections.jsonl):

- aeWETH (Arbitrum 0x8b194beae1d3e0788a1a35173978001acdfba668,
  withdrawTo): burn-funded. The function burns the caller's
  own aeWETH and returns the same amount of ETH; a stranger
  receives 0. The old engine verified it on a zero-amount
  probe plus a positive contract native balance.
- MVK / MetaVerseKombat (BSC
  0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0, claimReward):
  caller-metered. The payout is the caller's pro-rata share
  (balanceOf(caller) * pool / totalSupply) and the function
  does not revert for a zero-balance stranger - it pays them
  exactly 0.

The fixture sources below reproduce the flagged functions
VERBATIM from the verified sources (aeWETH: the complete
deployed contract block from the Sourcify bundle; MVK: the
complete claimReward function plus the state declarations it
reads, Sourcify exact match fetched 2026-11-08). When the
staged full sources are present on this machine
(~/workspace/recon-v2-run-2026-11-08/src_cache/), the same
assertions also run against the complete verified sources.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins.auto_validator import validate_candidate  # noqa: E402

AEWETH_SRC = """
contract aeWETH is L2GatewayToken, IWETH9 {
    function initialize(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        address _l2Gateway,
        address _l1Address
    ) external {
        L2GatewayToken._initialize(_name, _symbol, _decimals, _l2Gateway, _l1Address);
    }

    function bridgeMint(address account, uint256 amount) external virtual override {
        // we want weth to always be fully collaterized
        revert("NO_BRIDGE_MINT");
    }

    function bridgeBurn(address account, uint256 amount) external virtual override onlyGateway {
        _burn(account, amount);
        (bool success, ) = msg.sender.call{ value: amount }("");
        require(success, "FAIL_TRANSFER");
    }

    function deposit() external payable override {
        depositTo(msg.sender);
    }

    function withdraw(uint256 amount) external override {
        withdrawTo(msg.sender, amount);
    }

    function depositTo(address account) public payable {
        _mint(account, msg.value);
    }

    function withdrawTo(address account, uint256 amount) public {
        _burn(msg.sender, amount);
        (bool success, ) = account.call{ value: amount }("");
        require(success, "FAIL_TRANSFER");
    }

    receive() external payable {
        depositTo(msg.sender);
    }
}
"""

MVK_SRC = """
contract MetaVerseKombat {
    using SafeMath for uint256;
    uint256 private _tTotal;
    mapping(address => uint256) private _rOwned;
    mapping (address => uint256) public UserrewardPoolOnLastClaim;
    uint256 public _rewardPool;
    uint256 public _claimedRewardPool;
    mapping(address => bool) private exist;

    function totalSupply() public view returns (uint256) {
        return _tTotal;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _rOwned[account];
    }

    function claimReward() public {
        uint256 rewardPool=UserrewardPoolOnLastClaim[msg.sender];
        uint256 remainPool=_rewardPool-rewardPool;
        if(remainPool>0 && balanceOf(msg.sender)>0 && exist[msg.sender]){
            uint256 userShare = (balanceOf(msg.sender).mul(remainPool)).div(totalSupply());
            payable(msg.sender).transfer(userShare);
            _claimedRewardPool+=userShare;
        }
        UserrewardPoolOnLastClaim[msg.sender]=_rewardPool;
    }
}
"""

AEWETH_NATIVE_WEI = 31401841031371963  # ~0.031 ETH, live fact
MVK_NATIVE_WEI = 84400000000000000     # 0.0844 BNB, live fact

_SRC_CACHE = os.path.expanduser(
    "~/workspace/recon-v2-run-2026-11-08/src_cache")


def _aeweth(source, token_self):
    return validate_candidate({
        "address": "0x8b194beae1d3e0788a1a35173978001acdfba668",
        "chain": "arbitrum",
        "function": "withdrawTo",
        "kind": "recipient_bridge_release_unproven",
        "source": source,
        "contract_name": "aeWETH",
        "probe": {"status": "success", "detail": "0x",
                  "via": "regression fixture (live fact)"},
        "balances": {"native_wei": AEWETH_NATIVE_WEI,
                     "token_self_wei": token_self}})


def _mvk(source, balances):
    return validate_candidate({
        "address": "0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0",
        "chain": "bsc",
        "function": "claimReward",
        "kind": "holder_reward_claim",
        "source": source,
        "contract_name": "MetaVerseKombat",
        "probe": {"status": "success", "detail": "0x",
                  "via": "regression fixture (live fact)"},
        "balances": balances})


def test_aeweth_withdrawto_is_false_positive():
    # Every value of the contract's own-token balance: the
    # burn shape settles it before balances are consulted.
    for token_self in (0, None, 10 ** 18):
        v = _aeweth(AEWETH_SRC, token_self)
        assert v["verdict"] == "FALSE_POSITIVE", v
        assert "self-funded" in v["reason"]


def test_mvk_claimreward_zero_basis_is_false_positive():
    v = _mvk(MVK_SRC, {"native_wei": MVK_NATIVE_WEI,
                       "stranger_token_self_wei": 0})
    assert v["verdict"] == "FALSE_POSITIVE", v
    assert v["evidence"].get("caller_metered", {}).get(
        "basis") == "token_self"
    assert "measured" in v["reason"]


def test_mvk_claimreward_unmeasured_basis_stays_unverified():
    # The metering shape alone must NOT mint a false positive:
    # without the lane actually measuring the stranger's basis
    # at 0, the receipt is unmeasured, not proven zero.
    v = _mvk(MVK_SRC, {"native_wei": MVK_NATIVE_WEI})
    assert v["verdict"] == "UNVERIFIED", v
    v = _mvk(MVK_SRC, {"native_wei": MVK_NATIVE_WEI,
                       "stranger_token_self_wei": 10 ** 18})
    assert v["verdict"] == "UNVERIFIED", v


def _load_staged(chain_addr):
    path = os.path.join(_SRC_CACHE, chain_addr + ".json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


@pytest.mark.skipif(
    _load_staged(
        "arbitrum_0x8b194beae1d3e0788a1a35173978001acdfba668")
    is None,
    reason="staged full aeWETH source not present on this box")
def test_aeweth_full_verified_source_is_false_positive():
    doc = _load_staged(
        "arbitrum_0x8b194beae1d3e0788a1a35173978001acdfba668")
    for token_self in (0, None, 10 ** 18):
        v = _aeweth(doc["source"], token_self)
        assert v["verdict"] == "FALSE_POSITIVE", v


@pytest.mark.skipif(
    _load_staged("bsc_0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0")
    is None,
    reason="staged full MVK source not present on this box")
def test_mvk_full_verified_source_is_false_positive():
    doc = _load_staged(
        "bsc_0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0")
    v = _mvk(doc["source"], {"native_wei": MVK_NATIVE_WEI,
                             "stranger_token_self_wei": 0})
    assert v["verdict"] == "FALSE_POSITIVE", v


# ---------------------------------------------------------------------------
# The measured-receipt invariant, both directions
# ---------------------------------------------------------------------------

OVERDRAW_SRC = """
contract VulnVault {
    function withdraw(uint256 amount) public {
        require(address(this).balance >= amount, "insolvent");
        payable(msg.sender).transfer(amount);
    }
}
"""


def _overdraw(**kw):
    cand = {
        "address": "0xabc", "chain": "ethereum",
        "function": "withdraw", "kind": "recipient_overdraw_withdraw",
        "source": OVERDRAW_SRC, "contract_name": "VulnVault",
        "probe": {"status": "success", "via": "test", "detail": ""},
        "balances": {"native_wei": 10 ** 18,
                     "stranger_native_wei": 0,
                     "stranger_token_self_wei": 0}}
    cand.update(kw)
    return validate_candidate(cand)


def test_decisive_probe_measures_receipt_and_verifies():
    v = _overdraw(decisive_probe={
        "status": "success", "amount": 1, "slot": 0,
        "via": "test"})
    assert v["verdict"] == "VERIFIED_REAL", v
    assert "decisive" in v["reason"]


def test_balance_bound_alone_no_longer_verifies():
    # The exact aeWETH-era evidence shape - boundary probe
    # success + positive contract balance, no measurement -
    # must park at UNVERIFIED, never VERIFIED_REAL.
    v = _overdraw()
    assert v["verdict"] == "UNVERIFIED", v
    assert "measured receipt" in " ".join(v["missing"])


def test_decisive_probe_revert_leaves_unverified():
    v = _overdraw(decisive_probe={
        "status": "revert", "amount": 1, "slot": 0,
        "via": "test"})
    assert v["verdict"] == "UNVERIFIED", v


def test_decisive_amount_must_exceed_stranger_funding():
    # A "decisive" record whose amount the stranger could
    # self-fund is not a measurement: the engine re-checks it
    # against the recorded stranger funding.
    v = _overdraw(
        balances={"native_wei": 10 ** 18,
                  "stranger_native_wei": 10 ** 18,
                  "stranger_token_self_wei": 0},
        decisive_probe={"status": "success", "amount": 1,
                        "slot": 0, "via": "test"})
    assert v["verdict"] == "UNVERIFIED", v
