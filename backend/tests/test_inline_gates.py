"""Inline static validation gates: the aeWETH / MVK shapes
settled statically, before any live probe is spent.

The gates (app.plugins.inline_gates) reuse validator v2's own
detectors (_self_funded / _caller_metered) over the same
scoping and recipient classification v2 uses. These tests pin:

- aeWETH withdrawTo (burn-funded) -> GATED_SELF_FUNDED, on the
  verbatim fixture source AND the full staged verified source;
- MVK claimReward (caller-metered) -> GATED_CALLER_METERED,
  same two source forms;
- the Base survivor (BurnableMintableCappedERC20, ungated
  execute) must NOT gate - a genuine candidate shape passes
  through to v2 untouched;
- clean-vault and plain overdraw shapes must NOT gate;
- the hard limits: measured-receipt evidence, access gates,
  non-stranger recipients, missing functions and missing
  source all force PASS, and the caller-metered fast-path row
  cannot be written without a measured-zero stranger basis.

Fixture sources AEWETH_SRC / MVK_SRC / OVERDRAW_SRC are the
verbatim fixtures of tests/test_validator_v2_regressions.py.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins.auto_validator import validate_candidate  # noqa: E402
from app.plugins.inline_gates import (  # noqa: E402
    GATE_CALLER_METERED, GATE_PASS, GATE_SELF_FUNDED,
    gate_candidate, gate_verdict)

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

OVERDRAW_SRC = """
contract VulnVault {
    function withdraw(uint256 amount) public {
        require(address(this).balance >= amount, "insolvent");
        payable(msg.sender).transfer(amount);
    }
}
"""

# Shape fixture for the Base survivor candidate
# (0xeb466342c4d449bc9f53a865d5cb90586f405215): an ungated
# execute() that forwards an arbitrary call. The fuzz lane ran
# the real contract and it was clean; the gate must not touch
# it either way - no caller-funded payout, no caller metering.
SURVIVOR_SRC = """
contract BurnableMintableCappedERC20 {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;
    uint256 public cap;
    function balanceOf(address a) public view returns (uint256) {
        return _balances[a];
    }
    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }
    function burn(uint256 amount) public {
        _burn(msg.sender, amount);
    }
    function _burn(address account, uint256 amount) internal {
        _balances[account] -= amount;
        _totalSupply -= amount;
    }
    function execute(address target, bytes calldata data)
            external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call failed");
        return ret;
    }
}
"""

CLEAN_VAULT_SRC = """
contract CleanVault {
    mapping(address => uint256) public deposits;
    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }
    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

GATED_BURN_SRC = """
contract GatedBurn {
    mapping(address => uint256) private _balances;
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    function withdrawTo(address account, uint256 amount)
            public onlyOwner {
        _burn(msg.sender, amount);
        (bool success, ) = account.call{ value: amount }("");
        require(success, "FAIL_TRANSFER");
    }
    function _burn(address account, uint256 amount) internal {
        _balances[account] -= amount;
    }
}
"""

_SRC_CACHE = os.path.expanduser(
    "~/workspace/recon-v2-run-2026-11-08/src_cache")


def _load_staged(chain_addr):
    path = os.path.join(_SRC_CACHE, chain_addr + ".json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def _aeweth_cand(source):
    return {"address": "0x8b194beae1d3e0788a1a35173978001acdfba668",
            "chain": "arbitrum", "function": "withdrawTo",
            "kind": "recipient_bridge_release_unproven",
            "source": source, "contract_name": "aeWETH"}


def _mvk_cand(source):
    return {"address": "0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0",
            "chain": "bsc", "function": "claimReward",
            "kind": "holder_reward_claim",
            "source": source, "contract_name": "MetaVerseKombat"}


# ---------------------------------------------------------------------------
# The two shapes gate
# ---------------------------------------------------------------------------

def test_aeweth_withdrawto_gates_self_funded():
    g = gate_candidate(_aeweth_cand(AEWETH_SRC))
    assert g["gate"] == GATE_SELF_FUNDED, g
    assert g["recipient"] == "CALLER-SUPPLIED"
    assert g["evidence"]["self_funded"]["burn_funded"] is True
    assert "self-funded" in g["reason"]


def test_mvk_claimreward_gates_caller_metered():
    g = gate_candidate(_mvk_cand(MVK_SRC))
    assert g["gate"] == GATE_CALLER_METERED, g
    assert g["recipient"] == "CALLER"
    assert g["basis"]["basis"] == "token_self"
    assert g["requires_basis_zero"] is True


@pytest.mark.skipif(
    _load_staged(
        "arbitrum_0x8b194beae1d3e0788a1a35173978001acdfba668")
    is None,
    reason="staged full aeWETH source not present on this box")
def test_aeweth_full_verified_source_gates_self_funded():
    doc = _load_staged(
        "arbitrum_0x8b194beae1d3e0788a1a35173978001acdfba668")
    g = gate_candidate(_aeweth_cand(doc["source"]))
    assert g["gate"] == GATE_SELF_FUNDED, g


@pytest.mark.skipif(
    _load_staged("bsc_0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0")
    is None,
    reason="staged full MVK source not present on this box")
def test_mvk_full_verified_source_gates_caller_metered():
    doc = _load_staged("bsc_0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0")
    g = gate_candidate(_mvk_cand(doc["source"]))
    assert g["gate"] == GATE_CALLER_METERED, g
    assert g["basis"]["basis"] == "token_self"


def test_gates_agree_with_v2_verdicts_on_fixtures():
    # The gate's FP fast path must land where v2 lands on the
    # same candidates once v2 has its evidence.
    cand = _aeweth_cand(AEWETH_SRC)
    cand["probe"] = {"status": "success", "detail": "0x",
                     "via": "test"}
    cand["balances"] = {"native_wei": 31401841031371963,
                        "token_self_wei": 0}
    assert validate_candidate(cand)["verdict"] == \
        "FALSE_POSITIVE"
    cand = _mvk_cand(MVK_SRC)
    cand["probe"] = {"status": "success", "detail": "0x",
                     "via": "test"}
    cand["balances"] = {"native_wei": 84400000000000000,
                        "stranger_token_self_wei": 0}
    assert validate_candidate(cand)["verdict"] == \
        "FALSE_POSITIVE"


# ---------------------------------------------------------------------------
# Genuine candidates and clean shapes never gate
# ---------------------------------------------------------------------------

def test_survivor_ungated_execute_does_not_gate():
    g = gate_candidate({
        "address": "0xeb466342c4d449bc9f53a865d5cb90586f405215",
        "chain": "base", "function": "execute",
        "kind": "ungated_arbitrary_call",
        "source": SURVIVOR_SRC,
        "contract_name": "BurnableMintableCappedERC20"})
    assert g["gate"] == GATE_PASS, g


def test_clean_vault_does_not_gate():
    for fn_name in ("withdraw", "deposit"):
        g = gate_candidate({
            "address": "0x0", "chain": "ethereum",
            "function": fn_name, "kind": "vault_flow",
            "source": CLEAN_VAULT_SRC, "contract_name": "CleanVault"})
        assert g["gate"] == GATE_PASS, (fn_name, g)


def test_plain_overdraw_candidate_does_not_gate():
    g = gate_candidate({
        "address": "0xabc", "chain": "ethereum",
        "function": "withdraw", "kind": "recipient_overdraw_withdraw",
        "source": OVERDRAW_SRC, "contract_name": "VulnVault"})
    assert g["gate"] == GATE_PASS, g


# ---------------------------------------------------------------------------
# Hard limits: ambiguity and evidence always fall through
# ---------------------------------------------------------------------------

def test_measured_receipt_evidence_forces_pass():
    cand = _aeweth_cand(AEWETH_SRC)
    cand["simulation"] = {"ran": True, "stranger_received": 5,
                          "unit": "ETH", "detail": "test"}
    assert gate_candidate(cand)["gate"] == GATE_PASS
    cand = _aeweth_cand(AEWETH_SRC)
    cand["decisive_probe"] = {"status": "success", "amount": 1,
                               "slot": 0, "via": "test"}
    assert gate_candidate(cand)["gate"] == GATE_PASS


def test_access_gated_shape_forces_pass():
    g = gate_candidate({
        "address": "0x0", "chain": "ethereum",
        "function": "withdrawTo", "kind": "burn_withdraw",
        "source": GATED_BURN_SRC, "contract_name": "GatedBurn"})
    assert g["gate"] == GATE_PASS, g


def test_missing_source_and_function_force_pass():
    cand = _aeweth_cand(AEWETH_SRC)
    cand["source"] = ""
    assert gate_candidate(cand)["gate"] == GATE_PASS
    cand = _aeweth_cand(AEWETH_SRC)
    cand["function"] = "noSuchFunction"
    assert gate_candidate(cand)["gate"] == GATE_PASS


def test_authority_class_and_override_force_pass():
    cand = _mvk_cand(MVK_SRC)
    cand["authority_class"] = True
    assert gate_candidate(cand)["gate"] == GATE_PASS
    cand = _mvk_cand(MVK_SRC)
    cand["recipient_override"] = "CALLER"
    assert gate_candidate(cand)["gate"] == GATE_PASS


# ---------------------------------------------------------------------------
# The fast-path verdict rows
# ---------------------------------------------------------------------------

def test_gate_verdict_self_funded_row():
    cand = _aeweth_cand(AEWETH_SRC)
    row = gate_verdict(cand, gate_candidate(cand))
    assert row["verdict"] == "FALSE_POSITIVE"
    assert row["gate"] == GATE_SELF_FUNDED
    assert row["evidence"]["inline_gate"]["gate"] == \
        GATE_SELF_FUNDED
    assert "self-funded" in row["reason"]


def test_gate_verdict_caller_metered_needs_measured_zero_basis():
    cand = _mvk_cand(MVK_SRC)
    g = gate_candidate(cand)
    with pytest.raises(ValueError):
        gate_verdict(cand, g)
    with pytest.raises(ValueError):
        gate_verdict(cand, g, basis_measured_zero=False)
    row = gate_verdict(cand, g, basis_measured_zero=True)
    assert row["verdict"] == "FALSE_POSITIVE"
    assert row["gate"] == GATE_CALLER_METERED
    assert row["evidence"]["inline_gate"][
        "stranger_basis_measured"] == 0


def test_gate_verdict_rejects_pass():
    cand = _mvk_cand(MVK_SRC)
    g = gate_candidate({"address": "0x0", "chain": "bsc",
                        "function": "claimReward",
                        "kind": "x", "source": "",
                        "contract_name": ""})
    assert g["gate"] == GATE_PASS
    with pytest.raises(ValueError):
        gate_verdict(cand, g)
