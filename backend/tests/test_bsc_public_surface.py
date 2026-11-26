"""Public-surface gate for the BSC detector-spec registry.

A detector that says "anyone / any stranger / ungated" may only make that
claim about code a stranger can actually reach with a live public call:
a public or external function that is not access-gated. Internal/private
helpers and gated entry points belong to a privileged account, so they
must not be reported as an open hole.

This is the regression gate for the batch-28 live run, where
``bridge_deposit_event_spoofing`` fired 77 times on internal ``_mint``
helpers and other gated bridge mints.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bsc100_fixtures as fx  # noqa: E402
import bsc100_support as support  # noqa: E402

STRANGER_CLAIM = re.compile(
    r"anyone|any caller|stranger|no access gate|no gate|ungated", re.I)

INTERNAL_ONLY = r"""
pragma solidity ^0.8.20;
contract SpoofBridge {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
        totalSupply += amount;
    }
}
"""

GATED_CLAIM = r"""
pragma solidity ^0.8.20;
contract SpoofBridge {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
        totalSupply += amount;
    }
    function claimDeposit(uint256 amount) external onlyOwner {
        _mint(msg.sender, amount);
    }
}
"""

PUBLIC_CLAIM = r"""
pragma solidity ^0.8.20;
contract SpoofBridge {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
        totalSupply += amount;
    }
    function claimDeposit(uint256 amount) external {
        _mint(msg.sender, amount);
    }
}
"""

GATED_WITHDRAW = r"""
pragma solidity ^0.8.20;
contract GatedWithdrawBridge {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }
    function withdraw(uint256 amount, address to) external onlyOwner {
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok);
    }
}
"""

INTERNAL_MESSAGE = r"""
pragma solidity ^0.8.20;
contract InjectBridge {
    function executeMessage(address target, bytes calldata data) internal {
        target.call(data);
    }
}
"""


def _spec(spec_id):
    return support.all_specs()[spec_id]


def _signature_for(src, fn_name):
    m = re.search(r"function\s+" + re.escape(fn_name) +
                  r"\s*\([^)]*\)([^{;]*)", src)
    return m.group(1).strip() if m else ""


def test_stranger_claims_are_public_only_and_gate_aware():
    offenders = []
    for spec_id, spec in support.all_specs().items():
        if spec.scope != "function" or spec.custom:
            continue
        if STRANGER_CLAIM.search(spec.detail) and not (
                spec.public_only and spec.gated_suppresses):
            offenders.append(spec_id)
    assert offenders == [], (
        "stranger-reachable detector(s) without public_only + "
        f"gated_suppresses: {offenders}")


def test_stranger_claims_fire_only_on_public_functions():
    for spec_id, spec in support.all_specs().items():
        if spec.scope != "function" or spec.custom:
            continue
        if not STRANGER_CLAIM.search(spec.detail):
            continue
        src = fx.VULN[spec_id]
        for hit in support.hits_for(src, spec):
            sig = _signature_for(src, hit["function"])
            assert re.search(r"\b(public|external)\b", sig), (
                f"{spec_id}: stranger claim fired on non-public "
                f"function {hit['function']} ({sig!r})")


def test_bridge_claim_ignores_internal_mint_helper():
    hits = support.hits_for(INTERNAL_ONLY, _spec("bridge_deposit_event_spoofing"))
    assert hits == [], hits


def test_bridge_claim_ignores_gated_claim():
    hits = support.hits_for(GATED_CLAIM, _spec("bridge_deposit_event_spoofing"))
    assert hits == [], hits


def test_bridge_claim_still_fires_on_public_claim():
    hits = support.hits_for(PUBLIC_CLAIM, _spec("bridge_deposit_event_spoofing"))
    assert hits, "public ungated claimDeposit must still fire"
    assert {h["function"] for h in hits} == {"claimDeposit"}, hits


def test_bridge_withdraw_ignores_gated_withdraw():
    hits = support.hits_for(
        GATED_WITHDRAW, _spec("bridge_withdrawer_identity_spoof"))
    assert hits == [], hits


def test_bridge_message_ignores_internal_helper():
    hits = support.hits_for(
        INTERNAL_MESSAGE, _spec("bridge_message_payload_injection"))
    assert hits == [], hits
