"""Tests for cryptopack_protocol: passive, target-served-source only.

Network-free: exercises audit_protocol_source() on fixture Solidity and
asserts registry growth + plugin metadata. No RPC, no transaction, no
live target is touched by any test here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.cryptopack_protocol import audit_protocol_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

VULN = """
pragma solidity ^0.8.0;
contract Proto {
    function grant() public {
        token.approve(spender, type(uint256).max);
    }
    function shares(uint amount) public view returns (uint) {
        return amount / totalSupply * balance;
    }
    function price() public view returns (uint) {
        return reserve0 / reserve1;
    }
    function trade() public {
        router.swap(amountOutMin: 0, deadline: type(uint256).max);
    }
    function permit(address o, uint v, bytes32 r, bytes32 s) public {
        address signer = ecrecover(hash, v, r, s);
        require(signer == o);
    }
    function pay(address to, uint amount) public {
        token.transfer(to, amount);
    }
    function mint(address to, uint amount) public onlyOwner {
        _mint(to, amount);
    }
    function setFee(uint f) public onlyOwner {
        fee = f;
    }
    function pickWinner() public {
        uint r = uint(keccak256(abi.encodePacked(block.timestamp))) % players.length;
        winner = players[r];
    }
}
"""

SAFE = """
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
contract SafeProto {
    uint public maxSupply = 1000000;
    function grant() public {
        token.approve(spender, 1000);
    }
    function reward(uint amount) public view returns (uint) {
        return amount * rate / 10000;
    }
    function price() public view returns (uint) {
        return twapConsult();
    }
    function trade() public {
        router.swap(amountOutMin: 100, deadline: block.timestamp + 300);
    }
    function permit(address o, uint d, bytes32 r, bytes32 s) public {
        require(d > block.timestamp);
        address signer = ecrecover(hash, 27, r, s);
        require(nonces[o]++ == 0);
        require(DOMAIN_SEPARATOR == expected);
    }
    function pay(address to, uint amount) public {
        token.safeTransfer(to, amount);
    }
    function mint(address to, uint amount) public onlyOwner {
        require(totalSupply + amount <= maxSupply);
        _mint(to, amount);
    }
    function setFee(uint f) public onlyOwner {
        require(f <= 1000);
        fee = f;
    }
    function draw() public {
        requestRandomWords();
    }
}
"""

CHECKS = ["unlimited_approval", "rounding_order", "single_source_oracle",
          "unbounded_slippage", "permit_signature_replay",
          "unchecked_erc20_return", "centralized_mint_fee",
          "timestamp_randomness"]


def _checks(src):
    return {r["check"] for r in audit_protocol_source(src)}


def test_all_eight_fire_on_vuln_fixture():
    got = _checks(VULN)
    missing = [c for c in CHECKS if c not in got]
    assert not missing, f"missing checks: {missing} got={sorted(got)}"


def test_safe_fixture_fires_none():
    got = _checks(SAFE)
    assert not got, f"safe fixture should fire nothing, got={sorted(got)}"


def test_each_check_individually_named():
    # One assertion per check so a regression names the broken detector.
    res = audit_protocol_source(VULN)
    by_check = {r["check"]: r for r in res}
    for c in CHECKS:
        assert c in by_check, f"{c} did not fire"
        assert by_check[c]["severity"] in ("low", "medium", "high")
        assert by_check[c]["function"] or c in (
            "unlimited_approval", "single_source_oracle", "unbounded_slippage")
        assert len(by_check[c]["snippet"]) <= 200


def test_registry_grew_by_eight():
    reg = discover()
    assert len(reg) == 635  # 634 + 1 idor/error-leak plugin (feature/idor-error-leak)
    for c in CHECKS:
        pid = f"cp_proto_{c}"
        assert pid in reg, f"{pid} missing from registry"
        p = reg[pid]()
        assert p.group == "web3"
        assert p.passive is True
        assert "Detection only" in p.description
        assert "No RPC" in p.description


def test_no_secret_material_in_findings():
    # Snippets must never carry a private-key-shaped value.
    import re
    for r in audit_protocol_source(VULN):
        assert not re.search(r"0x[0-9a-fA-F]{64}", r["snippet"])
        assert "private" not in r["detail"].lower() or \
            "private data" in r["detail"].lower()
