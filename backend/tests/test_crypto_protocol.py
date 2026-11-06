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
    assert len(reg) == 1165  # 927 = master 655 + 100 BSC/BNB detectors (bsc100) + 1 ast_visual_audit plugin + 5 deep-audit detectors + 6 deep-audit batch-2 detectors + 6 recipient-first detectors + 1 auto-validator + 4 deep-analysis plugins (deep_layers) + 5 deep3 detectors + 3 deep-audit batch-4 detectors (deep_audit4) + 8 deep-audit batch-9 detectors (deep_audit9) + 1 unified keyword search plugin (unified_keyword_search) + 5 deep-audit batch-10 detectors (deep_audit10) + 6 beyond-recon plugins (nuclei_templates, lifecycle, content_discovery, param_discovery_arjun, js_linkfinder, wayback_surface) + 5 sec_* secret-exposure detectors (secretpack) + 1 idorleak detector (idor-error-leak) + 1 meta_orchestrator plugin (PR #77) + 10 Tier-1 OSINT plugins (PR #119) + 8 Tier-2 Enumeration plugins (PR #124) + 6 Tier-3 Fuzzing plugins (PR #121) + 10 Tier-4 Vuln/CVE plugins (PR #125) + 10 Tier-5 Orchestration plugins (PR #123) + 8 Tier-6 Detection plugins (PR #126) + 10 Tier-7 Blockchain Ingestion plugins (PR #127) + 5 Tier-8 Static Analysis plugins (PR #129) + 8 Tier-9 plugins (PR #128) + 10 Tier-10 Mempool/MEV plugins (PR #130)
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
