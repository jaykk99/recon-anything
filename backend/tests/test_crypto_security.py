"""Functional tests for crypto security scanners (network-free).

Exercises the pure static-analysis functions with sample Solidity
snippets and asserts the expected checks fire. Run with pytest.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.contract_audit import audit_source
from app.plugins.defi_risk import scan_defi_risks
from app.plugins.meme_coin import audit_meme_token


def checks(results):
    return {(r["check"], r.get("function", "")) for r in results}


# ---------- contract_audit additions ----------

VULN_CONTRACT = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint) public balances;
    address public impl;
    function withdraw() public {
        uint amt = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amt}("");
        balances[msg.sender] = 0;
    }
    function upgrade(address _impl) public {
        (bool s,) = _impl.delegatecall(abi.encodeWithSignature("init()"));
        require(s);
    }
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
    function setPrice(uint p) public { price = p; }
    uint public price;
    function buy() public payable { /* uses price */ }
    function initialize() public { owner = msg.sender; }
    function onFlashLoan(address a, uint b) public { /* no caller check */ }
}
"""

SAFE_CONTRACT = """
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    address public immutable impl = 0x1234567890123456789012345678901234567890;
    function withdraw() public nonReentrant {
        uint amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
    }
    function upgrade() public onlyOwner {
        (bool s,) = impl.delegatecall(abi.encodeWithSignature("init()"));
        require(s);
    }
}
"""


def test_delegatecall_untrusted_fires():
    c = checks(audit_source(VULN_CONTRACT))
    assert ("delegatecall_untrusted", "upgrade") in c


def test_delegatecall_hardcoded_address_no_flag():
    c = checks(audit_source(SAFE_CONTRACT))
    assert not any(k == "delegatecall_untrusted" for k, _ in c)


def test_selfdestruct_fires():
    c = checks(audit_source(VULN_CONTRACT))
    assert any(k == "selfdestruct" for k, _ in c)


def test_selfdestruct_absent_in_safe():
    c = checks(audit_source(SAFE_CONTRACT))
    assert not any(k == "selfdestruct" for k, _ in c)


def test_frontrunning_setprice_plus_buy():
    c = checks(audit_source(VULN_CONTRACT))
    assert any(k == "frontrunning" for k, _ in c)


def test_frontrunning_oracle_without_staleness():
    src = ("pragma solidity ^0.8.0; contract O { function p() public view "
           "returns (uint) { (,int256 a,,,) = feed.latestRoundData(); "
           "return uint(a); } }")
    c = checks(audit_source(src))
    assert any(k == "frontrunning" for k, _ in c)


def test_frontrunning_oracle_with_staleness_check_ok():
    src = ("pragma solidity ^0.8.0; contract O { function p() public view "
           "returns (uint) { (uint80 rid,int256 a,,,uint80 ans) = "
           "feed.latestRoundData(); require(ans >= rid); "
           "require(block.timestamp - updatedAt < 3600); return uint(a); } }")
    c = checks(audit_source(src))
    assert not any(k == "frontrunning" for k, _ in c)


def test_flashloan_callback_fires():
    c = checks(audit_source(VULN_CONTRACT))
    assert ("flashloan_callback", "onFlashLoan") in c


def test_unprotected_initializer_fires():
    c = checks(audit_source(VULN_CONTRACT))
    assert ("unprotected_initializer", "initialize") in c


def test_reentrancy_notes_missing_nonreentrant():
    res = audit_source(VULN_CONTRACT)
    reen = [r for r in res if r["check"] == "reentrancy"
            and r["function"] == "withdraw"]
    assert reen and "nonReentrant" in reen[0]["detail"]


def test_reentrancy_no_note_when_guarded():
    res = audit_source(SAFE_CONTRACT)
    reen = [r for r in res if r["check"] == "reentrancy"]
    # effects-before-interactions means no reentrancy flag at all
    assert not reen


# ---------- meme_coin ----------

HONEYPOT = """
pragma solidity ^0.8.0;
contract Scam {
    mapping(address => uint) private _balances;
    mapping(address => bool) private _isBlacklisted;
    address public uniswapV2Pair;
    address public owner;
    uint256 public _buyTax = 5;
    uint256 public _sellTax = 45;
    function owner() public view returns (address) { return owner; }
    function _transfer(address from, address to, uint amount) internal {
        require(!_isBlacklisted[from], "blacklisted");
        require(from == uniswapV2Pair || to == uniswapV2Pair, "only dex");
        _balances[from] -= amount;
        _balances[to] += amount;
    }
    function mint(address to, uint amt) public { _balances[to] += amt; }
    function setBlacklist(address a, bool b) public { _isBlacklisted[a] = b; }
    function setSellTax(uint t) public { _sellTax = t; }
    function setTrading(bool b) public { tradingEnabled = b; }
    bool public tradingEnabled;
}
"""

CLEAN_TOKEN = """
pragma solidity ^0.8.20;
contract Fine {
    uint256 public _buyTax = 2;
    uint256 public _sellTax = 2;
    function renounceOwnership() public {}
    function _transfer(address from, address to, uint amount) internal {}
}
"""


def test_honeypot_blacklist_fires():
    c = {r["check"] for r in audit_meme_token(HONEYPOT)}
    assert "honeypot" in c
    assert "rug_blacklist" in c


def test_rug_mint_uncapped_fires():
    c = {r["check"] for r in audit_meme_token(HONEYPOT)}
    assert "rug_mint" in c
    sev = {r["check"]: r["severity"] for r in audit_meme_token(HONEYPOT)}
    assert sev["rug_mint"] == "high"


def test_rug_tax_unbounded_fires():
    c = {r["check"] for r in audit_meme_token(HONEYPOT)}
    assert "rug_tax" in c


def test_rug_tax_declared_high_fires():
    # _sellTax = 45 declared above 25%
    res = audit_meme_token(HONEYPOT)
    tax = [r for r in res if r["check"] == "rug_tax"]
    assert any("45" in r["detail"] or "above 25" in r["detail"] for r in tax)


def test_rug_trading_toggle_fires():
    c = {r["check"] for r in audit_meme_token(HONEYPOT)}
    assert "rug_trading" in c


def test_asymmetric_tax_fires():
    sev = {r["check"]: r["severity"] for r in audit_meme_token(HONEYPOT)}
    assert sev.get("asymmetric_tax") == "medium"


def test_owner_not_renounced_fires():
    c = {r["check"] for r in audit_meme_token(HONEYPOT)}
    assert "owner_not_renounced" in c


def test_clean_token_no_flags():
    res = audit_meme_token(CLEAN_TOKEN)
    assert res == []


def test_meme_findings_have_remediation():
    for r in audit_meme_token(HONEYPOT):
        assert r.get("remediation"), r["check"]


# ---------- defi_risk additions ----------

DEFI_VULN = """
pragma solidity ^0.8.0;
contract Pool {
    address public owner;
    mapping(address => mapping(address => uint)) public allowance;
    AggregatorV3Interface public feed;
    function approve(address spender, uint amount) public {
        allowance[msg.sender][spender] = type(uint256).max;
    }
    function swap() public {
        (,int256 price,,,) = feed.latestRoundData();
        // no staleness check
    }
    function admin() public { require(msg.sender == owner); }
    function rebase() public { /* elastic supply */ }
}
"""

DEFI_SAFE = """
pragma solidity ^0.8.0;
contract Pool {
    address public timelock;
    function approve(address spender, uint amount) public {
        allowance[msg.sender][spender] = amount;
    }
    function swap() public {
        (uint80 rid, int256 price, , uint256 updatedAt, uint80 ans) =
            feed.latestRoundData();
        require(ans >= rid);
        require(block.timestamp - updatedAt < 3600);
    }
}
"""


def test_approve_unbounded_fires():
    c = {r["check"]: r["severity"] for r in scan_defi_risks(DEFI_VULN)}
    assert c.get("approve_unbounded") == "medium"


def test_approve_bounded_no_flag():
    c = {r["check"] for r in scan_defi_risks(DEFI_SAFE)}
    assert "approve_unbounded" not in c


def test_oracle_stale_fires():
    c = {r["check"]: r["severity"] for r in scan_defi_risks(DEFI_VULN)}
    assert c.get("oracle_stale") == "medium"


def test_oracle_stale_checked_ok():
    c = {r["check"] for r in scan_defi_risks(DEFI_SAFE)}
    assert "oracle_stale" not in c


def test_single_key_admin_fires():
    src = ("pragma solidity ^0.8.0; contract P { function setFee(uint f) "
           "public onlyOwner { fee = f; } }")
    c = {r["check"]: r["severity"] for r in scan_defi_risks(src)}
    assert c.get("single_key_admin") == "medium"


def test_single_key_admin_with_timelock_ok():
    src = ("pragma solidity ^0.8.0; contract P { address public timelock; "
           "function setFee(uint f) public onlyOwner { fee = f; } }")
    c = {r["check"] for r in scan_defi_risks(src)}
    assert "single_key_admin" not in c


def test_rebase_fires():
    c = {r["check"]: r["severity"] for r in scan_defi_risks(DEFI_VULN)}
    assert c.get("rebase") == "medium"


def test_defi_findings_have_remediation():
    for r in scan_defi_risks(DEFI_VULN):
        assert r.get("remediation"), r["check"]


# ---------------------------------------------------------------------------
# delegatecall receiver-based trust (fixed 2026-10-20: the audit used to
# inspect the call *arguments* - the forwarded calldata - instead of the
# *receiver*, which is the actual target address).
# ---------------------------------------------------------------------------

def dcall_checks(src):
    return {(r["check"], r["function"]) for r in audit_source(src)}


def test_delegatecall_receiver_immutable_not_flagged():
    src = ("pragma solidity ^0.8.20; contract P { "
           "address public immutable impl = 0x1234567890123456789012345678901234567890; "
           "function upgrade() public onlyOwner { "
           "(bool s,) = impl.delegatecall(abi.encodeWithSignature(\"init()\")); "
           "require(s); } }")
    assert "delegatecall_untrusted" not in {k for k, _ in dcall_checks(src)}


def test_delegatecall_receiver_constant_not_flagged():
    src = ("pragma solidity ^0.8.20; contract P { "
           "address constant IMPL = 0x1234567890123456789012345678901234567890; "
           "function upgrade() public onlyOwner { "
           "(bool s,) = IMPL.delegatecall(\"\"); require(s); } }")
    assert "delegatecall_untrusted" not in {k for k, _ in dcall_checks(src)}


def test_delegatecall_literal_address_not_flagged():
    src = ("pragma solidity ^0.8.20; contract P { "
           "function upgrade() public onlyOwner { "
           "(bool s,) = 0x1234567890123456789012345678901234567890"
           ".delegatecall(\"\"); require(s); } }")
    assert "delegatecall_untrusted" not in {k for k, _ in dcall_checks(src)}


def test_delegatecall_mutable_state_var_flagged():
    src = ("pragma solidity ^0.8.20; contract P { "
           "address public impl; "
           "function setImpl(address a) public { impl = a; } "
           "function upgrade() public { "
           "(bool s,) = impl.delegatecall(abi.encodeWithSignature(\"init()\")); "
           "require(s); } }")
    assert ("delegatecall_untrusted", "upgrade") in dcall_checks(src)


def test_delegatecall_function_arg_flagged():
    src = ("pragma solidity ^0.8.20; contract P { "
           "function upgrade(address target) public { "
           "(bool s,) = target.delegatecall(\"\"); require(s); } }")
    assert ("delegatecall_untrusted", "upgrade") in dcall_checks(src)


def test_delegatecall_detail_names_receiver():
    src = ("pragma solidity ^0.8.20; contract P { "
           "address public logic; "
           "function upgrade() public { (bool s,) = logic.delegatecall(\"\"); } }")
    rows = [r for r in audit_source(src)
            if r["check"] == "delegatecall_untrusted"]
    assert rows and "logic" in rows[0]["detail"]
