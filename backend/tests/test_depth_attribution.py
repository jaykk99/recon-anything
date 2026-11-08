"""Depth fix 1 (2026-11-05): recipient + function attribution
in bundled source.

Covers:
- _Scope stamps every function dict with its owning contract
  (fn["contract"]).
- classify_recipient sees token-ledger CREDIT destinations in
  mint-shaped functions (a mint that writes balanceOf[to]
  directly, with no transfer/_mint call).
- classify_recipient_path expands internal helpers WITH
  argument binding: the destination is classified from what
  the entry actually passes (msg.sender / its own address
  parameter / a stored address).
- validate_candidate: automatic sibling-scope FALSE_POSITIVE
  (no manual function_out_of_scope flag) and proxy ->
  bundled-implementation attribution.
"""
from app.plugins import contract_logic as cl
from app.plugins import recipient_first as rf
from app.plugins.auto_validator import validate_candidate


# ---------------------------------------------------------------------------
# Fixtures (mirroring the plugin-depth benchmark corpus)
# ---------------------------------------------------------------------------

MINT_DIRECT = """
contract VulnMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

MINT_GATED = """
contract CleanRoleMint {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public minters;
    constructor() { owner = msg.sender; }
    modifier onlyMinter() { require(minters[msg.sender], "not minter"); _; }
    function mint(address to, uint256 amount) public onlyMinter {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

MINT_FIXED = """
contract FixedMint {
    address public treasury;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(uint256 amount) public {
        totalSupply += amount;
        balanceOf[treasury] += amount;
    }
}
"""

HELPER_CALLER = """
contract PayCaller {
    function withdraw(uint256 amount) public {
        _payout(msg.sender, amount);
    }
    function _payout(address dst, uint256 amount) internal {
        payable(dst).transfer(amount);
    }
    receive() external payable {}
}
"""

HELPER_SUPPLIED = """
contract PaySupplied {
    function withdrawTo(address to, uint256 amount) public {
        _payout(to, amount);
    }
    function _payout(address dst, uint256 amount) internal {
        payable(dst).transfer(amount);
    }
    receive() external payable {}
}
"""

HELPER_FIXED = """
contract PayFixed {
    address public treasury;
    function withdraw(uint256 amount) public {
        _payout(treasury, amount);
    }
    function _payout(address dst, uint256 amount) internal {
        payable(dst).transfer(amount);
    }
    receive() external payable {}
}
"""

HELPER_TWO_HOP = """
contract PayTwoHop {
    function withdraw(uint256 amount) public {
        _mid(amount);
    }
    function _mid(uint256 amount) internal {
        _payout(msg.sender, amount);
    }
    function _payout(address dst, uint256 amount) internal {
        payable(dst).transfer(amount);
    }
    receive() external payable {}
}
"""

BUNDLED_IMPL = """
// ==== contracts/Proxy.sol ====
contract Proxy {
    address public implementation;
    address public admin;
    constructor(address _impl) { implementation = _impl; admin = msg.sender; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}
// ==== contracts/Impl.sol ====
contract Impl {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function withdrawTo(address to, uint256 amount) public {
        payable(to).transfer(amount);
    }
    receive() external payable {}
}
"""

SIBLING = """
// ==== contracts/Token.sol ====
contract Token {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function mint(address to, uint256 amount) public onlyOwner {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
// ==== contracts/DepositHandler.sol ====
contract DepositHandler {
    bool private locked;
    modifier noReenter() { require(!locked, "reentrant"); locked = true; _; locked = false; }
    function execute(address callee, bytes memory data) public noReenter {
        (bool ok, ) = callee.call(data);
        require(ok, "call failed");
    }
}
"""


def _fn(scope, name):
    return next(f for f in scope.functions if f["name"] == name
                and "{" in f["text"])


def _candidate(source, contract_name, function, probe="success",
               balances=None):
    return {"address": "0x00000000000000000000000000000000000000aa",
            "chain": "ethereum", "function": function,
            "kind": "access_control_flaw", "source": source,
            "contract_name": contract_name,
            "probe": {"status": probe, "via": "test"},
            "balances": balances or {}}


# ---------------------------------------------------------------------------
# 1. fn["contract"] ownership
# ---------------------------------------------------------------------------

def test_scope_stamps_owning_contract():
    full = cl._Scope(BUNDLED_IMPL, "")
    owners = {f["name"]: f.get("contract")
              for f in full.functions if "{" in f["text"]}
    assert owners["withdrawTo"] == "Impl"
    assert owners["fallback"] == "Proxy"
    scoped = cl._Scope(BUNDLED_IMPL, "Proxy")
    assert all(f.get("contract") == "Proxy"
               for f in scoped.functions if "{" in f["text"])


# ---------------------------------------------------------------------------
# 2. Ledger-credit mint classification
# ---------------------------------------------------------------------------

def test_direct_write_mint_classifies_caller_supplied():
    scope = cl._Scope(MINT_DIRECT, "VulnMint")
    fn = _fn(scope, "mint")
    recipient, _detail = cl.classify_recipient(fn["text"])
    assert recipient == "CALLER-SUPPLIED"
    recipient_path, _d, _t = cl.classify_recipient_path(scope, fn)
    assert recipient_path == "CALLER-SUPPLIED"


def test_direct_write_mint_to_stored_address_is_fixed():
    scope = cl._Scope(MINT_FIXED, "FixedMint")
    recipient, _detail = cl.classify_recipient(
        _fn(scope, "mint")["text"])
    assert recipient == "FIXED"


def test_gated_direct_write_mint_stays_non_candidate():
    findings = rf.analyze_recipient_source(
        MINT_GATED, "recipient_mint_to_caller", "", "CleanRoleMint")
    assert not [f for f in findings
                if f.get("report_class") == "candidate"]


def test_direct_write_mint_detector_candidate_and_validator():
    findings = rf.analyze_recipient_source(
        MINT_DIRECT, "recipient_mint_to_caller", "", "VulnMint")
    cand = [f for f in findings
            if f.get("report_class") == "candidate"
            and f["function"] == "mint"]
    assert cand and cand[0]["recipient"] == "CALLER-SUPPLIED"
    cand = _candidate(
        MINT_DIRECT, "VulnMint", "mint",
        balances={"token_pair_reserves":
                  {"reserve0": 10 ** 20, "reserve1": 10 ** 18},
                  "stranger_native_wei": 0,
                  "stranger_token_self_wei": 0})
    # Measured receipt: decisive probe at a nonzero amount in
    # the amount slot (slot 1) the stranger cannot self-fund.
    cand["decisive_probe"] = {"status": "success", "amount": 1,
                              "slot": 1, "via": "test"}
    v = validate_candidate(cand)
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["recipient"] == "CALLER-SUPPLIED"


# ---------------------------------------------------------------------------
# 3. Helper-path argument binding
# ---------------------------------------------------------------------------

def test_helper_path_entry_passes_msg_sender():
    scope = cl._Scope(HELPER_CALLER, "PayCaller")
    recipient, _d, path = cl.classify_recipient_path(
        scope, _fn(scope, "withdraw"))
    assert recipient == "CALLER"
    assert "payable(msg.sender).transfer" in path


def test_helper_path_entry_passes_own_param():
    scope = cl._Scope(HELPER_SUPPLIED, "PaySupplied")
    recipient, _d, _t = cl.classify_recipient_path(
        scope, _fn(scope, "withdrawTo"))
    assert recipient == "CALLER-SUPPLIED"


def test_helper_path_entry_passes_stored_address():
    scope = cl._Scope(HELPER_FIXED, "PayFixed")
    recipient, _d, _t = cl.classify_recipient_path(
        scope, _fn(scope, "withdraw"))
    assert recipient == "FIXED"


def test_helper_path_two_hops():
    scope = cl._Scope(HELPER_TWO_HOP, "PayTwoHop")
    recipient, _d, _t = cl.classify_recipient_path(
        scope, _fn(scope, "withdraw"))
    assert recipient == "CALLER"


def test_helper_recipient_detector_candidate():
    src = """
contract VulnHelperPay {
    function withdraw(uint256 amount) public {
        _payout(amount);
    }
    function _payout(uint256 amount) internal {
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""
    findings = rf.analyze_recipient_source(
        src, "recipient_overdraw_withdraw", "", "VulnHelperPay")
    cand = [f for f in findings
            if f.get("report_class") == "candidate"
            and f["function"] == "withdraw"]
    assert cand and cand[0]["recipient"] == "CALLER"


# ---------------------------------------------------------------------------
# 4a. Validator: automatic sibling out-of-scope
# ---------------------------------------------------------------------------

def test_validator_sibling_auto_false_positive_on_revert():
    v = validate_candidate(_candidate(
        SIBLING, "Token", "execute", probe="revert"))
    assert v["verdict"] == "FALSE_POSITIVE"
    assert "not found in the verified source" not in v["reason"]


def test_validator_sibling_auto_unverified_without_revert():
    v = validate_candidate(_candidate(
        SIBLING, "Token", "execute", probe="success"))
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == ["flagged function in deployed "
                            "contract scope"]
    assert "exists in the verified compilation" in v["reason"]


def test_validator_function_absent_everywhere_reason():
    v = validate_candidate(_candidate(
        SIBLING, "Token", "nonexistent", probe="revert"))
    assert v["verdict"] == "UNVERIFIED"
    assert v["missing"] == ["flagged function in verified source"]


# ---------------------------------------------------------------------------
# 4b. Validator: proxy attribution to the bundled implementation
# ---------------------------------------------------------------------------

def test_validator_proxy_attribution_verified_real():
    cand = _candidate(
        BUNDLED_IMPL, "Proxy", "withdrawTo",
        balances={"native_wei": 10 ** 18,
                  "stranger_native_wei": 0,
                  "stranger_token_self_wei": 0})
    # Measured receipt: decisive probe at a nonzero amount in
    # the amount slot the stranger cannot self-fund.
    cand["decisive_probe"] = {"status": "success", "amount": 1,
                              "slot": 1, "via": "test"}
    v = validate_candidate(cand)
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["recipient"] == "CALLER-SUPPLIED"
    assert v["evidence"].get("attributed_to") == "Impl"
    assert v["evidence"].get("attribution") == (
        "bundled implementation surface behind proxy target")


def test_validator_no_attribution_for_non_proxy_sibling():
    v = validate_candidate(_candidate(
        SIBLING, "Token", "execute", probe="revert"))
    assert "attributed_to" not in v["evidence"]
