"""contract_logic false-positive filters (2026-11-02 adjudication).

The 10,000-contract sweep produced 103 hand-validated candidates;
99 were false positives and 3 were trigger-only. The fixtures
below are the adjudicated shapes (several function bodies are
VERBATIM from the scan evidence in the validation snapshot):

1. Overflow: OpenZeppelin internals (internal + bounds checked
   before the unchecked block), WETH9 deposit/withdraw.
2. Gates the old detector missed: require(_msgSender() == x),
   boolean role mappings, hasMinterRole modifiers, registry-
   indirect gates, helper-enforced gates. A supply CAP alone is
   NOT a gate and must still flag.
3. Scope: sibling contracts, test fixtures, and free functions
   bundled in one compilation are not the target's methods;
   ancestors of the target ARE in scope.
4. Recipient: fixed-destination value moves are TRIGGER-ONLY
   (low severity, report_class="trigger_only"); caller-reachable
   value stays candidate-grade. POL's initialize() must REMAIN
   a high candidate (genuine open item, never special-cased).

Positive controls are asserted alongside: the fixes must not
blind the detector to real ungated drains/mints.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_logic  # noqa: E402
from app.plugins.contract_logic import analyze_logic_source  # noqa: E402


def _cand(src, name="", kind=None, function=None):
    """Candidate-grade findings (severity high/medium, not
    trigger-only), optionally filtered."""
    out = []
    for f in analyze_logic_source(src, "", contract_name=name):
        if f.get("report_class") == "trigger_only":
            continue
        if f["severity"] not in ("high", "medium"):
            continue
        if kind and f["kind"] != kind:
            continue
        if function and f["function"] != function:
            continue
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Fix 1: overflow suppressions
# ---------------------------------------------------------------------------

WETH9_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.4.18;

contract WETH9 {
    mapping(address => uint256) public balanceOf;

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        emit Withdrawal(msg.sender, wad);
    }
}
"""


def test_weth9_never_flags():
    assert analyze_logic_source(WETH9_SOURCE, "",
                                contract_name="WETH9") == []


OZ_STYLE_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BackedTokenProxy {
    address public minter;
    address public pauser;
    bool public isPaused;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    function _transfer(address from, address to, uint256 amount)
        internal virtual
    {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - amount;
        }
        _balances[to] += amount;
    }

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");
        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        unchecked {
            _balances[account] = accountBalance - amount;
        }
        _totalSupply -= amount;
    }

    function mint(address account, uint256 amount) virtual external {
        require(_msgSender() == minter, "BackedToken: Only minter");
        _mint(account, amount);
    }

    function setPause(bool newPauseMode) external {
        require(_msgSender() == pauser, "BackedToken: Only pauser");
        isPaused = newPauseMode;
    }
}
"""


def test_oz_internals_and_msgsender_gates_never_flag():
    assert analyze_logic_source(OZ_STYLE_SOURCE, "",
                                contract_name="BackedTokenProxy") == []


def test_public_unchecked_still_flags():
    # Positive control: a PUBLIC function doing unchecked
    # arithmetic on supply with no bounds check is a real finding.
    src = r"""
    pragma solidity ^0.8.20;
    contract Vault {
        uint256 public totalSupply;
        function addUnchecked(uint256 amount) external {
            unchecked { totalSupply += amount; }
        }
    }
    """
    hits = _cand(src, "Vault", kind="integer_overflow")
    assert len(hits) == 1
    assert hits[0]["function"] == "addUnchecked"


# ---------------------------------------------------------------------------
# Fix 2: in-body / call-path gates
# ---------------------------------------------------------------------------

GATES_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GateShapes {
    address public minter;
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1000000;
    mapping(address => bool) public isMinter;
    mapping(address => uint256) private _balances;
    mapping(address => Supply) public bridges;
    struct Supply { uint256 cap; uint256 total; }

    function mintMapGate(address to, uint256 amount) external {
        require(isMinter[msg.sender], "not a minter");
        _mint(to, amount);
    }

    function mintRevertGate(address to, uint256 amount) external {
        if (!isMinter[msg.sender]) revert("UNAUTHORIZED");
        _mint(to, amount);
    }

    function mintRoleCall(address to, uint256 amount) external {
        require(hasMinterRole(msg.sender), "no role");
        _mint(to, amount);
    }

    function mintRegistry(address _to, uint256 _amount) external returns (bool) {
        Supply storage b = bridges[msg.sender];
        require(b.cap > 0, "invalid caller");
        b.total += _amount;
        require(b.total <= b.cap, "exceeds bridge supply cap");
        _mint(_to, _amount);
        return true;
    }

    function _checkMinter() internal view {
        require(msg.sender == minter, "not minter");
    }

    function mintHelperGate(address to, uint256 amount) external {
        _checkMinter();
        _mint(to, amount);
    }

    function mintModifierGate(address to, uint256 amount)
        external hasMinterRole
    {
        _mint(to, amount);
    }

    function mintCapOnly(address to, uint256 amount) external {
        require(totalSupply + amount <= MAX_SUPPLY, "cap");
        _mint(to, amount);
    }
}
"""


def test_in_body_gates_suppress_access_flags():
    hits = _cand(GATES_SOURCE, "GateShapes",
                 kind="access_control_flaw")
    fns = {h["function"] for h in hits}
    # The ONLY survivor is the cap-only mint: a supply cap bounds
    # damage but is not an access gate, and its recipient is the
    # caller-supplied `to` - a genuine candidate.
    assert fns == {"mintCapOnly"}
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"
    assert hits[0]["report_class"] == "candidate"


PBTC_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract PToken {
    address public pNetwork;
    function mint(address recipient, uint256 value) public returns (bool) {
        require(
            _msgSender() == pNetwork,
            "Only the pNetwork can mint tokens!"
        );
        require(recipient != address(0), "cannot mint to zero");
        _mint(recipient, value);
        return true;
    }
}
"""


def test_msgsender_multiline_require_is_a_gate():
    assert _cand(PBTC_SOURCE, "PToken",
                 kind="access_control_flaw") == []


# ---------------------------------------------------------------------------
# Fix 3: compilation scope
# ---------------------------------------------------------------------------

SCOPE_SOURCE = r"""
// ==== contracts/token/ShopToken.sol ====
pragma solidity ^0.8.0;
contract ShopToken is TokenBase {
    function withdrawTo(address to) external {
        payable(to).transfer(address(this).balance);
    }
}

// ==== contracts/token/TokenBase.sol ====
pragma solidity ^0.8.0;
contract TokenBase {
    uint256 public fee;
    function setFee(uint256 newFee) external {
        fee = newFee;
    }
}

// ==== contracts/token/DepositHandler.sol ====
pragma solidity ^0.8.0;
contract DepositHandler {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

// ==== contracts/test/ignore-errors/RiskyFreeFunctions.sol ====
pragma solidity ^0.8.0;
function freeDelegateCall(address target, bytes memory data) {
    (bool ok, ) = target.delegatecall(data);
    require(ok);
}
contract UnsafeFixture {
    function d() external {
        selfdestruct(payable(msg.sender));
    }
}
"""


def test_scope_excludes_siblings_tests_and_free_functions():
    hits = _cand(SCOPE_SOURCE, "ShopToken")
    fns = {(h["function"], h["kind"]) for h in hits}
    # Target's own ungated payout: IN (caller-supplied recipient).
    assert ("withdrawTo", "access_control_flaw") in fns
    # Ancestor's ungated setter: IN (inherited = deployed code).
    assert ("setFee", "access_control_flaw") in fns
    # Sibling contract's destroy: OUT.
    assert ("destroy", "access_control_flaw") not in fns
    # Test fixture + free function: OUT.
    assert ("d", "access_control_flaw") not in fns
    assert all(h["function"] != "freeDelegateCall" for h in hits)


def test_scope_follows_the_named_target():
    hits = _cand(SCOPE_SOURCE, "DepositHandler")
    fns = {h["function"] for h in hits}
    assert "destroy" in fns
    assert "withdrawTo" not in fns


def test_scope_unknown_name_falls_back_to_all_contracts():
    # The plugin's stubbed tests use contract_name="Fixture" for
    # sources that define other names; the analyzer must not go
    # blind - it falls back to all non-test contracts.
    hits = _cand(SCOPE_SOURCE, "NoSuchContract")
    fns = {h["function"] for h in hits}
    assert "withdrawTo" in fns
    assert "destroy" in fns          # sibling back in (no target)
    assert "d" not in fns            # test path still excluded
    assert all(h["function"] != "freeDelegateCall" for h in hits)


# ---------------------------------------------------------------------------
# Fix 4: recipient dataflow + the POL open thread
# ---------------------------------------------------------------------------

TRIGGER_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DERC20 {
    address private _owner;
    uint256 public currentYearStart;
    uint256 private _totalSupply;
    address public projectTaxRecipient;
    mapping(address => uint256) private _balances;

    function owner() public view returns (address) {
        return _owner;
    }

    function mintInflation() public {
        require(currentYearStart != 0, "MintingNotStartedYet");
        uint256 mintableAmount = 10;
        _mint(owner(), mintableAmount);
    }

    function rescueExcessToken(address token) external {
        IERC20(token).transfer(
            projectTaxRecipient,
            IERC20(token).balanceOf(address(this)));
    }

    function emergencyWithdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""


def test_fixed_recipients_are_trigger_only():
    findings = analyze_logic_source(TRIGGER_SOURCE, "",
                                    contract_name="DERC20")
    by_fn = {f["function"]: f for f in findings
             if f["kind"] == "access_control_flaw"}
    for fn in ("mintInflation", "rescueExcessToken"):
        assert fn in by_fn, fn
        assert by_fn[fn]["report_class"] == "trigger_only"
        assert by_fn[fn]["severity"] == "low"
        assert by_fn[fn]["recipient"] == "FIXED"
    # The stranger-receivable drain stays candidate-grade.
    assert by_fn["emergencyWithdraw"]["report_class"] == "candidate"
    assert by_fn["emergencyWithdraw"]["severity"] == "high"
    assert by_fn["emergencyWithdraw"]["recipient"] == "CALLER"


def test_classify_recipient_shapes():
    cr = contract_logic.classify_recipient
    assert cr("function f() public { _mint(owner(), 1); }")[0] == "FIXED"
    assert cr("function f(address t) public { _mint(t, 1); }")[0] == \
        "CALLER-SUPPLIED"
    assert cr("function f() public { payable(msg.sender)"
              ".transfer(1); }")[0] == "CALLER"
    assert cr("function f() public { }")[0] == "UNRESOLVED"


POL_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract MRC20 {
    bool public isInitialized;
    address public token;
    address public owner;
    uint256 public currentSupply;

    function _transferOwnership(address newOwner) internal {
        owner = newOwner;
    }

    function balanceOf(address a) public view returns (uint256) {
        return 0;
    }

    function initialize(address _childChain, address _token) public {
        require(!isInitialized, "The contract is already initialized");
        isInitialized = true;
        token = _token;
        _transferOwnership(_childChain);
    }

    function withdraw(uint256 amount) public payable {
        address user = msg.sender;
        uint256 input = balanceOf(user);
        currentSupply = currentSupply.sub(amount);
        require(
            amount > 0 && msg.value == amount,
            "Insufficient amount"
        );
        emit Withdraw(token, user, amount, input, balanceOf(user));
    }
}
"""


def test_pol_initialize_remains_a_candidate():
    # Genuine open item: the one-shot isInitialized flag is NOT an
    # access gate, and this must never be special-cased away.
    hits = _cand(POL_SOURCE, "MRC20", kind="access_control_flaw",
                 function="initialize")
    assert len(hits) == 1
    assert hits[0]["logic_kind"] == "unprotected_initializer"
    assert hits[0]["severity"] == "high"


def test_pol_withdraw_is_self_funded_not_a_flaw():
    hits = _cand(POL_SOURCE, "MRC20", function="withdraw")
    assert hits == []


# ---------------------------------------------------------------------------
# Reentrancy: rollback writes are not CEI violations
# ---------------------------------------------------------------------------

DIVIDEND_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DragonKing {
    address public ETH;
    mapping(address => uint256) public withdrawnDividends;

    function withdrawDividend() public virtual {
        _withdrawDividendOfUser(payable(msg.sender));
    }

    function _withdrawDividendOfUser(address payable user)
        internal
        returns (uint256)
    {
        uint256 _withdrawableDividend = withdrawableDividendOf(user);
        if (_withdrawableDividend > 0) {
            withdrawnDividends[user] = withdrawnDividends[user] + _withdrawableDividend;
            bool success = IERC20(ETH).transfer(user, _withdrawableDividend);
            if (!success) {
                withdrawnDividends[user] = withdrawnDividends[user] - _withdrawableDividend;
                return 0;
            }
            return _withdrawableDividend;
        }
        return 0;
    }

    function withdrawableDividendOf(address _owner)
        public view returns (uint256)
    {
        return withdrawnDividends[_owner];
    }
}
"""


def test_rollback_write_is_not_reentrancy():
    hits = _cand(DIVIDEND_SOURCE, "DragonKing", kind="reentrancy")
    assert hits == []
