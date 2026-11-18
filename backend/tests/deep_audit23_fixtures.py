"""Fixtures for the deep-audit batch-23 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value lands at a FIXED destination, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate.

Cross-talk by construction:
- The accrual fixture divides accrued interest by a
  net-supply variable (cash + borrows - reserves); its
  EXTRA_CLEAN is the lending-accumulator shape (division by
  plain totalSupply) and MUST stay silent under the accrual
  detector - that is the deep_audit11 adjudication pin.
- The capacity fixture's snapshot is a period-start variable
  the payout never refreshes; its CLEAN refreshes the snapshot
  in the payout and its EXTRA_CLEAN reads live collateral -
  both MUST stay silent. The deep_audit20 cover fixtures (no
  snapshot variable, no collateral reduction in the payout)
  MUST stay silent under the capacity detector - pinned in the
  test file, not here.
- The cap fixture's setter re-arms passSupply; its CLEAN has
  no setter (constructor only) and its EXTRA_CLEAN derives
  the cap from totalSupply() - both MUST stay silent.
- The finalize fixture transfers the whole pot balance; its
  CLEAN sets the closed flag before the transfer, its
  EXTRA_VULN sets the flag after the transfer (still fires).
- The ledger fixture credits without debiting; its CLEAN
  debits the same amount on the same ledger and its
  EXTRA_CLEAN is a pure external token transfer - both MUST
  stay silent.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. interest_accrual_near_zero_denominator_inflation (Kava Lend)
# ---------------------------------------------------------------------------

_ACCRUAL_VULN = _TOKEN_IFACE + """
contract KavaLendVuln {
    IERC20Like public token;
    uint256 public cash;
    uint256 public borrows;
    uint256 public reserves;
    uint256 public netSupply;
    uint256 public accruedInterest;
    uint256 public borrowIndex;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function borrow(uint256 amount, address to) external {
        netSupply = cash + borrows - reserves;
        if (netSupply == 0) return;
        borrowIndex = accruedInterest / netSupply;
        uint256 value = amount * borrowIndex / 1e18;
        token.transfer(to, value);
    }
}
"""

_ACCRUAL_VARIANT = _TOKEN_IFACE + """
contract KavaLendFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public cash;
    uint256 public borrows;
    uint256 public reserves;
    uint256 public netSupply;
    uint256 public accruedInterest;
    uint256 public borrowIndex;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function borrow(uint256 amount) external {
        netSupply = cash + borrows - reserves;
        if (netSupply == 0) return;
        borrowIndex = accruedInterest / netSupply;
        uint256 value = amount * borrowIndex / 1e18;
        token.transfer(treasury, value);
    }
}
"""

# A minimum-denominator floor: the near-zero path is closed.
_ACCRUAL_CLEAN = _TOKEN_IFACE + """
contract KavaLendClean {
    IERC20Like public token;
    uint256 public cash;
    uint256 public borrows;
    uint256 public reserves;
    uint256 public netSupply;
    uint256 public accruedInterest;
    uint256 public borrowIndex;
    uint256 public constant MIN_SUPPLY = 1000;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function borrow(uint256 amount, address to) external {
        netSupply = cash + borrows - reserves;
        require(netSupply >= MIN_SUPPLY, "net supply too low");
        borrowIndex = accruedInterest / netSupply;
        uint256 value = amount * borrowIndex / 1e18;
        token.transfer(to, value);
    }
}
"""

# The lending-accumulator shape (deep_audit11): the rate divides
# by plain totalSupply, not by a net-supply expression - so the
# accrual-denominator detector MUST stay silent here.
_ACCRUAL_EXTRA_CLEAN = _TOKEN_IFACE + """
contract ZTokenMarketShape {
    IERC20Like public token;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function exchangeRate() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return token.balanceOf(address(this)) * 1e18 / totalSupply;
    }

    function deposit(uint256 amount, address to) external {
        uint256 shares = amount * 1e18 / exchangeRate();
        balanceOf[to] += shares;
        totalSupply += shares;
        token.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 shares, address to) external {
        uint256 amount = shares * exchangeRate() / 1e18;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        token.transfer(to, amount);
    }
}
"""

# The totalSupply-minus-reserves spelling of the same bug.
_ACCRUAL_EXTRA_VULN = _TOKEN_IFACE + """
contract KavaLendInline {
    IERC20Like public token;
    uint256 public totalSupply;
    uint256 public reserves;
    uint256 public accruedInterest;
    uint256 public borrowIndex;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function borrow(uint256 amount, address to) external {
        if (totalSupply == reserves) return;
        borrowIndex = accruedInterest / (totalSupply - reserves);
        uint256 value = amount * borrowIndex / 1e18;
        token.transfer(to, value);
    }
}
"""

# Live-corpus false-positive regressions (2026-11-16 live run):
# a reflection token's _getRate divides rSupply by tSupply,
# where tSupply is totalSupply minus excluded balances - a
# subtraction-derived denominator, but there is no borrow /
# collateral consumer and the rate only feeds reflection
# conversions. The detector must stay silent.
_ACCRUAL_EXTRA_CLEAN_REFLECTION = _TOKEN_IFACE + """
contract ReflectionRateShape {
    IERC20Like public token;
    uint256 public _rTotal;
    uint256 public _tTotal;
    mapping(address => uint256) public _rOwned;
    mapping(address => uint256) public _tOwned;
    address[] public _excluded;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _getRate() private view returns (uint256) {
        (uint256 rSupply, uint256 tSupply) = _getCurrentSupply();
        return rSupply / tSupply;
    }

    function _getCurrentSupply() private view returns (uint256, uint256) {
        uint256 rSupply = _rTotal;
        uint256 tSupply = _tTotal;
        for (uint256 i = 0; i < _excluded.length; i++) {
            if (_rOwned[_excluded[i]] > rSupply || _tOwned[_excluded[i]] > tSupply) return (_rTotal, _tTotal);
            rSupply = rSupply - _rOwned[_excluded[i]];
            tSupply = tSupply - _tOwned[_excluded[i]];
        }
        if (rSupply < _rTotal / _tTotal) return (_rTotal, _tTotal);
        return (rSupply, tSupply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 rate = _getRate();
        uint256 rAmount = amount * rate;
        return token.transfer(to, rAmount);
    }
}
"""

# Live-corpus false-positive regression (2026-11-16 live run):
# a staking reward-per-share distribute divides the rewards by
# totalShares, where totalShares is updated by subtraction -
# a subtraction-derived denominator, but the payout is pro-rata
# to the caller's own shares and there is no borrow / collateral
# consumer. The detector must stay silent.
_ACCRUAL_EXTRA_CLEAN_REWARD = _TOKEN_IFACE + """
contract RewardPerShareShape {
    IERC20Like public token;
    uint256 public totalShares;
    uint256 public tokenPerShare;
    uint256 public constant SCALE_FACTOR = 1e18;
    uint256 public constant PRECISION = 1e18;

    struct Share {
        uint256 amount;
    }
    mapping(address => Share) public shares;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function updateShares(address user, uint256 balance) external {
        totalShares = totalShares - shares[user].amount + balance;
        shares[user].amount = balance;
    }

    function distribute(uint256 amountToDistribute) public {
        if (totalShares == 0) return;
        tokenPerShare += (amountToDistribute * SCALE_FACTOR * PRECISION) / totalShares;
    }

    function claim() external {
        uint256 reward = shares[msg.sender].amount * tokenPerShare / PRECISION;
        token.transfer(msg.sender, reward);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. stale_capacity_snapshot_after_payout (Firelight #88615)
# ---------------------------------------------------------------------------

_CAPACITY_VULN = _TOKEN_IFACE + """
contract CoverAllocatorVuln {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public periodStartCapacity;
    uint256 public soldCover;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function startPeriod() external {
        periodStartCapacity = totalCollateral;
    }

    function availableCapacity() public view returns (uint256) {
        return periodStartCapacity - soldCover;
    }

    function sellCover(uint256 amount, address recipient) external {
        require(amount <= availableCapacity(), "exceeds capacity");
        soldCover += amount;
        token.transfer(recipient, amount);
    }

    function payClaim(uint256 amount) external {
        totalCollateral -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_CAPACITY_VARIANT = _TOKEN_IFACE + """
contract CoverAllocatorFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public totalCollateral;
    uint256 public periodStartCapacity;
    uint256 public soldCover;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function startPeriod() external {
        periodStartCapacity = totalCollateral;
    }

    function availableCapacity() public view returns (uint256) {
        return periodStartCapacity - soldCover;
    }

    function sellCover(uint256 amount) external {
        require(amount <= availableCapacity(), "exceeds capacity");
        soldCover += amount;
        token.transfer(treasury, amount);
    }

    function payClaim(uint256 amount) external {
        totalCollateral -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# The payout refreshes the snapshot: capacity stays live.
_CAPACITY_CLEAN = _TOKEN_IFACE + """
contract CoverAllocatorClean {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public periodStartCapacity;
    uint256 public soldCover;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function startPeriod() external {
        periodStartCapacity = totalCollateral;
    }

    function availableCapacity() public view returns (uint256) {
        return periodStartCapacity - soldCover;
    }

    function sellCover(uint256 amount, address recipient) external {
        require(amount <= availableCapacity(), "exceeds capacity");
        soldCover += amount;
        token.transfer(recipient, amount);
    }

    function payClaim(uint256 amount) external {
        totalCollateral -= amount;
        periodStartCapacity = totalCollateral;
        token.transfer(msg.sender, amount);
    }
}
"""

# Capacity reads live collateral: no stale snapshot is consumed.
_CAPACITY_EXTRA_CLEAN = _TOKEN_IFACE + """
contract CoverAllocatorLive {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public periodStartCapacity;
    uint256 public soldCover;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function startPeriod() external {
        periodStartCapacity = totalCollateral;
    }

    function availableCapacity() public view returns (uint256) {
        return totalCollateral - soldCover;
    }

    function sellCover(uint256 amount, address recipient) external {
        require(amount <= availableCapacity(), "exceeds capacity");
        soldCover += amount;
        token.transfer(recipient, amount);
    }

    function payClaim(uint256 amount) external {
        totalCollateral -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. cap_counter_reset_by_setter (Beatland M-01)
# ---------------------------------------------------------------------------

_CAP_VULN = _TOKEN_IFACE + """
contract PassSaleVuln {
    IERC20Like public token;
    uint256 public passSupply;
    uint256 public maxSupply = 1000;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function configurePass(uint256 _passSupply) external {
        passSupply = _passSupply;
    }

    function buyPass(uint256 amount) external {
        require(passSupply + amount <= maxSupply, "sold out");
        passSupply += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_CAP_VARIANT = _TOKEN_IFACE + """
contract PassSaleFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public passSupply;
    uint256 public maxSupply = 1000;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function configurePass(uint256 _passSupply) external {
        passSupply = _passSupply;
    }

    function buyPass(uint256 amount) external {
        require(passSupply + amount <= maxSupply, "sold out");
        passSupply += amount;
        token.transfer(treasury, amount);
    }
}
"""

# No setter: the counter is only ever written by the buy path
# (and never in the constructor either - it starts at zero).
_CAP_CLEAN = _TOKEN_IFACE + """
contract PassSaleClean {
    IERC20Like public token;
    uint256 public passSupply;
    uint256 public maxSupply = 1000;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function buyPass(uint256 amount) external {
        require(passSupply + amount <= maxSupply, "sold out");
        passSupply += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# The cap is derived from totalSupply() directly, not from the
# resettable counter - the setter cannot re-arm the cap.
_CAP_EXTRA_CLEAN = _TOKEN_IFACE + """
contract PassSaleTotalSupply {
    IERC20Like public token;
    uint256 public passSupply;
    uint256 public maxSupply = 1000;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function totalSupply() public view returns (uint256) {
        return passSupply;
    }

    function configurePass(uint256 _passSupply) external {
        passSupply = _passSupply;
    }

    function buyPass(uint256 amount) external {
        require(totalSupply() + amount <= maxSupply, "sold out");
        passSupply += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# The setter resets the counter to zero outright.
_CAP_EXTRA_VULN = _TOKEN_IFACE + """
contract PassSaleResetZero {
    IERC20Like public token;
    uint256 public passSupply;
    uint256 public maxSupply = 1000;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function resetPassSupply() external {
        passSupply = 0;
    }

    function buyPass(uint256 amount) external {
        require(passSupply + amount <= maxSupply, "sold out");
        passSupply += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. finalize_recallable_drains_pot (MyCut H-4)
# ---------------------------------------------------------------------------

_FINALIZE_VULN = _TOKEN_IFACE + """
contract PotVuln {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function closePot() external {
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}
"""

_FINALIZE_VARIANT = _TOKEN_IFACE + """
contract PotFixed {
    IERC20Like public token;
    address public treasury;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function closePot() external {
        token.transfer(treasury, token.balanceOf(address(this)));
    }
}
"""

# The finalized flag is checked at entry AND set before the
# transfer: a second call reverts before moving value.
_FINALIZE_CLEAN = _TOKEN_IFACE + """
contract PotClean {
    IERC20Like public token;
    bool public closed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function closePot() external {
        require(!closed, "already closed");
        closed = true;
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}
"""

# The flag is checked at entry but only set AFTER the transfer:
# the transfer itself is unguarded, so this still fires.
_FINALIZE_EXTRA_VULN = _TOKEN_IFACE + """
contract PotFlagAfter {
    IERC20Like public token;
    bool public closed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function closePot() external {
        require(!closed, "already closed");
        token.transfer(msg.sender, token.balanceOf(address(this)));
        closed = true;
    }
}
"""

# ---------------------------------------------------------------------------
# 5. internal_transfer_credit_without_debit (Arcus Perps)
# ---------------------------------------------------------------------------

_LEDGER_VULN = _TOKEN_IFACE + """
contract LedgerVuln {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function transferBetween(address from, address to, uint256 amount) external {
        balances[to] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_LEDGER_VARIANT = _TOKEN_IFACE + """
contract LedgerFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function transferBetween(address from, address to, uint256 amount) external {
        balances[to] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        token.transfer(treasury, amount);
    }
}
"""

# The transfer debits the same amount on the same ledger:
# zero-sum, so nothing is created.
_LEDGER_CLEAN = _TOKEN_IFACE + """
contract LedgerClean {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function transferBetween(address from, address to, uint256 amount) external {
        balances[from] -= amount;
        balances[to] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# A pure external token transfer: no internal ledger is written.
_LEDGER_EXTRA_CLEAN = _TOKEN_IFACE + """
contract LedgerExternal {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function transferBetween(address from, address to, uint256 amount) external {
        token.transferFrom(from, to, amount);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

VULN = {
    "interest_accrual_near_zero_denominator_inflation": _ACCRUAL_VULN,
    "stale_capacity_snapshot_after_payout": _CAPACITY_VULN,
    "cap_counter_reset_by_setter": _CAP_VULN,
    "finalize_recallable_drains_pot": _FINALIZE_VULN,
    "internal_transfer_credit_without_debit": _LEDGER_VULN,
}

CLEAN = {
    "interest_accrual_near_zero_denominator_inflation": _ACCRUAL_CLEAN,
    "stale_capacity_snapshot_after_payout": _CAPACITY_CLEAN,
    "cap_counter_reset_by_setter": _CAP_CLEAN,
    "finalize_recallable_drains_pot": _FINALIZE_CLEAN,
    "internal_transfer_credit_without_debit": _LEDGER_CLEAN,
}

VARIANT = {
    "interest_accrual_near_zero_denominator_inflation": _ACCRUAL_VARIANT,
    "stale_capacity_snapshot_after_payout": _CAPACITY_VARIANT,
    "cap_counter_reset_by_setter": _CAP_VARIANT,
    "finalize_recallable_drains_pot": _FINALIZE_VARIANT,
    "internal_transfer_credit_without_debit": _LEDGER_VARIANT,
}

EXTRA_CLEAN = {
    "interest_accrual_near_zero_denominator_inflation": _ACCRUAL_EXTRA_CLEAN,
    "interest_accrual_near_zero_denominator_inflation_reflection": _ACCRUAL_EXTRA_CLEAN_REFLECTION,
    "interest_accrual_near_zero_denominator_inflation_reward": _ACCRUAL_EXTRA_CLEAN_REWARD,
    "stale_capacity_snapshot_after_payout": _CAPACITY_EXTRA_CLEAN,
    "cap_counter_reset_by_setter": _CAP_EXTRA_CLEAN,
    "finalize_recallable_drains_pot": _FINALIZE_CLEAN,
    "internal_transfer_credit_without_debit": _LEDGER_EXTRA_CLEAN,
}

EXTRA_VULN = {
    "interest_accrual_near_zero_denominator_inflation": _ACCRUAL_EXTRA_VULN,
    "cap_counter_reset_by_setter": _CAP_EXTRA_VULN,
    "finalize_recallable_drains_pot": _FINALIZE_EXTRA_VULN,
}
