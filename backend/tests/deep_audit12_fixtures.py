"""Fixtures for the deep-audit batch-12 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the recipient / power is FIXED, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. zero_amount_withdrawal_full_balance
# ---------------------------------------------------------------------------

_ZERO_VULN = _TOKEN_IFACE + """
contract B14gStakingVuln {
    IERC20Like public token;
    mapping(address => uint256) public stakes;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function stake(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        stakes[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        uint256 staked = stakes[msg.sender];
        require(amount <= staked, "exceeds stake");
        uint256 payout = amount;
        if (amount == 0) {
            payout = staked;
        }
        stakes[msg.sender] = staked - payout;
        token.transfer(msg.sender, payout);
    }
}
"""

_ZERO_CLEAN = _TOKEN_IFACE + """
contract B14gStakingClean {
    IERC20Like public token;
    mapping(address => uint256) public stakes;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function stake(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        stakes[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        uint256 staked = stakes[msg.sender];
        require(amount <= staked, "exceeds stake");
        stakes[msg.sender] = staked - amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_ZERO_VARIANT = _TOKEN_IFACE + """
contract B14gStakingFixed {
    IERC20Like public token;
    mapping(address => uint256) public stakes;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function withdraw(uint256 amount) external {
        uint256 staked = stakes[msg.sender];
        require(amount <= staked, "exceeds stake");
        uint256 payout = amount;
        if (amount == 0) {
            payout = staked;
        }
        stakes[msg.sender] = staked - payout;
        token.transfer(treasury, payout);
    }
}
"""

_ZERO_EXTRA_CLEAN = _TOKEN_IFACE + """
contract B14gStakingStrictAmount {
    IERC20Like public token;
    mapping(address => uint256) public stakes;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function withdraw(uint256 amount) external {
        uint256 staked = stakes[msg.sender];
        require(amount <= staked, "exceeds stake");
        stakes[msg.sender] = staked - amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. scheduled_settlement_books_unpaid
# ---------------------------------------------------------------------------

_SETTLE_VULN = _TOKEN_IFACE + """
contract TranchePoolVuln {
    IERC20Like public token;
    mapping(uint256 => uint256) public dailyPayment;
    mapping(uint256 => uint256) public dayEnd;
    uint256 public outstandingDebt;
    uint256 public totalSettled;
    uint256 public lastSettledDay;

    function settleDay(uint256 day) external {
        require(block.timestamp >= dayEnd[day], "day not over");
        uint256 due = dailyPayment[day];
        outstandingDebt -= due;
        totalSettled += due;
        lastSettledDay = day;
    }
}
"""

_SETTLE_CLEAN = _TOKEN_IFACE + """
contract TranchePoolClean {
    IERC20Like public token;
    mapping(uint256 => uint256) public dailyPayment;
    mapping(uint256 => uint256) public dayEnd;
    uint256 public outstandingDebt;
    uint256 public totalSettled;
    uint256 public lastSettledDay;

    function settleDay(uint256 day) external {
        require(block.timestamp >= dayEnd[day], "day not over");
        uint256 balanceBefore = token.balanceOf(address(this));
        uint256 due = dailyPayment[day];
        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        require(received >= due, "payment not received");
        outstandingDebt -= due;
        totalSettled += due;
        lastSettledDay = day;
    }
}
"""

_SETTLE_VARIANT = _TOKEN_IFACE + """
contract TranchePoolFixed {
    IERC20Like public token;
    mapping(uint256 => uint256) public dailyPayment;
    mapping(uint256 => uint256) public dayEnd;
    uint256 public outstandingDebt;
    uint256 public totalSettled;
    uint256 public lastSettledDay;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function settleDay(uint256 day) external {
        require(block.timestamp >= dayEnd[day], "day not over");
        uint256 due = dailyPayment[day];
        outstandingDebt -= due;
        totalSettled += due;
        lastSettledDay = day;
        token.transfer(treasury, due / 100);
    }
}
"""

_SETTLE_EXTRA_CLEAN = _TOKEN_IFACE + """
contract TranchePoolNoBooking {
    IERC20Like public token;
    mapping(uint256 => uint256) public dailyPayment;
    mapping(uint256 => uint256) public dayEnd;
    uint256 public lastSettledDay;

    function settleDay(uint256 day) external {
        require(block.timestamp >= dayEnd[day], "day not over");
        lastSettledDay = day;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. vesting_release_cancel_double_debit
# ---------------------------------------------------------------------------

_VESTING_VULN = _TOKEN_IFACE + """
contract UncxVestingVuln {
    IERC20Like public token;
    uint256 public totalShares;
    uint256 public tokenPerShare;

    struct Position {
        uint256 shares;
        uint256 released;
        address beneficiary;
    }

    mapping(uint256 => Position) public positions;

    function release(uint256 positionId) external {
        Position storage position = positions[positionId];
        uint256 releasableShares = position.shares / 2;
        uint256 amount = releasableShares * tokenPerShare;
        totalShares -= releasableShares;
        position.released += amount;
        token.transfer(position.beneficiary, amount);
    }

    function cancel(uint256 positionId) external {
        Position storage position = positions[positionId];
        totalShares -= position.shares;
        uint256 remaining = position.shares * tokenPerShare;
        delete positions[positionId];
        token.transfer(msg.sender, remaining);
    }
}
"""

_VESTING_CLEAN = _TOKEN_IFACE + """
contract UncxVestingClean {
    IERC20Like public token;
    uint256 public totalShares;
    uint256 public tokenPerShare;

    struct Position {
        uint256 shares;
        uint256 released;
        address beneficiary;
    }

    mapping(uint256 => Position) public positions;

    function release(uint256 positionId) external {
        Position storage position = positions[positionId];
        uint256 releasableShares = position.shares / 2;
        uint256 amount = releasableShares * tokenPerShare;
        totalShares -= releasableShares;
        position.shares -= releasableShares;
        position.released += amount;
        token.transfer(position.beneficiary, amount);
    }

    function cancel(uint256 positionId) external {
        Position storage position = positions[positionId];
        totalShares -= position.shares;
        uint256 remaining = position.shares * tokenPerShare;
        delete positions[positionId];
        token.transfer(msg.sender, remaining);
    }
}
"""

_VESTING_VARIANT = _TOKEN_IFACE + """
contract UncxVestingFixed {
    IERC20Like public token;
    uint256 public totalShares;
    uint256 public tokenPerShare;
    address public treasury;

    struct Position {
        uint256 shares;
        uint256 released;
        address beneficiary;
    }

    mapping(uint256 => Position) public positions;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function release(uint256 positionId) external {
        Position storage position = positions[positionId];
        uint256 releasableShares = position.shares / 2;
        uint256 amount = releasableShares * tokenPerShare;
        totalShares -= releasableShares;
        position.released += amount;
        token.transfer(position.beneficiary, amount);
    }

    function cancel(uint256 positionId) external {
        Position storage position = positions[positionId];
        totalShares -= position.shares;
        uint256 remaining = position.shares * tokenPerShare;
        delete positions[positionId];
        token.transfer(treasury, remaining);
    }
}
"""

_VESTING_EXTRA_CLEAN = _TOKEN_IFACE + """
contract UncxVestingNoTotal {
    IERC20Like public token;
    uint256 public tokenPerShare;

    struct Position {
        uint256 shares;
        uint256 released;
        address beneficiary;
    }

    mapping(uint256 => Position) public positions;

    function release(uint256 positionId) external {
        Position storage position = positions[positionId];
        uint256 releasableShares = position.shares / 2;
        uint256 amount = releasableShares * tokenPerShare;
        position.shares -= releasableShares;
        position.released += amount;
        token.transfer(position.beneficiary, amount);
    }

    function cancel(uint256 positionId) external {
        Position storage position = positions[positionId];
        uint256 remaining = position.shares * tokenPerShare;
        delete positions[positionId];
        token.transfer(msg.sender, remaining);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. intent_deposit_ghost_credit_no_rollback
# ---------------------------------------------------------------------------

_GHOST_VULN = _TOKEN_IFACE + """
contract HotOmniIntentVuln {
    mapping(address => uint256) public balances;

    function deposit(address token, uint256 amount) external {
        balances[msg.sender] += amount;
        IERC20Like(token).transferFrom(msg.sender, address(this), amount);
        _routeIntent(token, amount);
    }

    function _routeIntent(address token, uint256 amount) internal {
        (bool ok, ) = token.call(abi.encodeWithSignature("route(uint256)", amount));
        require(ok, "route failed");
    }

    function refundFailedDeposit(address token, address user, uint256 amount) external {
        IERC20Like(token).transfer(user, amount);
    }

    function withdraw(address token, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        IERC20Like(token).transfer(msg.sender, amount);
    }
}
"""

_GHOST_CLEAN = _TOKEN_IFACE + """
contract HotOmniIntentClean {
    mapping(address => uint256) public balances;

    function deposit(address token, uint256 amount) external {
        IERC20Like(token).transferFrom(msg.sender, address(this), amount);
        _routeIntent(token, amount);
        balances[msg.sender] += amount;
    }

    function _routeIntent(address token, uint256 amount) internal {
        (bool ok, ) = token.call(abi.encodeWithSignature("route(uint256)", amount));
        require(ok, "route failed");
    }

    function refundFailedDeposit(address token, address user, uint256 amount) external {
        IERC20Like(token).transfer(user, amount);
    }

    function withdraw(address token, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        IERC20Like(token).transfer(msg.sender, amount);
    }
}
"""

_GHOST_VARIANT = _TOKEN_IFACE + """
contract HotOmniIntentFixed {
    mapping(address => uint256) public balances;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function deposit(address token, uint256 amount) external {
        balances[msg.sender] += amount;
        IERC20Like(token).transferFrom(msg.sender, address(this), amount);
        _routeIntent(token, amount);
    }

    function _routeIntent(address token, uint256 amount) internal {
        (bool ok, ) = token.call(abi.encodeWithSignature("route(uint256)", amount));
        require(ok, "route failed");
    }

    function refundFailedDeposit(address token, uint256 amount) external {
        IERC20Like(token).transfer(treasury, amount);
    }

    function withdraw(address token, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        IERC20Like(token).transfer(msg.sender, amount);
    }
}
"""

_GHOST_EXTRA_CLEAN = _TOKEN_IFACE + """
contract HotOmniIntentRefundClears {
    mapping(address => uint256) public balances;

    function deposit(address token, uint256 amount) external {
        balances[msg.sender] += amount;
        IERC20Like(token).transferFrom(msg.sender, address(this), amount);
        _routeIntent(token, amount);
    }

    function _routeIntent(address token, uint256 amount) internal {
        (bool ok, ) = token.call(abi.encodeWithSignature("route(uint256)", amount));
        require(ok, "route failed");
    }

    function refundFailedDeposit(address token, address user, uint256 amount) external {
        balances[user] = 0;
        IERC20Like(token).transfer(user, amount);
    }

    function withdraw(address token, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        IERC20Like(token).transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. aa_execute_ungated
# ---------------------------------------------------------------------------

_AA_VULN = """
contract SimpleSmartAccountVuln {
    address public owner;
    address public entryPoint;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    function executeBatch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas) external payable {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call{value: values[i]}(datas[i]);
            require(ok, "call failed");
        }
    }
}
"""

_AA_CLEAN = """
contract SimpleSmartAccountClean {
    address public owner;
    address public entryPoint;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    function execute(address target, uint256 value, bytes calldata data) external payable onlyOwner returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    function executeBatch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas) external payable onlyOwner {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call{value: values[i]}(datas[i]);
            require(ok, "call failed");
        }
    }
}
"""

_AA_VARIANT = """
contract SimpleSmartAccountFixed {
    address public owner;
    address public entryPoint;
    address public treasury;

    constructor(address _owner, address _entryPoint, address _treasury) {
        owner = _owner;
        entryPoint = _entryPoint;
        treasury = _treasury;
    }

    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = treasury.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }
}
"""

_AA_EXTRA_CLEAN = """
contract SimpleSmartAccountEntryPoint {
    address public owner;
    address public entryPoint;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        require(msg.sender == entryPoint, "not entrypoint");
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }
}
"""

VULN = {
    "zero_amount_withdrawal_full_balance": _ZERO_VULN,
    "scheduled_settlement_books_unpaid": _SETTLE_VULN,
    "vesting_release_cancel_double_debit": _VESTING_VULN,
    "intent_deposit_ghost_credit_no_rollback": _GHOST_VULN,
    "aa_execute_ungated": _AA_VULN,
}

CLEAN = {
    "zero_amount_withdrawal_full_balance": _ZERO_CLEAN,
    "scheduled_settlement_books_unpaid": _SETTLE_CLEAN,
    "vesting_release_cancel_double_debit": _VESTING_CLEAN,
    "intent_deposit_ghost_credit_no_rollback": _GHOST_CLEAN,
    "aa_execute_ungated": _AA_CLEAN,
}

VARIANT = {
    "zero_amount_withdrawal_full_balance": _ZERO_VARIANT,
    "scheduled_settlement_books_unpaid": _SETTLE_VARIANT,
    "vesting_release_cancel_double_debit": _VESTING_VARIANT,
    "intent_deposit_ghost_credit_no_rollback": _GHOST_VARIANT,
    "aa_execute_ungated": _AA_VARIANT,
}

EXTRA_CLEAN = {
    "zero_amount_withdrawal_full_balance": _ZERO_EXTRA_CLEAN,
    "scheduled_settlement_books_unpaid": _SETTLE_EXTRA_CLEAN,
    "vesting_release_cancel_double_debit": _VESTING_EXTRA_CLEAN,
    "intent_deposit_ghost_credit_no_rollback": _GHOST_EXTRA_CLEAN,
    "aa_execute_ungated": _AA_EXTRA_CLEAN,
}
