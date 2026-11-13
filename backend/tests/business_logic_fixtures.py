"""Fixtures for the business-logic invariant detectors.

VULN: the vulnerable shape (must fire as a candidate, high
severity, with code/detail/function/gate_analysis and a
caller-reachable recipient).
VARIANT: the same shape with the value landing at a FIXED
destination (must fire as trigger_only, low severity, never a
candidate).
CLEAN: the protected shape (must stay silent under ALL five
detectors).

Each detector is exercised by its own VULN / VARIANT / CLEAN
triple; the shape-(a) reward accumulator (balance-derived) has
its own extra VULN entry.
"""
from __future__ import annotations

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function decimals() external view returns (uint8);
}

interface IPriceFeed {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
"""

# ---------------------------------------------------------------------------
# 1. rounding_iterated_drain
# ---------------------------------------------------------------------------

_ROUNDING_VULN = _TOKEN_IFACE + """
contract VaultRoundingVuln {
    IERC20Like public asset;
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;

    function deposit(uint256 amount, address to) external {
        uint256 minted = amount * totalSupply / totalAssets;
        balanceOf[to] += minted;
        totalSupply += minted;
        totalAssets += amount;
        asset.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 s, address to) external {
        uint256 amount = s * totalAssets / totalSupply;
        balanceOf[msg.sender] -= s;
        totalSupply -= s;
        totalAssets -= amount;
        asset.transfer(to, amount);
    }
}
"""

_ROUNDING_VARIANT = _TOKEN_IFACE + """
contract VaultRoundingFixed {
    IERC20Like public asset;
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function deposit(uint256 amount) external {
        uint256 minted = amount * totalSupply / totalAssets;
        balanceOf[treasury] += minted;
        totalSupply += minted;
        totalAssets += amount;
        asset.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 s) external {
        uint256 amount = s * totalAssets / totalSupply;
        balanceOf[treasury] -= s;
        totalSupply -= s;
        totalAssets -= amount;
        asset.transfer(treasury, amount);
    }
}
"""

_ROUNDING_CLEAN = _TOKEN_IFACE + """
contract VaultRoundingGuarded {
    IERC20Like public asset;
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;
    uint256 public constant MIN_DEPOSIT = 1000;

    function deposit(uint256 amount, address to) external {
        require(amount >= MIN_DEPOSIT, "too small");
        uint256 minted = amount * totalSupply / totalAssets;
        balanceOf[to] += minted;
        totalSupply += minted;
        totalAssets += amount;
        asset.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 s, address to) external {
        uint256 amount = s * totalAssets / totalSupply;
        balanceOf[msg.sender] -= s;
        totalSupply -= s;
        totalAssets -= amount;
        asset.transfer(to, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. reward_distribution_manipulation
# ---------------------------------------------------------------------------

_REWARD_VULN = _TOKEN_IFACE + """
contract StakingRewardsVuln {
    IERC20Like public stakeToken;
    IERC20Like public rewardToken;
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;

    function rewardPerToken() public view returns (uint256) {
        return rewardPerTokenStored;
    }

    function earned(address account) public view returns (uint256) {
        return balances[account] * rewardPerTokenStored / 1e18;
    }

    function updateReward(address account) public {
        rewardPerTokenStored = rewardPerTokenStored + 1;
        rewards[account] = earned(account);
    }

    function stake(uint256 amount) external {
        balances[msg.sender] += amount;
        totalSupply += amount;
        updateReward(msg.sender);
        stakeToken.transferFrom(msg.sender, address(this), amount);
    }

    function claim() external {
        updateReward(msg.sender);
        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }
}
"""

# Shape (a): the accumulator itself is computed from the raw
# token balance, so any deposit inflates the rate.
_REWARD_VULN_A = _TOKEN_IFACE + """
contract StakingRewardsBalanceVuln {
    IERC20Like public stakeToken;
    IERC20Like public rewardToken;
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;

    function earned(address account) public view returns (uint256) {
        return balances[account] * rewardPerTokenStored / 1e18;
    }

    function updateReward(address account) public {
        rewardPerTokenStored = rewardToken.balanceOf(address(this)) * 1e18 / totalSupply;
        rewards[account] = earned(account);
    }

    function stake(uint256 amount) external {
        updateReward(msg.sender);
        balances[msg.sender] += amount;
        totalSupply += amount;
        stakeToken.transferFrom(msg.sender, address(this), amount);
    }

    function claim() external {
        updateReward(msg.sender);
        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }
}
"""

_REWARD_VARIANT = _TOKEN_IFACE + """
contract StakingRewardsFixed {
    IERC20Like public stakeToken;
    IERC20Like public rewardToken;
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function earned(address account) public view returns (uint256) {
        return balances[account] * rewardPerTokenStored / 1e18;
    }

    function updateReward(address account) public {
        rewardPerTokenStored = rewardPerTokenStored + 1;
        rewards[account] = earned(account);
    }

    function stake(uint256 amount) external {
        balances[treasury] += amount;
        totalSupply += amount;
        updateReward(treasury);
        stakeToken.transferFrom(msg.sender, address(this), amount);
    }

    function claim() external {
        updateReward(treasury);
        uint256 reward = rewards[treasury];
        rewards[treasury] = 0;
        rewardToken.transfer(treasury, reward);
    }
}
"""

_REWARD_CLEAN = _TOKEN_IFACE + """
contract StakingRewardsGuarded {
    IERC20Like public stakeToken;
    IERC20Like public rewardToken;
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;

    function earned(address account) public view returns (uint256) {
        return balances[account] * rewardPerTokenStored / 1e18;
    }

    function updateReward(address account) public {
        rewardPerTokenStored = rewardPerTokenStored + 1;
        rewards[account] = earned(account);
    }

    function stake(uint256 amount) external {
        updateReward(msg.sender);
        balances[msg.sender] += amount;
        totalSupply += amount;
        stakeToken.transferFrom(msg.sender, address(this), amount);
    }

    function claim() external {
        updateReward(msg.sender);
        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. flashloan_same_block_state_inconsistency
# ---------------------------------------------------------------------------

_FLASH_VULN = _TOKEN_IFACE + """
contract FlashLoanCallbackVuln {
    IERC20Like public token;
    uint256 public exchangeRate;
    uint256 public totalDeposits;

    function onFlashLoan(address initiator, address token_, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {
        totalDeposits += amount;
        exchangeRate = token.balanceOf(address(this)) * 1e18 / totalDeposits;
        uint256 out = amount * exchangeRate / 1e18;
        totalDeposits -= amount;
        token.transfer(msg.sender, out);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
"""

_FLASH_VARIANT = _TOKEN_IFACE + """
contract FlashLoanCallbackFixed {
    IERC20Like public token;
    uint256 public exchangeRate;
    uint256 public totalDeposits;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function onFlashLoan(address initiator, address token_, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {
        totalDeposits += amount;
        exchangeRate = token.balanceOf(address(this)) * 1e18 / totalDeposits;
        uint256 out = amount * exchangeRate / 1e18;
        totalDeposits -= amount;
        token.transfer(treasury, out);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
"""

_FLASH_CLEAN = _TOKEN_IFACE + """
contract FlashLoanCallbackGuarded {
    IERC20Like public token;
    uint256 public exchangeRate;
    uint256 public storedRate;
    uint256 public totalDeposits;
    uint256 public lastUpdateBlock;

    function onFlashLoan(address initiator, address token_, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {
        require(block.number > lastUpdateBlock, "same block");
        totalDeposits += amount;
        exchangeRate = storedRate;
        uint256 out = amount * exchangeRate / 1e18;
        totalDeposits -= amount;
        token.transfer(msg.sender, out);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
"""

# ---------------------------------------------------------------------------
# 4. multistep_state_order_violation
# ---------------------------------------------------------------------------

_ORDER_VULN = _TOKEN_IFACE + """
contract LendingOrderVuln {
    IERC20Like public token;
    mapping(address => uint256) public borrows;
    mapping(address => uint256) public collateral;
    uint256 public totalBorrows;

    function isSolvent(address account) public view returns (bool) {
        return collateral[account] >= borrows[account];
    }

    function borrow(uint256 amount, address to) external {
        require(isSolvent(msg.sender), "insolvent");
        borrows[msg.sender] += amount;
        totalBorrows += amount;
        token.transfer(to, amount);
    }
}
"""

_ORDER_VARIANT = _TOKEN_IFACE + """
contract LendingOrderFixed {
    IERC20Like public token;
    mapping(address => uint256) public borrows;
    mapping(address => uint256) public collateral;
    uint256 public totalBorrows;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function isSolvent(address account) public view returns (bool) {
        return collateral[account] >= borrows[account];
    }

    function borrow(uint256 amount) external {
        require(isSolvent(msg.sender), "insolvent");
        borrows[msg.sender] += amount;
        totalBorrows += amount;
        token.transfer(treasury, amount);
    }
}
"""

_ORDER_CLEAN = _TOKEN_IFACE + """
contract LendingOrderGuarded {
    IERC20Like public token;
    mapping(address => uint256) public borrows;
    mapping(address => uint256) public collateral;
    uint256 public totalBorrows;

    function isSolvent(address account) public view returns (bool) {
        return collateral[account] >= borrows[account];
    }

    function borrow(uint256 amount, address to) external {
        borrows[msg.sender] += amount;
        totalBorrows += amount;
        require(isSolvent(msg.sender), "insolvent");
        token.transfer(to, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. oracle_trust_assumption_break
# ---------------------------------------------------------------------------

_ORACLE_VULN = _TOKEN_IFACE + """
contract OracleLendingVuln {
    IERC20Like public token;
    IPriceFeed public feed;
    mapping(address => uint256) public borrows;

    function borrow(uint256 amount, address to) external {
        (, int256 price, , , ) = feed.latestRoundData();
        uint256 value = amount * uint256(price) / 1e8;
        require(value > 0, "zero value");
        borrows[msg.sender] += amount;
        token.transfer(to, amount);
    }
}
"""

_ORACLE_VARIANT = _TOKEN_IFACE + """
contract OracleLendingFixed {
    IERC20Like public token;
    IPriceFeed public feed;
    mapping(address => uint256) public borrows;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function borrow(uint256 amount) external {
        (, int256 price, , , ) = feed.latestRoundData();
        uint256 value = amount * uint256(price) / 1e8;
        require(value > 0, "zero value");
        borrows[msg.sender] += amount;
        token.transfer(treasury, amount);
    }
}
"""

_ORACLE_CLEAN = _TOKEN_IFACE + """
contract OracleLendingGuarded {
    IERC20Like public token;
    IPriceFeed public feed;
    mapping(address => uint256) public borrows;

    function borrow(uint256 amount, address to) external {
        (uint80 roundId, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(updatedAt > block.timestamp - 3600, "stale price");
        require(price > 0, "bad price");
        uint256 value = amount * uint256(price) / 1e8;
        borrows[msg.sender] += amount;
        token.transfer(to, amount);
    }
}
"""

FIXTURES = {
    "rounding_iterated_drain": {
        "vuln": _ROUNDING_VULN,
        "variant": _ROUNDING_VARIANT,
        "clean": _ROUNDING_CLEAN,
    },
    "reward_distribution_manipulation": {
        "vuln": _REWARD_VULN,
        "vuln_a": _REWARD_VULN_A,
        "variant": _REWARD_VARIANT,
        "clean": _REWARD_CLEAN,
    },
    "flashloan_same_block_state_inconsistency": {
        "vuln": _FLASH_VULN,
        "variant": _FLASH_VARIANT,
        "clean": _FLASH_CLEAN,
    },
    "multistep_state_order_violation": {
        "vuln": _ORDER_VULN,
        "variant": _ORDER_VARIANT,
        "clean": _ORDER_CLEAN,
    },
    "oracle_trust_assumption_break": {
        "vuln": _ORACLE_VULN,
        "variant": _ORACLE_VARIANT,
        "clean": _ORACLE_CLEAN,
    },
}
