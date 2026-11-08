"""Fixtures for the deep-audit batch-11 detectors.

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
# 1. amm_scale_rounding_wrong_direction
# ---------------------------------------------------------------------------

_AMM_VULN = _TOKEN_IFACE + """
contract BalancerPoolVuln {
    IERC20Like public tokenIn;
    IERC20Like public tokenOut;
    uint256 public scalingFactor;

    constructor(address _in, address _out, uint256 _factor) {
        tokenIn = IERC20Like(_in);
        tokenOut = IERC20Like(_out);
        scalingFactor = _factor;
    }

    function _upscale(uint256 amount, uint256 scalingFactor) internal pure returns (uint256) {
        return amount * scalingFactor / 1e18;
    }

    function swap(uint256 amountIn, uint256 amountOut, address to) external {
        uint256 scaledOut = _upscale(amountOut, scalingFactor);
        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(to, scaledOut);
    }
}
"""

_AMM_CLEAN = _TOKEN_IFACE + """
contract BalancerPoolClean {
    IERC20Like public tokenIn;
    IERC20Like public tokenOut;
    uint256 public scalingFactor;

    constructor(address _in, address _out, uint256 _factor) {
        tokenIn = IERC20Like(_in);
        tokenOut = IERC20Like(_out);
        scalingFactor = _factor;
    }

    function _upscale(uint256 amount, uint256 scalingFactor) internal pure returns (uint256) {
        return amount.mulUp(scalingFactor);
    }

    function swap(uint256 amountIn, uint256 amountOut, address to) external {
        uint256 scaledOut = _upscale(amountOut, scalingFactor);
        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(to, scaledOut);
    }
}
"""

_AMM_CEIL_DIV = _TOKEN_IFACE + """
contract BalancerPoolCeilDiv {
    IERC20Like public tokenIn;
    IERC20Like public tokenOut;
    uint256 public scalingFactor;

    constructor(address _in, address _out, uint256 _factor) {
        tokenIn = IERC20Like(_in);
        tokenOut = IERC20Like(_out);
        scalingFactor = _factor;
    }

    function _upscale(uint256 amount, uint256 scalingFactor) internal pure returns (uint256) {
        return (amount * scalingFactor + 1e18 - 1) / 1e18;
    }

    function swap(uint256 amountIn, uint256 amountOut, address to) external {
        uint256 scaledOut = _upscale(amountOut, scalingFactor);
        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(to, scaledOut);
    }
}
"""

_AMM_IN_ONLY = _TOKEN_IFACE + """
contract BalancerPoolInOnly {
    IERC20Like public tokenIn;
    IERC20Like public tokenOut;
    uint256 public scalingFactor;

    constructor(address _in, address _out, uint256 _factor) {
        tokenIn = IERC20Like(_in);
        tokenOut = IERC20Like(_out);
        scalingFactor = _factor;
    }

    function _upscale(uint256 amount, uint256 scalingFactor) internal pure returns (uint256) {
        return amount * scalingFactor / 1e18;
    }

    function swap(uint256 amountIn, address to) external {
        uint256 scaledIn = _upscale(amountIn, scalingFactor);
        tokenIn.transferFrom(msg.sender, address(this), scaledIn);
        tokenOut.transfer(to, amountIn);
    }
}
"""

_AMM_VARIANT = _TOKEN_IFACE + """
contract BalancerPoolFixed {
    IERC20Like public tokenIn;
    IERC20Like public tokenOut;
    uint256 public scalingFactor;
    address public treasury;

    constructor(address _in, address _out, uint256 _factor, address _treasury) {
        tokenIn = IERC20Like(_in);
        tokenOut = IERC20Like(_out);
        scalingFactor = _factor;
        treasury = _treasury;
    }

    function _upscale(uint256 amount, uint256 scalingFactor) internal pure returns (uint256) {
        return amount * scalingFactor / 1e18;
    }

    function swap(uint256 amountIn, uint256 amountOut) external {
        uint256 scaledOut = _upscale(amountOut, scalingFactor);
        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(treasury, scaledOut);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. lending_accumulator_donation_inflation
# ---------------------------------------------------------------------------

_LENDING_VULN = _TOKEN_IFACE + """
contract ZTokenMarketVuln {
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

_LENDING_CLEAN = _TOKEN_IFACE + """
contract ZTokenMarketClean {
    IERC20Like public token;
    uint256 public totalSupply;
    uint256 public totalCash;
    mapping(address => uint256) public balanceOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function exchangeRate() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return totalCash * 1e18 / totalSupply;
    }

    function deposit(uint256 amount, address to) external {
        uint256 shares = amount * 1e18 / exchangeRate();
        balanceOf[to] += shares;
        totalSupply += shares;
        totalCash += amount;
        token.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 shares, address to) external {
        uint256 amount = shares * exchangeRate() / 1e18;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalCash -= amount;
        token.transfer(to, amount);
    }
}
"""

_LENDING_MIN_GUARD = _TOKEN_IFACE + """
contract ZTokenMarketMinGuard {
    IERC20Like public token;
    uint256 public totalSupply;
    uint256 public constant MINIMUM_SHARES = 1000;
    mapping(address => uint256) public balanceOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function exchangeRate() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return token.balanceOf(address(this)) * 1e18 / totalSupply;
    }

    function deposit(uint256 amount, address to) external {
        require(amount >= MINIMUM_SHARES, "dust");
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

_LENDING_VARIANT = _TOKEN_IFACE + """
contract ZTokenMarketFixed {
    IERC20Like public token;
    uint256 public totalSupply;
    address public treasury;
    mapping(address => uint256) public balanceOf;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function exchangeRate() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return token.balanceOf(address(this)) * 1e18 / totalSupply;
    }

    function deposit(uint256 amount) external {
        uint256 shares = amount * 1e18 / exchangeRate();
        balanceOf[treasury] += shares;
        totalSupply += shares;
        token.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 shares) external {
        uint256 amount = shares * exchangeRate() / 1e18;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. batch_deferred_check_flag_reset
# ---------------------------------------------------------------------------

_BATCH_VULN = _TOKEN_IFACE + """
contract CauldronCookVuln {
    IERC20Like public mim;
    bool public solvencyCheckRequired;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;

    constructor(address _mim) {
        mim = IERC20Like(_mim);
    }

    function _borrow(address to, uint256 amount) internal {
        solvencyCheckRequired = true;
        userDebt[msg.sender] += amount;
        mim.transfer(to, amount);
    }

    function _noOp() internal {
        solvencyCheckRequired = false;
    }

    function _checkSolvency(address user) internal view {
        require(userCollateral[user] >= userDebt[user], "insolvent");
    }

    function cook(uint8[] calldata actions, address to, uint256 amount) external {
        for (uint256 i = 0; i < actions.length; i++) {
            if (actions[i] == 5) {
                _borrow(to, amount);
            } else if (actions[i] == 0) {
                _noOp();
            }
        }
        if (solvencyCheckRequired) {
            _checkSolvency(msg.sender);
        }
    }
}
"""

_BATCH_CLEAN = _TOKEN_IFACE + """
contract CauldronCookClean {
    IERC20Like public mim;
    bool public solvencyCheckRequired;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;

    constructor(address _mim) {
        mim = IERC20Like(_mim);
    }

    function _borrow(address to, uint256 amount) internal {
        solvencyCheckRequired = true;
        userDebt[msg.sender] += amount;
        mim.transfer(to, amount);
    }

    function _noOp() internal {
    }

    function _checkSolvency(address user) internal view {
        require(userCollateral[user] >= userDebt[user], "insolvent");
    }

    function cook(uint8[] calldata actions, address to, uint256 amount) external {
        for (uint256 i = 0; i < actions.length; i++) {
            if (actions[i] == 5) {
                _borrow(to, amount);
            } else if (actions[i] == 0) {
                _noOp();
            }
        }
        if (solvencyCheckRequired) {
            _checkSolvency(msg.sender);
        }
    }
}
"""

_BATCH_UNCONDITIONAL = _TOKEN_IFACE + """
contract CauldronCookUnconditional {
    IERC20Like public mim;
    bool public solvencyCheckRequired;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;

    constructor(address _mim) {
        mim = IERC20Like(_mim);
    }

    function _borrow(address to, uint256 amount) internal {
        solvencyCheckRequired = true;
        userDebt[msg.sender] += amount;
        mim.transfer(to, amount);
    }

    function _noOp() internal {
        solvencyCheckRequired = false;
    }

    function _checkSolvency(address user) internal view {
        require(userCollateral[user] >= userDebt[user], "insolvent");
    }

    function cook(uint8[] calldata actions, address to, uint256 amount) external {
        for (uint256 i = 0; i < actions.length; i++) {
            if (actions[i] == 5) {
                _borrow(to, amount);
            } else if (actions[i] == 0) {
                _noOp();
            }
        }
        _checkSolvency(msg.sender);
    }
}
"""

_BATCH_VARIANT = _TOKEN_IFACE + """
contract CauldronCookFixed {
    IERC20Like public mim;
    bool public solvencyCheckRequired;
    address public treasury;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;

    constructor(address _mim, address _treasury) {
        mim = IERC20Like(_mim);
        treasury = _treasury;
    }

    function _borrow(uint256 amount) internal {
        solvencyCheckRequired = true;
        userDebt[msg.sender] += amount;
        mim.transfer(treasury, amount);
    }

    function _noOp() internal {
        solvencyCheckRequired = false;
    }

    function _checkSolvency(address user) internal view {
        require(userCollateral[user] >= userDebt[user], "insolvent");
    }

    function cook(uint8[] calldata actions, uint256 amount) external {
        for (uint256 i = 0; i < actions.length; i++) {
            if (actions[i] == 5) {
                _borrow(amount);
            } else if (actions[i] == 0) {
                _noOp();
            }
        }
        if (solvencyCheckRequired) {
            _checkSolvency(msg.sender);
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 4. liquidation_residual_collateral_reborrow
# ---------------------------------------------------------------------------

_LIQUIDATION_VULN = _TOKEN_IFACE + """
contract GMCauldronVuln {
    IERC20Like public collateralToken;
    IERC20Like public mim;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;
    mapping(address => uint256) public userOrders;

    constructor(address _collateral, address _mim) {
        collateralToken = IERC20Like(_collateral);
        mim = IERC20Like(_mim);
    }

    function depositCollateral(uint256 amount) external {
        userCollateral[msg.sender] += amount;
        userOrders[msg.sender] += 1;
        collateralToken.transferFrom(msg.sender, address(this), amount);
    }

    function borrow(uint256 amount, address to) external {
        require(userCollateral[msg.sender] >= amount * 2, "undercollateralized");
        userDebt[msg.sender] += amount;
        mim.transfer(to, amount);
    }

    function liquidate(address borrower) external {
        uint256 seized = userCollateral[borrower];
        userDebt[borrower] = 0;
        collateralToken.transfer(msg.sender, seized);
    }
}
"""

_LIQUIDATION_CLEAN = _TOKEN_IFACE + """
contract GMCauldronClean {
    IERC20Like public collateralToken;
    IERC20Like public mim;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;
    mapping(address => uint256) public userOrders;

    constructor(address _collateral, address _mim) {
        collateralToken = IERC20Like(_collateral);
        mim = IERC20Like(_mim);
    }

    function depositCollateral(uint256 amount) external {
        userCollateral[msg.sender] += amount;
        userOrders[msg.sender] += 1;
        collateralToken.transferFrom(msg.sender, address(this), amount);
    }

    function borrow(uint256 amount, address to) external {
        require(userCollateral[msg.sender] >= amount * 2, "undercollateralized");
        userDebt[msg.sender] += amount;
        mim.transfer(to, amount);
    }

    function liquidate(address borrower) external {
        uint256 seized = userCollateral[borrower];
        userDebt[borrower] = 0;
        userCollateral[borrower] = 0;
        userOrders[borrower] = 0;
        collateralToken.transfer(msg.sender, seized);
    }
}
"""

_LIQUIDATION_VARIANT = _TOKEN_IFACE + """
contract GMCauldronFixed {
    IERC20Like public collateralToken;
    IERC20Like public mim;
    address public treasury;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;
    mapping(address => uint256) public userOrders;

    constructor(address _collateral, address _mim, address _treasury) {
        collateralToken = IERC20Like(_collateral);
        mim = IERC20Like(_mim);
        treasury = _treasury;
    }

    function depositCollateral(uint256 amount) external {
        userCollateral[msg.sender] += amount;
        userOrders[msg.sender] += 1;
        collateralToken.transferFrom(msg.sender, address(this), amount);
    }

    function borrow(uint256 amount, address to) external {
        require(userCollateral[msg.sender] >= amount * 2, "undercollateralized");
        userDebt[msg.sender] += amount;
        mim.transfer(to, amount);
    }

    function liquidate(address borrower) external {
        uint256 seized = userCollateral[borrower];
        userDebt[borrower] = 0;
        collateralToken.transfer(treasury, seized);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. transient_slot_reuse_auth_bypass
# ---------------------------------------------------------------------------

_TRANSIENT_VULN = _TOKEN_IFACE + """
contract SIRVaultVuln {
    IERC20Like public token;
    address public pool;

    constructor(address _token, address _pool) {
        token = IERC20Like(_token);
        pool = _pool;
    }

    function mint(address to, uint256 amount) external returns (uint256 minted) {
        minted = amount * 2;
        address poolAddr = pool;
        assembly {
            tstore(1, poolAddr)
        }
        token.transfer(to, minted);
    }

    function uniswapV3SwapCallback(uint256 amount0, uint256 amount1, bytes calldata data) external {
        address storedPool;
        assembly {
            storedPool := tload(1)
        }
        require(msg.sender == storedPool, "not pool");
        uint256 minted = abi.decode(data, (uint256));
        token.transfer(msg.sender, minted);
        assembly {
            tstore(1, minted)
        }
    }
}
"""

_TRANSIENT_CLEAN = _TOKEN_IFACE + """
contract SIRVaultClean {
    IERC20Like public token;
    address public pool;

    constructor(address _token, address _pool) {
        token = IERC20Like(_token);
        pool = _pool;
    }

    function mint(address to, uint256 amount) external returns (uint256 minted) {
        minted = amount * 2;
        address poolAddr = pool;
        assembly {
            tstore(1, poolAddr)
        }
        token.transfer(to, minted);
    }

    function uniswapV3SwapCallback(uint256 amount0, uint256 amount1, bytes calldata data) external {
        address storedPool;
        assembly {
            storedPool := tload(1)
        }
        require(msg.sender == storedPool, "not pool");
        uint256 minted = abi.decode(data, (uint256));
        token.transfer(msg.sender, minted);
        assembly {
            tstore(2, minted)
        }
    }
}
"""

_TRANSIENT_CLEARED = _TOKEN_IFACE + """
contract SIRVaultCleared {
    IERC20Like public token;
    address public pool;

    constructor(address _token, address _pool) {
        token = IERC20Like(_token);
        pool = _pool;
    }

    function mint(address to, uint256 amount) external returns (uint256 minted) {
        minted = amount * 2;
        address poolAddr = pool;
        assembly {
            tstore(1, poolAddr)
        }
        token.transfer(to, minted);
    }

    function uniswapV3SwapCallback(uint256 amount0, uint256 amount1, bytes calldata data) external {
        address storedPool;
        assembly {
            storedPool := tload(1)
        }
        require(msg.sender == storedPool, "not pool");
        uint256 minted = abi.decode(data, (uint256));
        token.transfer(msg.sender, minted);
        assembly {
            tstore(1, minted)
            tstore(1, 0)
        }
    }
}
"""

_TRANSIENT_VARIANT = _TOKEN_IFACE + """
contract SIRVaultFixed {
    IERC20Like public token;
    address public pool;
    address public treasury;

    constructor(address _token, address _pool, address _treasury) {
        token = IERC20Like(_token);
        pool = _pool;
        treasury = _treasury;
    }

    function mint(address to, uint256 amount) external returns (uint256 minted) {
        minted = amount * 2;
        address poolAddr = pool;
        assembly {
            tstore(1, poolAddr)
        }
        token.transfer(to, minted);
    }

    function uniswapV3SwapCallback(uint256 amount0, uint256 amount1, bytes calldata data) external {
        address storedPool;
        assembly {
            storedPool := tload(1)
        }
        require(msg.sender == storedPool, "not pool");
        uint256 minted = abi.decode(data, (uint256));
        token.transfer(treasury, minted);
        assembly {
            tstore(1, minted)
        }
    }
}
"""

VULN = {
    "amm_scale_rounding_wrong_direction": _AMM_VULN,
    "lending_accumulator_donation_inflation": _LENDING_VULN,
    "batch_deferred_check_flag_reset": _BATCH_VULN,
    "liquidation_residual_collateral_reborrow": _LIQUIDATION_VULN,
    "transient_slot_reuse_auth_bypass": _TRANSIENT_VULN,
}

CLEAN = {
    "amm_scale_rounding_wrong_direction": _AMM_CLEAN,
    "lending_accumulator_donation_inflation": _LENDING_CLEAN,
    "batch_deferred_check_flag_reset": _BATCH_CLEAN,
    "liquidation_residual_collateral_reborrow": _LIQUIDATION_CLEAN,
    "transient_slot_reuse_auth_bypass": _TRANSIENT_CLEAN,
}

VARIANT = {
    "amm_scale_rounding_wrong_direction": _AMM_VARIANT,
    "lending_accumulator_donation_inflation": _LENDING_VARIANT,
    "batch_deferred_check_flag_reset": _BATCH_VARIANT,
    "liquidation_residual_collateral_reborrow": _LIQUIDATION_VARIANT,
    "transient_slot_reuse_auth_bypass": _TRANSIENT_VARIANT,
}

# Extra clean shapes (not the primary CLEAN control, asserted
# separately in the test file).
EXTRA_CLEAN = {
    "amm_scale_rounding_wrong_direction_ceil_div": _AMM_CEIL_DIV,
    "amm_scale_rounding_wrong_direction_in_only": _AMM_IN_ONLY,
    "lending_accumulator_donation_inflation_min_guard": _LENDING_MIN_GUARD,
    "batch_deferred_check_flag_reset_unconditional": _BATCH_UNCONDITIONAL,
    "transient_slot_reuse_auth_bypass_cleared": _TRANSIENT_CLEARED,
}
