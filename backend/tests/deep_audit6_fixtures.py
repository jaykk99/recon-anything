"""Fixtures for the deep-audit batch-6 detectors (Financial +
Oracle slices).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, gate analysis and report_class "candidate" at
the spec severity; VARIANT[id] (recipient-carrying specs
only) carries the same vulnerable shape but the recipient is
FIXED, so it MUST fire with report_class "trigger_only" at
low severity - never a candidate; CLEAN[id] (the protected
shape of the same class) MUST stay silent under ALL nine
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk).
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. unchecked_math_user_input (FIN-001 slice)
# ---------------------------------------------------------------------------

_UNCHECKED_VULN = """
pragma solidity ^0.8.0;
""" + _TOKEN_IFACE + """
contract UncheckedSettleVuln {
    IERC20Like public token;
    uint256 public totalSettled;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function settle(uint256 amount, uint256 feeBps) public onlyOwner {
        uint256 payout;
        unchecked {
            uint256 fee = amount * feeBps / 10000;
            payout = amount - fee;
        }
        totalSettled += payout;
        token.transfer(msg.sender, payout);
    }
}
"""

_UNCHECKED_VARIANT = """
pragma solidity ^0.8.0;
""" + _TOKEN_IFACE + """
contract UncheckedSettleFixedVariant {
    IERC20Like public token;
    uint256 public totalSettled;
    address public owner;
    address public treasury;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        owner = msg.sender;
        treasury = _treasury;
    }

    function settle(uint256 amount, uint256 feeBps) public onlyOwner {
        uint256 payout;
        unchecked {
            uint256 fee = amount * feeBps / 10000;
            payout = amount - fee;
        }
        totalSettled += payout;
        token.transfer(treasury, payout);
    }
}
"""

_UNCHECKED_CLEAN = _TOKEN_IFACE + """
contract UncheckedConstantsClean {
    uint256 public total;

    function bump() public {
        unchecked {
            uint256 step = 100 * 2;
            total += step;
        }
    }
}
"""

_UNCHECKED_CLEAN_LOOP = _TOKEN_IFACE + """
contract UncheckedLoopClean {
    uint256 public total;

    function count(uint256 n) public {
        uint256 acc = 0;
        for (uint256 i = 0; i < n; i++) {
            unchecked {
                acc += 1;
            }
        }
        total = acc;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. strict_balance_equality (FIN-003)
# ---------------------------------------------------------------------------

_BALANCE_VULN = _TOKEN_IFACE + """
contract BalanceGateVuln {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function release(uint256 target, uint256 amount) public {
        require(address(this).balance == target, "not funded exactly");
        token.transfer(msg.sender, amount);
    }
}
"""

_BALANCE_VARIANT = _TOKEN_IFACE + """
contract BalanceGateFixedVariant {
    IERC20Like public token;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function release(uint256 target, uint256 amount) public {
        uint256 bal = address(this).balance;
        require(bal == target, "not funded exactly");
        token.transfer(treasury, amount);
    }
}
"""

_BALANCE_CLEAN = _TOKEN_IFACE + """
contract BalanceGateClean {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function release(uint256 target, uint256 amount) public {
        uint256 bal = address(this).balance;
        require(bal >= target, "underfunded");
        token.transfer(msg.sender, amount);
    }

    function releaseDirect(uint256 target, uint256 amount) public {
        require(address(this).balance > target, "underfunded");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3+4. swap_fixed_min_amount_out (FIN-005) / swap_deadline_unbound (FIN-006)
# ---------------------------------------------------------------------------

_ROUTER_IFACE = """
interface IRouterLike {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory amounts);
    function swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory amounts);
    function swapExactETHForTokens(uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external payable returns (uint256[] memory amounts);
    function swapTokensForExactETH(uint256 amountOut, uint256 amountInMax, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory amounts);
}
"""

_SWAP_MIN_VULN = _ROUTER_IFACE + """
contract SwapFixedMinVuln {
    IRouterLike public router;

    constructor(address _router) {
        router = IRouterLike(_router);
    }

    function swap(uint256 amountIn, address[] calldata path) public {
        router.swapExactTokensForTokens(amountIn, 1000, path, msg.sender, block.timestamp + 600);
    }
}
"""

_SWAP_MIN_VARIANT = _ROUTER_IFACE + """
contract SwapFixedMinFixedVariant {
    IRouterLike public router;
    address public treasury;

    constructor(address _router, address _treasury) {
        router = IRouterLike(_router);
        treasury = _treasury;
    }

    function swap(uint256 amountIn, address[] calldata path) public {
        router.swapExactTokensForTokens(amountIn, 2500, path, treasury, block.timestamp + 600);
    }
}
"""

_SWAP_DEADLINE_VULN = _ROUTER_IFACE + """
contract SwapDeadlineVuln {
    IRouterLike public router;

    constructor(address _router) {
        router = IRouterLike(_router);
    }

    function swap(uint256 amountIn, uint256 minOut, address[] calldata path) public {
        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, 9999999999);
    }
}
"""

_SWAP_DEADLINE_VARIANT = _ROUTER_IFACE + """
contract SwapDeadlineFixedVariant {
    IRouterLike public router;
    address public treasury;

    constructor(address _router, address _treasury) {
        router = IRouterLike(_router);
        treasury = _treasury;
    }

    function swap(uint256 amountIn, uint256 minOut, address[] calldata path) public {
        router.swapExactTokensForTokens(amountIn, minOut, path, treasury, type(uint256).max);
    }
}
"""

_SWAP_CLEAN = _ROUTER_IFACE + """
contract SwapBoundedClean {
    IRouterLike public router;
    uint256 public quotedMinOut;

    constructor(address _router) {
        router = IRouterLike(_router);
    }

    function swap(uint256 amountIn, uint256 minOut, address[] calldata path) public {
        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp + 600);
    }

    function swapEth(address[] calldata path) public payable {
        router.swapExactETHForTokens(quotedMinOut, path, msg.sender, block.timestamp + 300);
    }

    function swapOut(uint256 amountOut, uint256 maxIn, address[] calldata path) public {
        router.swapTokensForExactETH(amountOut, maxIn, path, msg.sender, block.timestamp + 600);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. shadowed_state_variable_legacy (FIN-008 slice)
# ---------------------------------------------------------------------------

_SHADOW_VULN = """
pragma solidity ^0.5.0;

contract ShadowBase {
    uint256 public totalShares;
    address public owner;

    function setShares(uint256 v) public {
        totalShares = v;
    }
}

contract ShadowDerived is ShadowBase {
    uint256 public totalShares;

    function bump(uint256 v) public {
        totalShares = v;
    }
}
"""

_SHADOW_CLEAN = """
pragma solidity ^0.8.0;

contract ShadowBaseModern {
    uint256 public totalShares;
    address public owner;

    function setShares(uint256 v) public {
        totalShares = v;
    }
}

contract ShadowDerivedModern is ShadowBaseModern {
    uint256 public totalShares;

    function bump(uint256 v) public {
        totalShares = v;
    }
}
"""

_SHADOW_CLEAN_NO_SHARED = """
pragma solidity ^0.5.0;

contract LegacyBase {
    uint256 public totalShares;

    function setShares(uint256 v) public {
        totalShares = v;
    }
}

contract LegacyDerived is LegacyBase {
    uint256 public derivedShares;

    function bump(uint256 v) public {
        derivedShares = v;
    }
}
"""

# ---------------------------------------------------------------------------
# 6. hardcoded_decimals_scaling (FIN-009 slice)
# ---------------------------------------------------------------------------

_DECIMALS_VULN = _TOKEN_IFACE + """
contract DecimalsScaleVuln {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function quoteAndSend(uint256 usdAmount) public returns (uint256) {
        uint256 tokens = usdAmount * 1e18;
        token.transfer(msg.sender, tokens);
        return tokens;
    }
}
"""

_DECIMALS_VARIANT = _TOKEN_IFACE + """
contract DecimalsScaleFixedVariant {
    IERC20Like public token;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function quoteAndSend(uint256 usdAmount) public returns (uint256) {
        uint256 tokens = usdAmount * 10 ** 18;
        token.transfer(treasury, tokens);
        return tokens;
    }
}
"""

_DECIMALS_CLEAN = """
interface IERC20Decimals {
    function transfer(address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}
""" + """
contract DecimalsAwareClean {
    IERC20Decimals public token;

    constructor(address _token) {
        token = IERC20Decimals(_token);
    }

    function quoteAndSend(uint256 usdAmount) public returns (uint256) {
        uint256 d = token.decimals();
        uint256 tokens = usdAmount * 10 ** d;
        token.transfer(msg.sender, tokens);
        return tokens;
    }
}
"""

_DECIMALS_CLEAN_INTERNAL = """
contract InternalScaleClean {
    uint256 public totalScaled;

    function scale(uint256 amount) public {
        totalScaled = amount * 1e18;
    }
}
"""

# ---------------------------------------------------------------------------
# 7. twap_observe_window_short (ORC-001 slice)
# ---------------------------------------------------------------------------

_OBSERVE_IFACE = """
interface IPoolObserveLike {
    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
    function consult(address token, uint128 amountIn) external view returns (uint256 amountOut);
}
"""

_TWAP_VULN = _OBSERVE_IFACE + """
contract TwapShortVuln {
    IPoolObserveLike public pool;

    constructor(address _pool) {
        pool = IPoolObserveLike(_pool);
    }

    function twapTick() public view returns (int56) {
        (int56[] memory tickCumulatives, ) = pool.observe([uint32(300), uint32(0)]);
        return tickCumulatives[0];
    }
}
"""

_TWAP_CLEAN = _OBSERVE_IFACE + """
contract TwapLongClean {
    IPoolObserveLike public pool;
    uint32 public constant TWAP_PERIOD = 3600;

    constructor(address _pool) {
        pool = IPoolObserveLike(_pool);
    }

    function twapTick() public view returns (int56) {
        (int56[] memory tickCumulatives, ) = pool.observe([uint32(3600), uint32(0)]);
        return tickCumulatives[0];
    }

    function twapVariable(uint32[] calldata secondsAgos) public view returns (int56) {
        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        return tickCumulatives[0];
    }
}
"""

# ---------------------------------------------------------------------------
# 8. chainlink_price_unbounded (ORC-003)
# ---------------------------------------------------------------------------

_FEED_IFACE = """
interface IPriceFeedLike {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
"""

_CHAINLINK_VULN = _FEED_IFACE + _TOKEN_IFACE + """
contract ChainlinkUnboundedVuln {
    IPriceFeedLike public feed;
    IERC20Like public token;

    constructor(address _feed, address _token) {
        feed = IPriceFeedLike(_feed);
        token = IERC20Like(_token);
    }

    function buy(uint256 amount) public {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(updatedAt > 0, "no round");
        uint256 price = uint256(answer);
        uint256 payout = amount * price / 1000;
        token.transfer(msg.sender, payout);
    }
}
"""

_CHAINLINK_VARIANT = _FEED_IFACE + _TOKEN_IFACE + """
contract ChainlinkUnboundedFixedVariant {
    IPriceFeedLike public feed;
    IERC20Like public token;
    address public treasury;

    constructor(address _feed, address _token, address _treasury) {
        feed = IPriceFeedLike(_feed);
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function buy(uint256 amount) public {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(updatedAt > 0, "no round");
        uint256 price = uint256(answer);
        uint256 payout = amount * price / 1000;
        token.transfer(treasury, payout);
    }
}
"""

_CHAINLINK_CLEAN = _FEED_IFACE + _TOKEN_IFACE + """
contract ChainlinkBoundedClean {
    IPriceFeedLike public feed;
    IERC20Like public token;
    uint256 public constant MIN_PRICE = 100;
    uint256 public constant MAX_PRICE = 10000000;

    constructor(address _feed, address _token) {
        feed = IPriceFeedLike(_feed);
        token = IERC20Like(_token);
    }

    function buy(uint256 amount) public {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(updatedAt > 0, "no round");
        uint256 price = uint256(answer);
        require(price >= MIN_PRICE && price <= MAX_PRICE, "price out of band");
        uint256 payout = amount * price / 1000;
        token.transfer(msg.sender, payout);
    }
}
"""

# ---------------------------------------------------------------------------
# 9. view_price_no_reentrancy_protection (ORC-006 slice)
# ---------------------------------------------------------------------------

_PAIR_IFACE = """
interface IPairLike {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}
"""

_VIEW_PRICE_VULN = _PAIR_IFACE + _TOKEN_IFACE + """
contract UnguardedPriceVuln {
    IPairLike public pair;
    IERC20Like public token;

    constructor(address _pair, address _token) {
        pair = IPairLike(_pair);
        token = IERC20Like(_token);
    }

    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1000000 / uint256(r0);
    }

    function buy(uint256 amount) public {
        token.transfer(msg.sender, amount);
    }
}
"""

_VIEW_PRICE_CLEAN = _PAIR_IFACE + _TOKEN_IFACE + """
contract GuardedPriceClean {
    IPairLike public pair;
    IERC20Like public token;
    uint256 private _status = 1;

    modifier lock() {
        require(_status == 1, "locked");
        _status = 2;
        _;
        _status = 1;
    }

    constructor(address _pair, address _token) {
        pair = IPairLike(_pair);
        token = IERC20Like(_token);
    }

    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1000000 / uint256(r0);
    }

    function buy(uint256 amount) public lock {
        token.transfer(msg.sender, amount);
    }
}
"""

_VIEW_PRICE_CLEAN_NO_WRITERS = _PAIR_IFACE + """
contract ReadOnlyPriceClean {
    IPairLike public pair;

    constructor(address _pair) {
        pair = IPairLike(_pair);
    }

    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1000000 / uint256(r0);
    }
}
"""

VULN = {
    "unchecked_math_user_input": _UNCHECKED_VULN,
    "strict_balance_equality": _BALANCE_VULN,
    "swap_fixed_min_amount_out": _SWAP_MIN_VULN,
    "swap_deadline_unbound": _SWAP_DEADLINE_VULN,
    "shadowed_state_variable_legacy": _SHADOW_VULN,
    "hardcoded_decimals_scaling": _DECIMALS_VULN,
    "twap_observe_window_short": _TWAP_VULN,
    "chainlink_price_unbounded": _CHAINLINK_VULN,
    "view_price_no_reentrancy_protection": _VIEW_PRICE_VULN,
}

VARIANT = {
    "unchecked_math_user_input": _UNCHECKED_VARIANT,
    "strict_balance_equality": _BALANCE_VARIANT,
    "swap_fixed_min_amount_out": _SWAP_MIN_VARIANT,
    "swap_deadline_unbound": _SWAP_DEADLINE_VARIANT,
    "hardcoded_decimals_scaling": _DECIMALS_VARIANT,
    "chainlink_price_unbounded": _CHAINLINK_VARIANT,
}

CLEAN = {
    "unchecked_math_user_input": _UNCHECKED_CLEAN,
    "unchecked_math_user_input_loop": _UNCHECKED_CLEAN_LOOP,
    "strict_balance_equality": _BALANCE_CLEAN,
    "swap_fixed_min_amount_out": _SWAP_CLEAN,
    "swap_deadline_unbound": _SWAP_CLEAN,
    "shadowed_state_variable_legacy": _SHADOW_CLEAN,
    "shadowed_state_variable_legacy_no_shared": _SHADOW_CLEAN_NO_SHARED,
    "hardcoded_decimals_scaling": _DECIMALS_CLEAN,
    "hardcoded_decimals_scaling_internal": _DECIMALS_CLEAN_INTERNAL,
    "twap_observe_window_short": _TWAP_CLEAN,
    "chainlink_price_unbounded": _CHAINLINK_CLEAN,
    "view_price_no_reentrancy_protection": _VIEW_PRICE_CLEAN,
    "view_price_no_reentrancy_protection_no_writers":
        _VIEW_PRICE_CLEAN_NO_WRITERS,
}
