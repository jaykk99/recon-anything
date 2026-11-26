"""Fixtures for the deep-audit batch-30 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and gate analysis. The two vault-swap
detectors fire as candidates (high severity); the OFT
detector fires without a candidate classification (medium,
fund-locking class - the batch-28 period-exit precedent);
the two hook-fee detectors fire trigger-only at low severity
with recipient FIXED (the fee lands at the hook itself - the
batch-21 redeem_burns_shares_for_zero_assets precedent).
VARIANT[id] (vault swaps only) carries the same vulnerable
shape but the payout lands at a FIXED destination, so it
MUST fire trigger-only at low severity - never a candidate.
CLEAN[id] (the protected shape of the same class) MUST stay
silent under ALL five detectors.

Cross-talk by construction: the OFT fixture credits through
an internal ledger (no _mint, no digest, no lzReceive); the
hook fixtures carry a poolManager caller check, are CEI-clean
(no token callback, no delta take) and compute no fee in the
other detector's shape (#2's VULN branches correctly on the
legs only in afterSwap terms - it never computes a fee from
the unspecified amount; #3's VULN computes its fee from the
realised delta in afterSwap and never from amountSpecified
in beforeSwap); the vault fixtures reset the router approval
to zero after the swap in #4's VULN (so #5 stays silent)
and verify the sold token was taken in #5's VULN (so #4
stays silent), both sum every valuation leg unconditionally
(so share_price_excludes_subthreshold_collateral stays
silent), call a FIXED router through a typed interface
method (so settlement_swap_executes_caller_target_spends_
approvals stays silent - the attacker-controlled part is
the ORDER, not the target), and measure deposits by balance
delta with a dead-share bootstrap (so fee_on_transfer_
overcredit and vault_share_inflation stay silent).
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}
"""

_ROUTER_IFACE = """
interface ISwapRouter {
    function executeOrder(bytes calldata order) external;
}
"""

_HOOK_STUBS = """
interface IPoolManager {
    struct SwapParams {
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
    }
}

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

struct BalanceDelta {
    int128 amount0;
    int128 amount1;
}

struct BeforeSwapDelta {
    int128 specifiedDelta;
    int128 unspecifiedDelta;
}

function toBeforeSwapDelta(int128 specified, int128 unspecified) pure returns (BeforeSwapDelta memory) {
    return BeforeSwapDelta(specified, unspecified);
}
"""

# ---------------------------------------------------------------------------
# 1. oft_credit_accumulator_underflow
# ---------------------------------------------------------------------------

_OFT_VULN = _TOKEN_IFACE + """
contract MyOFTVuln {
    IERC20Like public token;
    mapping(address => uint256) public balances;
    mapping(uint32 => bool) public peers;
    uint256 public totalBridgedOut;

    constructor(address _token) {
        token = IERC20Like(_token);
        peers[1] = true;
    }

    function _credit(address to, uint256 amount) internal override {
        totalBridgedOut -= amount;
        balances[to] += amount;
    }

    function send(uint32 dstEid, address to, uint256 amount) external {
        require(peers[dstEid], "unknown peer");
        require(amount <= balances[msg.sender], "insufficient balance");
        balances[msg.sender] -= amount;
        _credit(to, amount);
    }
}
"""

# The subtraction is guarded: protected shape.
_OFT_CLEAN = _TOKEN_IFACE + """
contract MyOFTClean {
    IERC20Like public token;
    mapping(address => uint256) public balances;
    mapping(uint32 => bool) public peers;
    uint256 public totalBridgedOut;

    constructor(address _token) {
        token = IERC20Like(_token);
        peers[1] = true;
    }

    function _credit(address to, uint256 amount) internal override {
        require(totalBridgedOut >= amount, "underflow");
        totalBridgedOut -= amount;
        balances[to] += amount;
    }

    function send(uint32 dstEid, address to, uint256 amount) external {
        require(peers[dstEid], "unknown peer");
        require(amount <= balances[msg.sender], "insufficient balance");
        balances[msg.sender] -= amount;
        _credit(to, amount);
    }
}
"""

# The accumulator is initialized in the constructor: the
# subtraction can no longer underflow on first credit.
_OFT_INITIALIZED = _TOKEN_IFACE + """
contract MyOFTInitialized {
    IERC20Like public token;
    mapping(address => uint256) public balances;
    mapping(uint32 => bool) public peers;
    uint256 public totalBridgedOut;

    constructor(address _token) {
        token = IERC20Like(_token);
        peers[1] = true;
        totalBridgedOut = 1000;
    }

    function _credit(address to, uint256 amount) internal override {
        totalBridgedOut -= amount;
        balances[to] += amount;
    }

    function send(uint32 dstEid, address to, uint256 amount) external {
        require(peers[dstEid], "unknown peer");
        require(amount <= balances[msg.sender], "insufficient balance");
        balances[msg.sender] -= amount;
        _credit(to, amount);
    }
}
"""

# A plain unguarded accumulator subtraction with no OFT
# markers at all: not this detector's class.
_OFT_NO_MARKER = _TOKEN_IFACE + """
contract ReserveVaultPlain {
    IERC20Like public token;
    mapping(address => uint256) public balances;
    uint256 public reserve;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function withdraw(uint256 amount) external {
        require(amount <= balances[msg.sender], "insufficient balance");
        reserve -= amount;
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. hook_fee_on_requested_not_realized
# ---------------------------------------------------------------------------

_HOOK2_VULN = _HOOK_STUBS + """
contract HookFeeRequestedVuln {
    IPoolManager public poolManager;
    uint256 public constant FEE_BPS = 50;
    uint256 public constant BPS = 10000;
    mapping(address => uint256) public storedFee;
    mapping(address => uint256) public storedRequested;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not poolManager");
        _;
    }

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        uint256 amount = params.amountSpecified < 0 ? uint256(-params.amountSpecified) : uint256(params.amountSpecified);
        uint256 fee = amount * FEE_BPS / BPS;
        storedFee[sender] = fee;
        storedRequested[sender] = amount;
        return (this.beforeSwap.selector, toBeforeSwapDelta(-int128(uint128(fee)), 0), 0);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        uint256 fee = storedFee[sender];
        storedFee[sender] = 0;
        storedRequested[sender] = 0;
        return (this.afterSwap.selector, 0);
    }
}
"""

# afterSwap compares the realised delta with the requested
# amount and adjusts the fee on a partial fill.
_HOOK2_CLEAN = _HOOK_STUBS + """
contract HookFeeRequestedClean {
    IPoolManager public poolManager;
    uint256 public constant FEE_BPS = 50;
    uint256 public constant BPS = 10000;
    mapping(address => uint256) public storedFee;
    mapping(address => uint256) public storedRequested;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not poolManager");
        _;
    }

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        uint256 amount = params.amountSpecified < 0 ? uint256(-params.amountSpecified) : uint256(params.amountSpecified);
        uint256 fee = amount * FEE_BPS / BPS;
        storedFee[sender] = fee;
        storedRequested[sender] = amount;
        return (this.beforeSwap.selector, toBeforeSwapDelta(-int128(uint128(fee)), 0), 0);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        uint256 fee = storedFee[sender];
        uint256 requestedAmount = storedRequested[sender];
        int256 delta0 = delta.amount0;
        uint256 realised = delta0 < 0 ? uint256(-delta0) : uint256(delta0);
        require(realised >= requestedAmount, "partial fill: fee exceeds realised");
        uint256 adjustedFee = fee * realised / requestedAmount;
        storedFee[sender] = 0;
        storedRequested[sender] = 0;
        return (this.afterSwap.selector, 0);
    }
}
"""

# beforeSwap charges a fee but there is no afterSwap at all:
# the fee is never collected without a realised check, so
# this detector has nothing to confirm.
_HOOK2_NO_AFTERSWAP = _HOOK_STUBS + """
contract HookFeeNoAfterSwap {
    IPoolManager public poolManager;
    uint256 public constant FEE_BPS = 50;
    uint256 public constant BPS = 10000;
    mapping(address => uint256) public storedFee;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not poolManager");
        _;
    }

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        uint256 amount = params.amountSpecified < 0 ? uint256(-params.amountSpecified) : uint256(params.amountSpecified);
        uint256 fee = amount * FEE_BPS / BPS;
        storedFee[sender] = fee;
        return (this.beforeSwap.selector, toBeforeSwapDelta(-int128(uint128(fee)), 0), 0);
    }
}
"""

# beforeSwap returns a zero delta and charges nothing.
_HOOK2_NO_FEE = _HOOK_STUBS + """
contract HookNoFee {
    IPoolManager public poolManager;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not poolManager");
        _;
    }

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        return (this.beforeSwap.selector, toBeforeSwapDelta(0, 0), 0);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        return (this.afterSwap.selector, 0);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. hook_fee_exact_output_wrong_leg
# ---------------------------------------------------------------------------

_HOOK3_VULN = _HOOK_STUBS + """
contract HookFeeWrongLegVuln {
    IPoolManager public poolManager;
    uint256 public targetOutput = 1000 * 1e18;
    mapping(address => uint256) public feesOwed;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not poolManager");
        _;
    }

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        return (this.beforeSwap.selector, toBeforeSwapDelta(0, 0), 0);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        _afterSwap(sender, key, params, delta, hookData);
        return (this.afterSwap.selector, 0);
    }

    function _afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) internal {
        int256 delta1 = delta.amount1;
        uint256 unspecified = delta1 < 0 ? uint256(-delta1) : uint256(delta1);
        uint256 feeAmount = unspecified - targetOutput;
        feesOwed[sender] += feeAmount;
    }
}
"""

# The fee branches on exactInput: the correct leg per
# direction is used.
_HOOK3_CLEAN = _HOOK_STUBS + """
contract HookFeeWrongLegClean {
    IPoolManager public poolManager;
    uint256 public targetOutput = 1000 * 1e18;
    mapping(address => uint256) public feesOwed;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not poolManager");
        _;
    }

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        return (this.beforeSwap.selector, toBeforeSwapDelta(0, 0), 0);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        _afterSwap(sender, key, params, delta, hookData);
        return (this.afterSwap.selector, 0);
    }

    function _afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) internal {
        int256 delta1 = delta.amount1;
        uint256 unspecified = delta1 < 0 ? uint256(-delta1) : uint256(delta1);
        bool exactInput = params.amountSpecified < 0;
        uint256 feeAmount;
        if (exactInput) {
            feeAmount = unspecified - targetOutput;
        } else {
            feeAmount = targetOutput - unspecified;
        }
        feesOwed[sender] += feeAmount;
    }
}
"""

# afterSwap charges a flat fee with no leg arithmetic at all.
_HOOK3_NO_LEG_MATH = _HOOK_STUBS + """
contract HookFeeFlat {
    IPoolManager public poolManager;
    uint256 public flatFee = 1e15;
    mapping(address => uint256) public feesOwed;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not poolManager");
        _;
    }

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        return (this.beforeSwap.selector, toBeforeSwapDelta(0, 0), 0);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        feesOwed[sender] += flatFee;
        return (this.afterSwap.selector, 0);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. swap_fake_order_no_sold_token_check
# ---------------------------------------------------------------------------

_VAULT_PREAMBLE = """
    IERC20Like public bold;
    IERC20Like public weth;
    ISwapRouter public router;
    uint256 public wethPrice = 3000 * 1e18;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    constructor(address _bold, address _weth, address _router) {
        bold = IERC20Like(_bold);
        weth = IERC20Like(_weth);
        router = ISwapRouter(_router);
        _mint(address(0), 1000);
        totalSupply = 1000;
    }

    function _mint(address to, uint256 amount) internal {
        shares[to] += amount;
        totalSupply += amount;
    }

    function totalAssets() public view returns (uint256) {
        uint256 boldBal = bold.balanceOf(address(this));
        uint256 wethBal = weth.balanceOf(address(this));
        return boldBal + wethBal * wethPrice / 1e18;
    }

    function deposit(uint256 amount) external {
        uint256 before = bold.balanceOf(address(this));
        bold.transferFrom(msg.sender, address(this), amount);
        uint256 received = bold.balanceOf(address(this)) - before;
        uint256 shareAmount = received * totalSupply / totalAssets();
        _mint(msg.sender, shareAmount);
    }
"""

_SWAP4_VULN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SBoldVaultVuln {
""" + _VAULT_PREAMBLE + """
    function swap(address soldToken, uint256 amountIn, bytes calldata order, uint256 minOut) external {
        IERC20Like sold = IERC20Like(soldToken);
        uint256 boldBefore = bold.balanceOf(address(this));
        sold.approve(address(router), amountIn);
        router.executeOrder(order);
        sold.approve(address(router), 0);
        uint256 received = bold.balanceOf(address(this)) - boldBefore;
        require(received >= minOut, "insufficient output");
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

_SWAP4_VARIANT = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SBoldVaultFixed {
""" + _VAULT_PREAMBLE + """
    address public treasury;

    function setTreasury(address _treasury) external {
        treasury = _treasury;
    }

    function swap(address soldToken, uint256 amountIn, bytes calldata order, uint256 minOut) external {
        IERC20Like sold = IERC20Like(soldToken);
        uint256 boldBefore = bold.balanceOf(address(this));
        sold.approve(address(router), amountIn);
        router.executeOrder(order);
        sold.approve(address(router), 0);
        uint256 received = bold.balanceOf(address(this)) - boldBefore;
        require(received >= minOut, "insufficient output");
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(treasury, assets);
    }
}
"""

# The swap verifies the sold token actually left.
_SWAP4_CLEAN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SBoldVaultClean {
""" + _VAULT_PREAMBLE + """
    function swap(address soldToken, uint256 amountIn, bytes calldata order, uint256 minOut) external {
        IERC20Like sold = IERC20Like(soldToken);
        uint256 soldBefore = sold.balanceOf(address(this));
        uint256 boldBefore = bold.balanceOf(address(this));
        sold.approve(address(router), amountIn);
        router.executeOrder(order);
        sold.approve(address(router), 0);
        uint256 soldAfter = sold.balanceOf(address(this));
        require(soldBefore - soldAfter >= amountIn, "sold token not taken");
        uint256 received = bold.balanceOf(address(this)) - boldBefore;
        require(received >= minOut, "insufficient output");
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. swap_approval_leftover_unrevoked
# ---------------------------------------------------------------------------

_SWAP5_VULN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SBoldVaultApprovalVuln {
""" + _VAULT_PREAMBLE + """
    function swap(address soldToken, uint256 amountIn, bytes calldata order, uint256 minOut) external {
        IERC20Like sold = IERC20Like(soldToken);
        uint256 soldBefore = sold.balanceOf(address(this));
        uint256 boldBefore = bold.balanceOf(address(this));
        sold.approve(address(router), type(uint256).max);
        router.executeOrder(order);
        uint256 soldAfter = sold.balanceOf(address(this));
        require(soldBefore - soldAfter >= amountIn, "sold token not taken");
        uint256 received = bold.balanceOf(address(this)) - boldBefore;
        require(received >= minOut, "insufficient output");
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

_SWAP5_VARIANT = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SBoldVaultApprovalFixed {
""" + _VAULT_PREAMBLE + """
    address public treasury;

    function setTreasury(address _treasury) external {
        treasury = _treasury;
    }

    function swap(address soldToken, uint256 amountIn, bytes calldata order, uint256 minOut) external {
        IERC20Like sold = IERC20Like(soldToken);
        uint256 soldBefore = sold.balanceOf(address(this));
        uint256 boldBefore = bold.balanceOf(address(this));
        sold.approve(address(router), type(uint256).max);
        router.executeOrder(order);
        uint256 soldAfter = sold.balanceOf(address(this));
        require(soldBefore - soldAfter >= amountIn, "sold token not taken");
        uint256 received = bold.balanceOf(address(this)) - boldBefore;
        require(received >= minOut, "insufficient output");
        bold.transfer(treasury, received);
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

# The approval is reset to zero right after the swap.
_SWAP5_CLEAN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SBoldVaultApprovalClean {
""" + _VAULT_PREAMBLE + """
    function swap(address soldToken, uint256 amountIn, bytes calldata order, uint256 minOut) external {
        IERC20Like sold = IERC20Like(soldToken);
        uint256 soldBefore = sold.balanceOf(address(this));
        uint256 boldBefore = bold.balanceOf(address(this));
        sold.approve(address(router), type(uint256).max);
        router.executeOrder(order);
        sold.approve(address(router), 0);
        uint256 soldAfter = sold.balanceOf(address(this));
        require(soldBefore - soldAfter >= amountIn, "sold token not taken");
        uint256 received = bold.balanceOf(address(this)) - boldBefore;
        require(received >= minOut, "insufficient output");
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

VULN = {
    "oft_credit_accumulator_underflow": _OFT_VULN,
    "hook_fee_on_requested_not_realized": _HOOK2_VULN,
    "hook_fee_exact_output_wrong_leg": _HOOK3_VULN,
    "swap_fake_order_no_sold_token_check": _SWAP4_VULN,
    "swap_approval_leftover_unrevoked": _SWAP5_VULN,
}

VARIANT = {
    "swap_fake_order_no_sold_token_check": _SWAP4_VARIANT,
    "swap_approval_leftover_unrevoked": _SWAP5_VARIANT,
}

CLEAN = {
    "oft_credit_accumulator_underflow": _OFT_CLEAN,
    "hook_fee_on_requested_not_realized": _HOOK2_CLEAN,
    "hook_fee_exact_output_wrong_leg": _HOOK3_CLEAN,
    "swap_fake_order_no_sold_token_check": _SWAP4_CLEAN,
    "swap_approval_leftover_unrevoked": _SWAP5_CLEAN,
}

EXTRA_CLEAN = {
    "oft_initialized": _OFT_INITIALIZED,
    "oft_no_marker": _OFT_NO_MARKER,
    "hook2_no_afterswap": _HOOK2_NO_AFTERSWAP,
    "hook2_no_fee": _HOOK2_NO_FEE,
    "hook3_no_leg_math": _HOOK3_NO_LEG_MATH,
}
