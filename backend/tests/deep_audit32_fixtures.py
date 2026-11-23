"""Fixtures for the deep-audit batch-32 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (the two recipient
detectors #1 and #2); detectors #3, #4 and #5 fire WITHOUT a
recipient classification (batch-28 period-exit precedent: #3
the caller is the victim of their own unbounded swap, #4 a
privileged freeze landing on users, #5 the credited recipient
is the FIXED router). VARIANT[id] (bridge redeem only)
carries the same vulnerable shape but the payout lands at a
FIXED treasury, so it MUST fire with report_class
"trigger_only" at low severity - never a candidate.
CLEAN[id] (the protected shape of the same class) MUST stay
silent under ALL five detectors; EXTRA_VULN carries the
second firing shape of the swap detector (an exactOutput call
with no max-input bound at all).

Cross-talk by construction: the bridge fixture redeems at a
fixed 1:1 rate but mints nothing (so
bridge_wrapped_token_mint_unbacked stays silent), reads no
oracle (so chainlink_price_unbounded stays silent) and
carries no signature / proof words on the release path; the
validator fixture carries a real ecrecover check, an
EntryPoint caller check, an address(0) check on the recovered
signer, and a nonce + deadline mention (so
aa_validation_ungated, ecrecover_zero_signer and
permit_signature_replay stay silent); the swap fixture has no
amountOutMin == 0 and no deadline == type(uint).max (so
cp_proto_unbounded_slippage stays silent) and approves
nothing; the period fixture names no checkpoint, capacity,
snapshot, rescue or bucket anywhere (so the period
checkpoint / capacity / rescue detectors stay silent); the
hook fixtures carry a poolManager caller check, are CEI-clean
(no token callback, no delta take) and compute no fee from
amountSpecified or on the wrong leg (so the hook-fee pair
stays silent).

Note on the bridge FIXED variant: the task's "FIXED variant:
redeem that reads a pause flag" is the CLEAN shape here (a
pause / circuit-breaker check on the redeem path is listed
in the task's own CLEAN line), so the pause-flag redeem is
CLEAN["bridge_redeem_no_peg_circuit_breaker"]-pause and stays
silent; the VARIANT is the batch-convention FIXED-recipient
shape (payout to a fixed treasury), which fires trigger-only.
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

_ROUTER_IFACE = """
interface ISwapRouter {
    struct ExactOutputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountOut;
        uint256 amountInMaximum;
        uint160 sqrtPriceLimitX96;
    }
    function exactOutputSingle(ExactOutputSingleParams calldata params) external returns (uint256 amountIn);
}
"""

# ---------------------------------------------------------------------------
# 1. bridge_redeem_no_peg_circuit_breaker
# ---------------------------------------------------------------------------

_BRIDGE_VULN = _TOKEN_IFACE + """
contract AceBridge {
    IERC20Like public wrappedAce;
    IERC20Like public reserveAce;
    mapping(address => uint256) public wrappedBalances;
    uint256 public totalWrappedBurned;

    constructor(address _wrapped, address _reserve) {
        wrappedAce = IERC20Like(_wrapped);
        reserveAce = IERC20Like(_reserve);
    }

    function redeem(uint256 amount) external {
        require(amount <= wrappedBalances[msg.sender], "insufficient wrapped balance");
        require(amount > 0, "zero amount");
        wrappedBalances[msg.sender] -= amount;
        totalWrappedBurned += amount;
        wrappedAce.burnFrom(msg.sender, amount);
        require(reserveAce.transfer(msg.sender, amount), "transfer failed");
    }

    function depositReserve(uint256 amount) external {
        require(reserveAce.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }
}
"""

_BRIDGE_VARIANT = _TOKEN_IFACE + """
contract AceBridgeFixedTreasury {
    IERC20Like public wrappedAce;
    IERC20Like public reserveAce;
    address public treasury;
    mapping(address => uint256) public wrappedBalances;
    uint256 public totalWrappedBurned;

    constructor(address _wrapped, address _reserve, address _treasury) {
        wrappedAce = IERC20Like(_wrapped);
        reserveAce = IERC20Like(_reserve);
        treasury = _treasury;
    }

    function redeem(uint256 amount) external {
        require(amount <= wrappedBalances[msg.sender], "insufficient wrapped balance");
        require(amount > 0, "zero amount");
        wrappedBalances[msg.sender] -= amount;
        totalWrappedBurned += amount;
        wrappedAce.burnFrom(msg.sender, amount);
        require(reserveAce.transfer(treasury, amount), "transfer failed");
    }

    function depositReserve(uint256 amount) external {
        require(reserveAce.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }
}
"""

# The redeem prices off a live peg feed with a bound.
_BRIDGE_CLEAN = _TOKEN_IFACE + """
interface IAcePriceFeed {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract AceBridgeClean {
    IERC20Like public wrappedAce;
    IERC20Like public reserveAce;
    IAcePriceFeed public priceFeed;
    int256 public constant MIN_PEG_PRICE = 95e16;
    mapping(address => uint256) public wrappedBalances;
    uint256 public totalWrappedBurned;

    constructor(address _wrapped, address _reserve, address _feed) {
        wrappedAce = IERC20Like(_wrapped);
        reserveAce = IERC20Like(_reserve);
        priceFeed = IAcePriceFeed(_feed);
    }

    function redeem(uint256 amount) external {
        require(amount <= wrappedBalances[msg.sender], "insufficient wrapped balance");
        require(amount > 0, "zero amount");
        (, int256 price, , , ) = priceFeed.latestRoundData();
        require(price >= MIN_PEG_PRICE, "peg broken");
        wrappedBalances[msg.sender] -= amount;
        totalWrappedBurned += amount;
        wrappedAce.burnFrom(msg.sender, amount);
        require(reserveAce.transfer(msg.sender, amount), "transfer failed");
    }

    function depositReserve(uint256 amount) external {
        require(reserveAce.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }
}
"""

# The redeem is gated by a pause flag (the task's FIXED
# variant shape: a pause read is the protected shape here).
_BRIDGE_CLEAN_PAUSE = _TOKEN_IFACE + """
contract AceBridgePaused {
    IERC20Like public wrappedAce;
    IERC20Like public reserveAce;
    bool public paused;
    mapping(address => uint256) public wrappedBalances;
    uint256 public totalWrappedBurned;

    constructor(address _wrapped, address _reserve) {
        wrappedAce = IERC20Like(_wrapped);
        reserveAce = IERC20Like(_reserve);
    }

    function redeem(uint256 amount) external {
        require(!paused, "paused");
        require(amount <= wrappedBalances[msg.sender], "insufficient wrapped balance");
        require(amount > 0, "zero amount");
        wrappedBalances[msg.sender] -= amount;
        totalWrappedBurned += amount;
        wrappedAce.burnFrom(msg.sender, amount);
        require(reserveAce.transfer(msg.sender, amount), "transfer failed");
    }

    function depositReserve(uint256 amount) external {
        require(reserveAce.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }
}
"""

# The redeem pays a computed amount (shares * rate), not the
# same amount burned: not a fixed 1:1 rate.
_BRIDGE_CLEAN_COMPUTED = _TOKEN_IFACE + """
contract AceBridgeComputed {
    IERC20Like public wrappedAce;
    IERC20Like public reserveAce;
    uint256 public rate = 1e18;
    mapping(address => uint256) public wrappedBalances;
    uint256 public totalWrappedBurned;

    constructor(address _wrapped, address _reserve) {
        wrappedAce = IERC20Like(_wrapped);
        reserveAce = IERC20Like(_reserve);
    }

    function redeem(uint256 amount) external {
        require(amount <= wrappedBalances[msg.sender], "insufficient wrapped balance");
        require(amount > 0, "zero amount");
        wrappedBalances[msg.sender] -= amount;
        totalWrappedBurned += amount;
        wrappedAce.burnFrom(msg.sender, amount);
        uint256 payout = amount * rate / 1e18;
        require(reserveAce.transfer(msg.sender, payout), "transfer failed");
    }

    function depositReserve(uint256 amount) external {
        require(reserveAce.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }
}
"""

# ---------------------------------------------------------------------------
# 2. aa_validator_owner_branch_no_execution_policy
# ---------------------------------------------------------------------------

_VALIDATOR_VULN = """
struct UserOpIntent {
    address sender;
    uint256 nonce;
    address target;
    bytes4 selector;
    uint256 value;
    bytes signature;
}

struct SessionKey {
    uint256 deadline;
    uint256 valueCap;
}

contract SessionAccountValidator {
    address public owner;
    address public entryPoint;
    mapping(address => bool) public sessionKeys;
    mapping(address => SessionKey) public sessionKeyData;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public allowedTargets;
    mapping(bytes4 => bool) public allowedSelectors;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(entryPoint), "only entry point");
    }

    function isTargetAllowed(address target) internal view returns (bool) {
        return allowedTargets[target];
    }

    function isSelectorAllowed(bytes4 selector) internal view returns (bool) {
        return allowedSelectors[selector];
    }

    function validateUserOp(UserOpIntent calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256 validationData) {
        _requireFromEntryPoint();
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(userOp.signature, (uint8, bytes32, bytes32));
        address recovered = ecrecover(userOpHash, v, r, s);
        require(recovered != address(0), "invalid signature");
        if (recovered == owner) {
            return 0;
        }
        if (sessionKeys[recovered]) {
            SessionKey memory key = sessionKeyData[recovered];
            require(block.timestamp <= key.deadline, "session expired");
            require(userOp.nonce == nonces[userOp.sender], "bad nonce");
            require(isTargetAllowed(userOp.target), "target not allowed");
            require(isSelectorAllowed(userOp.selector), "selector not allowed");
            require(userOp.value <= key.valueCap, "value over cap");
            return 0;
        }
        return 1;
    }
}
"""

# The owner branch is policy-checked too.
_VALIDATOR_CLEAN = """
struct UserOpIntent {
    address sender;
    uint256 nonce;
    address target;
    bytes4 selector;
    uint256 value;
    bytes signature;
}

struct SessionKey {
    uint256 deadline;
    uint256 valueCap;
}

contract SessionAccountValidatorClean {
    address public owner;
    address public entryPoint;
    uint256 public ownerValueCap;
    mapping(address => bool) public sessionKeys;
    mapping(address => SessionKey) public sessionKeyData;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public allowedTargets;
    mapping(bytes4 => bool) public allowedSelectors;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(entryPoint), "only entry point");
    }

    function isTargetAllowed(address target) internal view returns (bool) {
        return allowedTargets[target];
    }

    function isSelectorAllowed(bytes4 selector) internal view returns (bool) {
        return allowedSelectors[selector];
    }

    function validateUserOp(UserOpIntent calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256 validationData) {
        _requireFromEntryPoint();
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(userOp.signature, (uint8, bytes32, bytes32));
        address recovered = ecrecover(userOpHash, v, r, s);
        require(recovered != address(0), "invalid signature");
        if (recovered == owner) {
            require(isTargetAllowed(userOp.target), "target not allowed");
            require(isSelectorAllowed(userOp.selector), "selector not allowed");
            require(userOp.value <= ownerValueCap, "value over cap");
            return 0;
        }
        if (sessionKeys[recovered]) {
            SessionKey memory key = sessionKeyData[recovered];
            require(block.timestamp <= key.deadline, "session expired");
            require(userOp.nonce == nonces[userOp.sender], "bad nonce");
            require(isTargetAllowed(userOp.target), "target not allowed");
            require(isSelectorAllowed(userOp.selector), "selector not allowed");
            require(userOp.value <= key.valueCap, "value over cap");
            return 0;
        }
        return 1;
    }
}
"""

# Single-branch validator: owner only, no session branch.
_VALIDATOR_CLEAN_SINGLE = """
struct UserOpIntent {
    address sender;
    uint256 nonce;
    address target;
    bytes4 selector;
    uint256 value;
    bytes signature;
}

contract SingleBranchValidator {
    address public owner;
    address public entryPoint;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(entryPoint), "only entry point");
    }

    function validateUserOp(UserOpIntent calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256 validationData) {
        _requireFromEntryPoint();
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(userOp.signature, (uint8, bytes32, bytes32));
        address recovered = ecrecover(userOpHash, v, r, s);
        require(recovered != address(0), "invalid signature");
        if (recovered == owner) {
            return 0;
        }
        return 1;
    }
}
"""

# Two branches, but no policy anywhere: the session branch
# returns valid with no target / selector / value check.
_VALIDATOR_CLEAN_NO_POLICY = """
struct UserOpIntent {
    address sender;
    uint256 nonce;
    address target;
    bytes4 selector;
    uint256 value;
    bytes signature;
}

contract NoPolicyValidator {
    address public owner;
    address public entryPoint;
    mapping(address => bool) public sessionKeys;
    mapping(address => uint256) public nonces;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(entryPoint), "only entry point");
    }

    function validateUserOp(UserOpIntent calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256 validationData) {
        _requireFromEntryPoint();
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(userOp.signature, (uint8, bytes32, bytes32));
        address recovered = ecrecover(userOpHash, v, r, s);
        require(recovered != address(0), "invalid signature");
        if (recovered == owner) {
            return 0;
        }
        if (sessionKeys[recovered]) {
            require(userOp.nonce == nonces[userOp.sender], "bad nonce");
            return 0;
        }
        return 1;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. swap_exact_output_unbounded_max_input
# ---------------------------------------------------------------------------

_SWAP_VULN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapHelper {
    ISwapRouter public router;

    constructor(address _router) {
        router = ISwapRouter(_router);
    }

    function swapExactOutput(address tokenIn, address tokenOut, uint256 amountOut, address recipient) external returns (uint256 amountIn) {
        amountIn = router.exactOutputSingle(ISwapRouter.ExactOutputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: 3000,
            recipient: recipient,
            amountOut: amountOut,
            amountInMaximum: type(uint256).max,
            sqrtPriceLimitX96: 0
        }));
    }
}
"""

# No max-input bound at all: the struct literal omits
# amountInMaximum entirely.
_SWAP_VULN_NO_BOUND = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapHelperNoBound {
    ISwapRouter public router;

    constructor(address _router) {
        router = ISwapRouter(_router);
    }

    function swapExactOutput(address tokenIn, address tokenOut, uint256 amountOut, address recipient) external returns (uint256 amountIn) {
        amountIn = router.exactOutputSingle(ISwapRouter.ExactOutputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: 3000,
            recipient: recipient,
            amountOut: amountOut,
            sqrtPriceLimitX96: 0
        }));
    }
}
"""

# Caller-supplied slippage parameter bounds the input.
_SWAP_CLEAN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapHelperClean {
    ISwapRouter public router;

    constructor(address _router) {
        router = ISwapRouter(_router);
    }

    function swapExactOutput(address tokenIn, address tokenOut, uint256 amountOut, uint256 maxInput, address recipient) external returns (uint256 amountIn) {
        amountIn = router.exactOutputSingle(ISwapRouter.ExactOutputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: 3000,
            recipient: recipient,
            amountOut: amountOut,
            amountInMaximum: maxInput,
            sqrtPriceLimitX96: 0
        }));
    }
}
"""

# Computed cap: 5% over the requested output.
_SWAP_CLEAN_COMPUTED = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapHelperComputedCap {
    ISwapRouter public router;

    constructor(address _router) {
        router = ISwapRouter(_router);
    }

    function swapExactOutput(address tokenIn, address tokenOut, uint256 amountOut, address recipient) external returns (uint256 amountIn) {
        amountIn = router.exactOutputSingle(ISwapRouter.ExactOutputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: 3000,
            recipient: recipient,
            amountOut: amountOut,
            amountInMaximum: amountOut * 105 / 100,
            sqrtPriceLimitX96: 0
        }));
    }
}
"""

# The params struct is passed straight through from the
# caller: the bound (or lack of one) is the caller's, not
# the helper's.
_SWAP_CLEAN_PASSTHROUGH = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapHelperPassthrough {
    ISwapRouter public router;

    constructor(address _router) {
        router = ISwapRouter(_router);
    }

    function swapExactOutput(ISwapRouter.ExactOutputSingleParams calldata params) external returns (uint256 amountIn) {
        amountIn = router.exactOutputSingle(params);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. period_config_no_upper_bound_no_escape
# ---------------------------------------------------------------------------

_PERIOD_VULN = _TOKEN_IFACE + """
contract PeriodVault {
    IERC20Like public token;
    address public owner;
    uint256 public constant MIN_LOCKUP = 1 days;

    struct PeriodConfig {
        uint256 lockupDuration;
        bool active;
    }

    struct Deposit {
        uint256 amount;
        uint256 start;
    }

    mapping(uint256 => PeriodConfig) public periodConfigs;
    mapping(address => Deposit) public deposits;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function addPeriodConfiguration(uint256 periodId, uint256 lockupDuration) external onlyOwner {
        require(!periodConfigs[periodId].active, "already configured");
        require(lockupDuration >= MIN_LOCKUP, "lockup too short");
        periodConfigs[periodId] = PeriodConfig(lockupDuration, true);
    }

    function deposit(uint256 periodId, uint256 amount) external {
        require(periodConfigs[periodId].active, "unknown period");
        deposits[msg.sender] = Deposit(amount, block.timestamp);
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }

    function withdraw(uint256 periodId) external {
        Deposit memory dep = deposits[msg.sender];
        require(block.timestamp >= dep.start + periodConfigs[periodId].lockupDuration, "still locked");
        deposits[msg.sender].amount = 0;
        require(token.transfer(msg.sender, dep.amount), "transfer failed");
    }
}
"""

# Same setter WITH an upper bound.
_PERIOD_CLEAN = _TOKEN_IFACE + """
contract PeriodVaultBounded {
    IERC20Like public token;
    address public owner;
    uint256 public constant MIN_LOCKUP = 1 days;
    uint256 public constant MAX_LOCKUP = 365 days;

    struct PeriodConfig {
        uint256 lockupDuration;
        bool active;
    }

    struct Deposit {
        uint256 amount;
        uint256 start;
    }

    mapping(uint256 => PeriodConfig) public periodConfigs;
    mapping(address => Deposit) public deposits;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function addPeriodConfiguration(uint256 periodId, uint256 lockupDuration) external onlyOwner {
        require(!periodConfigs[periodId].active, "already configured");
        require(lockupDuration >= MIN_LOCKUP, "lockup too short");
        require(lockupDuration <= MAX_LOCKUP, "lockup too long");
        periodConfigs[periodId] = PeriodConfig(lockupDuration, true);
    }

    function deposit(uint256 periodId, uint256 amount) external {
        require(periodConfigs[periodId].active, "unknown period");
        deposits[msg.sender] = Deposit(amount, block.timestamp);
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }

    function withdraw(uint256 periodId) external {
        Deposit memory dep = deposits[msg.sender];
        require(block.timestamp >= dep.start + periodConfigs[periodId].lockupDuration, "still locked");
        deposits[msg.sender].amount = 0;
        require(token.transfer(msg.sender, dep.amount), "transfer failed");
    }
}
"""

# Same setter, but a cancel path exists.
_PERIOD_CLEAN_CANCEL = _TOKEN_IFACE + """
contract PeriodVaultCancellable {
    IERC20Like public token;
    address public owner;
    uint256 public constant MIN_LOCKUP = 1 days;

    struct PeriodConfig {
        uint256 lockupDuration;
        bool active;
    }

    struct Deposit {
        uint256 amount;
        uint256 start;
    }

    mapping(uint256 => PeriodConfig) public periodConfigs;
    mapping(address => Deposit) public deposits;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function addPeriodConfiguration(uint256 periodId, uint256 lockupDuration) external onlyOwner {
        require(!periodConfigs[periodId].active, "already configured");
        require(lockupDuration >= MIN_LOCKUP, "lockup too short");
        periodConfigs[periodId] = PeriodConfig(lockupDuration, true);
    }

    function cancelPeriodConfiguration(uint256 periodId) external onlyOwner {
        periodConfigs[periodId].active = false;
    }

    function deposit(uint256 periodId, uint256 amount) external {
        require(periodConfigs[periodId].active, "unknown period");
        deposits[msg.sender] = Deposit(amount, block.timestamp);
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }

    function withdraw(uint256 periodId) external {
        Deposit memory dep = deposits[msg.sender];
        require(block.timestamp >= dep.start + periodConfigs[periodId].lockupDuration, "still locked");
        deposits[msg.sender].amount = 0;
        require(token.transfer(msg.sender, dep.amount), "transfer failed");
    }
}
"""

# Same setter, but a sibling setter can replace the config.
_PERIOD_CLEAN_REPLACE = _TOKEN_IFACE + """
contract PeriodVaultReplaceable {
    IERC20Like public token;
    address public owner;
    uint256 public constant MIN_LOCKUP = 1 days;

    struct PeriodConfig {
        uint256 lockupDuration;
        bool active;
    }

    struct Deposit {
        uint256 amount;
        uint256 start;
    }

    mapping(uint256 => PeriodConfig) public periodConfigs;
    mapping(address => Deposit) public deposits;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function addPeriodConfiguration(uint256 periodId, uint256 lockupDuration) external onlyOwner {
        require(!periodConfigs[periodId].active, "already configured");
        require(lockupDuration >= MIN_LOCKUP, "lockup too short");
        periodConfigs[periodId] = PeriodConfig(lockupDuration, true);
    }

    function updatePeriodConfiguration(uint256 periodId, uint256 lockupDuration) external onlyOwner {
        require(lockupDuration >= MIN_LOCKUP, "lockup too short");
        periodConfigs[periodId] = PeriodConfig(lockupDuration, true);
    }

    function deposit(uint256 periodId, uint256 amount) external {
        require(periodConfigs[periodId].active, "unknown period");
        deposits[msg.sender] = Deposit(amount, block.timestamp);
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }

    function withdraw(uint256 periodId) external {
        Deposit memory dep = deposits[msg.sender];
        require(block.timestamp >= dep.start + periodConfigs[periodId].lockupDuration, "still locked");
        deposits[msg.sender].amount = 0;
        require(token.transfer(msg.sender, dep.amount), "transfer failed");
    }
}
"""

# ---------------------------------------------------------------------------
# 5. hook_sender_is_router_rebate_credit
# ---------------------------------------------------------------------------

_HOOK_VULN = _TOKEN_IFACE + _HOOK_STUBS + """
contract RebateHook {
    IPoolManager public poolManager;
    IERC20Like public rewardToken;
    uint256 public constant REBATE_PER_SWAP = 1e15;
    mapping(address => uint256) public rewards;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "only pool manager");
        _;
    }

    constructor(address _manager, address _reward) {
        poolManager = IPoolManager(_manager);
        rewardToken = IERC20Like(_reward);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        rewards[sender] += REBATE_PER_SWAP;
        return (this.afterSwap.selector, 0);
    }

    function claimRewards() external {
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "no rewards");
        rewards[msg.sender] = 0;
        require(rewardToken.transfer(msg.sender, amount), "transfer failed");
    }
}
"""

# The rebate is credited to the trader extracted from
# hookData, not to the router.
_HOOK_CLEAN = _TOKEN_IFACE + _HOOK_STUBS + """
contract RebateHookTrader {
    IPoolManager public poolManager;
    IERC20Like public rewardToken;
    uint256 public constant REBATE_PER_SWAP = 1e15;
    mapping(address => uint256) public rewards;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "only pool manager");
        _;
    }

    constructor(address _manager, address _reward) {
        poolManager = IPoolManager(_manager);
        rewardToken = IERC20Like(_reward);
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        address trader = abi.decode(hookData, (address));
        rewards[trader] += REBATE_PER_SWAP;
        return (this.afterSwap.selector, 0);
    }

    function claimRewards() external {
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "no rewards");
        rewards[msg.sender] = 0;
        require(rewardToken.transfer(msg.sender, amount), "transfer failed");
    }
}
"""

# The router is credited, but there is no claim path: the
# accrual is swept to a fixed treasury instead.
_HOOK_CLEAN_NO_CLAIM = _TOKEN_IFACE + _HOOK_STUBS + """
contract RebateHookSwept {
    IPoolManager public poolManager;
    IERC20Like public rewardToken;
    address public treasury;
    uint256 public constant REBATE_PER_SWAP = 1e15;
    mapping(address => uint256) public rewards;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "only pool manager");
        _;
    }

    constructor(address _manager, address _reward, address _treasury) {
        poolManager = IPoolManager(_manager);
        rewardToken = IERC20Like(_reward);
        treasury = _treasury;
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        rewards[sender] += REBATE_PER_SWAP;
        return (this.afterSwap.selector, 0);
    }

    function sweepToTreasury() external {
        uint256 amount = rewardToken.balanceOf(address(this));
        require(rewardToken.transfer(treasury, amount), "transfer failed");
    }
}
"""

# The router is credited and a claim exists, but the claim
# pays the fixed treasury, not the credited address.
_HOOK_CLEAN_CLAIM_TREASURY = _TOKEN_IFACE + _HOOK_STUBS + """
contract RebateHookClaimTreasury {
    IPoolManager public poolManager;
    IERC20Like public rewardToken;
    address public treasury;
    uint256 public constant REBATE_PER_SWAP = 1e15;
    mapping(address => uint256) public rewards;

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "only pool manager");
        _;
    }

    constructor(address _manager, address _reward, address _treasury) {
        poolManager = IPoolManager(_manager);
        rewardToken = IERC20Like(_reward);
        treasury = _treasury;
    }

    function afterSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        rewards[sender] += REBATE_PER_SWAP;
        return (this.afterSwap.selector, 0);
    }

    function claimRewards() external {
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "no rewards");
        rewards[msg.sender] = 0;
        require(rewardToken.transfer(treasury, amount), "transfer failed");
    }
}
"""

VULN = {
    "bridge_redeem_no_peg_circuit_breaker": _BRIDGE_VULN,
    "aa_validator_owner_branch_no_execution_policy": _VALIDATOR_VULN,
    "swap_exact_output_unbounded_max_input": _SWAP_VULN,
    "period_config_no_upper_bound_no_escape": _PERIOD_VULN,
    "hook_sender_is_router_rebate_credit": _HOOK_VULN,
}

CLEAN = {
    "bridge_redeem_no_peg_circuit_breaker": _BRIDGE_CLEAN,
    "aa_validator_owner_branch_no_execution_policy": _VALIDATOR_CLEAN,
    "swap_exact_output_unbounded_max_input": _SWAP_CLEAN,
    "period_config_no_upper_bound_no_escape": _PERIOD_CLEAN,
    "hook_sender_is_router_rebate_credit": _HOOK_CLEAN,
}

VARIANT = {
    "bridge_redeem_no_peg_circuit_breaker": _BRIDGE_VARIANT,
}

EXTRA_CLEAN = {
    "bridge_pause": _BRIDGE_CLEAN_PAUSE,
    "bridge_computed_rate": _BRIDGE_CLEAN_COMPUTED,
    "validator_single_branch": _VALIDATOR_CLEAN_SINGLE,
    "validator_no_policy_anywhere": _VALIDATOR_CLEAN_NO_POLICY,
    "swap_computed_cap": _SWAP_CLEAN_COMPUTED,
    "swap_passthrough": _SWAP_CLEAN_PASSTHROUGH,
    "period_cancel_path": _PERIOD_CLEAN_CANCEL,
    "period_replace_path": _PERIOD_CLEAN_REPLACE,
    "hook_no_claim": _HOOK_CLEAN_NO_CLAIM,
    "hook_claim_treasury": _HOOK_CLEAN_CLAIM_TREASURY,
}

EXTRA_VULN = {
    "swap_no_bound": _SWAP_VULN_NO_BOUND,
}
